#[cfg(feature = "multihop")]
use super::ParkedLinkStates;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use super::TestDrop;
use super::{
    DirectCounts, DirectState, IdleCounters, MeshSecrets, PingRound, Reach, RivalFlag, RosterEntry,
    RosterSnapshot, StateInit,
};
use crate::daemon::cohost_arm;
use crate::daemon::doc::MeshDoc;
use crate::daemon::probe_backoff::ProbeBackoff;
use crate::daemon::reassembly::{self, ReassemblyStore, ShardCache, ShardIngest};
use crate::daemon::setup::LiveCount;

use crate::transport::UdpTransport;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use iroh::{EndpointAddr, EndpointId};

use crate::daemon::message_log::MessageLog;
#[cfg(feature = "host")]
use crate::daemon::state_file::StateFile;
use crate::protocol::identity::Identity;
use crate::protocol::mesh::Mesh;
use crate::protocol::message::{Authored, Verified, WireFrame};
use crate::protocol::{
    AuthorKey, ContentHash, DedupKey, Nickname, ShardGroup, SymmetricKey, UnixSecs,
};
use crate::util::bounded_fifo_set::BoundedFifoSet;
use crate::util::bounded_queue::BoundedQueue;
use crate::util::clock::Instant;
use crate::util::cooldown::Cooldown;

use crate::util::tuning::{
    KNOWN_ENDPOINTS_CAP, LANE_WANTED, MESSAGE_LOG_SIZE, PENDING_OUTBOUND_CAP, QUIET_CAP,
    RECLAIM_WINDOW, REGRAFT_AFTER, RELINK_COOLDOWN, SEEN_IDS_CAP, STARVED,
};

use crate::gossip::{antientropy, lan};
use crate::protocol::{crypto, message};
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::transport::redial;
#[cfg(feature = "multihop")]
use crate::transport::underlay_webrtc;
use crate::transport::{graft_backoff, probe, proven_endpoints};
use crate::util::tuning;
use iroh::address_lookup::memory;
use tokio::sync::{mpsc, oneshot};

use crate::{beacon, gossip, protocol, transport};
/// All mutable state owned by the event loop.
///
/// Grouped into a single struct so handlers and timer ticks can take
/// `&mut EventLoopState` instead of each borrowing half a dozen
/// independent locals.
///
/// The peer-tracking fields are deliberately one-per-layer (see the
/// Concept Glossary in AGENTS.md): `linked_endpoints` (transport),
/// `peers` (membership roster), `surfaced` (presentation gate),
/// `quiet` (heartbeat-evicted). Never conflate them — they are keyed
/// differently (node id vs nickname) and have different lifetimes.
///
/// # Examples
///
/// The event loop state is the state that the node keeps between events. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::EventLoopState;
///
/// # fn demo(state: &EventLoopState) {
/// let _ = state;
/// # }
/// ```
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent lifecycle edges (gossip_open/rendezvous_linked/announced/meshed/degraded) plus the one-shot resident_memory_warned latch; each tracks a distinct transition, not a config bundle worth a sub-struct"
)]
#[derive(Debug)]
pub struct EventLoopState {
    /// Transport layer: the **live** gossip neighbor links, written only
    /// by `NeighborUp`/`NeighborDown` (a received `PeerInfo` is a dial
    /// hint, not a link). Link *truth* matters: the silent-partition WARN
    /// and the healer's re-bridge gate read this set, and an optimistic
    /// entry for a link that never formed has no `NeighborDown` to remove
    /// it — a permanent ghost that suppressed both (the 2026-06-12
    /// roster-collapse). Bounded by `HyParView`'s `active_view_capacity`.
    /// Distinct from `peers` — links are asymmetric and node-id
    /// keyed; the roster is symmetric and nickname keyed.
    pub(crate) linked_endpoints: HashSet<EndpointId>,
    /// When `linked_endpoints` last became empty, `None` while it holds a link. The census warns
    /// of a silent partition only when this gap outlasts a heal: see
    /// [`Self::silent_partition_due`].
    zero_links_since: Option<Instant>,
    /// Whether each known peer's data path is direct or relay-only: the
    /// `conn_path` snapshot `NeighborUp` logs, or a probe verdict. Keyed like
    /// `peer_endpoints` and pruned with it (`forget_peer_endpoint`), not on
    /// `NeighborDown`: the verdict describes the pooled connection, which
    /// outlives the gossip link. Feeds the census and the roster; when the
    /// relay is lookup only it is also what the send lanes consult before
    /// carrying payload.
    pub(crate) direct: HashMap<EndpointId, DirectState>,
    /// Mirrors `TransportPolicy::relay`, set once at loop start.
    pub(crate) relay_transport: transport::PayloadPath,
    /// Where a direct-path probe reports its verdict; the loop's receiver
    /// grafts on it (`transport::probe::on_outcome`). A detached sender until
    /// the real loop installs its channel.
    pub(crate) direct_proven: mpsc::UnboundedSender<probe::DirectOutcome>,
    /// The gossip transport, when the engine installs one (Phase 6, step 10). The split of the
    /// mesh topic hands it the frames, and counts a lag on it.
    pub(crate) gossip_handle: Option<habilis_network_iroh_gossip_transport::GossipHandle>,
    /// Where a path watcher reports a change of the selected path to a peer
    /// the race covers (`transport::probe::on_path_change`).
    pub(crate) path_changes: mpsc::UnboundedSender<probe::PathChange>,
    /// Where a flushed frame whose dial failed comes back to the loop, to be buffered again
    /// (`gossip::requeue_failed`). A detached sender until the real loop installs its channel.
    pub(crate) flush_failed: mpsc::UnboundedSender<(Verified, WireFrame)>,
    /// The pooled connection each watched peer's watcher follows, by stable
    /// id (`None` while its dial runs), so a replaced connection gets a fresh
    /// watcher and a stale one's reports are dropped.
    pub(crate) path_watchers: HashMap<EndpointId, Option<usize>>,
    /// The last selected path kind each watcher reported, for the alive
    /// tick's nudge of peers riding `WebRTC`.
    pub(crate) path_kinds: HashMap<EndpointId, probe::PathKind>,
    /// The multihop route that was last dialed for each pair on the relay, so that a route that
    /// arrives between two alive ticks is dialed once, and a route that was dialed is not dialed
    /// again by a link-state event (the alive tick dials it as the backstop).
    pub(crate) route_dialed: HashMap<EndpointId, iroh::TransportAddr>,
    /// Re-bridge memory: every peer `EndpointId` we've ever linked to,
    /// kept *across* `NeighborDown` (unlike `linked_endpoints`). When a
    /// node loses all links because the rendezvous/relay is unreachable,
    /// the healer re-dials these directly — iroh still holds their cached
    /// addresses — so the re-bridge no longer depends on the rendezvous.
    /// Bounded FIFO (cap `KNOWN_ENDPOINTS_CAP`) so it can't grow without limit.
    pub(crate) known_endpoints: BoundedFifoSet<EndpointId>,
    /// The endpoint each signing key proved in its `PeerInfo`: the only
    /// point-to-point target an anti-entropy answer may take, since a
    /// nickname is a label any signer can claim.
    pub(crate) proven_endpoints: proven_endpoints::ProvenEndpoints,
    /// Our own `PeerInfo` proof, made once: it is the same for the session.
    pub(crate) peer_info_proof: Option<String>,
    /// Per-endpoint re-link throttle: caps re-dialing + re-flooding a peer
    /// learned via `PeerInfo` to once per window. Tracked *across*
    /// `NeighborDown` (unlike `linked_endpoints`), so a flapping/unstable peer
    /// is re-linked at most once per `RELINK_COOLDOWN` — the choke that
    /// stops one bad node's flap from amplifying into a mesh-wide connection
    /// storm. Bounded by construction (see [`Cooldown`]).
    pub(crate) relink: Cooldown<EndpointId>,
    /// When we last flooded our `PeerInfo`, whatever triggered it. Stamped by
    /// `broadcast_peer_info`; read by the `joined` and `NeighborUp` re-flood gates.
    pub(crate) peerinfo_flooded_at: Option<Instant>,
    /// A `NeighborUp` wanted to flood our `PeerInfo` inside the window and was
    /// held back. The alive tick pays it once the window ends.
    pub(crate) peerinfo_deferred: bool,
    /// The address our last `PeerInfo` carried. `None` until the first flood.
    /// Stamped by `broadcast_peer_info`; read by `address_flood_due`.
    pub(crate) last_flooded_addr: Option<EndpointAddr>,
    /// Tests only: the closes of direct connections and the reconnects soon after.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) redials: redial::Redials,
    /// Since when this node holds two or more links fewer than G, with the link to
    /// the rendezvous counted. Cleared as soon as it holds G - 1. See `note_link_count`.
    pub(crate) below_target_since: Option<Instant>,
    /// When a graft last fell back to a `Join` for a starved node.
    pub(crate) join_fallback_at: Option<Instant>,
    /// The peers that refused a `Neighbor` request, and the wait before they are asked again.
    pub(crate) graft_backoff: graft_backoff::GraftBackoff,
    /// The lane peers that a frame is held for, and since when. Such a peer is offered a
    /// session although nothing was sent over a connection yet.
    lane_wanted: HashMap<EndpointId, Instant>,
    /// The proven peers whose gossip link went down, with the time of their quick re-graft.
    regraft_at: HashMap<EndpointId, Instant>,
    /// When each author's digest was last served. Keyed on the author key rather
    /// than the nickname, which an author picks freely. The key is an `Option`
    /// because a digest built with no signature is a valid input of the tests: `None`
    /// is its own bucket, as the empty string was.
    digest_serves: Cooldown<AuthorKey>,
    /// When we last reported an author whose digest we could not read. An `Option` key
    /// for the same reason as `digest_serves`.
    digest_unreadable: Cooldown<AuthorKey>,
    /// Where a digest answer goes, so that the loop never waits to send it. The
    /// task that drains it takes `resend_receiver` when the loop starts.
    pub(crate) resend_outbox: transport::ResendOutbox,
    /// Tests only: the one inbound frame to drop before the app reads it, as a full queue between
    /// the gossip layer and the loop does. The gossip layer has counted it as delivered.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) test_drop: Option<TestDrop>,
    /// Tests only: how many frames the hook dropped.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) test_drops_fired: u32,
    pub(crate) resend_receiver: Option<mpsc::Receiver<transport::Resend>>,
    /// When each asker's state or meta digest was last served, per plane. A
    /// new node sends a digest pair for every peer it sees, all with the same
    /// heads, and every holder hears each one; the plane is in the key so the
    /// asker's re-ask at its first real-peer link, answered point-to-point,
    /// is not refused by the gossip answer before it.
    pub(crate) state_digest_serves: antientropy::ServeBudget,
    /// This node's own fast rounds of state digests while it backfills.
    pub(crate) fast_rounds: antientropy::FastRounds,
    /// Membership layer: the peer roster. Nickname-keyed set of
    /// other peers, feeding the state file's `peer_count`
    /// (`peers.len() + 1`). Excludes self. Driven by
    /// `joined`/`left` presence messages (they reach every peer
    /// via gossip; `NeighborUp`/`PeerInfo` are asymmetric for
    /// bootstrap links), by implicit heartbeats from any received
    /// message (self-heal for a missed Joined), and by the sweeper's
    /// eviction of peers gone silent past `ALIVE_TIMEOUT`.
    pub(crate) peers: HashSet<Nickname>,
    /// Implicit-heartbeat tracker: nickname -> last time we heard
    /// anything from that peer. Drives sweep-based eviction.
    pub(crate) last_seen: HashMap<Nickname, Instant>,
    /// Bridge from membership back to transport: nickname -> the endpoint id
    /// that nickname last self-advertised in a signed `PeerInfo`. That
    /// signature is the only thing tying a nickname to an endpoint (the
    /// signing key is deliberately not the transport key), so this is the one
    /// place the roster can tell whether a peer is a live link.
    /// Last-writer-wins (a restart re-advertises a new endpoint under the same
    /// name). Pruned with `peers`, so it stays bounded by the roster.
    /// Feeds only the derived `reach` boolean in `roster_snapshot` — the node
    /// id never leaves this layer.
    pub(crate) peer_endpoints: HashMap<Nickname, EndpointAddr>,
    /// The mesh's rendezvous endpoint id, once known. Paired with
    /// `rendezvous_linked` so `reach_of` can count the rendezvous link as a
    /// live link to the beacon: the beacon gossips *as* the rendezvous, so a
    /// joiner's only link to it is that pseudo-node link (kept out of
    /// `linked_endpoints` by design). `None` until the loop learns it.
    pub(crate) rendezvous_id: Option<EndpointId>,
    /// Heartbeat layer: peers we've evicted as quiet (silent
    /// past `ALIVE_TIMEOUT`) but who may still reappear. Any
    /// message from a nickname in this set triggers a symmetric
    /// `peer_return` event and re-inclusion in `peers`. Bounded FIFO
    /// (cap `QUIET_CAP`): drained on return, so without the cap a churn /
    /// sybil stream of one-shot nicknames would grow it without bound.
    pub(crate) quiet: BoundedFifoSet<Nickname>,
    /// Recency companion to `quiet`: nickname -> the `last_seen` instant a
    /// quiet peer had when it was evicted, so [`roster_snapshot`] can still
    /// report how long ago it was last heard (the eviction drops its
    /// `last_seen` entry). Pruned to `quiet`'s membership on every sweep, so
    /// it stays bounded by `QUIET_CAP`; `roster_snapshot` only reads it for
    /// peers currently in `quiet`, so a stale entry never surfaces.
    pub(crate) quiet_since: HashMap<Nickname, Instant>,
    /// Peers that said goodbye, with the timestamp of their `left`. A message of such a peer
    /// that is stamped no later was sent before the goodbye and reached us after it (a
    /// re-announce still in flight, a replayed message): it is no proof of presence and brings
    /// the peer back into neither the roster nor the surfaced arrivals. A message stamped later is
    /// a real return. Bounded like `quiet`; pruned to the same FIFO on every sweep.
    pub(crate) left: BoundedFifoSet<Nickname>,
    /// The timestamps of [`Self::left`], pruned to its membership.
    pub(crate) left_at: HashMap<Nickname, UnixSecs>,
    /// The keys that said goodbye. A key is minted per run, so a key that left never speaks again:
    /// anything it signs afterwards is a replay, whatever its timestamp says. Keyed on the key
    /// and not on the nickname, which another run may take.
    ///
    /// Bounded like `quiet` and `left`, by the same rule: keys are free, so an unbounded set is
    /// a memory leak under churn. The bound is a second layer, not the first: a replay of a
    /// frame this node still holds is dropped by [`Self::mark_seen`] before membership sees it,
    /// whatever this set holds. What the bound gives up is narrow: a frame of a key that left
    /// more than `QUIET_CAP` departures ago, that this node never held, counts as an arrival
    /// until its author goes quiet.
    pub(crate) left_keys: BoundedFifoSet<AuthorKey>,
    /// Presentation layer: peers for whom we have *surfaced* an
    /// arrival (synthetic `joined`, real `Presence::Joined`, or
    /// `peer_return`). Gates departure surfacing so a peer whose
    /// join we never showed never produces a `went quiet` / `has left`
    /// line — keeps the join-horizon view symmetric. Presentation-only:
    /// the roster (`peers`) stays complete for
    /// anti-entropy/membership; `surfaced ⊆ peers` only governs
    /// what the operator/agent is shown.
    pub(crate) surfaced: HashSet<Nickname>,
    /// Last time we broadcast anything. Lets idle daemons suppress
    /// their `Alive` keepalive when they're already chatty.
    pub(crate) last_sent_at: Instant,
    /// Wall-clock unix seconds when this daemon started — its join
    /// instant. The node still receives & relays older messages
    /// (anti-entropy keeps the mesh's set uniform), but messages
    /// stamped before this are never *surfaced* (printed / `poll` /
    /// `fetch` / library API): the operator/agent view starts at join.
    pub(crate) joined_at: UnixSecs,
    /// Goes false when the receiver stream terminally ends; IPC
    /// keeps working for `msg` / `poll` after that.
    pub(crate) gossip_open: bool,
    /// Whether the gossip overlay currently links us to the co-hosted
    /// rendezvous (its `NeighborUp`/`NeighborDown` arms drive it). Gates
    /// the healer's connect-probe: probing the rendezvous while a live
    /// link exists makes the beacon's gossip *adopt* the probe
    /// connection and then mark the peer down when the probe handle
    /// drops — one rendezvous-link flap per heal tick, forever (the
    /// 2026-05-30 soak's residual flap).
    pub(crate) rendezvous_linked: bool,
    /// Whether we let go of the rendezvous link on purpose (see
    /// [`Self::should_release_rendezvous`]). The `NeighborDown` that follows
    /// is then no loss, so nothing re-grafts it or arms a reclaim for it.
    /// Cleared when the link comes back.
    pub(crate) rendezvous_released: bool,
    /// When a node that let go of the rendezvous on purpose wants it again, although it holds
    /// links enough: one period after the release, plus a share from its id. A mesh that split
    /// into islands, each with links enough, has no other reason to visit the rendezvous, which
    /// is the one place where the islands meet. The heal tick pays it as an owed return and sets
    /// the next one a period later ([`Self::pay_periodic_return`]); a link that comes back clears
    /// it, and the next release sets it again.
    pub(crate) rendezvous_return_due: Option<Instant>,
    /// A return to the rendezvous is owed, until this instant, although this
    /// node holds enough links to others. Set when a silent roster peer is
    /// swept on a node that is not linked to it (a partition may have split the
    /// mesh into islands, and the rendezvous is where they meet again) and on a
    /// resume edge (every link is stale). It ends when the link comes back, or
    /// at the deadline: an owed return is a debt with an end.
    pub(crate) rendezvous_comeback_until: Option<Instant>,
    /// A node that came back to the rendezvous does not let go before this
    /// instant, so that the beacon can introduce it to the other island.
    pub(crate) rendezvous_dwell_until: Option<Instant>,
    /// This process co-hosts the rendezvous. Its own link to it keeps the
    /// beacon's gossip view non-empty, which is what lets a joiner be
    /// introduced to the mesh: if the host let go as well, a joiner arriving
    /// after the early members had released would find an empty view and the
    /// mesh would split into islands (the 18-node test shows it). So this
    /// node never releases the link.
    pub(crate) hosts_rendezvous: bool,
    /// A holder with a lower member id said, in its `PeerInfo`, that it holds the rendezvous
    /// too. The next due re-check then sheds at once, whatever depends on this beacon: the
    /// rival's flag already settled who keeps it. Cleared by the shed and by a fresh claim.
    pub(crate) yield_to_lower: bool,
    /// What the last `PeerInfo` we flooded said about `hosts_rendezvous`, so the flag is sent
    /// again when it changes.
    pub(crate) beacon_flag_flooded: bool,
    /// The members that said in their `PeerInfo` that they hold the rendezvous, by the signing
    /// key and the endpoint that key proved. A `PeerInfo` of the same signer without the flag,
    /// or the roster removal of the member, takes it out again. While it is not empty and we do
    /// not hold the rendezvous, we do not probe to claim it.
    pub(crate) rival_holders: HashMap<AuthorKey, EndpointId>,
    /// How many links to other members make this node release the rendezvous.
    /// A field, not a constant, so a test can set it.
    pub(crate) rendezvous_release_links: usize,
    /// Whether the held rendezvous `WebRTC` session has already survived one
    /// heal tick without producing a link — the arming half of the stale
    /// detach in `negotiate_rendezvous_session`.
    pub(crate) rendezvous_session_stale: bool,
    /// Whether an IP-capable node's rendezvous JSEP offer is armed. IP
    /// capability normally means the punch inside the bootstrap connection
    /// reaches the rendezvous — but it says nothing about the *beacon*: a
    /// browser-held rendezvous has no UDP to punch to. The first linkless
    /// heal tick sets this instead of offering; the second offers. Cleared
    /// on the rendezvous `NeighborUp`, so a healthy mesh never offers.
    pub(crate) rendezvous_offer_fallback: bool,
    /// Whether this mesh's rendezvous answers JSEP. Only a public beacon does
    /// (`beacon::build_rendezvous_endpoint`); a private ladder rendezvous has
    /// no `WebRTC` handle, so an offer to it can never attach, and the offer
    /// fallback must never arm there.
    pub(crate) rendezvous_answers_jsep: bool,
    /// Whether the previous rival probe read the public rendezvous as free.
    /// A claim needs two: a single free verdict may have landed inside a
    /// live beacon's rival-re-check release window, and claiming on it is
    /// what created rival copies that shed each other indefinitely. Both
    /// must fall in one arbitration, so every reopen or settle of the
    /// rendezvous identity clears it (`forget_rendezvous_verdict`).
    pub(crate) rendezvous_probe_read_free: bool,
    /// The wait between two rival probes started on the heal tick; see `ProbeBackoff`.
    pub(crate) probe_backoff: ProbeBackoff,
    /// Whether grafting the rendezvous must wait for an attached `WebRTC`
    /// session — true for a webrtc-shaped node on a lookup-only mesh; see
    /// `transport::webrtc::rendezvous::rendezvous_graftable`.
    pub(crate) rendezvous_graft_needs_session: bool,
    /// Whether this node runs IP transports (`TransportOpts::ip`, and never
    /// on wasm). The local half of every `WebRTC` lane decision — read from
    /// here, not from the endpoint address, which is empty whenever the relay
    /// link is down.
    pub(crate) local_udp_transport: UdpTransport,
    /// Set once we've broadcast our arrival (`joined` + `PeerInfo`).
    /// The announce is deferred to the first `NeighborUp` so it isn't
    /// lost into an unconnected overlay; subsequent neighbors only get
    /// a (log-invisible) `PeerInfo` re-send.
    pub(crate) announced: bool,
    /// Set once we have a link to a *real peer* (a non-
    /// rendezvous `NeighborUp`). `announced` flips on any neighbor —
    /// including the rendezvous relay — which is too early to deliver
    /// user content (the relay path may not be converged). Outbound
    /// user messages are buffered until `meshed`, then flushed, so the
    /// first message after a join can't be a lost one-shot.
    pub(crate) meshed: bool,
    /// The unicast (point-to-point) connection pool: dials + reuses a QUIC
    /// connection to each addressable peer so a directed message goes
    /// p2p instead of flooding the gossip mesh. Interior-mutable (Arc), so the
    /// send helpers reach it through `&EventLoopState`. `new` installs a
    /// detached pool; the real loop replaces it with an endpoint-backed one.
    /// Independent of `linked_endpoints` by design (unicast can reach a
    /// non-neighbor). See [`crate::transport`].
    pub(crate) unicast_pool: transport::UnicastPool,
    /// The multi-hop transport handle, when the mesh policy registered it
    /// on the peer endpoint. Owns the routing table (fed from received
    /// `LinkState` frames) and the underlay endpoint. `None` when multihop is off
    /// or on a non-peer (beacon/rendezvous) endpoint. See
    /// [`habilis_network_iroh_multihop_transport`].
    #[cfg(feature = "multihop")]
    pub(crate) multihop: Option<habilis_network_iroh_multihop_transport::MultihopHandle>,
    /// The `WebRTC` leg of the multihop underlay: its handle, admission table and
    /// endpoint. `None` when multihop is off. See
    /// [`crate::transport::underlay_webrtc`].
    #[cfg(feature = "multihop")]
    pub(crate) underlay_webrtc: Option<underlay_webrtc::UnderlayWebRtc>,
    /// The link vectors whose author has no endpoint bound in the roster yet, until the binding
    /// is written (see `bind_peer_endpoint`).
    #[cfg(feature = "multihop")]
    pub(crate) parked_link_states: ParkedLinkStates,
    /// The links that this node advertised in its last link vector, whichever arm sent it. A link
    /// that comes up sends a vector only when the set is another one, so that a link that flaps
    /// does not cause a broadcast per flap, and a second link that comes up 100 ms after the
    /// first is not held back until the tick. See `event_loop::linkstate_now`.
    #[cfg(feature = "multihop")]
    pub(crate) last_advertised: Option<Vec<(EndpointId, u32)>>,
    /// Tests only: while set, this node advertises no link-vector, on the tick or on a link
    /// event. A test sets it to force the order "the path is lost before any route exists".
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "multihop",
        not(target_arch = "wasm32")
    ))]
    pub(crate) linkstate_held: bool,
    /// Tests only: this node claims no rendezvous, neither on a heal tick nor in a reclaim window,
    /// while it is set. A test uses it to force the order "a late joiner claims the free rung
    /// before any old member does", which a heal tick of a few seconds would otherwise win.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) claims_held: bool,
    /// What this node knows of the busy rungs of a private ladder, and the probe tasks that find
    /// out more. The claim walk and the check of the lower rungs read it and never wait.
    pub(crate) rungs: beacon::RungWatch,
    /// Tests only: the beacon is shed at the top of the next turn of the loop, as a re-check
    /// shed does (`Beacons::ShedBeacon`).
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) shed_requested: bool,
    /// Tests only: the beacon stops answering at the top of the next turn of the loop
    /// (`Beacons::StallBeacon`).
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) stall_requested: bool,
    /// What this node already asked of the members it heard on the LAN.
    pub(crate) lan_grafts: lan::LanGrafts,
    /// The `WebRTC` transport handle, when one is registered on this peer's
    /// endpoint. Portable — it is the browser's only direct path, and an
    /// opportunistic extra one for a native peer. `None` on the beacon.
    pub(crate) webrtc: Option<habilis_network_iroh_webrtc_transport::WebRtcHandle>,
    /// Who may start a JSEP round, and how many may run at once.
    ///
    /// `has_session` only flips at *attach*, so without an in-flight record a
    /// membership event and a re-flood of the same `PeerInfo` both start a
    /// negotiation with the same peer, and the loser fails on duplicate attach
    /// after paying a full gathering budget.
    ///
    /// Shared with the signal *acceptor* on the Router, not owned by the loop,
    /// so the direct-peer ceiling is one number for this node rather than one
    /// per role. See [`crate::transport::SignalAdmission`].
    pub(crate) webrtc_admission: transport::SignalAdmission,
    /// The address book of the member endpoint (`lookup::address_book`): where the addresses of the
    /// peers are registered with `lookup::add_peer_addr`.
    pub(crate) address_book: memory::MemoryLookup,
    /// How far ICE may reach when this peer gathers candidates. Host-only on a
    /// loopback mesh, which promises to make no external network call —
    /// `IceConfig::default()` would query two public STUN servers.
    pub(crate) webrtc_ice: transport::IceProfile,
    /// When `Some(deadline)` and not yet elapsed, the event loop runs
    /// a fast `beacon::ensure` burst (event-driven failover). Armed by
    /// `arm_reclaim`, mostly on `NeighborDown` — the beacon may have just
    /// died — so a survivor claims the freed rendezvous port in ~1s rather
    /// than waiting for the next 15s heal tick.
    pub(crate) reclaim_until: Option<Instant>,
    /// When `Some(deadline)`, the next rival re-check *shed* of an
    /// `EagerProbed` public beacon: at the deadline the holder drops its
    /// co-host and lets probe-before-claim re-arbitrate, so a same-id
    /// rival that claimed inside our probe window is finally found and
    /// yielded to (see `event_loop::shed_rival_beacon_if_due`). `None`
    /// while not holding a shed-eligible beacon.
    pub(crate) next_rival_recheck: Option<Instant>,
    /// How many rival re-check sheds have run. Round 0 (the claim made at
    /// startup, before any shed) schedules the *fast first* re-check with
    /// the deterministic endpoint-id tie-break offset — the likeliest
    /// rival started within seconds of us; later rounds run the steady
    /// jittered cadence.
    pub(crate) rival_recheck_rounds: u32,
    /// When a sign of a second group last brought the re-check forward
    /// ([`Self::note_second_group_sign`]).
    pub(crate) second_group_sign_at: Option<Instant>,
    /// When the member last said that every rung of its ladder is held by another process.
    pub(crate) no_rung_noted_at: Option<Instant>,
    /// Consecutive due sheds held back because a data-channel peer depends
    /// on this beacon; see `cohost_arm::defer_shed`. Cleared by a shed and by a
    /// fresh claim (`cohost_arm::schedule_rival_recheck`).
    pub(crate) rival_recheck_deferrals: u32,
    /// The close of the beacon that a rival re-check just shed: when it resolves the loop
    /// re-probes the id at once, instead of at the next reclaim tick. `None` when no shed runs.
    pub(crate) beacon_closing: Option<oneshot::Receiver<()>>,
    /// Recently-seen message ids, for duplicate suppression. Gossip
    /// (GRAFT/repair, topology churn, our own re-broadcasts, anti-entropy
    /// re-sends, the rendezvous double-path) can deliver the same message
    /// twice; `mark_seen` drops the repeat before it reaches the log /
    /// inbound push channel / agent. Bounded (`SEEN_IDS_CAP`, 2× the message log)
    /// so it always covers the retention window.
    pub(crate) seen: BoundedFifoSet<DedupKey>,
    /// User messages sent before we had a real-peer link (no gossip
    /// path yet — a bare `broadcast` would be a lost one-shot). Drained in
    /// FIFO order once `meshed` flips, each routed through the send decision;
    /// the parsed frame rides beside its wire bytes so the flush never
    /// re-parses what this node just serialized. A bounded FIFO queue (cap
    /// `PENDING_OUTBOUND_CAP`) so the backlog can't grow without limit.
    pub(crate) pending_outbound: BoundedQueue<(Verified, WireFrame)>,
    #[cfg(feature = "host")]
    pub(crate) state_file: Option<StateFile>,
    /// Whether the event loop is serving IPC yet. Starts `false` (the
    /// pre-loop state-file write reports "identity up, not yet serving");
    /// flipped `true` once the loop is draining, so a state-file reader
    /// (a readiness gate) can gate on a write that means the daemon will answer.
    pub(crate) ready: bool,
    /// When advertising (`create --advertise`), the directory's
    /// re-broadcast task reads the live peer count from here.
    /// Mirrors `peer_count` (`peers.len() + 1`), refreshed
    /// alongside every `write_peer_count`. `None` for the common
    /// non-advertising case (no shared counter to maintain).
    pub(crate) live_count: Option<LiveCount>,
    pub(crate) message_log: MessageLog,
    /// Shard groups already reassembled + surfaced, so a body is surfaced
    /// once even if a shard is re-fetched (via anti-entropy) after its id aged
    /// out of [`seen`](Self::seen). Bounded — groups are rare and short-lived.
    pub(crate) reassembled_groups: BoundedFifoSet<ShardGroup>,
    /// Partial multipart bodies buffering toward reassembly — dedicated and
    /// byte-budgeted, decoupled from the message log so log eviction can
    /// never break reassembly. Swept for stale groups on the prune tick.
    pub(crate) reassembly: ReassemblyStore,
    /// Serialized frames of our recent big (unlogged) outbound shard groups —
    /// the re-serve source for peers' `shard/repair` requests (big groups
    /// skip the message log, so anti-entropy can't heal them).
    pub(crate) shard_cache: ShardCache,
    /// The `state` channel: an automerge CRDT plus the signed change frames that
    /// carried it (the re-serve store). Convergence and card authorization live
    /// in [`crate::daemon::doc`]; reconciliation is heads-based anti-entropy. This is the
    /// document a consumer's `state get` surface reads.
    pub(crate) state_doc: MeshDoc,
    /// The `meta` channel's document — a second, independent shared-state channel.
    /// Gates foreign-card writes (unlike `state`), since a `meta` card carries a
    /// peer's cryptographic identity.
    pub(crate) meta_doc: MeshDoc,
    /// Rolling start index for the **chat** anti-entropy digest window: each
    /// round advertises `message_log[digest_cursor ..]` (up to
    /// `ANTIENTROPY_DIGEST_MAX_IDS`), then advances/wraps so a log larger
    /// than one digest is swept over several rounds. (State/meta reconcile by
    /// automerge heads and need no cursor.)
    ///
    /// A position in the log in bound order, and the log changes between rounds:
    /// an insert before the cursor moves every later position by one, so a sweep
    /// can skip a slice or list one twice. Each window is still right by
    /// itself, and the next sweep covers a skipped slice, so it only delays.
    pub(crate) digest_cursor: usize,
    /// This member's signing identity (Ed25519). Shared with the
    /// send path so messages we author are signed before broadcast.
    /// The public key is the durable identity; the nickname is a
    /// non-unique display label (see `docs/history-integrity.md`).
    pub(crate) identity: Arc<Identity>,
    /// Our own per-author log cursor (Phase 2): `self_seq` is the next
    /// `Msg` sequence number to emit, `self_prev` the content hash of our
    /// last sent `Msg` (`None` until the first). Advanced on every send so
    /// our `Msg` stream is a `seq`+`prev` hash chain.
    pub(crate) self_seq: u64,
    pub(crate) self_prev: Option<ContentHash>,
    /// Phase 2 fork detection: per author key, the content hash
    /// seen at each `Msg` `seq`. A *different* hash at an already-seen
    /// `(author, seq)` is cryptographic proof of equivocation → a `fork`
    /// event. Order-independent (gossip delivers out of order).
    pub(crate) author_seqs: HashMap<AuthorKey, HashMap<u64, ContentHash>>,
    /// Author keys already flagged as forked, so one `fork` event fires
    /// per offending key rather than per message.
    pub(crate) forked: HashSet<AuthorKey>,
    /// Cross-author DAG (Phase 3): `by_hash` maps each known `Msg`'s content
    /// hash to its timestamp (for the `ts ≥ max(parents.ts)` backdating
    /// rule); `dag_heads` is the current tip set (hashes with no observed
    /// child) — the `parents` stamped on the next `Msg` we author. Both are
    /// pruned alongside the message-log eviction.
    pub(crate) by_hash: HashMap<ContentHash, UnixSecs>,
    pub(crate) dag_heads: HashSet<ContentHash>,
    /// When the last *verified* inbound gossip message arrived — the
    /// starvation watchdog's signal. Keyed on messages, not neighbor
    /// events: the roster-collapse showed links can look alive (or flap)
    /// while no traffic flows, and traffic is what membership feeds on.
    pub(crate) last_inbound_at: Instant,
    /// When the watchdog last ran a starvation recovery, if ever.
    /// Paired with `recovery_trips` to back off repeated attempts so a
    /// legitimately-last-survivor node settles into a sparse retry
    /// instead of warning every threshold period.
    pub(crate) last_recovery_at: Option<Instant>,
    /// Consecutive starvation recoveries without any inbound in between
    /// (drives the backoff; reset by `note_inbound`).
    pub(crate) recovery_trips: u32,
    /// `meshed` was cleared by a fault path (starvation recovery / hard
    /// resume edge) rather than never having been set. Gates
    /// `note_inbound`'s meshed-restore so a fresh joiner's pre-mesh
    /// inbound never flips `meshed` early; only a degraded node heals
    /// on traffic. See [`Self::note_degraded`].
    pub(crate) degraded: bool,
    /// Latch for the warn-only resident-memory leak signal: set once this
    /// process's resident memory first crosses `tuning::resident_memory_warn_mb`,
    /// so the `warn` fires exactly once per process rather than every prune
    /// tick. Purely observability — never gates behavior (see
    /// `timers::tick_prune`).
    pub(crate) resident_memory_warned: bool,
    /// Active ping round, if one is in flight. Armed by the
    /// `Ping` IPC command, filled by inbound `Pong`s, and finalized
    /// into a `ping_report` when its `deadline` elapses. One at a time:
    /// a fresh ping replaces any in-flight round. Boxed to keep the
    /// rarely-set round off the hot event-loop future's stack size.
    pub(crate) ping_round: Option<Box<PingRound>>,
    /// The raw mesh password when the mesh is password-protected (`None`
    /// otherwise). Handed to the blob server on its first offload so every
    /// blob ticket inherits the same password — a scraped ticket then can't be
    /// redeemed without it. Kept out of logs (`Password` redacts its `Debug`).
    pub(crate) mesh_password: Option<crypto::Password>,
    /// The invite-only **creator's** mesh (secrets and all), retained so the
    /// `invite` IPC command can mint. `Some` only on the creator; set from
    /// [`EventLoopConfig`] after construction, so `new` defaults it to `None`
    /// and the many test call sites need no new argument.
    pub(crate) mint_mesh: Option<Mesh>,
    /// Symmetric key for broadcast-chat app bodies on a passworded
    /// mesh, `derive_secret(mesh_key, "broadcast")` — domain-separated from
    /// the state/meta doc keys. `None` ⇒ chat stays plaintext. Wiped on drop.
    pub(crate) broadcast_key: Option<SymmetricKey>,
    /// Where the event loop's wakeups went since the last census.
    pub(crate) idle: IdleCounters,
}

impl EventLoopState {
    /// Build a fresh event-loop state. `now` is passed explicitly so
    /// tests can pin a deterministic instant. `secrets` is taken by value (not
    /// `&MeshSecrets`) so its `key` is dropped (zeroized) here once the
    /// per-channel keys are derived, rather than lingering in the caller.
    #[expect(
        clippy::too_many_lines,
        reason = "one initializer for every field of the state"
    )]
    pub(crate) fn new(init: StateInit, now: Instant) -> Self {
        let StateInit {
            #[cfg(feature = "host")]
            state_file,
            identity,
            secrets,
            per_peer_gate,
            webrtc_admission,
            address_book,
            webrtc_ice,
        } = init;
        let MeshSecrets {
            password: mesh_password,
            key: mesh_key,
        } = secrets;
        let (resend_outbox, resend_receiver) =
            transport::ResendOutbox::new(tuning::RESEND_OUTBOX_CAP);
        // Per-channel encryption keys, domain-separated from each other and from
        // every other seed-derived secret. `None` (passwordless) ⇒ the docs and
        // broadcast chat stay plaintext, exactly as before.
        let state_key = mesh_key.as_ref().map(|key| key.derive(b"state-doc"));
        let meta_key = mesh_key.as_ref().map(|key| key.derive(b"meta-doc"));
        let broadcast_key = mesh_key.as_ref().map(|key| key.derive(b"broadcast"));
        Self {
            linked_endpoints: HashSet::new(),
            zero_links_since: None,
            direct: HashMap::new(),
            relay_transport: transport::PayloadPath::DirectOnly,
            direct_proven: mpsc::unbounded_channel().0,
            gossip_handle: None,
            path_changes: mpsc::unbounded_channel().0,
            flush_failed: mpsc::unbounded_channel().0,
            path_watchers: HashMap::new(),
            path_kinds: HashMap::new(),
            route_dialed: HashMap::new(),
            known_endpoints: BoundedFifoSet::new(KNOWN_ENDPOINTS_CAP),
            proven_endpoints: proven_endpoints::ProvenEndpoints::new(KNOWN_ENDPOINTS_CAP),
            peer_info_proof: None,
            relink: Cooldown::new(RELINK_COOLDOWN),
            peerinfo_flooded_at: None,
            peerinfo_deferred: false,
            last_flooded_addr: None,
            below_target_since: None,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            redials: redial::Redials::default(),
            join_fallback_at: None,
            graft_backoff: graft_backoff::GraftBackoff::default(),
            lane_wanted: HashMap::new(),
            regraft_at: HashMap::new(),
            digest_serves: Cooldown::new(tuning::ANTIENTROPY_SERVE_COOLDOWN),
            digest_unreadable: Cooldown::new(super::UNREADABLE_DIGEST_LOG_WINDOW),
            resend_outbox,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            test_drop: None,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            test_drops_fired: 0,
            resend_receiver: Some(resend_receiver),
            state_digest_serves: antientropy::ServeBudget::default(),
            fast_rounds: antientropy::FastRounds::default(),
            peers: HashSet::new(),
            last_seen: HashMap::new(),
            peer_endpoints: HashMap::new(),
            rendezvous_id: None,
            quiet: BoundedFifoSet::new(QUIET_CAP),
            quiet_since: HashMap::new(),
            left: BoundedFifoSet::new(QUIET_CAP),
            left_at: HashMap::new(),
            left_keys: BoundedFifoSet::new(QUIET_CAP),
            surfaced: HashSet::new(),
            last_sent_at: now,
            joined_at: UnixSecs::now(),
            gossip_open: true,
            rendezvous_linked: false,
            rendezvous_released: false,
            rendezvous_return_due: None,
            rendezvous_comeback_until: None,
            rendezvous_dwell_until: None,
            hosts_rendezvous: false,
            yield_to_lower: false,
            beacon_flag_flooded: false,
            rival_holders: HashMap::new(),
            rendezvous_release_links: tuning::RENDEZVOUS_RELEASE_LINKS,
            rendezvous_session_stale: false,
            rendezvous_offer_fallback: false,
            rendezvous_answers_jsep: true,
            rendezvous_probe_read_free: false,
            probe_backoff: ProbeBackoff::default(),
            rendezvous_graft_needs_session: false,
            local_udp_transport: UdpTransport::Present,
            announced: false,
            meshed: false,
            unicast_pool: transport::UnicastPool::disconnected(),
            #[cfg(feature = "multihop")]
            multihop: None,
            #[cfg(feature = "multihop")]
            underlay_webrtc: None,
            #[cfg(feature = "multihop")]
            parked_link_states: ParkedLinkStates::default(),
            #[cfg(feature = "multihop")]
            last_advertised: None,
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "multihop",
                not(target_arch = "wasm32")
            ))]
            linkstate_held: false,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            claims_held: false,
            rungs: beacon::RungWatch::detached(),
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            shed_requested: false,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            stall_requested: false,
            lan_grafts: lan::LanGrafts::default(),
            webrtc: None,
            webrtc_admission,
            address_book,
            webrtc_ice,
            reclaim_until: None,
            next_rival_recheck: None,
            rival_recheck_rounds: 0,
            second_group_sign_at: None,
            no_rung_noted_at: None,
            rival_recheck_deferrals: 0,
            beacon_closing: None,
            seen: BoundedFifoSet::new(SEEN_IDS_CAP),
            pending_outbound: BoundedQueue::new(PENDING_OUTBOUND_CAP),
            #[cfg(feature = "host")]
            state_file,
            ready: false,
            live_count: None,
            message_log: MessageLog::new(MESSAGE_LOG_SIZE),
            reassembled_groups: BoundedFifoSet::new(MESSAGE_LOG_SIZE),
            reassembly: ReassemblyStore::default(),
            shard_cache: ShardCache::default(),
            state_doc: MeshDoc::new_ungated().key(state_key),
            meta_doc: match per_peer_gate {
                Some(gate) => MeshDoc::new_gated(gate),
                None => MeshDoc::new_ungated(),
            }
            .key(meta_key),
            digest_cursor: 0,
            identity,
            self_seq: 0,
            self_prev: None,
            author_seqs: HashMap::new(),
            forked: HashSet::new(),
            by_hash: HashMap::new(),
            dag_heads: HashSet::new(),
            last_inbound_at: now,
            last_recovery_at: None,
            recovery_trips: 0,
            degraded: false,
            resident_memory_warned: false,
            ping_round: None,
            mesh_password,
            mint_mesh: None,
            broadcast_key,
            idle: IdleCounters::default(),
        }
    }

    /// Write `peer_count = peers.len() + 1` (we add 1
    /// for self) to the state file, if configured, carrying the current
    /// `ready` flag, and mirror the count into the advertise counter, if
    /// present. No-op for neither.
    pub(crate) fn write_peer_count(&self) {
        let count = self.peers.len() + 1;
        #[cfg(feature = "host")]
        if let Some(sf) = self.state_file.as_ref() {
            sf.write(count, self.ready);
        }
        if let Some(live) = self.live_count.as_ref() {
            live.store(count, Ordering::Relaxed);
        }
    }

    /// Snapshot the live roster (active peers + quiet evictees),
    /// sorted most-recently-seen first. Backs a consumer's roster surfaces, the MCP
    /// `mesh_info` roster, and the task sender's target picker /
    /// nickname validation.
    #[must_use]
    pub fn roster_snapshot(&self) -> RosterSnapshot {
        let now = Instant::now();
        let secs_since = |seen: &Instant| now.duration_since(*seen).as_secs();
        let mut peers: Vec<RosterEntry> = self
            .peers
            .iter()
            .map(|nick| RosterEntry {
                nickname: nick.clone(),
                // Active peers: their live `last_seen`.
                last_seen_secs_ago: self.last_seen.get(nick).map(secs_since),
                quiet: false,
                reach: self.reach_of(nick),
                transport: transport::lane_for(nick, self),
            })
            .chain(self.quiet.iter().map(|nick| RosterEntry {
                nickname: nick.clone(),
                // Quiet peers: their last-heard instant, retained in
                // `quiet_since` (the eviction drops `last_seen`). A quiet
                // peer has no live link, so it is always `Gossip`.
                last_seen_secs_ago: self.quiet_since.get(nick).map(secs_since),
                quiet: true,
                reach: Reach::Gossip,
                transport: transport::lane_for(nick, self),
            }))
            .collect();
        // Most-recently-seen first; unknown recency (no heartbeat yet) sorts last.
        peers.sort_by_key(|entry| entry.last_seen_secs_ago.unwrap_or(u64::MAX));
        RosterSnapshot {
            peers,
            count: self.peers.len() + 1,
        }
    }

    /// `Direct` only when this nickname's last self-advertised endpoint is a
    /// live link right now; otherwise `Gossip`. A live link is a neighbor in
    /// `linked_endpoints`, or the rendezvous itself when we're linked to it —
    /// the beacon gossips *as* the rendezvous, so a joiner's only link to the
    /// beacon is that one. A peer we haven't yet seen a `PeerInfo` from (or
    /// whose link dropped) reads `Gossip` and flips to `Direct` once its next
    /// advertisement lands.
    fn reach_of(&self, nick: &Nickname) -> Reach {
        let linked = self.peer_endpoints.get(nick).is_some_and(|endpoint| {
            self.linked_endpoints.contains(&endpoint.id)
                || (self.rendezvous_id == Some(endpoint.id) && self.rendezvous_linked)
        });
        if linked { Reach::Direct } else { Reach::Gossip }
    }

    /// `true` if we re-dialed + re-flooded `peer` within the last
    /// `RELINK_COOLDOWN` of `now`, so the caller should skip re-linking
    /// it again. Breaks the flap → re-dial → re-flood loop that otherwise
    /// turns one unstable peer into a mesh-wide CPU storm.
    pub(crate) fn relink_on_cooldown(&self, peer: EndpointId, now: Instant) -> bool {
        self.relink.on_cooldown(&peer, now)
    }

    /// Record a re-link of `peer` at `now`.
    pub(crate) fn note_relink(&mut self, peer: EndpointId, now: Instant) {
        self.relink.note(peer, now);
    }

    /// Whether a `NeighborUp` at `now` re-floods our `PeerInfo`: once per
    /// window since any flood, whichever neighbor brings it. A key per neighbor
    /// let every new link flood again, and every flood is answered by a graft
    /// from each peer that hears it. A flapping link floods once per window too.
    pub(crate) fn neighbor_up_refloods_peerinfo(&self, now: Instant) -> bool {
        self.joined_refloods_peerinfo(false, now)
    }

    /// Record how many links this node holds out of `max_peers` (G). Below G - 1 starts
    /// the clock of a starved node, and G - 1 or more stops it.
    pub(crate) fn note_link_count(&mut self, linked: usize, max_peers: usize, now: Instant) {
        if linked.saturating_add(1) < max_peers {
            self.below_target_since.get_or_insert(now);
        } else {
            self.below_target_since = None;
        }
    }

    /// A frame is held for the lane peer `peer` at `now`: its session is wanted.
    pub(crate) fn want_lane_session(&mut self, peer: EndpointId, now: Instant) {
        let window = LANE_WANTED;
        self.lane_wanted
            .retain(|_, since| now.saturating_duration_since(*since) < window);
        self.lane_wanted.insert(peer, now);
    }

    /// Whether a frame was held for `peer` within the last `LANE_WANTED`.
    pub(crate) fn lane_session_wanted(&self, peer: EndpointId, now: Instant) -> bool {
        self.lane_wanted
            .get(&peer)
            .is_some_and(|since| now.saturating_duration_since(*since) < LANE_WANTED)
    }

    /// A proven pair lost its gossip link while its path reads as the relay or as the gossip
    /// rung (the recursion rule closes a link on that rung). Returns the address to offer a
    /// session to, now, and marks the session wanted.
    ///
    /// The path comes from [`Self::pair_path_kind`]: the watcher's report if there is one, else
    /// the admission table, which is the source for a pair that only gossips. A loss that nobody
    /// can read (no kind) is left to the retry tick.
    pub(crate) fn relay_race_on_link_loss(
        &mut self,
        peer: EndpointId,
        now: Instant,
    ) -> Option<EndpointAddr> {
        use crate::transport::probe::PathKind;
        if self.direct.get(&peer) != Some(&DirectState::Direct)
            || !matches!(
                self.pair_path_kind(peer),
                Some(PathKind::Relay | PathKind::Gossip)
            )
        {
            return None;
        }
        let address = self
            .peer_endpoints
            .values()
            .find(|address| address.id == peer)?
            .clone();
        self.want_lane_session(peer, now);
        Some(address)
    }

    /// The gossip link of a proven peer went down: plan its re-graft at
    /// `now` plus [`REGRAFT_AFTER`] with a jitter of 30 % either way (`spread` in
    /// `-1.0..=1.0`). A peer on its relink cooldown is left to the heal tick, so a flapping
    /// pair does not dial every second. A pair that reads as the relay is left to
    /// [`Self::relay_race_on_link_loss`]: its graft follows the attach, and a dial over the relay
    /// would arm the graft backoff for nothing. Both ends plan, so their grafts can cross: the
    /// tie-break pinned in the fork (51ec92d) keeps one of the two links, and the relink cooldown
    /// (10 s) paces what is left. Returns whether a re-graft is planned.
    pub(crate) fn plan_regraft_on_link_loss(
        &mut self,
        peer: EndpointId,
        now: Instant,
        spread: f64,
    ) -> bool {
        if self.direct.get(&peer) != Some(&DirectState::Direct)
            || self.pair_path_kind(peer) == Some(probe::PathKind::Relay)
            || self.rides_gossip_rung(peer)
            || self.relink_on_cooldown(peer, now)
        {
            return false;
        }
        let jitter = 1.0 + 0.3 * spread.clamp(-1.0, 1.0);
        let after = REGRAFT_AFTER.mul_f64(jitter);
        self.regraft_at.insert(peer, now + after);
        true
    }

    /// The peers whose planned re-graft is due at `now` and that are still unlinked.
    pub(crate) fn take_regrafts_due(&mut self, now: Instant) -> Vec<EndpointId> {
        let due: Vec<EndpointId> = self
            .regraft_at
            .iter()
            .filter(|(_, at)| now >= **at)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in &due {
            self.regraft_at.remove(peer);
        }
        due.into_iter()
            .filter(|peer| !self.linked_endpoints.contains(peer))
            .collect()
    }

    /// The session of `peer` attached: it is no longer wanted.
    pub(crate) fn clear_lane_wanted(&mut self, peer: EndpointId) {
        self.lane_wanted.remove(&peer);
    }

    /// A direct path to `peer` is proven. This is new information, so a refusal of the peer
    /// before it no longer holds the graft that follows. The proof says that the pair is
    /// reachable, not that the peer has room: one more ask per attach is the price.
    pub(crate) fn note_path_proven(&mut self, peer: EndpointId) {
        self.direct.insert(peer, DirectState::Direct);
        self.clear_lane_wanted(peer);
        self.graft_backoff.reset(peer);
    }

    /// Whether a graft at `now` falls back to a `Join` for a starved node: it has held
    /// two or more links fewer than G for `STARVED`, and the last fallback is
    /// `STARVED` old. A `true` stamps the fallback.
    pub(crate) fn starved_join_due(&mut self, now: Instant) -> bool {
        let due = self.starved_join_ready(now);
        if due {
            self.join_fallback_at = Some(now);
        }
        due
    }

    /// [`Self::starved_join_due`] without the stamp: whether a fallback would be due at `now`.
    pub(crate) fn starved_join_ready(&self, now: Instant) -> bool {
        let window = STARVED;
        let starved = self
            .below_target_since
            .is_some_and(|since| now.duration_since(since) >= window);
        let waited = self
            .join_fallback_at
            .is_none_or(|at| now.duration_since(at) >= window);
        starved && waited
    }

    /// Whether a graft leaves `peer` alone at `now`: it refused a `Neighbor` request and its
    /// wait runs. A starved node whose fallback is due asks every peer, because a `Join` is not
    /// refused: those dials, one per peer once per `STARVED`, are expected.
    pub(crate) fn graft_blocked(&self, peer: EndpointId, now: Instant) -> bool {
        self.graft_backoff.is_blocked(&peer, now) && !self.starved_join_ready(now)
    }

    /// Read which `Neighbor` requests were refused. Every alive tick.
    pub(crate) fn settle_graft_backoff(&mut self, now: Instant) {
        let spread = rand::Rng::random_range(&mut rand::rng(), -1.0..=1.0);
        let linked = &self.linked_endpoints;
        for (peer, wait) in self
            .graft_backoff
            .settle(now, |peer| linked.contains(peer), spread)
        {
            tracing::info!(target: "habilis_network::transport", %peer, wait_secs = wait.as_secs(), "no link after a Neighbor request: read as a refusal, the peer waits");
        }
    }

    /// Remember that a `NeighborUp` was held back by the flood window.
    ///
    /// The flood is paid at the first alive tick after the window ends. In a burst of
    /// new neighbors a neighbor can wait for our `PeerInfo` up to one window (10 s)
    /// plus one alive tick (30 s), that is 40 s.
    pub(crate) fn defer_peerinfo(&mut self) {
        self.peerinfo_deferred = true;
    }

    /// Whether a held-back `PeerInfo` flood is due at `now`: the window since the
    /// last flood has ended. Taking it clears the mark.
    pub(crate) fn take_deferred_peerinfo(&mut self, now: Instant) -> bool {
        let due = self.peerinfo_deferred && self.neighbor_up_refloods_peerinfo(now);
        if due {
            self.peerinfo_deferred = false;
        }
        due
    }

    /// Whether our own address, `current`, differs from the one our last `PeerInfo`
    /// carried. The window of the `NeighborUp` and `joined` gates damps link storms;
    /// a changed address (the home relay arriving after the arrival flood, an
    /// interface change) is not one, and no later flood would repair it. Before the
    /// first flood there is nothing to repair: the arrival flood takes the current
    /// address. `EndpointAddr` holds its addresses in a set, so only a gained or
    /// lost address counts, not their order.
    pub(crate) fn address_flood_due(&self, current: &EndpointAddr) -> bool {
        self.last_flooded_addr
            .as_ref()
            .is_some_and(|flooded| flooded != current)
    }

    /// Whether a `joined` received at `now` re-floods our `PeerInfo`. A first
    /// sighting (`joined_new`) always does: the newcomer linked to the
    /// rendezvous, so no `NeighborUp` on this loop will send it our address.
    /// A re-announce does only once per window since any flood: one newcomer
    /// makes every member re-announce, and a per-trigger key would let each
    /// member flood once per re-announce it hears (N²).
    pub(crate) fn joined_refloods_peerinfo(&self, joined_new: bool, now: Instant) -> bool {
        joined_new
            || self
                .peerinfo_flooded_at
                .is_none_or(|at| now.duration_since(at) >= RELINK_COOLDOWN)
    }

    /// Drop `nick`'s dial hint and, with it, the path verdict keyed on that
    /// endpoint. The two share a key space: the verdict describes the pooled
    /// connection, which outlives a gossip link but not the peer.
    pub(crate) fn forget_peer_endpoint(&mut self, nick: &str) -> Option<EndpointAddr> {
        let address = self.peer_endpoints.remove(nick)?;
        self.graft_backoff.reset(address.id);
        self.proven_endpoints.forget_endpoint(address.id);
        self.forget_rival_holder(address.id);
        self.direct.remove(&address.id);
        self.path_watchers.remove(&address.id);
        self.path_kinds.remove(&address.id);
        Some(address)
    }

    /// A `NeighborDown` for `peer`: the gossip link is gone, the path verdict
    /// stays. It describes the pooled unicast connection, which outlives the
    /// link; erasing it parked every directed frame on a link flap until the
    /// alive tick re-probed (about 40 s with the relink cooldown).
    /// Remember that `nick` said goodbye at `at`. A later `left` of the same peer moves the mark
    /// forward, and an older one (a delayed copy) leaves it where it is.
    pub(crate) fn note_left(&mut self, nick: &Nickname, key: AuthorKey, at: UnixSecs) {
        self.left.insert(nick.clone());
        self.left_keys.insert(key);
        let mark = self.left_at.entry(nick.clone()).or_insert(at);
        *mark = (*mark).max(at);
    }

    pub(crate) fn key_said_goodbye(&self, key: AuthorKey) -> bool {
        self.left_keys.contains(&key)
    }

    /// Drop a departed key's presence frames from the log and from the indexes kept beside it,
    /// as an eviction would (see `gossip::recv::push_to_log`).
    pub(crate) fn drop_departed_presence(&mut self, key: &AuthorKey) {
        for gone in self.message_log.drop_presence_of(key) {
            let hash = gone.content_hash();
            self.forget_hash(&hash);
            if let Some(seq) = gone.seq {
                self.forget_msg_seq(&gone.key(), seq, &hash);
            }
        }
    }

    /// Whether a message of `nick` stamped `at` was sent no later than the goodbye of `nick`.
    pub(crate) fn sent_before_goodbye(&self, nick: &Nickname, at: UnixSecs) -> bool {
        self.left_at.get(nick).is_some_and(|left| at <= *left)
    }

    pub(crate) fn unlink(&mut self, peer: EndpointId) {
        self.linked_endpoints.remove(&peer);
        if self.linked_endpoints.is_empty() {
            self.zero_links_since.get_or_insert_with(Instant::now);
        }
        self.webrtc_admission.set_neighbors(&self.linked_endpoints);
    }

    /// Whether the census calls the state a silent partition: a meshed member that knows
    /// `roster_len` peers has held no link for longer than
    /// [`silent_partition_after`](crate::util::tuning::silent_partition_after). A shorter gap is
    /// a heal on its way, or a link closed on purpose.
    pub(crate) fn silent_partition_due(&self, roster_len: usize, now: Instant) -> bool {
        self.meshed
            && roster_len > 0
            && self.linked_endpoints.is_empty()
            && self.zero_links_since.is_some_and(|since| {
                now.saturating_duration_since(since) >= tuning::silent_partition_after()
            })
    }

    /// Whether a reclaim tick asks another known peer for a link: the fast reclaim window is
    /// open and this member held links and lost every one. A low priority request is refused by
    /// a peer whose view is full, and the peers that were lost are full first; waiting for the
    /// heal tick would leave the member alone for up to a heal interval.
    pub(crate) fn isolated_refill_due(&self, now: Instant) -> bool {
        self.linked_endpoints.is_empty()
            && self.zero_links_since.is_some()
            && self.reclaim_until.is_some_and(|until| now < until)
    }

    /// A gossip link to `peer` is up.
    pub(crate) fn link(&mut self, peer: EndpointId) {
        self.linked_endpoints.insert(peer);
        self.zero_links_since = None;
        self.regraft_at.remove(&peer);
        self.graft_backoff.reset(peer);
        self.webrtc_admission.set_neighbors(&self.linked_endpoints);
    }

    /// A member's `PeerInfo` read: `flag.held` says it holds the rendezvous. A flag from a
    /// proven sender is remembered whether we hold the rendezvous or not; it moves our re-check
    /// only while we hold it too.
    pub(crate) fn note_rival_beacon_flag(
        &mut self,
        own: EndpointId,
        signer: AuthorKey,
        sender: EndpointId,
        flag: RivalFlag,
        now: Instant,
    ) {
        if !flag.held {
            self.rival_holders.remove(&signer);
            return;
        }
        if !flag.proven || sender == own {
            return;
        }
        let newly = self.rival_holders.insert(signer, sender) != Some(sender);
        if !self.hosts_rendezvous {
            return;
        }
        if (beacon::Contest { own, rival: sender }).own_yields() {
            self.yield_to_lower = true;
            self.next_rival_recheck = Some(now);
        } else if newly {
            // Once per holder, so that a holder that sends its flag again and again cannot keep
            // our re-check away. Pushed, not dropped: a holder that never re-checks never finds
            // a co-host it does not know of.
            let pushed = now
                + cohost_arm::next_recheck_delay(
                    self.rival_recheck_rounds.max(1),
                    self.peers.len(),
                    own,
                );
            self.next_rival_recheck = Some(
                self.next_rival_recheck
                    .map_or(pushed, |due| due.max(pushed)),
            );
        }
    }

    /// A sign that another group of this mesh may exist: a member that we do not know linked to
    /// our beacon, or the LAN named a member that we are not linked to.
    ///
    /// A holder that has found no member re-checks its rendezvous only every hour or two, and two
    /// such holders of one room can stay apart that long. The sign brings the next re-check to
    /// the fast base and starts the rounds from it again, so a node that nobody approaches keeps
    /// its long wait. A sign counts once per steady interval: a burst of arrivals must not shed
    /// the beacon again and again.
    pub(crate) fn note_second_group_sign(&mut self, own: EndpointId, now: Instant) {
        let Some(due) = self.next_rival_recheck.filter(|_| self.hosts_rendezvous) else {
            return;
        };
        let spacing = tuning::rival_recheck_meshed();
        if self
            .second_group_sign_at
            .is_some_and(|at| now.saturating_duration_since(at) < spacing)
        {
            return;
        }
        let brisk = now + cohost_arm::next_recheck_delay(0, self.peers.len(), own);
        if due <= brisk {
            return;
        }
        self.second_group_sign_at = Some(now);
        self.rival_recheck_rounds = 0;
        self.next_rival_recheck = Some(brisk);
    }

    /// Whether some member is known to hold the rendezvous.
    pub(crate) fn rival_holder_known(&self) -> bool {
        !self.rival_holders.is_empty()
    }

    /// Open the fast `beacon::ensure` burst; the only writer of
    /// [`Self::reclaim_until`].
    pub(crate) fn arm_reclaim(&mut self, now: Instant) {
        self.reclaim_until = Some(now + RECLAIM_WINDOW);
        self.probe_backoff.reset();
    }

    /// Whether a test holds this node's claims back (`Beacons::HoldClaims`).
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) fn claims_are_held(&self) -> bool {
        self.claims_held
    }

    /// Whether a test holds this node's claims back: never, outside a test build.
    #[cfg(not(all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
    pub(crate) fn claims_are_held(&self) -> bool {
        let _ = self;
        false
    }

    /// Whether this node should hold, or come back to, the rendezvous link:
    /// while it has fewer than [`Self::rendezvous_release_links`] links to
    /// others, while a return is owed, and always on the node that hosts it.
    /// Every graft and offer to the rendezvous is gated on this one answer.
    pub(crate) fn rendezvous_wanted(&self) -> bool {
        self.hosts_rendezvous
            || self
                .rendezvous_comeback_until
                .is_some_and(|until| Instant::now() < until)
            || self.linked_endpoints.len() < self.rendezvous_release_links
    }

    /// A live holder of the rendezvous was read, and it is not us: a ladder walk answered "ours",
    /// or a probe found a beacon. If no member of our mesh is known to host it, the holder is
    /// outside our mesh, and a node that let go of the rendezvous on purpose would never learn of
    /// it: it owes a return, which the heal tick pays with a join. Nothing is owed while we host
    /// it, while we still hold the link, while we want the rendezvous anyway (so a joiner under
    /// the release count gets no longer visit), or while a holder of our own mesh is known: that
    /// is the healthy case, and every released member reads it on every heal tick.
    ///
    /// Owing makes [`Self::rendezvous_wanted`] true, so the next read owes nothing more: the debt
    /// is paid by the link, or it runs out after its window and the next read owes it once again.
    pub(crate) fn note_holder_outside_mesh(&mut self, now: Instant) {
        if self.rendezvous_linked || self.rendezvous_wanted() || self.rival_holder_known() {
            return;
        }
        tracing::info!(
            target: "habilis_network::gossip",
            links = self.linked_endpoints.len(),
            "a holder of the rendezvous that no member of our mesh hosts: owe a return"
        );
        self.owe_rendezvous_return(now);
        // The graft is the reclaim ticker's: it re-grafts within `RECLAIM_INTERVAL`, where
        // the heal tick would come round up to a heal interval later.
        self.arm_reclaim(now);
    }

    /// The claim of `endpoint` to hold the rendezvous is void: the member is gone, or silent.
    /// A holder that crashes never sends a `PeerInfo` without the flag, so the flag is dropped
    /// with the member, whatever else is remembered of it.
    pub(crate) fn forget_rival_holder(&mut self, endpoint: EndpointId) {
        self.rival_holders.retain(|_, holder| *holder != endpoint);
    }

    /// A return to the rendezvous is owed from now, for
    /// [`RENDEZVOUS_COMEBACK`](crate::util::tuning::RENDEZVOUS_COMEBACK).
    pub(crate) fn owe_rendezvous_return(&mut self, now: Instant) {
        self.rendezvous_comeback_until = Some(now + tuning::RENDEZVOUS_COMEBACK);
    }

    /// The periodic return, if it fell due, is owed like any other return: for a bounded time,
    /// and the next one is set one period later. A visit that finds no link is then wanted for
    /// the comeback window and no longer, and a member does not graft and offer at every tick for
    /// ever. Called on the heal tick.
    pub(crate) fn pay_periodic_return(&mut self, now: Instant, local: EndpointId) {
        if self.rendezvous_return_due.is_some_and(|due| now >= due) {
            self.owe_rendezvous_return(now);
            self.rendezvous_return_due = Some(now + super::rendezvous_return_after(local));
        }
    }

    /// The rendezvous link came up. If a return was owed, it is paid, and the
    /// visit lasts its dwell time at least.
    pub(crate) fn note_rendezvous_link_up(&mut self, now: Instant) {
        self.rendezvous_linked = true;
        self.rendezvous_released = false;
        let periodic_visit = self
            .rendezvous_return_due
            .take()
            .is_some_and(|due| now >= due);
        let owed_visit = self.rendezvous_comeback_until.take().is_some();
        self.rendezvous_dwell_until =
            (owed_visit || periodic_visit).then(|| now + tuning::RENDEZVOUS_DWELL);
    }

    /// Whether this node holds the rendezvous link, has not let go of it yet, is
    /// not its host, has links enough to others, and has stayed as long as a
    /// visit lasts: it lets go.
    /// Checked wherever a link comes up and on the heal tick, because a node
    /// that came back to a mesh whose links are all up would otherwise wait for
    /// a link event that never comes.
    pub(crate) fn should_release_rendezvous(&self, now: Instant) -> bool {
        self.rendezvous_linked
            && !self.rendezvous_released
            && !self.hosts_rendezvous
            && self.linked_endpoints.len() >= self.rendezvous_release_links
            && self.rendezvous_dwell_until.is_none_or(|until| now >= until)
    }

    /// The release, once gossip has been told to leave the rendezvous
    /// (`GossipSender::leave_peers`). The leave ends the link by itself, if
    /// gossip held one: `Ok` from `leave_peers` only says that the command
    /// reached the gossip actor. So this does not wait for a close to be seen:
    /// it marks the release at once, before the `NeighborDown` that follows is
    /// read, so that one reads as a choice.
    pub(crate) fn mark_rendezvous_released(&mut self, local: EndpointId) {
        self.rendezvous_released = true;
        self.rendezvous_return_due = Some(Instant::now() + super::rendezvous_return_after(local));
        tracing::info!(
            target: "habilis_network::gossip",
            local = %local.fmt_short(),
            links = self.linked_endpoints.len(),
            "enough links to members: released the rendezvous"
        );
    }

    /// The rendezvous arbitration was reopened or settled, so the previous
    /// probe's free reading describes a world that is gone. Pairing it with
    /// one fresh reading claims on what is effectively a single probe, which
    /// is the rival copy the two-verdict rule exists to stop.
    ///
    /// The same goes for a refusal of our offers: after a failover the
    /// rendezvous keeps its id, and the old holder's "at my cap" is not the new
    /// holder's.
    pub(crate) fn forget_rendezvous_verdict(&mut self) {
        self.rendezvous_probe_read_free = false;
        self.probe_backoff.reset();
        if let Some(rendezvous) = self.rendezvous_id {
            self.webrtc_admission.forget_refusal(rendezvous);
        }
    }

    /// Somebody else now holds the rendezvous identity, or nobody does: a signalling round to it
    /// that was started against the previous holder cannot find the new one, and holds the slot for
    /// the whole round deadline. End it, so that the next offer is made at once.
    pub(crate) fn cancel_rendezvous_round(&self) {
        if let Some(rendezvous) = self.rendezvous_id {
            self.webrtc_admission.cancel_round(rendezvous);
        }
    }

    /// A probe reported no direct path to `peer`. A peer that proved itself
    /// another way while the probe ran (its inbound graft landed), or that
    /// left meanwhile, keeps what it has.
    pub(crate) fn demote_unproven(&mut self, peer: EndpointId) -> bool {
        match self.direct.get_mut(&peer) {
            Some(verdict @ DirectState::Pending) => {
                *verdict = DirectState::RelayOnly;
                true
            }
            _ => false,
        }
    }

    /// Record `message` as seen and report whether it was *already* seen.
    /// `true` => this is a duplicate delivery the caller must drop. Keys on
    /// the author-bound [`Message::dedup_key`], so a forgery reusing a
    /// victim's id hashes to a different key and cannot suppress the genuine
    /// message. Delegates to the bounded [`BoundedFifoSet`], inverting its
    /// "was newly inserted" answer into "was a duplicate".
    ///
    /// A frame still in the message log is a duplicate too. The log keeps a frame as long as
    /// anti-entropy may re-send it, while `seen` is fed by every kind, most of which the log
    /// never keeps, so under enough of that traffic it forgets a retained frame first.
    pub(crate) fn mark_seen(&mut self, message: &Verified) -> bool {
        let key = message.dedup_key();
        self.message_log.contains(&key) || !self.seen.insert(key)
    }

    /// Try to reassemble the sharded body the `trigger` shard belongs to:
    /// buffer it in the dedicated [`reassembly`](Self::reassembly) store and,
    /// when it completes its group (and the group has not been surfaced
    /// before), return the synthesized logical [`Message`] — a surfacing view
    /// whose `id` is the group, so sender and receivers name it alike.
    ///
    /// Small (logged) groups get a second completion path off the message
    /// log: their shards are all retained there, so a shard healed by
    /// anti-entropy *after* the store's stale-group TTL reaped the partial
    /// buffer still completes the body — dedup (`seen`) means the healed
    /// shard is the only one re-ingested, and the store alone would sit on
    /// 1-of-N forever.
    pub(crate) fn reassemble(&mut self, trigger: &Verified) -> Option<Authored> {
        let shard = trigger.shard.as_ref()?;
        if self.reassembled_groups.contains(&shard.group) {
            return None;
        }
        match self.reassembly.ingest(trigger, Instant::now()) {
            ShardIngest::Complete(logical) => {
                self.reassembled_groups.insert(shard.group.clone());
                Some(*logical)
            }
            ShardIngest::Buffered | ShardIngest::Dropped => {
                let logical = self.reassemble_from_log(trigger)?;
                // The store may still hold a partial buffer for this group
                // (e.g. just the trigger, post-TTL) — release its budget.
                self.reassembly.forget(trigger);
                self.reassembled_groups.insert(shard.group.clone());
                Some(logical)
            }
            _ => None,
        }
    }

    /// The log-backed completion path for a **small** (logged) group: scan
    /// the message log for this author's shards and synthesize when every
    /// slot is present. Mirrors the store's synthesis exactly.
    fn reassemble_from_log(&self, trigger: &Verified) -> Option<Authored> {
        let shard = trigger.shard.as_ref()?;
        // A verified shard always has its author key.
        let author = trigger.key();
        if !message::shard_fits_log(trigger) {
            return None;
        }
        let slots = self
            .message_log
            .collect_shards(&shard.group, &author, shard.total);
        if slots.iter().any(Option::is_none) {
            return None; // a shard is still missing
        }
        let mut body = String::new();
        for slot in &slots {
            body.push_str(slot.expect("every slot filled above").body.as_str());
        }
        // The concatenation of valid bodies is itself valid (no new control
        // chars), but fail closed rather than surface a malformed body.
        let body = protocol::MessageBody::try_new(&body).ok()?;
        let header = slots[0].expect("shard 0 present");
        Some(reassembly::synthesize_from(header, body, &shard.group))
    }

    /// Record a `conn_path` reading for `peer`; a reading that proves nothing
    /// leaves what was known — a probe verdict or a gated link — in place.
    ///
    /// When the relay is lookup only, a `Relay` reading is one of those: the
    /// lanes never ride the relay, so what admitted this peer was the accept
    /// gate or the probe, and `conn_path` cannot see which path iroh selected
    /// underneath. Demoting on it would stop every payload lane to a peer that
    /// is proven direct. `gossip::recv` gates its own call for this reason;
    /// the census tick in `daemon::timers` does not, so the gate lives here.
    pub(crate) fn observe_path(&mut self, peer: EndpointId, summary: gossip::PathSummary) {
        if !self.relay_transport.relay_allowed() && summary == gossip::PathSummary::Relay {
            return;
        }
        if let Some(state) = DirectState::classify(summary) {
            self.direct.insert(peer, state);
        }
    }

    /// How many linked peers sit in each [`DirectState`], for the census.
    pub(crate) fn direct_counts(&self) -> DirectCounts {
        let mut counts = DirectCounts::default();
        for state in self.direct.values() {
            match state {
                DirectState::Direct => counts.direct += 1,
                DirectState::RelayOnly => counts.relay_only += 1,
                DirectState::Pending => counts.pending += 1,
            }
        }
        counts
    }

    /// Whether a gossip broadcast can reach anyone right now. `meshed` is the
    /// strict answer (a real-peer link), but it is stricter than the overlay:
    /// a node whose only neighbor is the rendezvous relay already exchanges
    /// presence over that link, and a peer behind the same relay (a browser
    /// tab, say) may never form a direct link at all. Document plumbing —
    /// heads digests, change frames — is small and reconciled by anti-entropy,
    /// so it rides the relay link too. User content keeps waiting on `meshed`.
    /// A degraded node is excluded: its overlay is suspected dead, and the
    /// relay link alone is no proof it recovered.
    pub(crate) fn overlay_reachable(&self) -> bool {
        self.meshed || (self.rendezvous_linked && !self.degraded)
    }

    /// Mark the mesh degraded: a fault path (starvation recovery, hard
    /// resume edge) cleared `meshed`, so outbound user content buffers in
    /// `pending_outbound` instead of broadcasting into a dead overlay.
    /// `note_inbound` undoes it on the first proof of live traffic.
    pub(crate) fn note_degraded(&mut self) {
        self.meshed = false;
        self.degraded = true;
    }

    /// Record a verified inbound gossip message: refresh the starvation
    /// watchdog's signal and disarm its backoff. Called *before* dedup —
    /// a duplicate delivery still proves the mesh carries traffic. Also
    /// the moment a *degraded* node turns healthy again: inbound traffic
    /// is proof of a live path, so `meshed` is restored (the caller
    /// flushes `pending_outbound` on the flip). A fresh joiner that has
    /// never meshed is NOT flipped here — pre-mesh, relayed traffic can
    /// arrive before the overlay can carry our outbound, so the first
    /// real-peer `NeighborUp` keeps that job. Returns `true` on the
    /// degraded→meshed edge.
    pub(crate) fn note_inbound(&mut self, now: Instant) -> bool {
        self.last_inbound_at = now;
        self.recovery_trips = 0;
        self.last_recovery_at = None;
        if self.degraded {
            self.degraded = false;
            self.meshed = true;
            // A node that held no link has had no unlink to start the gap that the census counts.
            // A gap that already runs keeps its start.
            if self.linked_endpoints.is_empty() {
                self.zero_links_since.get_or_insert(now);
            }
            return true;
        }
        false
    }

    /// Should the heal tick run a starvation recovery *now*? True only
    /// when this node has been part of a mesh (`announced`) and knows at
    /// least one real peer to re-dial, yet has received **nothing** for
    /// over `threshold` — the roster-collapse signature, keyed on
    /// traffic rather than the (fallible) link view. Repeated trips back
    /// off 1-2-4-8× so a genuinely-last-survivor node retries sparsely.
    /// Deliberately NOT gated on `meshed`: recovery clears `meshed`, so
    /// that gate would disarm the watchdog after a single attempt.
    pub(crate) fn starvation_due(&self, now: Instant, threshold: Duration) -> bool {
        if !self.announced || self.known_endpoints.is_empty() {
            return false;
        }
        if now.duration_since(self.last_inbound_at) <= threshold {
            return false;
        }
        let backoff = threshold.saturating_mul(1 << self.recovery_trips.min(3));
        self.last_recovery_at
            .is_none_or(|at| now.duration_since(at) > backoff)
    }

    /// Record that a starvation recovery ran at `now` (arms the backoff).
    pub(crate) fn note_recovery(&mut self, now: Instant) {
        self.recovery_trips = self.recovery_trips.saturating_add(1);
        self.last_recovery_at = Some(now);
    }

    /// Record a `Msg`'s `(author, seq, content-hash)` for fork detection.
    /// Returns `true` **exactly once** per offending key — when a *different*
    /// content hash is first seen at an already-recorded `(author, seq)`,
    /// which is cryptographic proof the author equivocated (signed two
    /// conflicting messages at one seq). Order-independent. The caller emits
    /// a `fork` event on `true`; the message itself is still processed.
    pub(crate) fn note_msg_seq(&mut self, author: &AuthorKey, seq: u64, hash: ContentHash) -> bool {
        let seen = self.author_seqs.entry(*author).or_default();
        match seen.get(&seq) {
            Some(existing) if *existing != hash => {} // conflict → fall through
            Some(_) => return false,                  // same message, already recorded
            None => {
                seen.insert(seq, hash);
                return false;
            }
        }
        // Equivocation: flag the key, returning true only on first detection.
        self.forked.insert(*author)
    }

    /// The `parents` to stamp on the next `Msg` we author: the current DAG
    /// tips, sorted (deterministic) and capped to `MAX_DAG_PARENTS` to
    /// bound message size. Usually a single head on a quiet mesh.
    pub fn dag_parents(&self) -> impl Iterator<Item = ContentHash> {
        let mut heads: Vec<ContentHash> = self.dag_heads.iter().copied().collect();
        heads.sort_unstable();
        heads.truncate(MAX_DAG_PARENTS);
        heads.into_iter()
    }

    /// Fold a content `Msg` (hash `hash`, `parents`, timestamp `ts`) into the
    /// DAG — for messages we receive *and* ones we author. Returns `true` if
    /// `ts` is **before** a known parent's timestamp (a backdating violation
    /// to flag). Updates `by_hash` and moves the tip set: the named parents
    /// are no longer tips, and `hash` becomes one. Unknown parents are left
    /// alone (the set converges via anti-entropy).
    pub fn note_dag(&mut self, hash: ContentHash, parents: &[ContentHash], ts: UnixSecs) -> bool {
        let mut backdated = false;
        for parent in parents {
            if let Some(&parent_ts) = self.by_hash.get(parent)
                && ts < parent_ts
            {
                backdated = true;
            }
            self.dag_heads.remove(parent);
        }
        self.by_hash.insert(hash, ts);
        self.dag_heads.insert(hash);
        backdated
    }

    /// Prune an evicted message's content hash from the DAG indexes, keeping
    /// `by_hash`/`dag_heads` bounded alongside the message-log `VecDeque`.
    pub fn forget_hash(&mut self, hash: &ContentHash) {
        self.by_hash.remove(hash);
        self.dag_heads.remove(hash);
    }

    /// Prune an evicted `Msg`'s `(author, seq)` from the fork-detection
    /// index, bounding `author_seqs`/`forked` to the message-log window: an
    /// identity whose messages have all aged out drops off both maps (so a
    /// sybil that fires once and vanishes is forgotten).
    ///
    /// Only drops the slot when `hash` is the one we recorded for that
    /// `(author, seq)`. A fork retains *two* messages at one `(author, seq)`;
    /// evicting the twin we did **not** record must not clear the recorded
    /// evidence, or a later anti-entropy resend of the still-retained twin
    /// would re-detect the equivocation as a fresh first sighting.
    pub fn forget_msg_seq(&mut self, author: &AuthorKey, seq: u64, hash: &ContentHash) {
        if let Some(seqs) = self.author_seqs.get_mut(author)
            && seqs.get(&seq).is_some_and(|recorded| recorded == hash)
        {
            seqs.remove(&seq);
            if seqs.is_empty() {
                self.author_seqs.remove(author);
                self.forked.remove(author);
            }
        }
    }
}

/// Max `parents` stamped on a `Msg` — bounds the wire size of the causal
/// links. A quiet mesh has one head; this only bites under heavy concurrency.
const MAX_DAG_PARENTS: usize = 16;

// ── Consumer surface ───────────────────────────────────────────────────────
//
// The application driver (`NodeApp` / `NodeDriver`) is handed `&mut
// EventLoopState` on every hook, but it is not a free-for-all: the fields are
// crate-private and each thing an app legitimately needs is a named method.
// Two reasons. The types are the smaller one — several fields are
// `pub(crate)` collections in private modules, so a consumer could touch the
// field but never name it. The larger one is that a bare field says nothing
// about the invariant around it, and the doc pair below is the example: every
// consumer that wanted one wrote the same `match channel` first.
impl EventLoopState {
    /// The shared document for `channel`. Replaces a `match` on
    /// [`Channel`](crate::protocol::Channel) at every call site.
    #[must_use]
    pub fn doc(&self, channel: protocol::Channel) -> &MeshDoc {
        match channel {
            protocol::Channel::State => &self.state_doc,
            protocol::Channel::Meta => &self.meta_doc,
            _ => unreachable!("a channel added later needs its own document"),
        }
    }

    /// Mutable [`Self::doc`], for applying a local change before broadcast.
    pub fn doc_mut(&mut self, channel: protocol::Channel) -> &mut MeshDoc {
        match channel {
            protocol::Channel::State => &mut self.state_doc,
            protocol::Channel::Meta => &mut self.meta_doc,
            _ => unreachable!("a channel added later needs its own document"),
        }
    }

    /// This member's signing identity.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The address book of the member endpoint: one per endpoint, made by
    /// `lookup::address_book`. Write to it with `add_peer_addr`.
    #[must_use]
    pub fn address_book(&self) -> &memory::MemoryLookup {
        &self.address_book
    }

    /// The roster, as a set of nicknames. See [`Self::roster_snapshot`] for the
    /// richer per-peer view.
    #[must_use]
    pub fn peers(&self) -> &HashSet<Nickname> {
        &self.peers
    }

    /// A peer's last known endpoint id, if one has been learned.
    #[must_use]
    pub fn peer_endpoint(&self, nickname: &Nickname) -> Option<EndpointId> {
        self.peer_endpoints
            .get(nickname.as_str())
            .map(|address| address.id)
    }

    /// Whether this member has meshed (has at least one gossip neighbour).
    #[must_use]
    pub fn is_meshed(&self) -> bool {
        self.meshed
    }

    /// Whether the gossip topic is currently open for broadcast.
    #[must_use]
    pub fn is_gossip_open(&self) -> bool {
        self.gossip_open
    }

    /// The multi-hop transport handle, when the mesh policy registered one.
    #[cfg(feature = "multihop")]
    #[must_use]
    pub fn multihop(&self) -> Option<&habilis_network_iroh_multihop_transport::MultihopHandle> {
        self.multihop.as_ref()
    }

    /// The Argon2id-derived broadcast key, for a password-protected mesh.
    #[must_use]
    pub fn broadcast_key(&self) -> Option<&SymmetricKey> {
        self.broadcast_key.as_ref()
    }

    /// The raw mesh password, retained for blob-ticket keying.
    #[must_use]
    pub fn mesh_password(&self) -> Option<&crypto::Password> {
        self.mesh_password.as_ref()
    }

    /// The creator's invite-minting mesh; `Some` only on the creator of an
    /// invite-only mesh.
    #[must_use]
    pub fn mint_mesh(&self) -> Option<&Mesh> {
        self.mint_mesh.as_ref()
    }

    /// Stamp the next position on this author's hash chain, advancing it.
    /// `prev` is the content hash of the message just authored.
    pub fn advance_chain(&mut self, previous: ContentHash) {
        self.self_seq += 1;
        self.self_prev = Some(previous);
    }

    /// This author's current chain position — the `seq` the next message takes
    /// and the hash it points back to.
    #[must_use]
    pub fn chain_head(&self) -> (u64, Option<ContentHash>) {
        (self.self_seq, self.self_prev)
    }

    /// Arm a ping round, replacing any already in flight.
    pub(crate) fn arm_ping_round(&mut self, round: PingRound) {
        self.ping_round = Some(Box::new(round));
    }

    /// Sender-side cache of serialized shard frames, for answering repair
    /// requests.
    pub fn shard_cache_mut(&mut self) -> &mut ShardCache {
        &mut self.shard_cache
    }

    /// Receiver-side partial-body store.
    pub fn reassembly_mut(&mut self) -> &mut ReassemblyStore {
        &mut self.reassembly
    }

    /// The anti-entropy message log — the retained window a reconnecting peer
    /// recovers from. Returns any message evicted by the push.
    pub fn message_log_mut(&mut self) -> &mut MessageLog {
        &mut self.message_log
    }

    /// How many messages the anti-entropy log holds. Tests only.
    #[cfg(feature = "iroh-test-utils")]
    #[must_use]
    pub fn message_log_len(&self) -> usize {
        self.message_log.len()
    }

    /// Whether this author's digest may be served now.
    ///
    /// Answering one costs up to `ANTIENTROPY_MAX_RESEND` mesh-wide broadcasts,
    /// so without a per-peer gate a single crafted digest buys that from every
    /// member — an amplifier that grows with the mesh. Serving at most one per
    /// window per author bounds it to the honest cadence.
    pub fn admit_digest(&mut self, author: AuthorKey, now: Instant) -> bool {
        if self.digest_serves.on_cooldown(&author, now) {
            return false;
        }
        self.digest_serves.note(author, now);
        true
    }

    /// The selected path of a pair: the path watcher's last report if it has one,
    /// else any live connection of the admission table (see
    /// [`crate::transport::probe::pair_kind`]).
    pub(crate) fn pair_path_kind(&self, peer: EndpointId) -> Option<probe::PathKind> {
        probe::pair_kind(
            self.path_kinds.get(&peer).copied(),
            self.webrtc_admission.selected_kind(peer),
        )
    }

    /// Whether the selected path of `peer` is the gossip rung. The recursion rule closes a gossip
    /// link on that path, so a graft only makes the gossip layer dial a link that dies at once.
    /// Not while a session is attached: it carries the pair whatever one connection reads, and the
    /// link rides it once iroh moves the connection.
    pub(crate) fn rides_gossip_rung(&self, peer: EndpointId) -> bool {
        self.pair_path_kind(peer) == Some(probe::PathKind::Gossip)
            && !self
                .webrtc
                .as_ref()
                .is_some_and(|handle| handle.has_session(&peer))
    }

    /// Whether to report that this author's digest could not be read: once per
    /// author per window. The author runs a build with another digest format, or
    /// sends garbage; either way the two never repair each other's gaps.
    pub fn report_unreadable_digest(&mut self, author: AuthorKey, now: Instant) -> bool {
        if self.digest_unreadable.on_cooldown(&author, now) {
            return false;
        }
        self.digest_unreadable.note(author, now);
        true
    }

    /// Record a peer's endpoint address, learned from its published card.
    ///
    /// The whole address, not just the id: the retry pass has to know whether a
    /// peer advertises IP, and rebuilding a bare address from the id there made
    /// every native peer look like a browser.
    pub fn note_peer_endpoint(&mut self, nickname: Nickname, endpoint: EndpointAddr) {
        let id = endpoint.id;
        let changed = self
            .peer_endpoints
            .get(&nickname)
            .is_some_and(|before| *before != endpoint);
        self.bind_peer_endpoint(nickname, endpoint);
        // A peer at a new address is not the peer that refused.
        if changed {
            self.graft_backoff.reset(id);
            if self.rendezvous_id == Some(id) {
                self.probe_backoff.reset();
            }
        }
    }

    /// Write the binding of `nickname` to its endpoint. The one place that does: a `PeerInfo`
    /// (`handle_peer_info`) and `note_peer_endpoint` both come here.
    pub(crate) fn bind_peer_endpoint(&mut self, nickname: Nickname, endpoint: EndpointAddr) {
        #[cfg(feature = "multihop")]
        let (parked, bound) = (self.parked_link_states.take(&nickname), endpoint.id);
        self.peer_endpoints.insert(nickname, endpoint);
        // The vector that came before this binding is fed now, not at the next tick.
        #[cfg(feature = "multihop")]
        if let Some(vector) = parked {
            self.feed_parked_link_state(vector, bound);
        }
    }

    /// Feed the link vector that waited for its author's binding, with the check that a vector
    /// that arrives after its binding goes through: the origin must be the bound endpoint. The
    /// underlay is ticked when the vector changed the topology, as at any other receipt.
    #[cfg(feature = "multihop")]
    fn feed_parked_link_state(
        &self,
        vector: habilis_network_iroh_multihop_transport::LinkVector,
        bound: EndpointId,
    ) {
        if vector.origin().get() != bound {
            tracing::debug!(target: "habilis_network::gossip",
                "dropping parked multihop link-state: its origin is not the endpoint bound to its author"
            );
            return;
        }
        let Some(handle) = self.multihop.as_ref() else {
            return;
        };
        let updated = handle.feed_topology(vector);
        tracing::debug!(target: "habilis_network::gossip",
            updated,
            "multihop link-state received after its binding"
        );
        if updated {
            underlay_webrtc::tick_now(self);
        }
    }

    /// Mark the gossip topic closed without a real stream end — how the
    /// adversarial suite makes the heal arm's resubscribe path observable.
    /// Feature-gated: no production caller may forge this.
    #[cfg(feature = "adversarial")]
    pub fn sever_gossip(&mut self) {
        self.gossip_open = false;
    }

    /// Tests only: drop the next inbound frame that `what` names, once, before the app reads it.
    /// The frame is named, not counted, so that no other frame can take the drop.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub fn drop_inbound(&mut self, what: TestDrop) {
        self.test_drop = Some(what);
    }

    /// Tests only: how many frames [`Self::drop_inbound`] has dropped.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    #[must_use]
    pub fn inbound_drops_fired(&self) -> u32 {
        self.test_drops_fired
    }

    /// Tests only: forget the proof that `peer` signs for its endpoint (the `PeerInfo` proof of
    /// `transport::proven_endpoints`). A state digest of an asker whose endpoint is not proven is
    /// answered on gossip, as it is for a late joiner before its `PeerInfo` arrives.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub fn forget_endpoint_proof(&mut self, peer: &Nickname) {
        if let Some(endpoint) = self.peer_endpoints.get(peer).map(|address| address.id) {
            self.proven_endpoints.forget_endpoint(endpoint);
        }
    }

    /// Frames queued for send while the topic was closed.
    pub fn pending_outbound_mut(&mut self) -> &mut BoundedQueue<(Verified, WireFrame)> {
        &mut self.pending_outbound
    }
}

/// A build with the `multihop` feature and no `host` (a browser) holds the multihop handle in its
/// state, as a host build does. This item does not compile without it.
#[cfg(all(feature = "multihop", not(feature = "host")))]
const _: fn(&EventLoopState) -> Option<&habilis_network_iroh_multihop_transport::MultihopHandle> =
    EventLoopState::multihop;
