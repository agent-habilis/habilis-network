use crate::transport::UdpTransport;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use n0_future::time::Instant as TokioInstant;

use iroh::{EndpointAddr, EndpointId};
use serde::Serialize;

use super::message_log::MessageLog;
#[cfg(feature = "host")]
use crate::daemon::state_file::StateFile;
use crate::protocol::identity::Identity;
use crate::protocol::mesh::Mesh;
use crate::protocol::message::{Authored, Verified, WireFrame};
use crate::protocol::{
    AuthorKey, ContentHash, DedupKey, Message, MessageId, Nickname, ShardGroup, SymmetricKey,
    UnixSecs,
};
use crate::util::bounded_fifo_set::BoundedFifoSet;
use crate::util::bounded_queue::BoundedQueue;
use crate::util::clock::{Instant, millis_saturating};
use crate::util::cooldown::Cooldown;

use crate::util::tuning::{
    KNOWN_ENDPOINTS_CAP, LANE_WANTED, MESSAGE_LOG_SIZE, PENDING_OUTBOUND_CAP, QUIET_CAP,
    RECLAIM_WINDOW, REGRAFT_AFTER, RELINK_COOLDOWN, SEEN_IDS_CAP, STARVED,
    rendezvous_periodic_return,
};

/// How long after it let go of the rendezvous a node wants it again. Every node waits the same
/// period, plus a share of up to half of it that the id of the node fixes: the pubkey bytes are
/// uniform, so n members do not come back together.
fn rendezvous_return_after(local: EndpointId) -> Duration {
    let period = rendezvous_periodic_return();
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&local.as_bytes()[..8]);
    let share_ms = u64::from_le_bytes(prefix) % (millis_saturating(period) / 2).max(1);
    period + Duration::from_millis(share_ms)
}

/// How long an author whose digest we could not read stays unreported. A build
/// that does not know the window format sends one every round, and one line per
/// author per window says it without filling the log.
const UNREADABLE_DIGEST_LOG_WINDOW: Duration = Duration::from_mins(10);

/// How we currently reach a peer: `Direct` when we hold a live gossip
/// link to its self-advertised endpoint, else `Gossip` (relayed). Derived
/// from `linked_endpoints` without surfacing the node id — see
/// `peer_endpoints`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Reach {
    Direct,
    Gossip,
}

/// Tests only: which inbound frame the drop hook takes.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TestDrop {
    /// The app frame whose body is this text.
    AppBody(String),
    /// A shared-state change.
    StateChange,
}

/// The most link vectors that wait for the binding of their author: one per author, and a mesh
/// holds fewer members than this. A flood of authors that never bind cannot grow the park.
#[cfg(feature = "multihop")]
const MAX_PARKED_LINK_STATES: usize = 256;

/// Link vectors that arrived before the roster bound an endpoint to their author, one per
/// author: a newer one replaces the older. The binding comes with the `PeerInfo` of the author,
/// which can arrive a few milliseconds after its first vector, now that vectors go out when a link
/// comes up. A vector that is dropped there is waited for until the next tick, 15 s on, and the
/// session that it makes possible comes too late for the route that it carries.
#[cfg(feature = "multihop")]
#[derive(Debug)]
pub(crate) struct ParkedLinkStates {
    by_author: HashMap<Nickname, habilis_network_iroh_multihop_transport::LinkVector>,
    cap: usize,
}

#[cfg(feature = "multihop")]
impl ParkedLinkStates {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            by_author: HashMap::new(),
            cap,
        }
    }

    /// Park `vector` for `author`, in place of the one that waited. Whether it was kept: the
    /// vector of an author that does not wait yet is refused at the cap.
    pub(crate) fn park(
        &mut self,
        author: Nickname,
        vector: habilis_network_iroh_multihop_transport::LinkVector,
    ) -> bool {
        if !self.by_author.contains_key(&author) && self.by_author.len() >= self.cap {
            return false;
        }
        self.by_author.insert(author, vector);
        true
    }

    /// The vector that waits for `author`, if any.
    pub(crate) fn take(
        &mut self,
        author: &Nickname,
    ) -> Option<habilis_network_iroh_multihop_transport::LinkVector> {
        self.by_author.remove(author)
    }
}

#[cfg(feature = "multihop")]
impl Default for ParkedLinkStates {
    fn default() -> Self {
        Self::new(MAX_PARKED_LINK_STATES)
    }
}

/// One peer in a [`RosterSnapshot`]. `last_seen_secs_ago` is
/// `None` until the peer's first heartbeat is timed; `quiet` marks a
/// peer heartbeat-evicted past `ALIVE_TIMEOUT` (still returnable);
/// `reach` is `direct` only while we hold a live link to it; `transport`
/// is the lane a directed frame to this peer would take right now (the
/// live `crate::transport` send decision — distinct from `reach`, which
/// is a gossip-overlay link fact). Serialized directly into the
/// consumer's roster surfaces.
#[derive(Debug, Clone, Serialize)]
pub struct RosterEntry {
    pub nickname: Nickname,
    pub last_seen_secs_ago: Option<u64>,
    pub quiet: bool,
    pub reach: Reach,
    pub transport: crate::transport::Lane,
}

/// Live peer roster: every known peer (active + quiet) sorted
/// most-recently-seen first, plus `count == peers.len() + 1` (the
/// `+1` is self — same definition as the statusline `peer_count`).
#[derive(Debug, Clone, Serialize)]
pub struct RosterSnapshot {
    pub peers: Vec<RosterEntry>,
    pub count: usize,
}

/// What a linked peer's selected data path is, as last observed. A link
/// starts on the relay and migrates to a direct path once iroh punches one,
/// so a value taken at `NeighborUp` is a first reading, refreshed by the
/// census.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectState {
    /// A probe (or a `WebRTC` negotiation) is in flight; the peer is held off
    /// the overlay until it reports.
    Pending,
    /// A hole-punched IP path or a custom transport (`WebRTC`, multihop).
    Direct,
    /// The relay is the only active path.
    RelayOnly,
}

impl DirectState {
    /// From a `conn_path` reading; `None` when the reading proves nothing.
    /// `Mixed` is such a reading: iroh keeps the relay path open beside a
    /// punched one, and `conn_path` cannot tell which is selected, so a mixed
    /// link is neither proven direct nor known relay-only.
    pub(crate) fn from_summary(summary: crate::gossip::PathSummary) -> Option<Self> {
        use crate::gossip::PathSummary;
        match summary {
            PathSummary::Direct => Some(Self::Direct),
            PathSummary::Relay => Some(Self::RelayOnly),
            PathSummary::Mixed | PathSummary::Unknown => None,
        }
    }
}

/// What a member's `PeerInfo` says about the rendezvous, and whether we believe the sender. One
/// struct for the pair, because both are a `bool` and a swap compiles and flips the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RivalFlag {
    /// The signer proved the endpoint it sent from.
    pub(crate) proven: bool,
    /// The `PeerInfo` carries the beacon flag: the member holds the rendezvous.
    pub(crate) held: bool,
}

/// Link counts by [`DirectState`], for the census line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectCounts {
    pub(crate) direct: usize,
    pub(crate) relay_only: usize,
    pub(crate) pending: usize,
}

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
    pub(crate) relay_transport: bool,
    /// Where a direct-path probe reports its verdict; the loop's receiver
    /// grafts on it (`transport::probe::on_outcome`). A detached sender until
    /// the real loop installs its channel.
    pub(crate) direct_proven:
        tokio::sync::mpsc::UnboundedSender<crate::transport::probe::DirectOutcome>,
    /// The gossip transport, when the engine installs one (Phase 6, step 10). The split of the
    /// mesh topic hands it the frames, and counts a lag on it.
    pub(crate) gossip_handle: Option<habilis_network_iroh_gossip_transport::GossipHandle>,
    /// Where a path watcher reports a change of the selected path to a peer
    /// the race covers (`transport::probe::on_path_change`).
    pub(crate) path_changes:
        tokio::sync::mpsc::UnboundedSender<crate::transport::probe::PathChange>,
    /// Where a flushed frame whose dial failed comes back to the loop, to be buffered again
    /// (`gossip::requeue_failed`). A detached sender until the real loop installs its channel.
    pub(crate) flush_failed: tokio::sync::mpsc::UnboundedSender<(Verified, WireFrame)>,
    /// The pooled connection each watched peer's watcher follows, by stable
    /// id (`None` while its dial runs), so a replaced connection gets a fresh
    /// watcher and a stale one's reports are dropped.
    pub(crate) path_watchers: HashMap<EndpointId, Option<usize>>,
    /// The last selected path kind each watcher reported, for the alive
    /// tick's nudge of peers riding `WebRTC`.
    pub(crate) path_kinds: HashMap<EndpointId, crate::transport::probe::PathKind>,
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
    pub(crate) proven_endpoints: crate::transport::endpoint_proof::ProvenEndpoints,
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
    pub(crate) redials: crate::transport::redial::Redials,
    /// Since when this node holds two or more links fewer than G, with the link to
    /// the rendezvous counted. Cleared as soon as it holds G - 1. See `note_link_count`.
    pub(crate) below_target_since: Option<Instant>,
    /// When a graft last fell back to a `Join` for a starved node.
    pub(crate) join_fallback_at: Option<Instant>,
    /// The peers that refused a `Neighbor` request, and the wait before they are asked again.
    pub(crate) graft_backoff: crate::transport::graft_backoff::GraftBackoff,
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
    pub(crate) resend_outbox: crate::transport::ResendOutbox,
    /// Tests only: the one inbound frame to drop before the app reads it, as a full queue between
    /// the gossip layer and the loop does. The gossip layer has counted it as delivered.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) test_drop: Option<TestDrop>,
    /// Tests only: how many frames the hook dropped.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) test_drops_fired: u32,
    pub(crate) resend_receiver: Option<tokio::sync::mpsc::Receiver<crate::transport::Resend>>,
    /// When each asker's state or meta digest was last served, per plane. A
    /// new node sends a digest pair for every peer it sees, all with the same
    /// heads, and every holder hears each one; the plane is in the key so the
    /// asker's re-ask at its first real-peer link, answered point-to-point,
    /// is not refused by the gossip answer before it.
    pub(crate) state_digest_serves: crate::gossip::antientropy::ServeBudget,
    /// This node's own fast rounds of state digests while it backfills.
    pub(crate) fast_rounds: crate::gossip::antientropy::FastRounds,
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
    pub(crate) probe_backoff: super::probe_backoff::ProbeBackoff,
    /// Whether grafting the rendezvous must wait for an attached `WebRTC`
    /// session — true for a webrtc-shaped node on a lookup-only mesh; see
    /// `transport::webrtc::rendezvous_graftable`.
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
    pub(crate) unicast_pool: crate::transport::UnicastPool,
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
    pub(crate) underlay_webrtc: Option<crate::transport::underlay_webrtc::UnderlayWebRtc>,
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
    pub(crate) rungs: crate::beacon::RungWatch,
    /// Tests only: the beacon is shed at the top of the next turn of the loop, as a re-check
    /// shed does (`Request::ShedBeacon`).
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) shed_requested: bool,
    /// Tests only: the beacon stops answering at the top of the next turn of the loop
    /// (`Request::StallBeacon`).
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) stall_requested: bool,
    /// What this node already asked of the members it heard on the LAN.
    pub(crate) lan_grafts: crate::gossip::lan::LanGrafts,
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
    pub(crate) webrtc_admission: crate::transport::SignalAdmission,
    /// The address book of the member endpoint (`lookup::address_book`): where the addresses of the
    /// peers are registered with `lookup::add_peer_addr`.
    pub(crate) address_book: iroh::address_lookup::memory::MemoryLookup,
    /// How far ICE may reach when this peer gathers candidates. Host-only on a
    /// loopback mesh, which promises to make no external network call —
    /// `IceConfig::default()` would query two public STUN servers.
    pub(crate) webrtc_ice: crate::transport::IceProfile,
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
    /// on this beacon; see `beacon_arm::defer_shed`. Cleared by a shed and by a
    /// fresh claim (`beacon_arm::schedule_rival_recheck`).
    pub(crate) rival_recheck_deferrals: u32,
    /// The close of the beacon that a rival re-check just shed: when it resolves the loop
    /// re-probes the id at once, instead of at the next reclaim tick. `None` when no shed runs.
    pub(crate) beacon_closing: Option<tokio::sync::oneshot::Receiver<()>>,
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
    pub(crate) live_count: Option<Arc<AtomicUsize>>,
    pub(crate) message_log: MessageLog,
    /// Shard groups already reassembled + surfaced, so a body is surfaced
    /// once even if a shard is re-fetched (via anti-entropy) after its id aged
    /// out of [`seen`](Self::seen). Bounded — groups are rare and short-lived.
    pub(crate) reassembled_groups: BoundedFifoSet<ShardGroup>,
    /// Partial multipart bodies buffering toward reassembly — dedicated and
    /// byte-budgeted, decoupled from the message log so log eviction can
    /// never break reassembly. Swept for stale groups on the prune tick.
    pub(crate) reassembly: super::reassembly::ReassemblyStore,
    /// Serialized frames of our recent big (unlogged) outbound shard groups —
    /// the re-serve source for peers' `shard/repair` requests (big groups
    /// skip the message log, so anti-entropy can't heal them).
    pub(crate) shard_cache: super::reassembly::ShardCache,
    /// The `state` channel: an automerge CRDT plus the signed change frames that
    /// carried it (the re-serve store). Convergence and card authorization live
    /// in [`super::doc`]; reconciliation is heads-based anti-entropy. This is the
    /// document a consumer's `state get` surface reads.
    pub(crate) state_doc: super::doc::MeshDoc,
    /// The `meta` channel's document — a second, independent shared-state channel.
    /// Gates foreign-card writes (unlike `state`), since a `meta` card carries a
    /// peer's cryptographic identity.
    pub(crate) meta_doc: super::doc::MeshDoc,
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
    pub(crate) mesh_password: Option<crate::protocol::crypto::Password>,
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

/// Wakeup attribution for the idle-cost work: one counter per `select!` arm,
/// reported as a delta on each `mesh census` line and reset there.
///
/// Plain `u64`, not atomics — the event loop owns `&mut EventLoopState`, so a
/// bump is an increment with no synchronization. That matters more than it
/// looks: the arms being measured fire up to 150×/min, and the cheapest thing
/// that could observe them (a `debug!` per tick) costs a write per wakeup and
/// would price its own instrumentation into the measurement.
///
/// Counting arms rather than timers is deliberate. It splits timer work from
/// inbound traffic, which is the split that says whether an idle daemon is
/// paying for its own housekeeping or for the peers talking to it.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct IdleCounters {
    /// Every loop iteration, whichever arm won. The denominator for the rest.
    pub wakeups: u64,
    pub prune: u64,
    pub alive: u64,
    pub sweep: u64,
    pub heal: u64,
    pub reclaim: u64,
    pub antientropy: u64,
    pub state_refresh: u64,
    pub linkstate: u64,
    /// Arms driven by something other than a maintenance timer — inbound
    /// gossip/unicast, IPC, HTTP, deadlines. Summed rather than split per arm:
    /// on an idle daemon this should read 0, and a non-zero value means the
    /// run was not idle, which is the only bit worth reporting.
    pub external: u64,
    /// Signed frames put on the wire by a maintenance tick. The direct cost
    /// driver behind `user` CPU: each one is an Ed25519 signature plus a
    /// serialization.
    pub broadcasts: u64,
    /// Messages a digest answer put in the resend outbox.
    pub resent: u64,
    /// Messages a digest answer could not put there because it was full: the
    /// next digest asks for them again.
    pub resend_dropped: u64,
}

impl IdleCounters {
    /// Read the counters and zero them, so each census line carries the
    /// interval's own work rather than a running total a reader has to
    /// difference (and that a rotated log would corrupt).
    pub(crate) fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}

/// An in-flight RTT round. [`start_ping_round`](crate::ops::start_ping_round), which a driver
/// calls, arms it and sends the first probe at `t1`; the event loop sends the second, a fresh
/// ping, at the middle of the window, so that a probe lost on the way (the peer was not linked
/// yet, a dropped frame) is made up for. A pong names the probe it answers, so its RTT is read
/// from that probe's send, and a pong that names no probe of this round is dropped. A peer's
/// first pong is the one kept. The price is one more broadcast per round and one more pong per
/// peer. The round is emitted and cleared at `deadline`.
#[derive(Debug)]
pub(crate) struct PingRound {
    pub(crate) t1: TokioInstant,
    pub(crate) deadline: TokioInstant,
    /// The probes of the round, by message id, with the instant each left.
    pub(crate) probes: HashMap<MessageId, TokioInstant>,
    /// The RTT of the first pong of each peer.
    pub(crate) pongs: HashMap<Nickname, Duration>,
    /// When set (the in-process `ping` request), the finalized RTT rows are
    /// delivered here instead of only emitted as a `ping_report` event — the
    /// in-process driver has no event stream to read the report from. `None`
    /// for the CLI/IPC path, which consumes the event.
    pub(crate) resp: Option<tokio::sync::oneshot::Sender<Vec<(Nickname, u64)>>>,
}

impl PingRound {
    /// A round whose first probe is `first`, sent at `t1`.
    pub(crate) fn new(
        first: &Message,
        t1: TokioInstant,
        deadline: TokioInstant,
        resp: Option<tokio::sync::oneshot::Sender<Vec<(Nickname, u64)>>>,
    ) -> Self {
        Self {
            t1,
            deadline,
            probes: HashMap::from([(first.id.clone(), t1)]),
            pongs: HashMap::new(),
            resp,
        }
    }

    /// When the second probe is due: the middle of the window, once.
    pub(crate) fn second_probe_at(&self) -> Option<TokioInstant> {
        (self.probes.len() < 2).then(|| self.t1 + self.deadline.duration_since(self.t1) / 2)
    }

    /// Record the pong of `peer` that answers `probe`, arriving at `arrival`: the RTT is read from
    /// that probe's send, and the first pong of a peer is kept. `false` when `probe` is no probe
    /// of this round.
    pub(crate) fn record_pong(
        &mut self,
        peer: Nickname,
        probe: &MessageId,
        arrival: TokioInstant,
    ) -> bool {
        let Some(sent) = self.probes.get(probe) else {
            return false;
        };
        let rtt = arrival.duration_since(*sent);
        self.pongs.entry(peer).or_insert(rtt);
        true
    }
}

/// The mesh's secret material, grouped so [`EventLoopState::new`] can take
/// both by value (the stretched key must be owned here so it drops/zeroizes
/// once the per-channel keys are derived) without blowing its argument budget.
#[derive(Default)]
pub(crate) struct MeshSecrets {
    pub password: Option<crate::protocol::crypto::Password>,
    pub key: Option<SymmetricKey>,
}

/// Everything [`EventLoopState::new`] needs beyond the clock, grouped for the
/// same reason [`MeshSecrets`] is: the argument budget. `now` stays separate
/// because tests pin it to a deterministic instant.
pub(crate) struct StateInit {
    #[cfg(feature = "host")]
    pub(crate) state_file: Option<StateFile>,
    pub(crate) identity: Arc<Identity>,
    pub secrets: MeshSecrets,
    /// The `meta` channel's per-peer write gate; `None` leaves it free-form.
    pub per_peer_gate: Option<crate::doc::SelfWriteGate>,
    /// The negotiation-slot table the Router's signal acceptor was built with.
    ///
    /// Taken at construction rather than assigned afterwards, because the cap
    /// only means anything if the dialing and answering sides count against the
    /// *same* table. Defaulting it here and overwriting it later left a second
    /// ceiling briefly existing and enforcing nothing.
    pub(crate) webrtc_admission: crate::transport::SignalAdmission,
    /// The address book of the member endpoint, made by `lookup::address_book` where the
    /// endpoint was built.
    pub(crate) address_book: iroh::address_lookup::memory::MemoryLookup,
    /// How far ICE may reach, derived from the mesh's own lookups so it cannot
    /// disagree with them.
    pub(crate) webrtc_ice: crate::transport::IceProfile,
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
            crate::transport::ResendOutbox::new(crate::util::tuning::RESEND_OUTBOX_CAP);
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
            relay_transport: false,
            direct_proven: tokio::sync::mpsc::unbounded_channel().0,
            gossip_handle: None,
            path_changes: tokio::sync::mpsc::unbounded_channel().0,
            flush_failed: tokio::sync::mpsc::unbounded_channel().0,
            path_watchers: HashMap::new(),
            path_kinds: HashMap::new(),
            route_dialed: HashMap::new(),
            known_endpoints: BoundedFifoSet::new(KNOWN_ENDPOINTS_CAP),
            proven_endpoints: crate::transport::endpoint_proof::ProvenEndpoints::new(
                KNOWN_ENDPOINTS_CAP,
            ),
            peer_info_proof: None,
            relink: Cooldown::new(RELINK_COOLDOWN),
            peerinfo_flooded_at: None,
            peerinfo_deferred: false,
            last_flooded_addr: None,
            below_target_since: None,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            redials: crate::transport::redial::Redials::default(),
            join_fallback_at: None,
            graft_backoff: crate::transport::graft_backoff::GraftBackoff::default(),
            lane_wanted: HashMap::new(),
            regraft_at: HashMap::new(),
            digest_serves: Cooldown::new(habilis_network_util::tuning::ANTIENTROPY_SERVE_COOLDOWN),
            digest_unreadable: Cooldown::new(UNREADABLE_DIGEST_LOG_WINDOW),
            resend_outbox,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            test_drop: None,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            test_drops_fired: 0,
            resend_receiver: Some(resend_receiver),
            state_digest_serves: crate::gossip::antientropy::ServeBudget::default(),
            fast_rounds: crate::gossip::antientropy::FastRounds::default(),
            peers: HashSet::new(),
            last_seen: HashMap::new(),
            peer_endpoints: HashMap::new(),
            rendezvous_id: None,
            quiet: BoundedFifoSet::new(QUIET_CAP),
            quiet_since: HashMap::new(),
            left: BoundedFifoSet::new(QUIET_CAP),
            left_at: HashMap::new(),
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
            rendezvous_release_links: crate::util::tuning::RENDEZVOUS_RELEASE_LINKS,
            rendezvous_session_stale: false,
            rendezvous_offer_fallback: false,
            rendezvous_answers_jsep: true,
            rendezvous_probe_read_free: false,
            probe_backoff: super::probe_backoff::ProbeBackoff::default(),
            rendezvous_graft_needs_session: false,
            local_udp_transport: UdpTransport::Present,
            announced: false,
            meshed: false,
            unicast_pool: crate::transport::UnicastPool::disconnected(),
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
            rungs: crate::beacon::RungWatch::detached(),
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            shed_requested: false,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            stall_requested: false,
            lan_grafts: crate::gossip::lan::LanGrafts::default(),
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
            reassembly: super::reassembly::ReassemblyStore::default(),
            shard_cache: super::reassembly::ShardCache::default(),
            state_doc: super::doc::MeshDoc::new_ungated().with_key(state_key),
            meta_doc: match per_peer_gate {
                Some(gate) => super::doc::MeshDoc::new_gated(gate),
                None => super::doc::MeshDoc::new_ungated(),
            }
            .with_key(meta_key),
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
                transport: crate::transport::lane_for(nick, self),
            })
            .chain(self.quiet.iter().map(|nick| RosterEntry {
                nickname: nick.clone(),
                // Quiet peers: their last-heard instant, retained in
                // `quiet_since` (the eviction drops `last_seen`). A quiet
                // peer has no live link, so it is always `Gossip`.
                last_seen_secs_ago: self.quiet_since.get(nick).map(secs_since),
                quiet: true,
                reach: Reach::Gossip,
                transport: crate::transport::lane_for(nick, self),
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
        let addr = self
            .peer_endpoints
            .values()
            .find(|addr| addr.id == peer)?
            .clone();
        self.want_lane_session(peer, now);
        Some(addr)
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
            || self.pair_path_kind(peer) == Some(crate::transport::probe::PathKind::Relay)
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
        let addr = self.peer_endpoints.remove(nick)?;
        self.graft_backoff.reset(addr.id);
        self.proven_endpoints.forget_endpoint(addr.id);
        self.forget_rival_holder(addr.id);
        self.direct.remove(&addr.id);
        self.path_watchers.remove(&addr.id);
        self.path_kinds.remove(&addr.id);
        Some(addr)
    }

    /// A `NeighborDown` for `peer`: the gossip link is gone, the path verdict
    /// stays. It describes the pooled unicast connection, which outlives the
    /// link; erasing it parked every directed frame on a link flap until the
    /// alive tick re-probed (about 40 s with the relink cooldown).
    /// Remember that `nick` said goodbye at `at`. A later `left` of the same peer moves the mark
    /// forward, and an older one (a delayed copy) leaves it where it is.
    pub(crate) fn note_left(&mut self, nick: &Nickname, at: UnixSecs) {
        self.left.insert(nick.clone());
        let mark = self.left_at.entry(nick.clone()).or_insert(at);
        *mark = (*mark).max(at);
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
                now.saturating_duration_since(since)
                    >= crate::util::tuning::silent_partition_after()
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
        if (crate::beacon::Contest { own, rival: sender }).own_yields() {
            self.yield_to_lower = true;
            self.next_rival_recheck = Some(now);
        } else if newly {
            // Once per holder, so that a holder that sends its flag again and again cannot keep
            // our re-check away. Pushed, not dropped: a holder that never re-checks never finds
            // a co-host it does not know of.
            let pushed = now
                + super::beacon_arm::next_recheck_delay(
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
        let spacing = crate::util::tuning::rival_recheck_meshed();
        if self
            .second_group_sign_at
            .is_some_and(|at| now.saturating_duration_since(at) < spacing)
        {
            return;
        }
        let brisk = now + super::beacon_arm::next_recheck_delay(0, self.peers.len(), own);
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

    /// Whether a test holds this node's claims back (`Request::HoldClaims`).
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
        self.rendezvous_comeback_until = Some(now + crate::util::tuning::RENDEZVOUS_COMEBACK);
    }

    /// The periodic return, if it fell due, is owed like any other return: for a bounded time,
    /// and the next one is set one period later. A visit that finds no link is then wanted for
    /// the comeback window and no longer, and a member does not graft and offer at every tick for
    /// ever. Called on the heal tick.
    pub(crate) fn pay_periodic_return(&mut self, now: Instant, local: EndpointId) {
        if self.rendezvous_return_due.is_some_and(|due| now >= due) {
            self.owe_rendezvous_return(now);
            self.rendezvous_return_due = Some(now + rendezvous_return_after(local));
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
            (owed_visit || periodic_visit).then(|| now + crate::util::tuning::RENDEZVOUS_DWELL);
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
        self.rendezvous_return_due = Some(Instant::now() + rendezvous_return_after(local));
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
    pub(crate) fn mark_seen(&mut self, message: &Verified) -> bool {
        !self.seen.insert(message.dedup_key())
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
            super::reassembly::ShardIngest::Complete(logical) => {
                self.reassembled_groups.insert(shard.group.clone());
                Some(*logical)
            }
            super::reassembly::ShardIngest::Buffered | super::reassembly::ShardIngest::Dropped => {
                let logical = self.reassemble_from_log(trigger)?;
                // The store may still hold a partial buffer for this group
                // (e.g. just the trigger, post-TTL) — release its budget.
                self.reassembly.forget(trigger);
                self.reassembled_groups.insert(shard.group.clone());
                Some(logical)
            }
        }
    }

    /// The log-backed completion path for a **small** (logged) group: scan
    /// the message log for this author's shards and synthesize when every
    /// slot is present. Mirrors the store's synthesis exactly.
    fn reassemble_from_log(&self, trigger: &Verified) -> Option<Authored> {
        let shard = trigger.shard.as_ref()?;
        // A verified shard always has its author key.
        let author = trigger.key();
        if !crate::protocol::message::shard_fits_log(trigger) {
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
        let body = crate::protocol::MessageBody::new(body).ok()?;
        let header = slots[0].expect("shard 0 present");
        Some(super::reassembly::synthesize_from(
            header,
            body,
            &shard.group,
        ))
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
    pub(crate) fn observe_path(&mut self, peer: EndpointId, summary: crate::gossip::PathSummary) {
        if !self.relay_transport && summary == crate::gossip::PathSummary::Relay {
            return;
        }
        if let Some(state) = DirectState::from_summary(summary) {
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
    #[must_use]
    pub fn dag_parents(&self) -> Vec<ContentHash> {
        let mut heads: Vec<ContentHash> = self.dag_heads.iter().copied().collect();
        heads.sort_unstable();
        heads.truncate(MAX_DAG_PARENTS);
        heads
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
    pub fn doc(&self, channel: crate::protocol::Channel) -> &crate::doc::MeshDoc {
        match channel {
            crate::protocol::Channel::State => &self.state_doc,
            crate::protocol::Channel::Meta => &self.meta_doc,
        }
    }

    /// Mutable [`Self::doc`], for applying a local change before broadcast.
    pub fn doc_mut(&mut self, channel: crate::protocol::Channel) -> &mut crate::doc::MeshDoc {
        match channel {
            crate::protocol::Channel::State => &mut self.state_doc,
            crate::protocol::Channel::Meta => &mut self.meta_doc,
        }
    }

    /// This member's signing identity.
    #[must_use]
    pub fn identity(&self) -> &Arc<Identity> {
        &self.identity
    }

    /// The address book of the member endpoint: one per endpoint, made by
    /// `lookup::address_book`. Write to it with `add_peer_addr`.
    #[must_use]
    pub fn address_book(&self) -> &iroh::address_lookup::memory::MemoryLookup {
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
            .map(|addr| addr.id)
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
    pub fn mesh_password(&self) -> Option<&crate::protocol::crypto::Password> {
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
    pub fn advance_chain(&mut self, prev: ContentHash) {
        self.self_seq += 1;
        self.self_prev = Some(prev);
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
    pub fn shard_cache_mut(&mut self) -> &mut super::reassembly::ShardCache {
        &mut self.shard_cache
    }

    /// Receiver-side partial-body store.
    pub fn reassembly_mut(&mut self) -> &mut super::reassembly::ReassemblyStore {
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
    pub(crate) fn pair_path_kind(
        &self,
        peer: EndpointId,
    ) -> Option<crate::transport::probe::PathKind> {
        crate::transport::probe::pair_kind(
            self.path_kinds.get(&peer).copied(),
            self.webrtc_admission.selected_kind(peer),
        )
    }

    /// Whether the selected path of `peer` is the gossip rung. The recursion rule closes a gossip
    /// link on that path, so a graft only makes the gossip layer dial a link that dies at once.
    /// Not while a session is attached: it carries the pair whatever one connection reads, and the
    /// link rides it once iroh moves the connection.
    pub(crate) fn rides_gossip_rung(&self, peer: EndpointId) -> bool {
        self.pair_path_kind(peer) == Some(crate::transport::probe::PathKind::Gossip)
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
            crate::transport::underlay_webrtc::tick_now(self);
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
    /// `transport::endpoint_proof`). A state digest of an asker whose endpoint is not proven is
    /// answered on gossip, as it is for a late joiner before its `PeerInfo` arrives.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub fn forget_endpoint_proof(&mut self, peer: &Nickname) {
        if let Some(endpoint) = self.peer_endpoints.get(peer).map(|addr| addr.id) {
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

#[cfg(test)]
mod tests {
    use super::{
        DirectCounts, DirectState, Duration, EndpointId, EventLoopState, Instant,
        KNOWN_ENDPOINTS_CAP, Message, PingRound, QUIET_CAP, RELINK_COOLDOWN, Reach, RivalFlag,
        TokioInstant,
    };
    use crate::protocol::{AppFrameParams, MeshId, MessageBody, MessageId};
    use crate::protocol::{AuthorKey, ContentHash, UnixSecs};
    use crate::testing::{author_of, endpoint_id, fresh_state, fresh_state_with_book, nick};
    use habilis_network_test_tracing::test;

    fn lower_and_higher() -> (EndpointId, EndpointId) {
        let first = endpoint_id(1);
        let second = endpoint_id(2);
        if first < second {
            (first, second)
        } else {
            (second, first)
        }
    }

    /// Two holders of one rendezvous that share an overlay, one dependent on each: the lower
    /// holder's flag must end the split now, not after the wait for the dependent.
    #[test]
    fn a_flag_from_a_lower_holder_makes_us_yield_at_once() {
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        let now = Instant::now();

        state.note_rival_beacon_flag(
            high,
            AuthorKey::from_bytes([9u8; 32]),
            low,
            RivalFlag {
                proven: true,
                held: true,
            },
            now,
        );

        assert!(state.yield_to_lower);
        assert_eq!(state.next_rival_recheck, Some(now));
    }

    /// The winner keeps its beacon. Its re-check is pushed one steady round, not dropped: a
    /// holder that never re-checks never finds a co-host it does not know of.
    #[test]
    fn a_flag_from_a_higher_holder_pushes_our_re_check_out() {
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        state.rival_recheck_rounds = 2;
        state.rival_recheck_deferrals = 1;
        let now = Instant::now();

        state.note_rival_beacon_flag(
            low,
            AuthorKey::from_bytes([9u8; 32]),
            high,
            RivalFlag {
                proven: true,
                held: true,
            },
            now,
        );

        assert!(!state.yield_to_lower);
        let next = state
            .next_rival_recheck
            .expect("the re-check is pushed out, not dropped");
        assert!(next > now, "a steady round out, not due");
        assert_eq!(state.rival_recheck_rounds, 2, "the rounds stay");
        assert_eq!(state.rival_recheck_deferrals, 1, "the deferrals stay");
    }

    /// The longest wait that the first round of a re-check can have: its fast base plus the
    /// offset of the id.
    fn brisk_wait() -> Duration {
        crate::util::tuning::rival_recheck_first() + crate::util::tuning::RIVAL_RECHECK_OFFSET_SPAN
    }

    /// A holder that has found no member has a re-check an hour or two out. A sign that another
    /// group may exist is all it has to go on: the re-check comes back to the fast base, and the
    /// rounds start from it again.
    #[test]
    fn a_sign_of_a_second_group_brings_the_re_check_to_the_brisk_base() {
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        state.rival_recheck_rounds = 7;
        let now = Instant::now();
        state.next_rival_recheck = Some(now + Duration::from_hours(1));

        state.note_second_group_sign(endpoint_id(1), now);

        let next = state.next_rival_recheck.expect("a re-check is armed");
        assert!(
            next <= now + brisk_wait(),
            "the re-check is due within the fast base"
        );
        assert_eq!(state.rival_recheck_rounds, 0, "the rounds start again");
    }

    /// A burst of members that arrive must not shed the beacon again and again.
    #[test]
    fn a_second_sign_inside_one_steady_interval_changes_nothing() {
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        let now = Instant::now();
        let far = now + Duration::from_hours(1);
        state.next_rival_recheck = Some(far);
        state.note_second_group_sign(endpoint_id(1), now);
        assert!(
            state.next_rival_recheck.is_some_and(|next| next < far),
            "the first sign counts"
        );

        state.next_rival_recheck = Some(far);
        state.rival_recheck_rounds = 3;
        state.note_second_group_sign(endpoint_id(1), now + Duration::from_secs(10));

        assert_eq!(state.next_rival_recheck, Some(far));
        assert_eq!(state.rival_recheck_rounds, 3);
    }

    #[test]
    fn a_sign_changes_nothing_while_we_do_not_hold_the_beacon() {
        let mut state = fresh_state();
        let now = Instant::now();
        let far = now + Duration::from_hours(1);
        state.next_rival_recheck = Some(far);

        state.note_second_group_sign(endpoint_id(1), now);

        assert_eq!(state.next_rival_recheck, Some(far));
    }

    /// A loopback room has no re-check, and the creator never has one: a sign arms nothing.
    #[test]
    fn a_sign_arms_no_re_check_where_none_applies() {
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        state.next_rival_recheck = None;

        state.note_second_group_sign(endpoint_id(1), Instant::now());

        assert_eq!(state.next_rival_recheck, None);
    }

    #[test]
    fn a_sign_does_not_push_out_a_re_check_that_is_due_sooner() {
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        state.rival_recheck_rounds = 4;
        let now = Instant::now();
        let soon = now + Duration::from_secs(1);
        state.next_rival_recheck = Some(soon);

        state.note_second_group_sign(endpoint_id(1), now);

        assert_eq!(state.next_rival_recheck, Some(soon));
        assert_eq!(state.rival_recheck_rounds, 4);
    }

    /// A flag is remembered only from a proven sender that is not us, and moves our re-check
    /// only while we hold the beacon.
    #[test]
    fn a_flag_that_does_not_count_changes_nothing() {
        let (low, high) = lower_and_higher();
        let signer = AuthorKey::from_bytes([9u8; 32]);
        let now = Instant::now();

        let mut no_flag = fresh_state();
        no_flag.hosts_rendezvous = true;
        no_flag.note_rival_beacon_flag(
            high,
            signer,
            low,
            RivalFlag {
                proven: true,
                held: false,
            },
            now,
        );

        let mut unproven = fresh_state();
        unproven.hosts_rendezvous = true;
        unproven.note_rival_beacon_flag(
            high,
            signer,
            low,
            RivalFlag {
                proven: false,
                held: true,
            },
            now,
        );

        let mut ourselves = fresh_state();
        ourselves.hosts_rendezvous = true;
        ourselves.note_rival_beacon_flag(
            high,
            signer,
            high,
            RivalFlag {
                proven: true,
                held: true,
            },
            now,
        );

        for state in [no_flag, unproven, ourselves] {
            assert!(!state.yield_to_lower);
            assert_eq!(state.next_rival_recheck, None);
            assert!(!state.rival_holder_known());
        }
    }

    /// A node that does not hold the rendezvous still learns who does: it is what keeps it from
    /// probing to claim. Its own re-check has nothing to move.
    #[test]
    fn a_flag_read_while_we_do_not_hold_is_remembered() {
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();

        state.note_rival_beacon_flag(
            high,
            AuthorKey::from_bytes([9u8; 32]),
            low,
            RivalFlag {
                proven: true,
                held: true,
            },
            Instant::now(),
        );

        assert!(state.rival_holder_known());
        assert!(!state.yield_to_lower);
        assert_eq!(state.next_rival_recheck, None);
    }

    /// A member that let go of the rendezvous and reads a holder that no member of its mesh hosts
    /// owes a return, and the debt opens the reclaim window that pays it.
    #[test]
    fn a_holder_outside_the_mesh_owes_a_return_to_a_released_member() {
        let mut state = fresh_state();
        state.rendezvous_release_links = 1;
        state.linked_endpoints.insert(endpoint_id(1));
        assert!(!state.rendezvous_wanted(), "enough links: it let go");

        state.note_holder_outside_mesh(Instant::now());

        assert!(state.rendezvous_wanted(), "a return is owed");
        assert!(state.reclaim_until.is_some(), "the reclaim ticker pays it");
    }

    /// The healthy case, which every released member reads on every heal tick: the holder is a
    /// member of our own mesh, and its flag is known. Nothing is owed, or the mesh would visit the
    /// rendezvous for ever.
    #[test]
    fn a_holder_of_our_own_mesh_owes_nothing() {
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();
        state.rendezvous_release_links = 1;
        state.linked_endpoints.insert(endpoint_id(1));
        state.note_rival_beacon_flag(
            high,
            AuthorKey::from_bytes([9u8; 32]),
            low,
            RivalFlag {
                proven: true,
                held: true,
            },
            Instant::now(),
        );
        assert!(state.rival_holder_known());

        state.note_holder_outside_mesh(Instant::now());

        assert!(state.rendezvous_comeback_until.is_none());
        assert!(!state.rendezvous_wanted());
    }

    /// A member that still holds the link, or hosts the beacon, or wants the rendezvous anyway
    /// (it has fewer links than the release count) owes nothing: a joiner would otherwise stay
    /// a dwell longer at every start.
    #[test]
    fn a_member_that_has_the_link_or_wants_it_anyway_owes_no_return() {
        let mut linked = fresh_state();
        linked.rendezvous_release_links = 1;
        linked.linked_endpoints.insert(endpoint_id(1));
        linked.rendezvous_linked = true;
        linked.note_holder_outside_mesh(Instant::now());
        assert!(
            linked.rendezvous_comeback_until.is_none(),
            "it holds the link"
        );

        let mut host = fresh_state();
        host.rendezvous_release_links = 1;
        host.linked_endpoints.insert(endpoint_id(1));
        host.hosts_rendezvous = true;
        host.note_holder_outside_mesh(Instant::now());
        assert!(host.rendezvous_comeback_until.is_none(), "it hosts it");

        let mut joiner = fresh_state();
        joiner.note_holder_outside_mesh(Instant::now());
        assert!(
            joiner.rendezvous_comeback_until.is_none(),
            "it wants it anyway"
        );
    }

    /// A debt that is owed is not moved by the next read: the window runs out on its own, and a
    /// read after it owes once again. Without this a node that reads the holder on every heal
    /// tick would hold the debt open for ever.
    #[test]
    fn a_second_read_inside_the_window_does_not_move_it() {
        let mut state = fresh_state();
        state.rendezvous_release_links = 1;
        state.linked_endpoints.insert(endpoint_id(1));
        let first = Instant::now();
        state.note_holder_outside_mesh(first);
        let due = state.rendezvous_comeback_until;
        assert!(due.is_some());

        state.note_holder_outside_mesh(first + Duration::from_secs(5));

        assert_eq!(state.rendezvous_comeback_until, due);
    }

    /// A holder that crashes never says that it let go. Its flag goes with the member.
    #[test]
    fn the_flag_of_a_forgotten_member_is_dropped() {
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();
        state.note_rival_beacon_flag(
            high,
            AuthorKey::from_bytes([1u8; 32]),
            low,
            RivalFlag {
                proven: true,
                held: true,
            },
            Instant::now(),
        );
        state.note_rival_beacon_flag(
            high,
            AuthorKey::from_bytes([2u8; 32]),
            endpoint_id(7),
            RivalFlag {
                proven: true,
                held: true,
            },
            Instant::now(),
        );

        state.forget_rival_holder(low);

        assert!(state.rival_holder_known(), "the other holder stays");
        state.forget_rival_holder(endpoint_id(7));
        assert!(!state.rival_holder_known());
    }

    /// A holder that sends its flag again and again must not keep our re-check away: the push
    /// happens once per holder, and exists only to hold our release until the higher one yields.
    #[test]
    fn a_holder_that_repeats_its_flag_pushes_our_re_check_out_once() {
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        let first = Instant::now();

        state.note_rival_beacon_flag(
            low,
            AuthorKey::from_bytes([9u8; 32]),
            high,
            RivalFlag {
                proven: true,
                held: true,
            },
            first,
        );
        let pushed = state.next_rival_recheck;
        assert!(pushed.is_some_and(|due| due > first), "pushed out once");

        state.note_rival_beacon_flag(
            low,
            AuthorKey::from_bytes([9u8; 32]),
            high,
            RivalFlag {
                proven: true,
                held: true,
            },
            first + Duration::from_secs(5),
        );

        assert_eq!(
            state.next_rival_recheck, pushed,
            "the repeat changes nothing"
        );
    }

    /// The push is to at least a steady round out. A re-check that is already later stays.
    #[test]
    fn a_push_never_brings_a_later_re_check_closer() {
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        let now = Instant::now();
        let far = now + Duration::from_secs(100_000);
        state.next_rival_recheck = Some(far);

        state.note_rival_beacon_flag(
            low,
            AuthorKey::from_bytes([9u8; 32]),
            high,
            RivalFlag {
                proven: true,
                held: true,
            },
            now,
        );

        assert_eq!(state.next_rival_recheck, Some(far));
    }

    /// The holder says it let go (a `PeerInfo` without the flag), or the member leaves: the
    /// rendezvous is no longer known to be held by it.
    #[test]
    fn a_holder_stops_counting_when_it_drops_the_flag_or_leaves() {
        let (low, high) = lower_and_higher();
        let signer = AuthorKey::from_bytes([9u8; 32]);
        let mut state = fresh_state();
        state.note_rival_beacon_flag(
            high,
            signer,
            low,
            RivalFlag {
                proven: true,
                held: true,
            },
            Instant::now(),
        );
        assert!(state.rival_holder_known());

        state.note_rival_beacon_flag(
            high,
            signer,
            low,
            RivalFlag {
                proven: true,
                held: false,
            },
            Instant::now(),
        );
        assert!(!state.rival_holder_known(), "no flag takes it out");

        state.note_rival_beacon_flag(
            high,
            signer,
            low,
            RivalFlag {
                proven: true,
                held: true,
            },
            Instant::now(),
        );
        state
            .peer_endpoints
            .insert(nick("bob"), iroh::EndpointAddr::new(low));
        state.forget_peer_endpoint("bob");
        assert!(
            !state.rival_holder_known(),
            "the roster removal takes it out"
        );
    }

    /// The accessor hands out the book that the state was built with, not a copy of it: an address
    /// written through it is in the book of the endpoint.
    #[test]
    fn the_address_book_of_the_state_is_the_book_it_was_given() {
        let book = iroh::address_lookup::memory::MemoryLookup::new();
        let state = fresh_state_with_book(book.clone());
        let bob = endpoint_id(1);
        assert!(
            book.get_endpoint_info(bob).is_none(),
            "the book starts empty"
        );

        crate::lookup::add_peer_addr(
            state.address_book(),
            iroh::EndpointAddr::new(bob).with_ip_addr("192.0.2.1:4000".parse().expect("address")),
        );

        assert!(
            book.get_endpoint_info(bob).is_some(),
            "an address written through the accessor reaches the book of the endpoint"
        );
    }

    /// A linked pair that proved a direct path and loses UDP is re-raced at once: the relay
    /// policy closes at 15 s, and the retry tick would wait up to 30 s for the offer.
    #[test]
    fn a_proven_pair_on_the_relay_is_raced_again_when_its_link_goes_down() {
        use crate::transport::probe::PathKind;
        let (bob, now) = (endpoint_id(1), Instant::now());
        let addr = iroh::EndpointAddr::new(bob)
            .with_relay_url("https://relay.invalid".parse().expect("relay url"));
        let node = |direct: Option<DirectState>, kind: PathKind| {
            let mut node = fresh_state();
            node.peer_endpoints.insert(nick("bob"), addr.clone());
            node.direct.extend(direct.map(|verdict| (bob, verdict)));
            node.path_kinds.insert(bob, kind);
            node
        };

        let mut proven = node(Some(DirectState::Direct), PathKind::Relay);
        assert_eq!(proven.relay_race_on_link_loss(bob, now), Some(addr.clone()));
        assert!(
            proven.lane_session_wanted(bob, now),
            "the offer is not held back"
        );
        assert_eq!(
            proven.relay_race_on_link_loss(endpoint_id(2), now),
            None,
            "an unknown peer"
        );
        for (direct, kind, why) in [
            (Some(DirectState::Direct), PathKind::Ip, "UDP still holds"),
            (
                Some(DirectState::RelayOnly),
                PathKind::Relay,
                "never proven",
            ),
            (None, PathKind::Relay, "no verdict"),
        ] {
            assert_eq!(
                node(direct, kind).relay_race_on_link_loss(bob, now),
                None,
                "{why}"
            );
        }
    }

    /// The recursion rule closes a gossip link on the gossip rung, and no re-graft follows (see
    /// `a_pair_that_rides_the_gossip_rung_is_not_regrafted`). The pair must be raced again then,
    /// or nothing brings a link back while the IP path is gone.
    #[test]
    fn a_proven_pair_on_the_gossip_rung_is_raced_again_when_its_link_goes_down() {
        use crate::transport::probe::PathKind;
        let (bob, now) = (endpoint_id(1), Instant::now());
        let addr = iroh::EndpointAddr::new(bob)
            .with_relay_url("https://relay.invalid".parse().expect("relay url"));
        let mut node = fresh_state();
        node.peer_endpoints.insert(nick("bob"), addr.clone());
        node.direct.insert(bob, DirectState::Direct);
        node.path_kinds.insert(bob, PathKind::Gossip);

        assert_eq!(node.relay_race_on_link_loss(bob, now), Some(addr));
        assert!(
            node.lane_session_wanted(bob, now),
            "the offer is not held back"
        );
    }

    /// A proven pair that loses its link is re-grafted in about a second, whatever the other links
    /// of the node are,
    /// not at the heal tick (10 to 15 s). A pair that flaps is paced by the relink cooldown.
    #[test]
    fn a_proven_peer_that_lost_its_link_is_regrafted_in_about_a_second() {
        let (bob, carol) = (endpoint_id(1), endpoint_id(2));
        let now = Instant::now();
        let after = |millis: u64| now + Duration::from_millis(millis);
        let lost = |peers_left: &[EndpointId], verdict: DirectState| {
            let mut node = fresh_state();
            node.direct.insert(bob, verdict);
            for peer in peers_left {
                node.link(*peer);
            }
            node
        };

        let mut centered = lost(&[], DirectState::Direct);
        assert!(centered.plan_regraft_on_link_loss(bob, now, 0.0));
        assert!(centered.take_regrafts_due(after(900)).is_empty(), "not yet");
        assert_eq!(centered.take_regrafts_due(after(1100)), vec![bob], "due");
        assert!(
            centered.take_regrafts_due(after(1200)).is_empty(),
            "taken once"
        );

        let mut early = lost(&[], DirectState::Direct);
        assert!(early.plan_regraft_on_link_loss(bob, now, -1.0));
        assert_eq!(
            early.take_regrafts_due(after(750)),
            vec![bob],
            "jitter down"
        );
        let mut late = lost(&[], DirectState::Direct);
        assert!(late.plan_regraft_on_link_loss(bob, now, 1.0));
        assert!(late.take_regrafts_due(after(1250)).is_empty(), "jitter up");
        assert_eq!(late.take_regrafts_due(after(1350)), vec![bob]);

        let mut back = lost(&[], DirectState::Direct);
        back.plan_regraft_on_link_loss(bob, now, 0.0);
        back.link(bob);
        assert!(
            back.take_regrafts_due(after(1100)).is_empty(),
            "the link came back"
        );

        let mut other_link = lost(&[carol], DirectState::Direct);
        assert!(
            other_link.plan_regraft_on_link_loss(bob, now, 0.0),
            "a proven pair is grafted again whatever the other links are"
        );
        let mut unproven = lost(&[], DirectState::RelayOnly);
        assert!(
            !unproven.plan_regraft_on_link_loss(bob, now, 0.0),
            "never proven"
        );
        let mut flapping = lost(&[], DirectState::Direct);
        flapping.note_relink(bob, now);
        assert!(
            !flapping.plan_regraft_on_link_loss(bob, now, 0.0),
            "on the relink cooldown"
        );
    }

    /// A pair that reads as the relay is raced again by `relay_race_on_link_loss`, and its graft
    /// follows the attach. A quick re-graft would dial the relay for nothing and arm the backoff.
    #[test]
    fn a_pair_that_reads_as_the_relay_is_not_regrafted_quickly() {
        use crate::transport::probe::PathKind;
        let (bob, now) = (endpoint_id(1), Instant::now());
        let lost = |kind: PathKind| {
            let mut node = fresh_state();
            node.direct.insert(bob, DirectState::Direct);
            node.path_kinds.insert(bob, kind);
            node
        };

        assert!(
            !lost(PathKind::Relay).plan_regraft_on_link_loss(bob, now, 0.0),
            "the relay reading belongs to the race"
        );
        assert!(
            lost(PathKind::Ip).plan_regraft_on_link_loss(bob, now, 0.0),
            "an IP path is grafted again"
        );
    }

    /// A gossip link on the gossip rung is closed by the recursion rule, so a graft of the pair
    /// only makes the gossip layer dial a link that dies.
    #[test]
    fn a_pair_that_rides_the_gossip_rung_is_not_regrafted() {
        use crate::transport::probe::PathKind;
        let (bob, now) = (endpoint_id(1), Instant::now());
        let mut node = fresh_state();
        node.direct.insert(bob, DirectState::Direct);
        node.path_kinds.insert(bob, PathKind::Gossip);

        assert!(node.rides_gossip_rung(bob));
        assert!(
            !node.plan_regraft_on_link_loss(bob, now, 0.0),
            "no re-graft is planned for a pair on the gossip rung"
        );
    }

    /// The release rule's two answers, on a node that lets go at two links.
    fn two_link_node() -> EventLoopState {
        let mut state = fresh_state();
        state.rendezvous_release_links = 2;
        state
    }

    #[test]
    fn a_node_below_the_release_count_wants_the_rendezvous() {
        let mut state = two_link_node();
        state.rendezvous_linked = true;
        state.linked_endpoints.insert(endpoint_id(1));
        assert!(state.rendezvous_wanted());
        assert!(
            !state.should_release_rendezvous(Instant::now()),
            "one link is not enough"
        );
    }

    #[test]
    fn a_node_at_the_release_count_lets_go_and_stops_wanting_it() {
        let mut state = two_link_node();
        state.rendezvous_linked = true;
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        assert!(state.should_release_rendezvous(Instant::now()));

        state.rendezvous_linked = false;
        assert!(
            !state.rendezvous_wanted(),
            "enough links: no graft, no offer"
        );
        assert!(
            !state.should_release_rendezvous(Instant::now()),
            "nothing left to let go of"
        );
    }

    /// Gossip ends the link some time after the release, and the heal tick and
    /// every link event ask again meanwhile. A node already released must not be
    /// due again, or it tells gossip to leave a second time and logs it twice.
    #[test]
    fn a_node_that_has_released_is_not_due_again_while_the_link_is_still_up() {
        let mut state = two_link_node();
        state.rendezvous_linked = true;
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        assert!(state.should_release_rendezvous(Instant::now()));

        state.mark_rendezvous_released(endpoint_id(9));

        assert!(!state.should_release_rendezvous(Instant::now()));
    }

    /// A mesh that split into islands, each with links enough, never visits the rendezvous on its
    /// own: nothing is owed and no link is below the count. Each node comes back once in a long
    /// while, and the beacon introduces the islands to each other.
    #[test]
    fn a_node_that_let_go_wants_the_rendezvous_again_when_its_return_falls_due() {
        let mut state = two_link_node();
        state.rendezvous_linked = true;
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.mark_rendezvous_released(endpoint_id(9));
        state.rendezvous_linked = false;
        assert!(
            !state.rendezvous_wanted(),
            "it let go a moment ago: no visit yet"
        );
        assert!(
            state.rendezvous_return_due.is_some(),
            "a release sets the time of its return"
        );

        state.rendezvous_return_due = Some(Instant::now());
        state.pay_periodic_return(Instant::now(), endpoint_id(9));

        assert!(
            state.rendezvous_wanted(),
            "a return that fell due is wanted although the links are enough"
        );
    }

    /// A return that fell due and found no link is not wanted for ever: the visit is bounded
    /// like an owed one, or a member whose visit cannot link grafts and offers at every tick.
    #[test]
    fn a_return_that_fell_due_and_got_no_link_is_not_wanted_after_the_comeback_window() {
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.mark_rendezvous_released(endpoint_id(9));
        let window = crate::util::tuning::RENDEZVOUS_COMEBACK;
        state.rendezvous_return_due = Instant::now().checked_sub(window + Duration::from_secs(1));

        assert!(
            !state.rendezvous_wanted(),
            "a return that fell due a window ago and found no link is wanted for ever"
        );
    }

    /// The periodic return is paid on the heal tick as an owed one: wanted for the comeback
    /// window, due again one period later, and not paid twice.
    #[test]
    fn a_periodic_return_that_fell_due_is_paid_once_and_set_again_one_period_later() {
        let local = endpoint_id(9);
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.mark_rendezvous_released(local);
        let now = Instant::now();
        state.rendezvous_return_due = Some(now);

        state.pay_periodic_return(now, local);

        assert!(state.rendezvous_wanted(), "the visit is wanted now");
        let period = crate::util::tuning::RENDEZVOUS_PERIODIC_RETURN;
        let next = state.rendezvous_return_due.expect("it is set again");
        assert!(next >= now + period, "the next return is a period away");
        let owed_until = state.rendezvous_comeback_until;

        state.pay_periodic_return(now + Duration::from_secs(1), local);

        assert_eq!(
            state.rendezvous_comeback_until, owed_until,
            "a return that is not due is not paid again"
        );
        state.rendezvous_comeback_until = now.checked_sub(Duration::from_secs(1));
        assert!(!state.rendezvous_wanted(), "the visit ends with its window");
    }

    #[test]
    fn the_return_of_a_node_that_let_go_falls_due_one_period_later_at_the_earliest() {
        let period = crate::util::tuning::RENDEZVOUS_PERIODIC_RETURN;
        for seed in 1..=8 {
            let after = super::rendezvous_return_after(endpoint_id(seed));
            assert!(
                after >= period,
                "seed {seed}: {after:?} is before the period"
            );
            assert!(
                after <= period + period / 2,
                "seed {seed}: {after:?} is later than half a period more"
            );
        }
        assert_ne!(
            super::rendezvous_return_after(endpoint_id(1)),
            super::rendezvous_return_after(endpoint_id(2)),
            "two members do not come back together"
        );
    }

    #[test]
    fn a_visit_that_the_period_asked_for_lasts_its_dwell_time_before_the_node_lets_go() {
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.mark_rendezvous_released(endpoint_id(9));
        let now = Instant::now();
        state.rendezvous_return_due = Some(now);

        state.note_rendezvous_link_up(now);

        assert!(
            !state.should_release_rendezvous(now),
            "the visit lasts its dwell time: the beacon needs it to introduce the islands"
        );
        let after_dwell = now + crate::util::tuning::RENDEZVOUS_DWELL;
        assert!(state.should_release_rendezvous(after_dwell));
    }

    #[test]
    fn a_link_that_comes_up_before_the_return_is_due_asks_for_no_dwell() {
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.mark_rendezvous_released(endpoint_id(9));
        let now = Instant::now();

        state.note_rendezvous_link_up(now);

        assert!(state.should_release_rendezvous(now));
    }

    #[test]
    fn a_link_that_comes_back_ends_the_wait_for_the_return() {
        let mut state = two_link_node();
        state.mark_rendezvous_released(endpoint_id(9));
        assert!(state.rendezvous_return_due.is_some());

        state.note_rendezvous_link_up(Instant::now());

        assert!(state.rendezvous_return_due.is_none());
    }

    #[test]
    fn a_node_that_falls_below_the_count_comes_back() {
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        assert!(!state.rendezvous_wanted());

        state.linked_endpoints.remove(&endpoint_id(2));

        assert!(state.rendezvous_wanted());
    }

    #[test]
    fn the_node_that_hosts_the_rendezvous_keeps_its_link() {
        let mut state = two_link_node();
        state.hosts_rendezvous = true;
        state.rendezvous_linked = true;
        for seed in 1..=5 {
            state.linked_endpoints.insert(endpoint_id(seed));
        }
        assert!(
            !state.should_release_rendezvous(Instant::now()),
            "its link keeps the beacon's gossip view non-empty for a joiner"
        );
        assert!(state.rendezvous_wanted());
    }

    #[test]
    fn an_owed_return_makes_a_node_with_enough_links_want_it() {
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.owe_rendezvous_return(Instant::now());
        assert!(state.rendezvous_wanted());
    }

    /// A debt with an end: a node refused again and again at the rendezvous
    /// stops offering when the return it owed expires.
    #[test]
    fn an_owed_return_ends_at_its_deadline() {
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        let long_ago = Instant::now()
            .checked_sub(crate::util::tuning::RENDEZVOUS_COMEBACK + Duration::from_secs(1))
            .expect("a past instant");
        state.owe_rendezvous_return(long_ago);

        assert!(!state.rendezvous_wanted());
    }

    /// A node that came back stays its dwell time before it lets go again, and
    /// lets go on its own once the time has passed, with no link event to
    /// trigger it.
    #[test]
    fn a_node_that_came_back_lets_go_again_after_its_dwell_time() {
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.owe_rendezvous_return(Instant::now());
        let now = Instant::now();
        state.note_rendezvous_link_up(now);
        assert!(state.rendezvous_linked);
        assert!(
            !state.should_release_rendezvous(now),
            "the visit has just begun"
        );

        let later = now + crate::util::tuning::RENDEZVOUS_DWELL + Duration::from_secs(1);

        assert!(
            state.should_release_rendezvous(later),
            "the dwell time has passed and the links are enough"
        );
        assert!(
            state.rendezvous_comeback_until.is_none(),
            "the debt was paid by the visit"
        );
    }

    /// A first visit has no dwell: a joiner lets go as soon as it has the links.
    #[test]
    fn a_first_visit_has_no_dwell_time() {
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.note_rendezvous_link_up(Instant::now());
        assert!(state.should_release_rendezvous(Instant::now()));
    }

    /// An unsigned chat message carrying `id` — enough to exercise
    /// `mark_seen`, which keys on `dedup_key()` (`SHA-256(pubkey ‖ id)`).
    fn msg_with_id(id: &MessageId) -> crate::protocol::message::Verified {
        plain_with_id(id).sign(&crate::protocol::Identity::generate())
    }

    fn plain_with_id(id: &MessageId) -> Message {
        let mut message = Message::new_app(
            &MeshId::from("test"),
            &nick("author-nick"),
            AppFrameParams {
                tag: crate::protocol::AppTag::new("app_msg").expect("a valid app tag"),
                to: None,
                corr: None,
                body: MessageBody::from("body"),
            },
        );
        message.id = id.clone();
        message
    }

    /// A content hash for a test: the hash of the name.
    fn hash_of(name: &str) -> ContentHash {
        ContentHash::of(name.as_bytes())
    }

    #[test]
    fn note_msg_seq_detects_equivocation_once() {
        let mut state = fresh_state();
        let key = author_of("alice-key");
        // First sighting at a seq → recorded, no fork.
        assert!(!state.note_msg_seq(&key, 0, hash_of("hashA")));
        // Same message again (same hash) → no fork.
        assert!(!state.note_msg_seq(&key, 0, hash_of("hashA")));
        // Different hash at the SAME seq → fork, reported exactly once.
        assert!(
            state.note_msg_seq(&key, 0, hash_of("hashB")),
            "conflict is a fork"
        );
        assert!(
            !state.note_msg_seq(&key, 0, hash_of("hashC")),
            "already flagged: one event per key"
        );
    }

    #[test]
    fn note_msg_seq_is_per_key_and_per_seq() {
        let mut state = fresh_state();
        assert!(!state.note_msg_seq(&author_of("alice"), 0, hash_of("h0")));
        // A new seq for the same author is just the next entry, not a fork.
        assert!(!state.note_msg_seq(&author_of("alice"), 1, hash_of("h1")));
        // A different key reusing seq 0 with its own hash is independent.
        assert!(!state.note_msg_seq(&author_of("bob"), 0, hash_of("other")));
        // But a conflict on alice's seq 0 still fires.
        assert!(state.note_msg_seq(&author_of("alice"), 0, hash_of("h0-prime")));
    }

    #[test]
    fn forget_msg_seq_prunes_author_and_fork_flag() {
        let mut state = fresh_state();
        state.note_msg_seq(&author_of("alice"), 0, hash_of("h0"));
        assert!(
            state.note_msg_seq(&author_of("alice"), 0, hash_of("h0-prime")),
            "fork"
        );
        assert!(state.forked.contains(&author_of("alice")));
        // Evicting the *recorded* twin (hash "h0") drops alice from both maps.
        state.forget_msg_seq(&author_of("alice"), 0, &hash_of("h0"));
        assert!(!state.author_seqs.contains_key(&author_of("alice")));
        assert!(
            !state.forked.contains(&author_of("alice")),
            "fork flag pruned with author"
        );
    }

    #[test]
    fn forget_msg_seq_keeps_evidence_when_other_twin_evicted() {
        // A fork keeps two twins at one (author, seq). Evicting the twin we did
        // NOT record must not clear the recorded slot / fork flag — otherwise a
        // later resend of the still-retained twin re-detects the fork as new.
        let mut state = fresh_state();
        state.note_msg_seq(&author_of("alice"), 0, hash_of("recorded"));
        assert!(
            state.note_msg_seq(&author_of("alice"), 0, hash_of("twin")),
            "fork fires"
        );
        assert!(state.forked.contains(&author_of("alice")));
        // Evict the non-recorded twin ("twin"): the slot for "recorded" stays.
        state.forget_msg_seq(&author_of("alice"), 0, &hash_of("twin"));
        assert!(
            state.author_seqs.contains_key(&author_of("alice")),
            "recorded slot retained"
        );
        assert!(
            state.forked.contains(&author_of("alice")),
            "fork flag retained"
        );
        // A resend of the recorded twin does not re-fire the fork (already
        // flagged), proving the evidence survived the eviction.
        assert!(!state.note_msg_seq(&author_of("alice"), 0, hash_of("twin")));
    }

    #[test]
    fn note_dag_moves_tip_set() {
        let mut state = fresh_state();
        // First message (no parents) becomes the sole tip.
        assert!(!state.note_dag(hash_of("h1"), &[], UnixSecs::from_secs(100)));
        assert_eq!(state.dag_parents(), vec![hash_of("h1")]);
        // A child referencing h1 makes h1 no longer a tip; h2 is the new one.
        assert!(!state.note_dag(hash_of("h2"), &[hash_of("h1")], UnixSecs::from_secs(101)));
        assert_eq!(state.dag_parents(), vec![hash_of("h2")]);
    }

    #[test]
    fn note_dag_keeps_concurrent_tips() {
        let mut state = fresh_state();
        state.note_dag(hash_of("a"), &[], UnixSecs::from_secs(1));
        state.note_dag(hash_of("b"), &[], UnixSecs::from_secs(1)); // concurrent: no shared parent
        let mut both = vec![hash_of("a"), hash_of("b")];
        both.sort();
        assert_eq!(state.dag_parents(), both, "both tips, in hash order");
    }

    #[test]
    fn note_dag_flags_backdating() {
        let mut state = fresh_state();
        state.note_dag(hash_of("parent"), &[], UnixSecs::from_secs(200));
        // Child claims an earlier timestamp than a parent it references.
        assert!(state.note_dag(
            hash_of("child"),
            &[hash_of("parent")],
            UnixSecs::from_secs(100)
        ));
        // A forward timestamp is fine.
        assert!(!state.note_dag(
            hash_of("ok"),
            &[hash_of("parent")],
            UnixSecs::from_secs(300)
        ));
    }

    #[test]
    fn forget_hash_prunes_dag() {
        let mut state = fresh_state();
        state.note_dag(hash_of("h"), &[], UnixSecs::from_secs(1));
        state.forget_hash(&hash_of("h"));
        assert!(state.dag_parents().is_empty());
    }

    /// A valid (curve-point) `EndpointId` derived deterministically from
    /// a seed — `EndpointId::from_bytes` rejects arbitrary bytes.
    // The `known_endpoints` / `quiet` fields are `BoundedFifoSet`s wired with
    // their caps — the generic FIFO/dedup/remove behavior is covered in
    // `bounded_fifo_set`; these only assert the state wires the right cap.
    #[test]
    fn known_endpoints_field_is_capped() {
        let mut state = fresh_state();
        let first = endpoint_id(0);
        state.known_endpoints.insert(first);
        for index in 0..KNOWN_ENDPOINTS_CAP {
            state
                .known_endpoints
                .insert(endpoint_id(u8::try_from(index + 1).unwrap()));
        }
        assert!(state.known_endpoints.len() <= KNOWN_ENDPOINTS_CAP);
        assert!(
            !state.known_endpoints.contains(&first),
            "oldest evicted past the cap"
        );
    }

    #[test]
    fn roster_reach_tags_only_live_links_direct() {
        let mut state = fresh_state();
        let linked_ep = endpoint_id(1);
        let stale_ep = endpoint_id(2);
        // A peer whose advertised endpoint is a live link → direct.
        state.peers.insert(nick("linked"));
        state
            .peer_endpoints
            .insert(nick("linked"), iroh::EndpointAddr::new(linked_ep));
        state.linked_endpoints.insert(linked_ep);
        // Advertised, but the endpoint is not (any longer) a live link → gossip.
        state.peers.insert(nick("unlinked"));
        state
            .peer_endpoints
            .insert(nick("unlinked"), iroh::EndpointAddr::new(stale_ep));
        // No PeerInfo seen yet → no binding → gossip.
        state.peers.insert(nick("unknown"));
        // Quiet evictees are never live-linked → gossip.
        state.quiet.insert(nick("quiet"));

        let snapshot = state.roster_snapshot();
        let reach = |name: &str| {
            snapshot
                .peers
                .iter()
                .find(|entry| entry.nickname.as_str() == name)
                .unwrap_or_else(|| panic!("{name} missing from roster"))
                .reach
        };
        assert_eq!(reach("linked"), Reach::Direct);
        assert_eq!(reach("unlinked"), Reach::Gossip);
        assert_eq!(reach("unknown"), Reach::Gossip);
        assert_eq!(reach("quiet"), Reach::Gossip);
    }

    #[test]
    fn direct_state_follows_conn_path_readings_and_counts() {
        use crate::gossip::PathSummary;
        let mut state = fresh_state();
        // The mapping only reaches `RelayOnly` on a mesh whose relay may carry
        // payload; the lookup-only half is
        // `a_relay_reading_never_demotes_a_proven_peer_on_a_lookup_only_mesh`.
        state.relay_transport = true;
        state.observe_path(endpoint_id(1), PathSummary::Direct);
        state.observe_path(endpoint_id(2), PathSummary::Relay);
        state.direct.insert(endpoint_id(3), DirectState::Pending);
        assert_eq!(
            state.direct_counts(),
            DirectCounts {
                direct: 1,
                relay_only: 1,
                pending: 1
            }
        );
    }

    /// A mixed or empty reading proves nothing about the selected path, so
    /// it must neither promote an unproven peer nor demote a proven one.
    #[test]
    fn a_mixed_or_unknown_reading_never_changes_what_is_known() {
        use crate::gossip::PathSummary;
        let mut state = fresh_state();
        state.observe_path(endpoint_id(1), PathSummary::Mixed);
        state.observe_path(endpoint_id(2), PathSummary::Unknown);
        assert!(state.direct.is_empty());
        state.direct.insert(endpoint_id(3), DirectState::Direct);
        state.observe_path(endpoint_id(3), PathSummary::Mixed);
        state.observe_path(endpoint_id(3), PathSummary::Unknown);
        assert_eq!(
            state.direct.get(&endpoint_id(3)),
            Some(&DirectState::Direct)
        );
        state.direct.insert(endpoint_id(4), DirectState::RelayOnly);
        state.observe_path(endpoint_id(4), PathSummary::Mixed);
        assert_eq!(
            state.direct.get(&endpoint_id(4)),
            Some(&DirectState::RelayOnly)
        );
    }

    /// On a lookup-only mesh the census reading cannot demote a proven peer.
    /// `gossip::recv` gates its own `observe_path` for the same reason — a link
    /// up *is* the proof there, and `conn_path` cannot see which path is
    /// selected — but the census tick (`daemon::timers`) calls it ungated, so
    /// the gate belongs here. A `Relay` reading on a peer the accept gate and
    /// the probe both admitted would otherwise stop every payload lane to it.
    #[test]
    fn a_relay_reading_never_demotes_a_proven_peer_on_a_lookup_only_mesh() {
        use crate::gossip::PathSummary;
        let mut state = fresh_state();
        state.relay_transport = false;
        state.direct.insert(endpoint_id(1), DirectState::Direct);
        state.observe_path(endpoint_id(1), PathSummary::Relay);
        assert_eq!(
            state.direct.get(&endpoint_id(1)),
            Some(&DirectState::Direct),
            "the relay may not carry payload, so a relayed reading proves nothing"
        );

        // With the relay allowed as transport the reading is real news: the
        // peer is reachable, over the relay, and the lanes may use it.
        state.relay_transport = true;
        state.observe_path(endpoint_id(1), PathSummary::Relay);
        assert_eq!(
            state.direct.get(&endpoint_id(1)),
            Some(&DirectState::RelayOnly)
        );
    }

    #[test]
    fn roster_reach_counts_the_rendezvous_link_for_the_beacon() {
        // The beacon gossips *as* the rendezvous, so a joiner's only link to
        // it is the rendezvous link (kept out of `linked_endpoints`). The
        // beacon's `PeerInfo` advertises the rendezvous endpoint, so the
        // roster must still tag it `direct` while we're rendezvous-linked.
        let mut state = fresh_state();
        let rendezvous_ep = endpoint_id(7);
        state.rendezvous_id = Some(rendezvous_ep);
        state.peers.insert(nick("beacon"));
        state
            .peer_endpoints
            .insert(nick("beacon"), iroh::EndpointAddr::new(rendezvous_ep));

        let reach = |current: &EventLoopState| {
            current
                .roster_snapshot()
                .peers
                .iter()
                .find(|entry| entry.nickname.as_str() == "beacon")
                .expect("beacon in roster")
                .reach
        };

        state.rendezvous_linked = true;
        assert_eq!(reach(&state), Reach::Direct, "linked rendezvous → direct");

        state.rendezvous_linked = false;
        assert_eq!(reach(&state), Reach::Gossip, "rendezvous down → gossip");
    }

    #[test]
    fn roster_transport_mirrors_the_send_decision() {
        use crate::transport::Lane;
        let mut state = fresh_state();
        state.meshed = true;
        // Known endpoint while meshed → unicast (the send path would dial it).
        state.peers.insert(nick("dialable"));
        state
            .peer_endpoints
            .insert(nick("dialable"), iroh::EndpointAddr::new(endpoint_id(1)));
        state.direct.insert(endpoint_id(1), DirectState::Direct);
        // No PeerInfo yet → nothing to dial → unreachable for directed frames.
        state.peers.insert(nick("unknown"));

        let lane = |current: &EventLoopState, name: &str| {
            current
                .roster_snapshot()
                .peers
                .iter()
                .find(|entry| entry.nickname.as_str() == name)
                .unwrap_or_else(|| panic!("{name} missing from roster"))
                .transport
        };
        assert_eq!(lane(&state, "dialable"), Lane::Unicast);
        assert_eq!(lane(&state, "unknown"), Lane::Unreachable);

        // Unmeshed: the known endpoint is reached via the multihop transport (iroh
        // picks a direct path when meshed, else the multihop one), so the column
        // reads `multihop` rather than a direct `unicast`.
        state.meshed = false;
        assert_eq!(lane(&state, "dialable"), Lane::Multihop);
    }

    #[test]
    fn quiet_field_is_capped() {
        // `quiet` is drained only on return, so the cap is what stops a churn /
        // sybil stream of one-shot nicknames from growing it without bound.
        let mut state = fresh_state();
        for index in 0..(QUIET_CAP + 5) {
            state.quiet.insert(nick(&format!("ghost-{index}")));
        }
        assert!(
            state.quiet.len() <= QUIET_CAP,
            "quiet stays capped under churn: {}",
            state.quiet.len()
        );
    }

    #[test]
    fn mark_seen_delegates_dedup() {
        // Smoke test the `EventLoopState` -> `BoundedFifoSet` delegation; the
        // bounded-FIFO/eviction logic itself is covered in `habilis-network-util`.
        let mut state = fresh_state();
        let message = msg_with_id(&MessageId::random());
        assert!(
            !state.mark_seen(&message),
            "first sighting is not a duplicate"
        );
        assert!(state.mark_seen(&message), "second sighting is a duplicate");
    }

    /// **One digest per peer per window.**
    ///
    /// Serving a digest costs up to `ANTIENTROPY_MAX_RESEND` mesh-wide
    /// broadcasts. With the budget counted per digest and nothing per peer, one
    /// small crafted frame bought 64 floods from every member that received it,
    /// so the cost grew with the mesh rather than with the attacker.
    #[test]
    fn an_unreadable_digest_is_reported_once_per_author_and_window() {
        let mut state = fresh_state();
        let now = Instant::now();
        assert!(
            state.report_unreadable_digest(author_of("aa"), now),
            "the first is reported"
        );
        assert!(
            !state.report_unreadable_digest(author_of("aa"), now + Duration::from_secs(10)),
            "the same author every round is one line, not one line per round"
        );
        assert!(
            state.report_unreadable_digest(author_of("bb"), now),
            "another author is reported on its own"
        );
        assert!(
            state.report_unreadable_digest(
                author_of("aa"),
                now + super::UNREADABLE_DIGEST_LOG_WINDOW + Duration::from_secs(1)
            ),
            "the author is reported again after the window"
        );
    }

    #[test]
    fn a_peer_is_served_one_digest_per_window() {
        let mut state = fresh_state();
        let now = Instant::now();
        let window = habilis_network_util::tuning::ANTIENTROPY_SERVE_COOLDOWN;

        assert!(
            state.admit_digest(author_of("aa"), now),
            "the first is served"
        );
        assert!(
            !state.admit_digest(author_of("aa"), now),
            "a second digest inside the window must not buy another round of resends"
        );
        assert!(
            state.admit_digest(author_of("bb"), now),
            "one peer's flood must not deny another peer service"
        );
        assert!(
            state.admit_digest(author_of("aa"), now + window + Duration::from_millis(1)),
            "the honest cadence resumes after the window"
        );
    }

    #[test]
    fn mark_seen_keys_on_pubkey_not_id() {
        // Two messages sharing an id but signed by different keys must NOT
        // dedup against each other — the fix for the id-collision suppression
        // attack. Distinct pubkeys ⇒ distinct `dedup_key`s.
        let mut state = fresh_state();
        let id = MessageId::random();
        let victim = crate::protocol::message::Verified::fixture_unchecked(
            plain_with_id(&id),
            AuthorKey::from_bytes([0xaa; 32]),
        );
        let attacker = crate::protocol::message::Verified::fixture_unchecked(
            plain_with_id(&id),
            AuthorKey::from_bytes([0xbb; 32]),
        );
        assert!(!state.mark_seen(&victim), "victim's message is fresh");
        assert!(
            !state.mark_seen(&attacker),
            "an id-reusing message under a different key must not be deduped as the victim's"
        );
        assert!(state.mark_seen(&victim), "victim's own resend is deduped");
    }

    // Replicates the mesh-wide CPU runaway at its mechanism: a peer whose
    // transport link flaps (each `NeighborDown` drops it from
    // `linked_endpoints`, each re-learned `PeerInfo` re-passes the novelty
    // gate) must NOT re-dial + re-flood once per flap. See memory
    // `cpu-runaway-membership-amplifier`.
    #[test]
    fn relink_cooldown_caps_a_flapping_peer() {
        let peer = endpoint_id(7);
        let start = Instant::now();

        // Baseline — documents the BUG: the bare novelty gate (remove+insert)
        // re-links on EVERY flap, i.e. unbounded amplification.
        let mut bare_state = fresh_state();
        let mut bare = 0;
        for _ in 0..100u32 {
            bare_state.linked_endpoints.remove(&peer);
            if bare_state.linked_endpoints.insert(peer) {
                bare += 1;
            }
        }
        assert_eq!(
            bare, 100,
            "without a cooldown every flap re-links — the runaway"
        );

        // With the cooldown: 100 flaps inside one window collapse to ONE re-link.
        let mut cooled = fresh_state();
        let mut relinks = 0;
        for index in 0..100u32 {
            let now = start + Duration::from_millis(u64::from(index) * 10);
            cooled.linked_endpoints.remove(&peer);
            if !cooled.relink_on_cooldown(peer, now) && cooled.linked_endpoints.insert(peer) {
                cooled.note_relink(peer, now);
                relinks += 1;
            }
        }
        assert_eq!(relinks, 1, "the cooldown caps re-links to once per window");

        // Past the window a genuine re-link is allowed again (no permanent lockout).
        let later = start + RELINK_COOLDOWN + Duration::from_secs(1);
        assert!(!cooled.relink_on_cooldown(peer, later));
    }

    // The arrival flood goes out on the first `NeighborUp`, in the same milliseconds in
    // which the endpoint gets its home relay, so it can carry no relay. Every later
    // flood is gated by the window, and the receiver keeps the first address it saw. A
    // changed address of our own must therefore call for a flood of its own.
    #[test]
    fn a_changed_own_address_is_due_a_flood_and_an_unchanged_one_is_not() {
        let id = endpoint_id(1);
        let relay: iroh::RelayUrl = "https://relay.example".parse().expect("a relay url");
        let ip: std::net::SocketAddr = "192.0.2.1:4000".parse().expect("an address");
        let other_ip: std::net::SocketAddr = "192.0.2.2:4000".parse().expect("an address");
        let without_relay = iroh::EndpointAddr::new(id).with_ip_addr(ip);
        let with_relay = without_relay.clone().with_relay_url(relay.clone());

        let mut state = fresh_state();
        assert!(
            !state.address_flood_due(&with_relay),
            "before the first flood there is nothing to repair"
        );

        state.last_flooded_addr = Some(without_relay.clone());
        assert!(
            !state.address_flood_due(&without_relay),
            "an address that did not change is not flooded again"
        );
        assert!(
            state.address_flood_due(&with_relay),
            "the relay arrived after the flood"
        );

        state.last_flooded_addr = Some(with_relay.clone());
        assert!(
            !state.address_flood_due(&with_relay),
            "the flooded address is the current one"
        );
        assert!(
            state.address_flood_due(
                &iroh::EndpointAddr::new(id)
                    .with_relay_url(relay)
                    .with_ip_addr(other_ip)
            ),
            "an IP address changed"
        );
        assert!(
            state.address_flood_due(&iroh::EndpointAddr::new(id).with_ip_addr(ip)),
            "the relay was lost"
        );
    }

    #[test]
    fn the_order_of_the_addresses_does_not_make_an_address_differ() {
        let id = endpoint_id(1);
        let first: std::net::SocketAddr = "192.0.2.1:4000".parse().expect("an address");
        let second: std::net::SocketAddr = "192.0.2.2:4000".parse().expect("an address");
        let mut state = fresh_state();
        state.last_flooded_addr = Some(
            iroh::EndpointAddr::new(id)
                .with_ip_addr(first)
                .with_ip_addr(second),
        );
        assert!(
            !state.address_flood_due(
                &iroh::EndpointAddr::new(id)
                    .with_ip_addr(second)
                    .with_ip_addr(first)
            )
        );
    }

    // The residual flap amplifier the re-link cooldown did NOT cover: every
    // `NeighborUp` re-floods our own `PeerInfo` to the whole mesh, and a
    // flapping link re-triggers `NeighborUp` on each up-transition. Every flood
    // is also answered by a graft from each peer that hears it, and a graft at
    // a full view evicts a neighbor, so a window per neighbor lets the floods
    // cascade. The window is per flood: one flapping peer, or five peers, flood
    // once per window.
    #[test]
    fn neighbors_up_in_one_window_flood_peerinfo_once() {
        let start = Instant::now();

        let mut flapping = fresh_state();
        let mut flapping_refloods = 0;
        for index in 0..100u32 {
            let now = start + Duration::from_millis(u64::from(index) * 10);
            if flapping.neighbor_up_refloods_peerinfo(now) {
                flapping.peerinfo_flooded_at = Some(now);
                flapping_refloods += 1;
            }
        }
        assert_eq!(
            flapping_refloods, 1,
            "a flapping peer floods once per window"
        );

        let mut state = fresh_state();
        let mut refloods = 0;
        for index in 0..5u64 {
            let now = start + Duration::from_millis(index * 10);
            if state.neighbor_up_refloods_peerinfo(now) {
                state.peerinfo_flooded_at = Some(now);
                refloods += 1;
            }
        }
        assert_eq!(refloods, 1, "five neighbors flood once per window");

        // Past the window a neighbor up floods once more (no permanent silence).
        let later = start + RELINK_COOLDOWN + Duration::from_secs(1);
        assert!(state.neighbor_up_refloods_peerinfo(later));
    }

    // A neighbor that comes up inside the window of a flood does not make a
    // flood of its own. It must not wait for another `NeighborUp`: the flood is
    // paid once the window ends.
    #[test]
    fn a_held_back_neighbor_up_floods_peerinfo_when_the_window_ends() {
        let start = Instant::now();
        let mut state = fresh_state();
        state.peerinfo_flooded_at = Some(start);

        assert!(!state.neighbor_up_refloods_peerinfo(start + Duration::from_secs(1)));
        state.defer_peerinfo();

        assert!(!state.take_deferred_peerinfo(start + Duration::from_secs(1)));
        let later = start + RELINK_COOLDOWN + Duration::from_secs(1);
        assert!(
            state.take_deferred_peerinfo(later),
            "due once the window ends"
        );
        assert!(!state.take_deferred_peerinfo(later), "paid once");
    }

    #[test]
    fn nothing_is_due_when_no_neighbor_up_was_held_back() {
        let start = Instant::now();
        let mut state = fresh_state();
        state.peerinfo_flooded_at = Some(start);
        assert!(!state.take_deferred_peerinfo(start + RELINK_COOLDOWN + Duration::from_secs(1)));
    }

    #[test]
    fn joined_refloods_peerinfo_once_per_window() {
        let start = Instant::now();
        let mut state = fresh_state();

        // Twenty re-announces from twenty peers inside one window.
        let mut refloods = 0;
        for index in 0..20u64 {
            let now = start + Duration::from_millis(index * 10);
            if state.joined_refloods_peerinfo(false, now) {
                state.peerinfo_flooded_at = Some(now);
                refloods += 1;
            }
        }
        assert_eq!(refloods, 1, "once per window, not once per peer");

        // A first sighting inside the window is not throttled.
        assert!(state.joined_refloods_peerinfo(true, start + Duration::from_secs(1)));

        // Past the window a re-announce floods once more (no permanent silence).
        let later = start + RELINK_COOLDOWN + Duration::from_secs(1);
        assert!(state.joined_refloods_peerinfo(false, later));
    }

    // A `NeighborDown` drops the gossip link, not the pooled unicast
    // connection the verdict describes. Erasing the verdict with the link
    // parked every directed frame on a flap until the alive tick re-probed.
    /// A session to a gossip neighbor is not a unit of the ceiling, because the gossip link
    /// holds the peer anyway. The ledger learns of a neighbor when the link comes up, and that
    /// the peer is not one when it goes down.
    #[test]
    fn a_session_counts_against_the_ceiling_only_while_its_peer_is_not_a_neighbor() {
        let mut state = fresh_state();
        let bob = endpoint_id(1);
        state.webrtc_admission.note_success(bob);
        assert_eq!(state.webrtc_admission.direct_units(), 1);

        state.link(bob);
        assert_eq!(state.webrtc_admission.direct_units(), 0, "a neighbor");

        state.unlink(bob);
        assert_eq!(state.webrtc_admission.direct_units(), 1, "no longer one");
    }

    /// A meshed member that lost every link is a silent partition once the gap outlasts a heal,
    /// not before: a link closed on purpose, or a heal on its way, shows the same zero.
    #[test]
    fn a_meshed_member_without_links_is_a_silent_partition_only_after_a_heal() {
        let (bob, roster) = (endpoint_id(1), 3);
        let after = crate::util::tuning::silent_partition_after();
        let mut state = fresh_state();
        state.meshed = true;

        state.link(bob);
        let far = Instant::now() + after + Duration::from_secs(1);
        assert!(!state.silent_partition_due(roster, far), "a link is up");

        state.unlink(bob);
        assert!(
            !state.silent_partition_due(roster, Instant::now()),
            "the gap is young"
        );
        assert!(
            state.silent_partition_due(roster, far),
            "the gap outlasted a heal"
        );
        assert!(
            !state.silent_partition_due(0, far),
            "there is nobody to be apart from"
        );
        state.meshed = false;
        assert!(!state.silent_partition_due(roster, far), "never meshed");
        state.meshed = true;

        // An unlink of a peer that was not linked leaves the clock where it was.
        state.unlink(endpoint_id(2));
        assert!(
            state.silent_partition_due(roster, far),
            "the clock did not restart"
        );

        // A link clears the gap, and the next loss starts a new one.
        state.link(bob);
        state.unlink(bob);
        assert!(
            !state.silent_partition_due(roster, Instant::now()),
            "a new gap is young"
        );
    }

    /// A degraded node that a relayed frame heals while it holds no link is meshed with zero links.
    /// It never lost a link, so no unlink started the gap: the heal starts it, and the census calls
    /// the state a silent partition once the gap outlasts a heal.
    #[test]
    fn a_degraded_node_that_heals_without_a_link_starts_counting_the_gap() {
        let roster = 3;
        let after = crate::util::tuning::silent_partition_after();
        let mut state = fresh_state();
        state.note_degraded();
        let healed_at = Instant::now();

        assert!(state.note_inbound(healed_at), "the first inbound heals it");

        assert!(
            !state.silent_partition_due(roster, healed_at),
            "the gap is young"
        );
        assert!(
            state.silent_partition_due(roster, healed_at + after + Duration::from_secs(1)),
            "meshed with no link for longer than a heal"
        );
    }

    /// A heal does not restart a gap that already runs: the unlink that began it is the start.
    #[test]
    fn a_heal_does_not_restart_a_gap_that_already_runs() {
        let (bob, roster) = (endpoint_id(1), 3);
        let after = crate::util::tuning::silent_partition_after();
        let mut state = fresh_state();
        state.meshed = true;
        state.link(bob);
        state.unlink(bob);
        let began = Instant::now();
        state.note_degraded();

        assert!(
            state.note_inbound(began + after / 2),
            "the first inbound heals it"
        );

        assert!(
            state.silent_partition_due(roster, began + after + Duration::from_secs(1)),
            "the heal restarted the clock"
        );
    }

    #[test]
    fn unlinking_a_peer_keeps_its_path_verdict() {
        let mut state = fresh_state();
        let bob = endpoint_id(1);
        state.linked_endpoints.insert(bob);
        state.direct.insert(bob, DirectState::Direct);
        state.unlink(bob);
        assert!(state.linked_endpoints.is_empty());
        assert_eq!(state.direct.get(&bob), Some(&DirectState::Direct));
    }

    #[test]
    fn a_late_unproven_verdict_only_demotes_a_pending_peer() {
        let mut state = fresh_state();
        let pending = endpoint_id(1);
        let proven = endpoint_id(2);
        let gone = endpoint_id(3);
        state.direct.insert(pending, DirectState::Pending);
        state.direct.insert(proven, DirectState::Direct);

        assert!(state.demote_unproven(pending));
        assert_eq!(state.direct.get(&pending), Some(&DirectState::RelayOnly));
        assert!(!state.demote_unproven(proven));
        assert_eq!(state.direct.get(&proven), Some(&DirectState::Direct));
        assert!(!state.demote_unproven(gone));
        assert!(!state.direct.contains_key(&gone));
    }

    #[test]
    fn forgetting_a_peer_endpoint_drops_its_path_verdict() {
        let mut state = fresh_state();
        let bob = endpoint_id(1);
        state
            .peer_endpoints
            .insert(nick("bob"), iroh::EndpointAddr::new(bob));
        state.direct.insert(bob, DirectState::Direct);
        assert_eq!(
            state.forget_peer_endpoint("bob").map(|addr| addr.id),
            Some(bob)
        );
        assert!(state.direct.is_empty());
        assert!(state.forget_peer_endpoint("bob").is_none());
    }

    // After a failover the rendezvous keeps its id, but a refusal from the old
    // holder says nothing about the new one: the wait starts over.
    #[test]
    fn a_new_rendezvous_verdict_starts_the_refusal_wait_over() {
        use habilis_network_iroh_webrtc_transport::{WebRtcHandle, WebRtcTransport};

        let mut state = fresh_state();
        let rendezvous = endpoint_id(7);
        state.rendezvous_id = Some(rendezvous);
        let hub = WebRtcHandle::new(WebRtcTransport::new(endpoint_id(0)));
        state.webrtc_admission.note_refused(rendezvous);
        assert!(
            state.webrtc_admission.try_admit(rendezvous, &hub).is_err(),
            "the refusal makes us wait"
        );

        state.forget_rendezvous_verdict();

        assert!(
            state.webrtc_admission.try_admit(rendezvous, &hub).is_ok(),
            "a new verdict ends the wait"
        );
    }

    // A departed peer read as riding WebRTC was nudged on every alive tick.
    #[test]
    fn forgetting_a_peer_endpoint_drops_its_path_watch() {
        let mut state = fresh_state();
        let bob = endpoint_id(1);
        state
            .peer_endpoints
            .insert(nick("bob"), iroh::EndpointAddr::new(bob));
        state.path_watchers.insert(bob, Some(7));
        state
            .path_kinds
            .insert(bob, crate::transport::probe::PathKind::WebRtc);
        state.forget_peer_endpoint("bob");
        assert!(state.path_watchers.is_empty());
        assert!(state.path_kinds.is_empty());
    }

    // `arms_reclaim` fires on any peer loss while the mesh is beaconless, and
    // the two probe rounds are ~5 s apart: clearing the verdict there lets
    // ordinary churn starve the two-verdict rule until nobody claims.
    #[test]
    fn only_a_rendezvous_change_drops_a_free_verdict() {
        let mut state = fresh_state();
        state.rendezvous_probe_read_free = true;

        state.arm_reclaim(Instant::now());
        assert!(state.rendezvous_probe_read_free);
        assert!(state.reclaim_until.is_some());

        state.forget_rendezvous_verdict();
        assert!(!state.rendezvous_probe_read_free);
    }

    // The probe wait ends at the three events that reopen the rendezvous: the reclaim window
    // opens, the arbitration is forgotten, and the rendezvous gets a new address. The address of
    // any other peer does not end it.
    #[test]
    fn the_events_that_reopen_the_rendezvous_end_the_probe_wait() {
        let now = Instant::now();
        let rendezvous = endpoint_id(9);
        let stranger = endpoint_id(8);
        let relay: iroh::RelayUrl = "https://relay.example".parse().expect("a relay url");

        let mut state = fresh_state();
        state.rendezvous_id = Some(rendezvous);
        state.probe_backoff.note_verdict(true, now, 0.0);
        assert!(!state.probe_backoff.due(now), "the wait is on");

        state.arm_reclaim(now);
        assert!(state.probe_backoff.due(now), "the reclaim window");

        state.probe_backoff.note_verdict(true, now, 0.0);
        state.forget_rendezvous_verdict();
        assert!(state.probe_backoff.due(now), "the arbitration is forgotten");

        state.probe_backoff.note_verdict(true, now, 0.0);
        state.note_peer_endpoint(nick("stranger"), iroh::EndpointAddr::new(stranger));
        state.note_peer_endpoint(
            nick("stranger"),
            iroh::EndpointAddr::new(stranger).with_relay_url(relay.clone()),
        );
        assert!(
            !state.probe_backoff.due(now),
            "a new address of another peer"
        );

        state.note_peer_endpoint(nick("host"), iroh::EndpointAddr::new(rendezvous));
        state.note_peer_endpoint(
            nick("host"),
            iroh::EndpointAddr::new(rendezvous).with_relay_url(relay),
        );
        assert!(
            state.probe_backoff.due(now),
            "a new address of the rendezvous"
        );
    }

    // Under a long flap storm against a steady peer set, every collection *we*
    // own stays flat — so the soak's monotonic 4.6 GB resident-memory climb is provably
    // below our layer (the iroh transport), not in daemon state. This replays
    // the per-flap state mutations the `NeighborUp`/`NeighborDown` arms +
    // `handle_peer_info` make, for many flaps over simulated hours.
    #[test]
    fn app_state_stays_bounded_under_flap_churn() {
        let mut state = fresh_state();
        let start = Instant::now();
        // A small, *steady* roster (the soak's shape: ~10 members, ~7.4k flaps),
        // not a sybil endpoint stream — endpoints are real curve points.
        let peers: Vec<EndpointId> = (0..8u8).map(endpoint_id).collect();

        for index in 0..10_000u32 {
            let now = start + Duration::from_millis(u64::from(index) * 100);
            let peer = peers[index as usize % peers.len()];
            // NeighborUp → PeerInfo reflood gate + (via handle_peer_info) link.
            if state.neighbor_up_refloods_peerinfo(now) {
                state.peerinfo_flooded_at = Some(now);
            }
            if !state.relink_on_cooldown(peer, now) {
                state.note_relink(peer, now);
                state.linked_endpoints.insert(peer);
                state.known_endpoints.insert(peer);
            }
            // NeighborDown drops the transport link (kept in known_endpoints).
            state.linked_endpoints.remove(&peer);
        }

        // None of our collections grew with the 10k flaps: each is bounded by
        // the roster size or its hard cap, never by the flap count.
        assert!(
            state.relink.len() <= peers.len(),
            "relink flat: {}",
            state.relink.len()
        );
        assert!(
            state.linked_endpoints.len() <= peers.len(),
            "linked_endpoints flat"
        );
        assert!(
            state.known_endpoints.len() <= KNOWN_ENDPOINTS_CAP.min(peers.len()),
            "known_endpoints bounded"
        );
    }

    #[test]
    fn relink_cooldown_is_per_peer_and_bounded() {
        let mut state = fresh_state();
        let start = Instant::now();
        let flapping = endpoint_id(7);
        let other = endpoint_id(8);

        // One peer's cooldown never gates a different peer.
        state.note_relink(flapping, start);
        assert!(state.relink_on_cooldown(flapping, start));
        assert!(!state.relink_on_cooldown(other, start));

        // Many distinct peers re-linked across more than a full window:
        // expired entries are pruned, so the map never accumulates them all.
        for seed in 0..50u8 {
            let when = start + Duration::from_secs(u64::from(seed));
            state.note_relink(endpoint_id(seed), when);
        }
        assert!(
            state.relink.len() <= usize::try_from(RELINK_COOLDOWN.as_secs()).unwrap() + 1,
            "expired cooldown entries are pruned (map stays bounded)"
        );
    }

    #[test]
    fn dedup_window_covers_the_retention_window() {
        use crate::util::tuning::MESSAGE_LOG_SIZE;

        // The cap relationship itself is asserted at compile time where both
        // consts live; this covers the behaviour it exists for.
        let mut state = fresh_state();
        let earliest = msg_with_id(&MessageId::random());
        assert!(!state.mark_seen(&earliest));
        // Mark a full buffer's worth of later messages.
        for _ in 1..MESSAGE_LOG_SIZE {
            state.mark_seen(&msg_with_id(&MessageId::random()));
        }
        // The earliest is still within the dedup window, so an anti-entropy
        // resend of it (while it is still retained in the log) is dropped as
        // a duplicate rather than surfaced a second time.
        assert!(
            state.mark_seen(&earliest),
            "a resend of a still-retained message must be deduped, not re-surfaced"
        );
    }

    const STARVE: Duration = Duration::from_secs(10);

    // The watchdog must only ever fire for a node that (a) was part of a
    // mesh and (b) knows a real peer to re-dial — a lone creator is alone
    // by construction, not starved.
    #[test]
    fn starvation_due_requires_announce_known_peers_and_silence() {
        let mut state = fresh_state();
        let past_threshold = Instant::now() + STARVE + Duration::from_secs(1);
        assert!(
            !state.starvation_due(past_threshold, STARVE),
            "never announced => never starved"
        );
        state.announced = true;
        assert!(
            !state.starvation_due(past_threshold, STARVE),
            "no known peers => alone, not starved"
        );
        state.known_endpoints.insert(endpoint_id(1));
        assert!(state.starvation_due(past_threshold, STARVE));
        // Fresh inbound disarms it until the threshold passes again.
        state.note_inbound(past_threshold);
        assert!(!state.starvation_due(past_threshold, STARVE));
        assert!(state.starvation_due(past_threshold + STARVE + Duration::from_secs(1), STARVE));
    }

    #[test]
    fn starvation_recovery_backs_off_then_resets_on_inbound() {
        let mut state = fresh_state();
        state.announced = true;
        state.known_endpoints.insert(endpoint_id(1));
        let first = Instant::now() + STARVE + Duration::from_secs(1);
        assert!(state.starvation_due(first, STARVE));
        state.note_recovery(first);
        // One trip: the next attempt waits 2x the threshold, not 1x.
        assert!(!state.starvation_due(first + STARVE + Duration::from_secs(1), STARVE));
        let second = first + (STARVE * 2) + Duration::from_secs(1);
        assert!(state.starvation_due(second, STARVE));
        state.note_recovery(second);
        // Two trips: 4x.
        assert!(!state.starvation_due(second + (STARVE * 2) + Duration::from_secs(1), STARVE));
        assert!(state.starvation_due(second + (STARVE * 4) + Duration::from_secs(1), STARVE));
        // Any inbound resets the backoff to the base threshold.
        let healed = second + (STARVE * 4) + Duration::from_secs(2);
        state.note_inbound(healed);
        assert_eq!(state.recovery_trips, 0);
        assert!(!state.starvation_due(healed + STARVE, STARVE));
        assert!(state.starvation_due(healed + STARVE + Duration::from_secs(1), STARVE));
    }

    #[test]
    fn starvation_backoff_caps_at_eight_threshold() {
        let mut state = fresh_state();
        state.announced = true;
        state.known_endpoints.insert(endpoint_id(1));
        let mut last_recovery = Instant::now() + STARVE + Duration::from_secs(1);
        // Trip well past the cap (`recovery_trips.min(3)` => 8x ceiling).
        for _ in 0..6 {
            state.note_recovery(last_recovery);
            last_recovery += STARVE * 8 + Duration::from_secs(1);
        }
        state.note_recovery(last_recovery);
        assert!(
            !state.starvation_due(last_recovery + STARVE * 8, STARVE),
            "inside the capped backoff window"
        );
        assert!(
            state.starvation_due(last_recovery + STARVE * 8 + Duration::from_secs(1), STARVE),
            "the backoff never grows past 8x the threshold"
        );
    }

    // `meshed` restoration on inbound is gated on the `degraded` fault
    // flag: a fresh joiner's pre-mesh inbound (relayed backlog) must not
    // flip `meshed` early — that stays the first real-peer NeighborUp's
    // job — while a degraded node heals on the first proof of traffic.
    #[test]
    fn note_inbound_restores_meshed_only_when_degraded() {
        let mut state = fresh_state();
        let now = Instant::now();
        assert!(
            !state.note_inbound(now),
            "pre-mesh inbound never flips meshed"
        );
        assert!(!state.meshed);
        state.meshed = true;
        assert!(!state.note_inbound(now), "healthy meshed: no edge");
        assert!(state.meshed);
        state.note_degraded();
        assert!(!state.meshed);
        assert!(
            state.note_inbound(now),
            "degraded node heals on first inbound (caller flushes)"
        );
        assert!(state.meshed);
        assert!(!state.degraded);
    }

    /// The second probe of a round is due at the middle of the window, and only once.
    #[test]
    fn the_second_probe_is_due_at_the_middle_of_the_window_and_only_once() {
        let t1 = TokioInstant::now();
        let first = Message::new_ping(&MeshId::from("test"), &nick("alice"));
        let mut round = PingRound::new(&first, t1, t1 + Duration::from_secs(10), None);

        assert_eq!(round.second_probe_at(), Some(t1 + Duration::from_secs(5)));
        let second = Message::new_ping(&MeshId::from("test"), &nick("alice"));
        round.probes.insert(second.id, t1 + Duration::from_secs(5));
        assert_eq!(round.second_probe_at(), None);
    }

    /// A pong reads its RTT from the probe it names, so a peer that answers only the second
    /// probe gets a true RTT.
    #[test]
    fn a_pong_reads_its_rtt_from_the_probe_it_names() {
        let t1 = TokioInstant::now();
        let mesh = MeshId::from("test");
        let first = Message::new_ping(&mesh, &nick("alice"));
        let second = Message::new_ping(&mesh, &nick("alice"));
        let mut round = PingRound::new(&first, t1, t1 + Duration::from_secs(10), None);
        round
            .probes
            .insert(second.id.clone(), t1 + Duration::from_secs(5));

        let at = t1 + Duration::from_secs(5) + Duration::from_millis(30);
        assert!(round.record_pong(nick("bob"), &second.id, at));
        assert!(round.record_pong(nick("carol"), &first.id, t1 + Duration::from_millis(40)));

        assert_eq!(round.pongs[&nick("bob")], Duration::from_millis(30));
        assert_eq!(round.pongs[&nick("carol")], Duration::from_millis(40));
    }

    /// The first pong of a peer is the one kept: the answer to the second probe does not replace
    /// it.
    #[test]
    fn the_first_pong_of_a_peer_is_kept() {
        let t1 = TokioInstant::now();
        let mesh = MeshId::from("test");
        let first = Message::new_ping(&mesh, &nick("alice"));
        let second = Message::new_ping(&mesh, &nick("alice"));
        let mut round = PingRound::new(&first, t1, t1 + Duration::from_secs(10), None);
        round
            .probes
            .insert(second.id.clone(), t1 + Duration::from_secs(5));

        round.record_pong(nick("bob"), &first.id, t1 + Duration::from_millis(10));
        round.record_pong(
            nick("bob"),
            &second.id,
            t1 + Duration::from_secs(5) + Duration::from_millis(20),
        );

        assert_eq!(round.pongs[&nick("bob")], Duration::from_millis(10));
    }

    /// A pong that names no probe of the round, such as the answer to a round that is over, is
    /// dropped.
    #[test]
    fn a_pong_that_names_no_probe_of_the_round_is_dropped() {
        let t1 = TokioInstant::now();
        let first = Message::new_ping(&MeshId::from("test"), &nick("alice"));
        let mut round = PingRound::new(&first, t1, t1 + Duration::from_secs(10), None);

        assert!(!round.record_pong(
            nick("bob"),
            &MessageId::random(),
            t1 + Duration::from_millis(5)
        ));
        assert!(round.pongs.is_empty());
    }
}
