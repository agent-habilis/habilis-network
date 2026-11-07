#[cfg(feature = "multihop")]
use super::ParkedLinkStates;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use super::TestDrop;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use super::TestHold;
use super::chat_continuations::ChatContinuations;
use super::peer_info_flood::PeerInfoFlood;
use super::proof_exchange::ProofExchange;
use super::{
    BeaconNote, DirectCounts, DirectState, IdleCounters, KeyOfError, Latch, MeshSecrets, PingRound,
    Reach, RendezvousFlag, RivalFlag, RosterEntry, RosterSnapshot, Standing, StateInit,
};
use crate::daemon::cohost_arm;
use crate::daemon::doc::MeshDoc;
use crate::daemon::probe_backoff::ProbeBackoff;
use crate::daemon::reassembly::{self, ReassemblyStore, ShardCache, ShardIngest};
use crate::daemon::setup::LiveCount;
use crate::doc;
use crate::doc::StampedPaths;

use crate::transport::{ResendOutbox, UdpTransport};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use iroh::{EndpointAddr, EndpointId};

use crate::daemon::message_log::MessageLog;
#[cfg(feature = "host")]
use crate::daemon::state_file::StateFile;
use crate::protocol::identity::{Identity, IdentityProof, verify_proof};
use crate::protocol::meshes::Mesh;
use crate::protocol::messages::{Authored, Verified, WireFrame, sole_addressee};
use crate::protocol::{
    AuthorKey, ContentHash, DedupKey, MeshId, Message, Nickname, ShardGroup, SymmetricKey, UnixSecs,
};
use crate::util::bounded_fifo_set::BoundedFifoSet;
use crate::util::bounded_queue::BoundedQueue;
use crate::util::clock::Instant;
use crate::util::consts::DOC_EPOCH_WRITE_ATTEMPTS;
use crate::util::cooldown::Cooldown;

use crate::util::tuning::{
    KNOWN_ENDPOINTS_CAP, LANE_WANTED, MESSAGE_LOG_SIZE, PENDING_OUTBOUND_CAP, QUIET_CAP,
    RECLAIM_WINDOW, REGRAFT_AFTER, RELINK_COOLDOWN, SEEN_IDS_CAP, STARVED, UNSUPPORTED_VERSION_CAP,
};

use crate::gossip::{antientropy, apply_merge_patch, lan};
use crate::protocol::{crypto, messages};
#[cfg(test)]
use crate::testing;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::transport::redial;
#[cfg(feature = "multihop")]
use crate::transport::underlay_webrtc;
use crate::transport::{graft_backoff, probe, proven_endpoints};
use crate::util::tuning;
use iroh::address_lookup::memory;
use n0_future::task::JoinHandle;
use tokio::sync::{mpsc, oneshot};

use crate::daemon::seed_job::SeedOutcome;

/// A run of live frames of one key, counted for a stamp that proves nothing alone: a stamp before
/// our join (`live_run`) or a stamp at or below the newest on record of a quiet peer (`step_back`). `last` is the stamp of the latest
/// frame that counted, `at` is when it arrived on our clock, and `count` is the number of frames
/// that counted. See `membership_update::note_live_run`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LiveRun {
    pub(crate) last: UnixSecs,
    pub(crate) at: Instant,
    pub(crate) count: u8,
}

/// A stretch of time that the wall clock counted and the monotonic clock did not, seen by the
/// sweep, and not yet vouched for by a peer. See `heartbeat::note_suspend`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PendingSuspend {
    pub(crate) missed: Duration,
    pub(crate) at: Instant,
}

/// The keys that said goodbye, in two bounded sets. Any key can sign a goodbye, so the goodbyes of
/// keys that were never peers of ours fill at the pace of the senders. They live apart from the
/// goodbyes of peers, or a flood of them would push the tombstone of a real leaver out of its set.
/// Same bound and same rule as `EventLoopState::quiet`.
#[derive(Debug)]
pub(crate) struct Goodbyes {
    peers: BoundedFifoSet<AuthorKey>,
    strangers: BoundedFifoSet<AuthorKey>,
}

impl Goodbyes {
    /// The goodbyes held, of peers and of strangers.
    pub(crate) fn len(&self) -> usize {
        self.peers.len() + self.strangers.len()
    }
}

impl Default for Goodbyes {
    fn default() -> Self {
        Self {
            peers: BoundedFifoSet::new(QUIET_CAP),
            strangers: BoundedFifoSet::new(QUIET_CAP),
        }
    }
}

/// What the receive path remembers about frames it handled or refused. Each set is bounded.
#[derive(Debug)]
pub(crate) struct ReceiveMemory {
    /// Shard groups already reassembled + surfaced, so a body is surfaced once even if a shard
    /// is re-fetched (via anti-entropy) after its id aged out of [`EventLoopState::seen`].
    /// Groups are rare and short-lived.
    pub(crate) reassembled_groups: BoundedFifoSet<ShardGroup>,
    /// The protocol versions of frames that did not parse, each one named once in an error line.
    /// The set stops at [`UNSUPPORTED_VERSION_CAP`] and evicts nothing, so a sender that makes up
    /// versions cannot get a line for each frame.
    refused_versions: HashSet<String>,
    /// Whether the one line that says that many versions are unknown went out.
    many_versions_told: bool,
}

impl ReceiveMemory {
    /// The error line for a frame of a version that this build does not read, or nothing when the
    /// version was named already or the line for the versions past the cap went out.
    pub(crate) fn refused_version_line(&mut self, version: &str) -> Option<String> {
        if self.refused_versions.contains(version) {
            return None;
        }
        if self.refused_versions.len() < UNSUPPORTED_VERSION_CAP {
            self.refused_versions.insert(version.to_owned());
            return Some(format!(
                "A peer sent protocol version {version}, which this build does not read"
            ));
        }
        if self.many_versions_told {
            return None;
        }
        self.many_versions_told = true;
        Some("Peers sent many unknown versions; this build names the first ones only".to_owned())
    }
}

impl Default for ReceiveMemory {
    fn default() -> Self {
        Self {
            reassembled_groups: BoundedFifoSet::new(MESSAGE_LOG_SIZE),
            refused_versions: HashSet::new(),
            many_versions_told: false,
        }
    }
}

/// What the lifecycle layer keeps about the clocks and the stamps of the peers, beyond
/// `peer_stamp`. Each map follows the roster in the sweep.
#[derive(Debug)]
pub(crate) struct ClockEvidence {
    /// The run of frames of a quiet peer that rise from a stamp below `peer_stamp`, which says
    /// that its clock stepped back. See `membership_update::note_step_back`.
    pub(crate) step_back: HashMap<AuthorKey, LiveRun>,
    /// The run of live frames of each peer whose stamps are behind our join, or behind the goodbye
    /// of an older run of its nickname. A backlog replay and a peer with a slow clock look the same
    /// in one frame. A run of frames of one key, each a time after the one before on both clocks
    /// and at the pace of our clock, shows that the peer sends now.
    pub(crate) live_run: HashMap<AuthorKey, LiveRun>,
    /// The peers that came back from quiet and are not shown yet, because every frame so far is
    /// stamped before our join. When the peer is shown, it is shown as returned.
    pub(crate) returned_unshown: HashSet<AuthorKey>,
    /// The real last-heard instant of each peer. The stall forgiveness moves the eviction mark
    /// (`last_seen`) and leaves this one, which the roster reports.
    pub(crate) heard: HashMap<AuthorKey, Instant>,
    /// The silence that the wall clock counted and the monotonic clock did not (a suspend), added
    /// to each quiet peer. A span, not a moved `Instant`: an `Instant` cannot go back past the
    /// origin of its clock, and a browser clock starts at the page load.
    pub(crate) quiet_aged: HashMap<AuthorKey, Duration>,
    /// Wall-clock time that the monotonic clock missed, until a live peer vouches for it.
    pub(crate) suspend: Option<PendingSuspend>,
    /// The suspends that a live peer vouched for, kept for one quiet TTL. A peer that was active
    /// then and goes quiet later is older by each suspend that came after it was last heard.
    pub(crate) confirmed_suspends: Vec<PendingSuspend>,
    /// The peers that left `quiet` after the quiet TTL. Their dial hint stays, because a peer that
    /// is silent for an hour and then sends again has no reason to send a `PeerInfo`: its links did
    /// not change. Bounded FIFO (cap `QUIET_CAP`), so the hints of one-shot nicknames cannot grow
    /// the map. The sweep drops the hint of the oldest entry that the cap pushes out.
    pub(crate) lapsed_quiet: BoundedFifoSet<AuthorKey>,
    /// The stamp of the newest frame that set the nickname of each key, on the clock of that key.
    /// It is the watermark of the nickname alone: a frame that proves no presence moves it too,
    /// and `peer_stamp` does not follow it.
    pub(crate) name_stamp: HashMap<AuthorKey, UnixSecs>,
}

impl Default for ClockEvidence {
    fn default() -> Self {
        Self {
            step_back: HashMap::new(),
            live_run: HashMap::new(),
            returned_unshown: HashSet::new(),
            heard: HashMap::new(),
            quiet_aged: HashMap::new(),
            suspend: None,
            confirmed_suspends: Vec::new(),
            lapsed_quiet: BoundedFifoSet::new(QUIET_CAP),
            name_stamp: HashMap::new(),
        }
    }
}

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
    /// Endpoints whose dial hint the sweep pruned while they still had a link. The state of such
    /// an endpoint stays for the regraft that follows the link loss. A later sweep drops it once
    /// the link is gone and no nickname binds the endpoint. Bounded by `linked_endpoints`: an entry
    /// leaves at the first sweep that sees no link.
    pub(crate) orphaned_endpoints: HashSet<EndpointId>,
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
    /// The last flood of our `PeerInfo`, whatever triggered it. Stamped by
    /// `broadcast_peer_info`; read by the `joined` and `NeighborUp` re-flood gates and by the
    /// periodic refresh.
    pub(crate) peerinfo_flood: Option<PeerInfoFlood>,
    /// The latches that this member has set and not yet cleared, see [`Latch`].
    pub(crate) latches: BTreeSet<Latch>,
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
    /// How many doc censuses this loop has run: one in `DOC_HEAVY_EVERY` is heavy. The count is of
    /// this loop, so that each document of a process that runs several loops gets its heavy census.
    pub(crate) doc_census_runs: u64,
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
    /// The chat continuations that an author gets inside its cooldown. Bounded: a run lives for one
    /// cooldown window, at most `CHAT_CONTINUATION_AUTHORS_MAX` authors hold one, and a new author
    /// is refused when the table is full (see `ChatContinuations`).
    chat_continuations: ChatContinuations,
    /// When we last reported an author whose digest we could not read. An `Option` key
    /// for the same reason as `digest_serves`.
    digest_unreadable: Cooldown<AuthorKey>,
    /// Where a digest answer goes, so that the loop never waits to send it. The
    /// task that drains it takes `resend_receiver` when the loop starts.
    pub(crate) resend_outbox: ResendOutbox,
    /// Tests only: the next ask of a fast round fails to start, once, as a send does when the
    /// connection cannot be opened. A default build has no such field.
    #[cfg(test)]
    fail_next_ask: bool,
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
    /// Membership layer: the peer roster. Set of the author keys of
    /// other peers, feeding the state file's `peer_count`
    /// (`peers.len() + 1`). Excludes self. Driven by
    /// `joined`/`left` presence messages (they reach every peer
    /// via gossip; `NeighborUp`/`PeerInfo` are asymmetric for
    /// bootstrap links), by implicit heartbeats from any received
    /// message (self-heal for a missed Joined), and by the sweeper's
    /// eviction of peers gone silent past `ALIVE_TIMEOUT`.
    pub(crate) peers: HashSet<AuthorKey>,
    /// Implicit-heartbeat tracker: author key -> last time we heard
    /// anything from that peer. Drives sweep-based eviction.
    pub(crate) last_seen: HashMap<AuthorKey, Instant>,
    /// The nickname that each key of the roster last used. The roster is keyed by author key: a
    /// nickname is a label, and two live keys can hold one, so each key is a peer of its own. A key
    /// that is neither a peer, quiet nor lapsed drops its entry in the sweep.
    pub(crate) names: HashMap<AuthorKey, Nickname>,
    /// The key whose `PeerInfo` made each dial hint of `peer_endpoints`. A directed send by
    /// nickname goes to the hint of the last `PeerInfo` under that nickname, whatever key sent it;
    /// the hint leaves with that key, when the key is no longer a peer, quiet or lapsed.
    pub(crate) hint_owner: HashMap<Nickname, AuthorKey>,
    /// The endpoint of a `PeerInfo` that bound no dial hint, because another live key holds the
    /// nickname of its signer. It waits here: the signer takes the nickname over when the other
    /// key leaves, and the sweep releases the endpoint of a signer that left the roster.
    ///
    /// Bounded by [`REFUSED_ENDPOINTS_CAP`]: when a new key arrives at the cap, the oldest key goes and
    /// its endpoint state with it.
    pub(crate) refused_endpoints: HashMap<AuthorKey, EndpointAddr>,
    /// The keys of `refused_endpoints` in the order that they were retained, oldest first. It may hold a key
    /// that left the map; it is cut to the keys of the map when it grows past twice the cap.
    refused_order: VecDeque<AuthorKey>,
    /// The newest stamp that we heard from each peer in a frame that proved it was alive, on the
    /// clock of that peer. A quiet peer returns only on a frame stamped after it: two stamps of
    /// one clock compare at any skew between that clock and ours.
    pub(crate) peer_stamp: HashMap<AuthorKey, UnixSecs>,
    /// The records of the stamps of the peers beyond `peer_stamp`: the step back of a clock, the
    /// live frames stamped before our join, and the goodbyes.
    pub(crate) clock_evidence: ClockEvidence,
    /// Bridge from membership back to transport: nickname -> the endpoint id
    /// that nickname last self-advertised in a signed `PeerInfo`. That
    /// signature is the only thing tying a nickname to an endpoint (the
    /// signing key is deliberately not the transport key), so this is the one
    /// place the roster can tell whether a peer is a live link.
    /// This is a store of hints, not the member list: a nickname holds one hint, and two live keys
    /// can share it. The transport plane reads the members through [`Self::member_addresses`].
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
    pub(crate) quiet: BoundedFifoSet<AuthorKey>,
    /// Recency companion to `quiet`: author key -> the `last_seen` instant a
    /// quiet peer had when it was evicted, so `roster_snapshot` can still
    /// report how long ago it was last heard (the eviction drops its
    /// `last_seen` entry). Pruned to `quiet`'s membership on every sweep, so
    /// it stays bounded by `QUIET_CAP`; `roster_snapshot` only reads it for
    /// peers currently in `quiet`, so a stale entry never surfaces.
    pub(crate) quiet_since: HashMap<AuthorKey, Instant>,
    /// The keys that said goodbye. A key is minted per run, so a key that left never speaks again:
    /// anything it signs afterwards is a replay, whatever its timestamp says. Keyed on the key
    /// and not on the nickname, which another run may take.
    ///
    /// Bounded like `quiet`, by the same rule: keys are free, so an unbounded set is
    /// a memory leak under churn. The bound is a second layer, not the first: a replay of a
    /// frame this node still holds is dropped by [`Self::mark_seen`] before membership sees it,
    /// whatever this set holds. What the bound gives up is narrow: a frame of a key that left
    /// more than `QUIET_CAP` departures ago, that this node never held, counts as an arrival
    /// until its author goes quiet.
    pub(crate) left_keys: Goodbyes,
    /// The identity proofs of the sessions this node verified, and the sessions it asked for one.
    /// Bounded by `QUIET_CAP`: a full book drops its oldest dead session, and refuses a new proof
    /// when every held session is live.
    pub(crate) proofs: ProofExchange,
    /// The run number of this start, which the proof of this session names.
    run: u64,
    /// The lock on the member key of this start: it lives as long as this node runs, so a second start of
    /// the same state path is refused for as long as this one lives. Held, never read.
    #[expect(dead_code, reason = "held for the lock it carries, never read")]
    // shared with the clones of the keys that the setup still holds: the lock goes when the last drops
    key_lock: Option<Arc<File>>,
    /// The highest run above ours that a session of our own member proved: a newer run of this member is
    /// active elsewhere, and this node is superseded. One number, so the memory is bounded.
    newest_own_run_seen: u64,
    /// Presentation layer: peers for whom we have *surfaced* an
    /// arrival (synthetic `joined`, real `Presence::Joined`, or
    /// `peer_return`). Gates departure surfacing so a peer whose
    /// join we never showed never produces a `went quiet` / `has left`
    /// line — keeps the join-horizon view symmetric. The roster (`peers`)
    /// stays complete for anti-entropy/membership; `surfaced ⊆ peers`
    /// governs what the operator/agent is shown: the rows of the roster
    /// snapshot hold the peers in `surfaced` and the quiet peers, and
    /// `member_count` counts only the peers in `surfaced`.
    pub(crate) surfaced: HashSet<AuthorKey>,
    /// Last time we broadcast anything. Lets idle daemons suppress
    /// their `Alive` keepalive when they're already chatty.
    pub(crate) last_sent_at: Instant,
    /// Wall-clock unix seconds when this daemon started — its join
    /// instant. The node still receives & relays older messages
    /// (anti-entropy keeps the mesh's set uniform), but messages
    /// stamped before this are never *surfaced* (printed / `poll` /
    /// `fetch` / library API): the operator/agent view starts at join.
    pub(crate) joined_at: UnixSecs,
    /// The steps this member has reached on its way into the mesh.
    pub(crate) standing: BTreeSet<Standing>,
    /// The rendezvous facts this node holds, see [`RendezvousFlag`].
    pub(crate) rendezvous_flags: BTreeSet<RendezvousFlag>,
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
    /// The notes this member keeps about its own beacon claim.
    pub(crate) beacon_notes: BTreeSet<BeaconNote>,
    /// The members that said in their `PeerInfo` that they hold the rendezvous, by the signing
    /// key and the endpoint that key proved. A `PeerInfo` of the same signer without the flag,
    /// or the roster removal of the member, takes it out again. While it is not empty and we do
    /// not hold the rendezvous, we do not probe to claim it.
    pub(crate) rival_holders: HashMap<AuthorKey, EndpointId>,
    /// How many links to other members make this node release the rendezvous.
    /// A field, not a constant, so a test can set it.
    pub(crate) rendezvous_release_links: usize,
    /// The wait between two rival probes started on the heal tick; see `ProbeBackoff`.
    pub(crate) probe_backoff: ProbeBackoff,
    /// Whether this node runs IP transports (`TransportOpts::ip`, and never
    /// on wasm). The local half of every `WebRTC` lane decision — read from
    /// here, not from the endpoint address, which is empty whenever the relay
    /// link is down.
    pub(crate) local_udp_transport: UdpTransport,
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
    /// The holds that a test places on this node, see [`TestHold`].
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) test_holds: BTreeSet<TestHold>,
    /// What this node knows of the busy rungs of a private ladder, and the probe tasks that find
    /// out more. The claim walk and the check of the lower rungs read it and never wait.
    pub(crate) rungs: beacon::RungWatch,
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
    /// When advertising (`create --advertise`), the directory's
    /// re-broadcast task reads the live peer count from here.
    /// Mirrors `peer_count` (`peers.len() + 1`), refreshed
    /// alongside every `write_peer_count`. `None` for the common
    /// non-advertising case (no shared counter to maintain).
    pub(crate) live_count: Option<LiveCount>,
    pub(crate) message_log: MessageLog,
    /// What the receive path remembers about frames it handled or refused, each in a bounded set.
    pub(crate) receive_memory: ReceiveMemory,
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
    /// The key that seals the bodies of the state channel (`None` on a mesh with no password): the
    /// build of a seed on another thread seals the frames that it measures with it.
    pub(crate) state_seal: Option<Arc<SymmetricKey>>,
    /// The build of the seed of a cut that runs on a blocking thread, one at a time. The event loop
    /// waits for it in its `select!` and then signs and sends the chain.
    pub(crate) seed_job: Option<JoinHandle<SeedOutcome>>,
    /// The values that the state channel must write again after an epoch switch (the replay of
    /// the writes that the seed lacks) or as a restore: a merge and the stamp of each path. The
    /// loop drains it after each tick and sends the frames. Bounded by `REPLAY_QUEUE_CAP`: when it
    /// is full the new item is refused and counted, and the node warns.
    pub(crate) replay_queue: BoundedQueue<(serde_json::Value, StampedPaths)>,
    /// The cuts of the state channel that this node made (a seed built, signed and sent), and the
    /// cuts that failed, since the node started: one integer each, for the census line.
    pub(crate) state_cuts: u64,
    pub(crate) state_cuts_failed: u64,
    /// When the state document stops waiting for its first sync and writes with the clock that it
    /// has (see `tuning::STATE_SYNC_WAIT`): counted from the start of the node, so a node with no peer
    /// is not held for ever.
    pub(crate) state_sync_deadline: Instant,
    /// When this node last sent a request for the first sync of the state channel (a digest with
    /// the flag `first`, on gossip or point-to-point). A closing digest ends the wait only for a
    /// short time after it (see `seed_job::closing_digest_seen`): a closing digest that arrives
    /// when this node asked nobody is the answer of no request, and any member can send one.
    pub(crate) first_asked_at: Option<Instant>,
    /// When this node sent its FIRST request for the first sync, set once. It is not renewed by a
    /// later digest or ask: the far jump of an epoch is allowed only within a few seconds of it (see
    /// `seed_job::far_jump_allowed`), so it does not stay open for the whole wait.
    pub(crate) first_request_at: Option<Instant>,
    /// The same for the meta channel: when this node sent its first meta request, set once, while
    /// the meta document awaits a far root.
    pub(crate) meta_first_request_at: Option<Instant>,
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
    /// The key that survives a restart. It signs the proof of this session and nothing else.
    pub(crate) member_identity: Option<Arc<Identity>>,
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
    /// `EventLoopConfig` after construction, so `new` defaults it to `None`
    /// and the many test call sites need no new argument.
    pub(crate) mint_mesh: Option<Mesh>,
    /// Symmetric key for broadcast-chat app bodies on a passworded
    /// mesh, `derive_secret(mesh_key, "broadcast")` — domain-separated from
    /// the state/meta doc keys. `None` ⇒ chat stays plaintext. Wiped on drop.
    pub(crate) broadcast_key: Option<SymmetricKey>,
    /// The switch of the meta document to a new epoch whose entry of this node is not written
    /// again yet, and the sweeps that failed to write it. One slot, so it is bounded.
    pub(crate) epoch_write: EpochWrite,
    /// Where the event loop's wakeups went since the last census.
    pub(crate) idle: IdleCounters,
}

/// The write of the entry of this node after the meta document moved to a new epoch. The sweep tick
/// writes the entry and empties the slot. A second switch before that keeps the entry of the first. A
/// failed write puts the switch back, and at `DOC_EPOCH_WRITE_ATTEMPTS` failures the switch is given
/// up, so a send that never works cannot keep the slot for ever.
#[derive(Clone, Debug, Default)]
pub(crate) struct EpochWrite {
    /// The switch whose entry waits to be written.
    pub(crate) switch: Option<doc::EpochSwitch>,
    /// How many sweeps failed to write it.
    pub(crate) attempts: u8,
}

impl EventLoopState {
    /// Build a fresh event-loop state. `now` is passed explicitly so
    /// tests can pin a deterministic instant. `secrets` is taken by value (not
    /// `&MeshSecrets`) so its `key` is dropped (zeroized) here once the
    /// per-channel keys are derived, rather than lingering in the caller.
    #[expect(
        clippy::too_many_lines,
        reason = "the member key is one field over the limit; the constructor is split in a later commit"
    )]
    pub(crate) fn new(init: StateInit, now: Instant) -> Self {
        let MeshSecrets {
            password: mesh_password,
            key: mesh_key,
        } = init.secrets;
        let (resend_outbox, resend_receiver) = ResendOutbox::new(tuning::RESEND_OUTBOX_CAP);
        // Per-channel keys, domain-separated from each other and from every other seed-derived
        // secret. `None` (passwordless): the docs and the broadcast chat stay plaintext.
        let [state_key, meta_key, broadcast_key] = Self::channel_keys(mesh_key.as_ref());
        Self {
            linked_endpoints: HashSet::new(),
            orphaned_endpoints: HashSet::new(),
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
            peerinfo_flood: None,
            latches: BTreeSet::new(),
            last_flooded_addr: None,
            below_target_since: None,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            redials: redial::Redials::default(),
            join_fallback_at: None,
            graft_backoff: graft_backoff::GraftBackoff::default(),
            doc_census_runs: 0,
            lane_wanted: HashMap::new(),
            regraft_at: HashMap::new(),
            digest_serves: Cooldown::new(tuning::ANTIENTROPY_SERVE_COOLDOWN),
            chat_continuations: ChatContinuations::default(),
            digest_unreadable: Cooldown::new(super::UNREADABLE_DIGEST_LOG_WINDOW),
            resend_outbox,
            #[cfg(test)]
            fail_next_ask: false,
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
            names: HashMap::new(),
            hint_owner: HashMap::new(),
            refused_endpoints: HashMap::new(),
            refused_order: VecDeque::new(),
            peer_stamp: HashMap::new(),
            clock_evidence: ClockEvidence::default(),
            left_keys: Goodbyes::default(),
            proofs: ProofExchange::with_cap(QUIET_CAP),
            run: init.keys.run,
            key_lock: init.keys.key_lock,
            newest_own_run_seen: 0,
            surfaced: HashSet::new(),
            last_sent_at: now,
            joined_at: UnixSecs::now(),
            standing: BTreeSet::from([Standing::GossipOpen]),
            rendezvous_flags: BTreeSet::from([RendezvousFlag::AnswersJsep]),
            rendezvous_return_due: None,
            rendezvous_comeback_until: None,
            rendezvous_dwell_until: None,
            beacon_notes: BTreeSet::new(),
            rival_holders: HashMap::new(),
            rendezvous_release_links: tuning::RENDEZVOUS_RELEASE_LINKS,
            probe_backoff: ProbeBackoff::default(),
            local_udp_transport: UdpTransport::Present,
            unicast_pool: transport::UnicastPool::disconnected(),
            #[cfg(feature = "multihop")]
            multihop: None,
            #[cfg(feature = "multihop")]
            underlay_webrtc: None,
            #[cfg(feature = "multihop")]
            parked_link_states: ParkedLinkStates::default(),
            #[cfg(feature = "multihop")]
            last_advertised: None,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            test_holds: BTreeSet::new(),
            rungs: beacon::RungWatch::detached(),
            lan_grafts: lan::LanGrafts::default(),
            webrtc: None,
            webrtc_admission: init.webrtc_admission,
            address_book: init.address_book,
            webrtc_ice: init.webrtc_ice,
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
            state_file: init.state_file,
            live_count: None,
            message_log: MessageLog::new(MESSAGE_LOG_SIZE),
            receive_memory: ReceiveMemory::default(),
            reassembly: ReassemblyStore::default(),
            shard_cache: ShardCache::default(),
            state_doc: MeshDoc::new_state(state_key),
            state_seal: mesh_key.as_ref().map(|key| {
                // Shared with the job that builds a seed on a blocking thread.
                Arc::new(key.derive(b"state-doc"))
            }),
            seed_job: None,
            replay_queue: BoundedQueue::new(REPLAY_QUEUE_CAP),
            state_cuts: 0,
            state_cuts_failed: 0,
            state_sync_deadline: Instant::now() + tuning::state_sync_wait(),
            first_asked_at: None,
            first_request_at: None,
            meta_first_request_at: None,
            meta_doc: Self::meta_channel(init.per_peer_gate, meta_key),
            digest_cursor: 0,
            identity: init.keys.session,
            member_identity: init.keys.member,
            self_seq: 0,
            self_prev: None,
            author_seqs: HashMap::new(),
            forked: HashSet::new(),
            by_hash: HashMap::new(),
            dag_heads: HashSet::new(),
            last_inbound_at: now,
            last_recovery_at: None,
            recovery_trips: 0,
            ping_round: None,
            mesh_password,
            mint_mesh: None,
            broadcast_key,
            epoch_write: EpochWrite::default(),
            idle: IdleCounters::default(),
        }
    }

    /// The keys of the `state` channel, the `meta` channel and the broadcast chat.
    fn channel_keys(mesh_key: Option<&SymmetricKey>) -> [Option<SymmetricKey>; 3] {
        [b"state-doc".as_slice(), b"meta-doc", b"broadcast"]
            .map(|label| mesh_key.map(|key| key.derive(label)))
    }

    /// The `meta` channel: gated by the application's per-peer map when it keeps one, free-form otherwise.
    /// Keep `switch` until the sweep writes the entry of this node again. If a switch is waiting
    /// already, its entry is kept: the document holds no entry of ours since the first switch except
    /// the writes made after it, so the new entry is partial. The two merge, the newer fields win
    /// (a deletion was applied to the waiting entry when it was made, see `follow_own_write`).
    pub(crate) fn note_epoch_switch(&mut self, mut switch: doc::EpochSwitch) {
        self.epoch_write.attempts = 0;
        let waiting = self
            .epoch_write
            .switch
            .take()
            .and_then(|held| held.own_entry);
        switch.own_entry = match (waiting, switch.own_entry.take()) {
            (Some(mut older), Some(newer)) => {
                apply_merge_patch(&mut older, &newer);
                Some(older)
            }
            (older, newer) => newer.or(older),
        };
        self.epoch_write.switch = Some(switch);
    }

    /// Put `switch` back in the slot after a failed write, for the next sweep to try again, unless
    /// it failed `DOC_EPOCH_WRITE_ATTEMPTS` times. Returns whether the switch waits.
    pub(crate) fn retry_epoch_switch(&mut self, switch: doc::EpochSwitch) -> bool {
        self.epoch_write.attempts = self.epoch_write.attempts.saturating_add(1);
        if self.epoch_write.attempts >= DOC_EPOCH_WRITE_ATTEMPTS {
            self.epoch_write.attempts = 0;
            return false;
        }
        self.epoch_write.switch = Some(switch);
        true
    }

    fn meta_channel(
        per_peer_gate: Option<doc::SelfWriteGate>,
        key: Option<SymmetricKey>,
    ) -> MeshDoc {
        match per_peer_gate {
            Some(gate) => MeshDoc::new_gated(gate),
            None => MeshDoc::new_ungated(),
        }
        .key(key)
        .awaiting_far_root()
    }

    /// The number of members of the mesh as this node counts them: the peers whose arrival was
    /// shown, and this node. A peer known only from a frame older than our join is in the roster
    /// for anti-entropy, but it is not counted: it can be a ghost that never surfaced. Every
    /// surface that shows a count (the state file, the live counter, the roster snapshot) reads it
    /// here.
    #[must_use]
    pub fn member_count(&self) -> usize {
        let shown = self
            .peers
            .iter()
            .filter(|peer| self.surfaced.contains(*peer));
        shown.count() + 1
    }

    /// Write `member_count` to the state file, if configured, carrying the current
    /// `ready` flag, and mirror the count into the advertise counter, if present. No-op for
    /// neither.
    pub(crate) fn write_peer_count(&self) {
        let count = self.member_count();
        #[cfg(feature = "host")]
        if let Some(sf) = self.state_file.as_ref() {
            sf.write(count, self.standing.contains(&Standing::Ready));
        }
        if let Some(live) = self.live_count.as_ref() {
            live.store(count, Ordering::Relaxed);
        }
    }

    /// The nickname of every peer that is in the roster and not quiet, shown or not, in no set
    /// order. Two live keys under one nickname are two peers, so a nickname can appear twice. The
    /// rows of [`Self::roster_snapshot`] list the peers whose arrival was shown, so a peer that is
    /// live and not shown yet (known from the backlog, or from a slow clock) is in this list and
    /// not in the rows. A reader that has to tell an absent peer from a live one that is not shown
    /// yet reads this list. A quiet peer and a peer that left are not in it.
    pub fn live_nicknames(&self) -> impl Iterator<Item = &Nickname> {
        let live = self.peers.iter();
        live.filter(|key| !self.quiet.contains(key))
            .filter_map(|key| self.names.get(key))
    }

    /// Snapshot the roster: the active peers whose arrival was shown, and the quiet evictees,
    /// sorted most-recently-seen first. A peer that is live and not shown yet (known from the
    /// backlog, or from a slow clock) is left out, and so is the count that goes with it (see
    /// `member_count`); [`Self::live_nicknames`] lists it. Backs a consumer's roster
    /// surfaces (the MCP `mesh_info` roster, the FFI, the netplay fan-out, agent-share) and the
    /// task sender's target picker / nickname validation.
    #[must_use]
    pub fn roster_snapshot(&self) -> RosterSnapshot {
        let now = Instant::now();
        let secs_since = |seen: &Instant| now.duration_since(*seen).as_secs();
        let heard_at = |key: &AuthorKey| -> Option<&Instant> {
            let heard = self.clock_evidence.heard.get(key);
            heard.or_else(|| self.last_seen.get(key))
        };
        let lane = |key: &AuthorKey| transport::lane_for(key, self);
        let shown = self.peers.iter().filter(|key| self.surfaced.contains(*key));
        // One row per key: two live keys under one nickname are two rows.
        let mut peers: Vec<RosterEntry> = shown
            .filter_map(|key| {
                let nick = self.names.get(key)?;
                Some(RosterEntry {
                    key: *key,
                    nickname: nick.clone(),
                    // Active peers: when they were really heard. A stall forgiveness moves
                    // `last_seen`, not `heard`.
                    last_seen_secs_ago: heard_at(key).map(secs_since),
                    quiet: false,
                    reach: self.reach_of(key),
                    transport: lane(key),
                })
            })
            .chain(self.quiet.iter().filter_map(|key| {
                let nick = self.names.get(key)?;
                Some(RosterEntry {
                    key: *key,
                    nickname: nick.clone(),
                    // Quiet peers: their last-heard instant, retained in
                    // `quiet_since` (the eviction drops `last_seen`). A quiet
                    // peer has no live link, so it is always `Gossip`.
                    last_seen_secs_ago: self
                        .quiet_silence(key, now)
                        .map(|silence| silence.as_secs()),
                    quiet: true,
                    reach: Reach::Gossip,
                    transport: lane(key),
                })
            }))
            .collect();
        // Most-recently-seen first; unknown recency (no heartbeat yet) sorts last.
        peers.sort_by_key(|entry| entry.last_seen_secs_ago.unwrap_or(u64::MAX));
        RosterSnapshot {
            peers,
            count: self.member_count(),
            live: self.live_nicknames().cloned().collect(),
        }
    }

    /// `Direct` only when the address that a send to this key dials is a
    /// live link right now; otherwise `Gossip`. A live link is a neighbor in
    /// `linked_endpoints`, or the rendezvous itself when we're linked to it —
    /// the beacon gossips *as* the rendezvous, so a joiner's only link to the
    /// beacon is that one. A peer we haven't yet seen a `PeerInfo` from (or
    /// whose link dropped) reads `Gossip` and flips to `Direct` once its next
    /// advertisement lands.
    ///
    /// The address is the one of [`address_of`](Self::address_of): the dial hint when the key made
    /// it, else the endpoint the key proved or retained. A second live key of a nickname owns no
    /// hint, and reads the link of its own endpoint.
    fn reach_of(&self, key: &AuthorKey) -> Reach {
        let linked: bool = self.address_of(key).is_some_and(|endpoint| {
            self.linked_endpoints.contains(&endpoint.id)
                || (self.rendezvous_id == Some(endpoint.id)
                    && self.rendezvous_flags.contains(&RendezvousFlag::Linked))
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
        let address = self.member_address_of(peer)?;
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
        self.latches.insert(Latch::PeerInfoDeferred);
    }

    /// Whether a held-back `PeerInfo` flood is due at `now`: the window since the
    /// last flood has ended. Taking it clears the mark.
    pub(crate) fn take_deferred_peerinfo(&mut self, now: Instant) -> bool {
        let due = self.latches.contains(&Latch::PeerInfoDeferred)
            && self.neighbor_up_refloods_peerinfo(now);
        if due {
            self.latches.remove(&Latch::PeerInfoDeferred);
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

    /// Whether our `PeerInfo` is due for a refresh at `now`. It is due for a meshed node that has
    /// flooded before, when the refresh period has passed since the last flood, whatever caused
    /// that flood. The period is [`tuning::peerinfo_refresh_period`] for the live members,
    /// lengthened by the spread that the last flood drew. A `PeerInfo` is not in the message log,
    /// so no digest repairs one that a member missed, and the flood of its sender is the only
    /// repair.
    pub(crate) fn peerinfo_refresh_due(&self, now: Instant) -> bool {
        if !self.standing.contains(&Standing::Meshed) {
            return false;
        }
        let Some(flood) = self.peerinfo_flood else {
            return false;
        };
        let members = self.peers.len().saturating_add(1);
        let period = tuning::peerinfo_refresh_period(members).mul_f64(flood.spread);
        now.duration_since(flood.at) >= period
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
                .peerinfo_flood
                .is_none_or(|flood| now.duration_since(flood.at) >= RELINK_COOLDOWN)
    }

    /// Drop `nick`'s dial hint and, with it, the path verdict keyed on that
    /// endpoint. The two share a key space: the verdict describes the pooled
    /// connection, which outlives a gossip link but not the peer.
    pub(crate) fn forget_peer_endpoint(&mut self, nick: &str) -> Option<EndpointAddr> {
        let address = self.peer_endpoints.remove(nick)?;
        self.hint_owner.remove(nick);
        // Another nickname can bind the same endpoint (a node that restarted under a new name).
        // A linked endpoint keeps its proof for the regraft after a link loss.
        if !self.endpoint_is_bound(address.id) {
            self.release_unbound_endpoint(address.id);
        }
        Some(address)
    }

    /// Whether a dial hint of any nickname names `endpoint`.
    pub(crate) fn endpoint_is_bound(&self, endpoint: EndpointId) -> bool {
        let retained = self.refused_endpoints.values();
        let hinted = self.peer_endpoints.values();
        hinted.chain(retained).any(|address| address.id == endpoint)
    }

    /// Drop the state of an endpoint that no nickname binds any more. A linked endpoint keeps its
    /// proof, direct path and backoff for the regraft after the link loss. The path watch goes:
    /// nothing names this endpoint, and a stale entry nudges it on each tick. A later sweep drops
    /// the rest.
    pub(crate) fn release_unbound_endpoint(&mut self, endpoint: EndpointId) {
        if self.linked_endpoints.contains(&endpoint) {
            self.path_kinds.remove(&endpoint);
            self.path_watchers.remove(&endpoint);
            self.orphaned_endpoints.insert(endpoint);
        } else {
            self.forget_endpoint_state(endpoint);
        }
    }

    /// Drop every state that is keyed by `endpoint`: the backoff, the proof, the rival flag, the
    /// direct state, the path state and the address of the endpoint, in the pool and in the book.
    pub(crate) fn forget_endpoint_state(&mut self, endpoint: EndpointId) {
        self.address_book.remove_endpoint_info(endpoint);
        self.graft_backoff.reset(endpoint);
        self.proven_endpoints.forget_endpoint(endpoint);
        self.forget_rival_holder(endpoint);
        self.direct.remove(&endpoint);
        self.path_watchers.remove(&endpoint);
        self.path_kinds.remove(&endpoint);
        self.unicast_pool.forget_addr(endpoint);
    }

    /// Drop everything the roster keeps about `key`, which left: its place in the roster, its
    /// stamps and runs, its claim to the rendezvous, its name, and every dial hint that its
    /// `PeerInfo` made, under each nickname it used. Returns the address of each hint that went.
    pub(crate) fn forget_key(&mut self, key: AuthorKey) -> Vec<EndpointAddr> {
        self.peers.remove(&key);
        self.last_seen.remove(&key);
        self.peer_stamp.remove(&key);
        self.quiet.remove(&key);
        self.quiet_since.remove(&key);
        self.clock_evidence.quiet_aged.remove(&key);
        self.surfaced.remove(&key);
        self.clock_evidence.step_back.remove(&key);
        self.clock_evidence.live_run.remove(&key);
        self.clock_evidence.heard.remove(&key);
        self.clock_evidence.returned_unshown.remove(&key);
        self.clock_evidence.lapsed_quiet.remove(&key);
        self.proofs.forget(&key);
        self.proven_endpoints.forget_trust(&key);
        self.rival_holders.remove(&key);
        self.names.remove(&key);
        self.clock_evidence.name_stamp.remove(&key);
        self.release_refused_endpoint(&key);
        self.drop_buffered_frames_to(&key);
        let left_hints = self.forget_hints_of(key);
        self.rebind_refused_endpoints();
        left_hints
    }

    /// Drop the buffered directed frames whose recipient is `key`, and keep the others in order.
    /// A key that left the roster, or that cannot return (a ghost, a key quiet past the quiet
    /// TTL), has no endpoint to wait for, so a frame to it would be requeued at every flush until
    /// the buffer is full.
    /// Returns how many frames went.
    pub(crate) fn drop_buffered_frames_to(&mut self, key: &AuthorKey) -> usize {
        let mut dropped = 0;
        for entry in self.pending_outbound.take() {
            if sole_addressee(&entry.0.kind) == Some(key) {
                dropped += 1;
            } else {
                self.pending_outbound.push(entry);
            }
        }
        dropped
    }

    /// Drop every dial hint that `key` made, under each nickname it used, and return the address
    /// of each. A key that renamed owns a hint under each nickname it used.
    pub(crate) fn forget_hints_of(&mut self, key: AuthorKey) -> Vec<EndpointAddr> {
        // The owned nicknames are read before any hint goes, since a removal changes the owner map.
        let owned_hints = self.hint_owner.iter().filter(|(_, owner)| **owner == key);
        let owned: Vec<Nickname> = owned_hints.map(|(nickname, _)| nickname.clone()).collect();
        let forget = |nickname: &Nickname| self.forget_peer_endpoint(nickname.as_str());
        owned.iter().filter_map(forget).collect()
    }

    /// Whether `key` is not live and another live peer uses `nickname`. A late `PeerInfo` of a
    /// lapsed or pruned key can pass the staleness test, and it must not bind a nickname that a
    /// live peer holds: a directed send would reach the old node until that peer sends its own.
    pub(crate) fn nickname_is_taken_by_live_other(
        &self,
        nickname: &Nickname,
        key: AuthorKey,
    ) -> bool {
        let mut users = self.peers.iter().filter_map(|other| self.names.get(other));
        !self.peers.contains(&key) && users.any(|name| name == nickname)
    }

    /// The address a directed send to `key` dials, from the first source that has one:
    /// - the dial hint under the nickname of `key`, when `key` made it;
    /// - the endpoint that `key` proved in its `PeerInfo`;
    /// - the endpoint of a `PeerInfo` of `key` that bound no hint, because another live key holds
    ///   the nickname.
    ///
    /// A quiet key keeps its address, so a peer that returns keeps its route. A key that left the
    /// roster has none. An endpoint that another key proved is not an address of `key`: a process
    /// that restarts keeps its endpoint and makes a new key, and until the old key times out, its
    /// hint still names the endpoint of the new process.
    pub(crate) fn address_of(&self, key: &AuthorKey) -> Option<EndpointAddr> {
        let hint = self.names.get(key).and_then(|nickname| {
            let owned = self.hint_owner.get(nickname) == Some(key);
            if owned {
                self.peer_endpoints.get(nickname).cloned()
            } else {
                None
            }
        });
        let proven = self.proven_endpoints.trusted(key).map(EndpointAddr::new);
        let retained = self.refused_endpoints.get(key).cloned();
        let address: EndpointAddr = hint.or(proven).or(retained)?;
        let holder = self.proven_endpoints.trusted_signer(address.id);
        holder
            .is_none_or(|signer| signer == *key)
            .then_some(address)
    }

    /// The dial address of each member of the roster: one for each key that is a peer, quiet or
    /// lapsed, as [`address_of`](Self::address_of) gives it, and the hint of a nickname that no key
    /// of the roster uses yet. A nickname is a label that two live keys can share, so a list
    /// by nickname holds one row where the roster holds two members. Two members never share an
    /// endpoint here: a row appears once for each endpoint.
    pub(crate) fn member_addresses(&self) -> Vec<EndpointAddr> {
        let mut seen: HashSet<EndpointId> = HashSet::new();
        let mut addresses: Vec<EndpointAddr> = self.member_address_stream().collect();
        addresses.retain(|address| seen.insert(address.id));
        addresses
    }

    /// The dial address of the member whose endpoint is `endpoint`, if the roster has one. It
    /// builds no list: the walk stops at the first row that names the endpoint.
    pub(crate) fn member_address_of(&self, endpoint: EndpointId) -> Option<EndpointAddr> {
        self.member_address_stream()
            .find(|address| address.id == endpoint)
    }

    /// The rows of [`Self::member_addresses`] before the removal of repeats: the address of each
    /// key of the roster, then the hint of each nickname that no key owns yet.
    fn member_address_stream(&self) -> impl Iterator<Item = EndpointAddr> + '_ {
        let by_key = self.names.keys().filter_map(|key| self.address_of(key));
        let unowned = self
            .peer_endpoints
            .iter()
            .filter(|(nickname, _)| !self.hint_owner.contains_key(*nickname));
        by_key.chain(unowned.map(|(_, address)| address.clone()))
    }

    /// The key that a send by nickname goes to: the one live key that uses `nickname`, as
    /// [`key_of`](Self::key_of) gives it, or, when no live key uses it, the one quiet key that
    /// does, because a peer that went quiet may return and was sent to before a frame named a key.
    /// Two quiet keys are as ambiguous as two live keys.
    ///
    /// # Errors
    /// [`KeyOfError::Unknown`] when no key of the roster uses the nickname, and
    /// [`KeyOfError::Ambiguous`] when two or more live keys, or two or more quiet keys with no
    /// live key, do.
    pub fn addressee_key(&self, nickname: &Nickname) -> Result<AuthorKey, KeyOfError> {
        match self.key_of(nickname) {
            Err(KeyOfError::Unknown) => {
                let named = self.keys_named(nickname);
                match named.as_slice() {
                    [] => Err(KeyOfError::Unknown),
                    [key] => Ok(*key),
                    _ => Err(KeyOfError::Ambiguous),
                }
            }
            found => found,
        }
    }

    /// The keys of the live peers: not the quiet ones, and not a key that left. Two live keys
    /// that share a nickname are two entries. An app that tracks peers by key reads the live set
    /// here, as [`live_nicknames`](Self::live_nicknames) gives it by name.
    pub fn live_keys(&self) -> impl Iterator<Item = &AuthorKey> {
        self.peers.iter()
    }

    /// The nickname that the roster holds for `key`, live or quiet. A quiet peer may return and a
    /// line about it still prints its name, so unlike [`nickname_of`](Self::nickname_of) this
    /// keeps answering for a quiet key. A key that left the roster has none: `forget_key` drops
    /// it, and an app that wants the name of a departed key keeps what `on_peer_left` gave it.
    #[must_use]
    pub fn known_nickname_of(&self, key: &AuthorKey) -> Option<Nickname> {
        self.names.get(key).cloned()
    }

    /// Whether `key` is a member we can still reach: a live peer, a quiet peer that may return, or
    /// a key with an address to dial. A directed frame to any other key has no one to wait for.
    pub(crate) fn knows_key(&self, key: &AuthorKey) -> bool {
        self.peers.contains(key) || self.quiet.contains(key) || self.address_of(key).is_some()
    }

    /// Whether the dial hint of `nickname` was made by a key other than `key` that is live. A quiet
    /// or gone owner does not hold it against a live key: the nickname answers there now.
    pub(crate) fn hint_is_held_by_other(&self, nickname: &Nickname, key: AuthorKey) -> bool {
        self.hint_owner
            .get(nickname)
            .is_some_and(|owner| *owner != key && self.peers.contains(owner))
    }

    /// How long the quiet peer `key` has been silent at `now`, suspends included.
    pub(crate) fn quiet_silence(&self, key: &AuthorKey, now: Instant) -> Option<Duration> {
        let since = self.quiet_since.get(key)?;
        let aged = self
            .clock_evidence
            .quiet_aged
            .get(key)
            .copied()
            .unwrap_or_default();
        Some(now.duration_since(*since).saturating_add(aged))
    }

    /// The keys of the roster, live or quiet, that use `nickname`.
    pub(crate) fn keys_named(&self, nickname: &Nickname) -> Vec<AuthorKey> {
        let roster = self.peers.iter().chain(self.quiet.iter());
        roster
            .filter(|key| self.names.get(*key) == Some(nickname))
            .copied()
            .collect()
    }

    /// Whether a live peer of the roster uses `nickname`. Two live keys under one nickname are two
    /// peers, so this asks whether at least one of them is there.
    #[must_use]
    pub fn is_peer(&self, nickname: &str) -> bool {
        self.peers.iter().any(|key| {
            self.names
                .get(key)
                .is_some_and(|name| name.as_str() == nickname)
        })
    }

    /// Whether two or more live peers use `nickname`. A directed send names a nickname, so it
    /// cannot tell which of them it means.
    pub(crate) fn nickname_is_ambiguous(&self, nickname: &Nickname) -> bool {
        self.key_of(nickname) == Err(KeyOfError::Ambiguous)
    }

    /// The one live key that uses `nickname`. A nickname is a label, so the lookup names a key
    /// only when the answer is certain. A quiet key is no live key, so it neither is the answer
    /// nor makes the nickname ambiguous.
    ///
    /// # Errors
    /// [`KeyOfError::Unknown`] when no live key uses the nickname, and [`KeyOfError::Ambiguous`]
    /// when two or more do.
    pub fn key_of(&self, nickname: &Nickname) -> Result<AuthorKey, KeyOfError> {
        let mut users = self
            .peers
            .iter()
            .filter(|key| self.names.get(*key) == Some(nickname));
        match (users.next(), users.next()) {
            (Some(key), None) => Ok(*key),
            (Some(_), Some(_)) => Err(KeyOfError::Ambiguous),
            (None, _) => Err(KeyOfError::Unknown),
        }
    }

    /// The nickname that a live key uses now, or `None` for a quiet key and for a key we never
    /// saw.
    #[must_use]
    pub fn nickname_of(&self, key: &AuthorKey) -> Option<Nickname> {
        if !self.peers.contains(key) {
            return None;
        }
        self.names.get(key).cloned()
    }

    /// Remember that `key` said goodbye. A key is minted per run, so it never speaks again.
    pub(crate) fn note_left(&mut self, key: AuthorKey) {
        self.left_keys.peers.insert(key);
    }

    /// Remember that `key`, which is no peer of ours, said goodbye.
    pub(crate) fn note_stranger_left(&mut self, key: AuthorKey) {
        self.left_keys.strangers.insert(key);
    }

    pub(crate) fn key_said_goodbye(&self, key: AuthorKey) -> bool {
        self.left_keys.peers.contains(&key) || self.left_keys.strangers.contains(&key)
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

    /// A `NeighborDown` for `peer`: the gossip link is gone, the path verdict
    /// stays. It describes the pooled unicast connection, which outlives the
    /// link; erasing it parked every directed frame on a link flap until the
    /// alive tick re-probed (about 40 s with the relink cooldown).
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
        self.standing.contains(&Standing::Meshed)
            && roster_len > 0
            && self.linked_endpoints.is_empty()
            && self.zero_links_since.is_some_and(|since| {
                now.saturating_duration_since(since) >= tuning::silent_partition_after()
            })
    }

    /// Tests only: the gap of zero links began at `since`, so a test need not wait for a heal.
    #[cfg(test)]
    pub(crate) fn start_zero_links_gap_at(&mut self, since: Instant) {
        self.zero_links_since = Some(since);
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
        if !self
            .rendezvous_flags
            .contains(&RendezvousFlag::HostsRendezvous)
        {
            return;
        }
        if (beacon::Contest { own, rival: sender }).own_yields() {
            self.beacon_notes.insert(BeaconNote::YieldToLower);
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
        let Some(due) = self.next_rival_recheck.filter(|_| {
            self.rendezvous_flags
                .contains(&RendezvousFlag::HostsRendezvous)
        }) else {
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
        self.test_holds.contains(&TestHold::Claims)
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
        self.rendezvous_flags
            .contains(&RendezvousFlag::HostsRendezvous)
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
        if self.rendezvous_flags.contains(&RendezvousFlag::Linked)
            || self.rendezvous_wanted()
            || self.rival_holder_known()
        {
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
        self.rendezvous_flags.insert(RendezvousFlag::Linked);
        self.rendezvous_flags.remove(&RendezvousFlag::Released);
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
        let flags = &self.rendezvous_flags;
        let linked_alone = flags.contains(&RendezvousFlag::Linked)
            && !flags.contains(&RendezvousFlag::Released)
            && !flags.contains(&RendezvousFlag::HostsRendezvous);
        linked_alone
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
        self.rendezvous_flags.insert(RendezvousFlag::Released);
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
        self.rendezvous_flags.remove(&RendezvousFlag::ProbeReadFree);
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
    /// the author-bound `Message::dedup_key`, so a forgery reusing a
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
    /// before), return the synthesized logical `Message` — a surfacing view
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
        if self
            .receive_memory
            .reassembled_groups
            .contains(&shard.group)
        {
            return None;
        }
        match self.reassembly.ingest(trigger, Instant::now()) {
            ShardIngest::Complete(logical) => {
                self.receive_memory
                    .reassembled_groups
                    .insert(shard.group.clone());
                Some(*logical)
            }
            ShardIngest::Buffered | ShardIngest::Dropped => {
                let logical = self.reassemble_from_log(trigger)?;
                // The store may still hold a partial buffer for this group
                // (e.g. just the trigger, post-TTL) — release its budget.
                self.reassembly.forget(trigger);
                self.receive_memory
                    .reassembled_groups
                    .insert(shard.group.clone());
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
        if !messages::shard_fits_log(trigger) {
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
        self.standing.contains(&Standing::Meshed)
            || (self.rendezvous_flags.contains(&RendezvousFlag::Linked)
                && !self.standing.contains(&Standing::Degraded))
    }

    /// Mark the mesh degraded: a fault path (starvation recovery, hard
    /// resume edge) cleared `meshed`, so outbound user content buffers in
    /// `pending_outbound` instead of broadcasting into a dead overlay.
    /// `note_inbound` undoes it on the first proof of live traffic.
    pub(crate) fn note_degraded(&mut self) {
        self.standing.remove(&Standing::Meshed);
        self.standing.insert(Standing::Degraded);
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
        if self.standing.contains(&Standing::Degraded) {
            self.standing.remove(&Standing::Degraded);
            self.standing.insert(Standing::Meshed);
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
        if !self.standing.contains(&Standing::Announced) || self.known_endpoints.is_empty() {
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

/// How many replays and restores of the state channel wait for the loop to send them. A tick adds
/// at most 2 (the replay of a switch and the restores that are due), and the loop sends them after
/// the tick, so 8 is room for 4 ticks of a loop that is slow.
const REPLAY_QUEUE_CAP: usize = 8;

/// How many keys have an endpoint retained in `refused_endpoints`. The map takes the address of any signed
/// `PeerInfo` whose key is not the holder of its nickname, and a member mints keys for free, so a flood of them
/// would fill it until the next sweep. 256 is more than the live roster of a mesh of the size that one node
/// serves (the beacon limit is far below it), so a real peer is not pushed out; at the cap the oldest key goes
/// and its endpoint state with it.
pub(crate) const REFUSED_ENDPOINTS_CAP: usize = 256;

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

    /// The roster, as a set of nicknames. Two live keys of one nickname are one nickname here;
    /// [`Self::member_count`] counts the keys. See [`Self::roster_snapshot`] for the richer
    /// per-peer view.
    #[must_use]
    pub fn peers(&self) -> HashSet<&Nickname> {
        self.peers
            .iter()
            .filter_map(|key| self.names.get(key))
            .collect()
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
        self.standing.contains(&Standing::Meshed)
    }

    /// Whether the gossip topic is currently open for broadcast.
    #[must_use]
    pub fn is_gossip_open(&self) -> bool {
        self.standing.contains(&Standing::GossipOpen)
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

    /// The proof that this session speaks as `nickname` on `mesh` in run `run`. A node with no
    /// member key has none.
    #[must_use]
    pub(crate) fn own_proof(
        &self,
        nickname: &Nickname,
        mesh: &MeshId,
        run: u64,
    ) -> Option<IdentityProof> {
        let member = self.member_identity.as_ref()?;
        Some(member.prove(
            &self.identity.author_key(),
            nickname.as_ref(),
            mesh.as_ref(),
            run,
        ))
    }

    /// The `joined` frame this node announces: signed by the session key, with the proof of the
    /// session in the body.
    pub(crate) fn own_joined(&self, mesh: &MeshId, nickname: &Nickname) -> Verified {
        let joined = match self.own_proof(nickname, mesh, self.run) {
            Some(proof) => Message::new_joined_with_proof(mesh, nickname, &proof),
            None => Message::new_joined(mesh, nickname),
        };
        joined.sign(&self.identity)
    }

    /// The request to send for an `alive` frame whose session this node holds no proof for. It asks
    /// for a member of the roster and for a session that claims a bound nickname, since the proof is
    /// the way in. A stranger under a free nickname is not asked. The asks of sessions outside the
    /// roster are limited to 4 open for each nickname, so a flood of forged keys under one bound
    /// nickname replaces its own asks and no other.
    pub(crate) fn proof_request_for(
        &self,
        alive: &Verified,
        own: &Nickname,
        mesh: &MeshId,
    ) -> Option<Verified> {
        let key = alive.key();
        // A session of a bound nickname with no proof is no peer yet, and it is asked as well: the
        // proof is the way in.
        let asked_for = self.peers.contains(&key)
            || self
                .proofs
                .is_bound(&alive.author, |session| self.session_is_held(session));
        if !asked_for || !self.proofs.wants_proof(&key, Instant::now()) {
            return None;
        }
        Some(Message::new_proof_request(mesh, own, alive.key()).sign(&self.identity))
    }

    /// The request for the proof of `session` went out: its retry clock starts. A request that
    /// did not go out, for lack of a warm path, is not noted, so the next alive frame asks again.
    pub(crate) fn note_proof_request_sent(
        &mut self,
        session: &AuthorKey,
        claimed: Option<&Nickname>,
    ) {
        let (peers, quiet) = (&self.peers, &self.quiet);
        self.proofs
            .note_asked(session, Instant::now(), claimed, |asked| {
                peers.contains(asked) || quiet.contains(asked)
            });
    }

    /// The answer to a proof request: a signed `joined` frame with the proof of this session, if
    /// the request is for this node and the answers of the last minute are under the cap.
    pub(crate) fn proof_answer(
        &mut self,
        request_to: &AuthorKey,
        asker: &AuthorKey,
        own: &Nickname,
        mesh: &MeshId,
        now: Instant,
    ) -> Option<Verified> {
        if *request_to != self.identity.author_key()
            || !self.proofs.may_answer(asker, now, self.peers.len())
        {
            return None;
        }
        let proof = self.own_proof(own, mesh, self.run)?;
        Some(Message::new_joined_with_proof(mesh, own, &proof).sign(&self.identity))
    }

    /// Whether `session` is in the roster, live or quiet. A quiet peer may return, so it still
    /// holds its nickname; a session that left or timed out holds nothing.
    pub(crate) fn session_is_held(&self, session: &AuthorKey) -> bool {
        self.peers.contains(session) || self.quiet.contains(session)
    }

    /// Hold the proof in the body of a `joined` frame, if it verifies for the author of the frame.
    /// A frame with an empty or bad body holds none. True means: this is the first proof that shows
    /// our own nickname bound to another member, which is the join error of this node.
    pub(crate) fn note_joined_proof(
        &mut self,
        message: &Verified,
        mesh: &MeshId,
        own: &Nickname,
    ) -> bool {
        let Some(proof) = message.joined_proof() else {
            return false;
        };
        let key = message.key();
        let ours = self.member_identity.as_ref().map(|member| member.public());
        if message.author == *own && ours.is_some_and(|ours| proof.identity != ours) {
            let proved = verify_proof(&proof, &key, message.author.as_ref(), mesh.as_ref());
            return proved && self.proofs.tell_once(&key);
        }
        let (peers, quiet) = (&self.peers, &self.quiet);
        self.proofs
            .accept(&key, &message.author, mesh, proof, |session| {
                peers.contains(session) || quiet.contains(session)
            });
        false
    }

    /// The run of a session of our own member that is newer than ours, when this frame is the first to show
    /// it: a newer run of this member is active elsewhere, so this node is superseded. It is admitted as
    /// before, and the caller says so once for each run number.
    pub(crate) fn newer_run_of_our_member(
        &mut self,
        message: &Verified,
        own: &Nickname,
    ) -> Option<u64> {
        let ours = self
            .member_identity
            .as_ref()
            .map(|member| member.public())?;
        let key = message.key();
        if message.author != *own || key == self.identity.author_key() {
            return None;
        }
        let run = self
            .proofs
            .proof_of(&key)
            .filter(|proof| proof.identity == ours)
            .map(|proof| proof.run)?;
        let newer = run > self.run && run > self.newest_own_run_seen;
        newer.then(|| {
            self.newest_own_run_seen = run;
            run
        })
    }

    /// Whether the frames of this session reach the roster. A session that claims a nickname that
    /// another member holds, with no proof of that member, does not. Our own nickname is held by
    /// our member key. A refusal is counted.
    pub(crate) fn admits_session(&mut self, message: &Verified, own: &Nickname) -> bool {
        let key = message.key();
        if message.author == *own {
            let ours = self.member_identity.as_ref().map(|member| member.public());
            // A session of our member is a peer only when its run is not older than the run live here: a
            // replay of an older run must not enter the roster beside it.
            let run = self.run;
            let proved = |proof: &IdentityProof| {
                ours.is_none_or(|ours| proof.identity == ours && proof.run >= run)
            };
            let ours_here = key == self.identity.author_key();
            let admitted =
                ours_here || ours.is_none() || self.proofs.proof_of(&key).is_some_and(proved);
            if !admitted {
                self.proofs.note_gate_refused();
            }
            return admitted;
        }
        let (peers, quiet) = (&self.peers, &self.quiet);
        self.proofs.admits(&key, &message.author, |session| {
            peers.contains(session) || quiet.contains(session)
        })
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
        self.chat_continuations
            .begin(author, now, tuning::ANTIENTROPY_SERVE_COOLDOWN);
        true
    }

    /// Whether a digest of `author` that came by unicast, inside the cooldown that `admit_digest`
    /// refused it for, is a continuation of its chat ask to serve now: at the pace of the asker, and
    /// up to its count. Only an author that was served has one. Bounded (see `ChatContinuations`).
    pub fn admit_chat_continuation(&mut self, author: AuthorKey, now: Instant) -> bool {
        self.digest_serves.on_cooldown(&author, now)
            && self
                .chat_continuations
                .admit(author, now, tuning::ANTIENTROPY_SERVE_COOLDOWN)
    }

    /// How many authors hold a run of chat continuations: the size gauge of the bound.
    #[cfg(test)]
    pub(crate) fn chat_continuations_len(&self) -> usize {
        self.chat_continuations.len()
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
    ///
    /// The card names a nickname and no key. The hint belongs to the one key that answers to the
    /// nickname; with no such key yet it has no owner; with two live keys the card does not say
    /// which one it is, so it binds no hint.
    pub fn note_peer_endpoint(&mut self, nickname: Nickname, endpoint: EndpointAddr) {
        let (live, quiet): (Vec<AuthorKey>, Vec<AuthorKey>) = self
            .keys_named(&nickname)
            .into_iter()
            .partition(|key| self.peers.contains(key));
        let owner = match (live.as_slice(), quiet.as_slice()) {
            ([only], _) | ([], [only]) => Some(*only),
            ([], []) => None,
            _ambiguous => return,
        };
        let id = endpoint.id;
        let changed = self
            .peer_endpoints
            .get(&nickname)
            .is_some_and(|before| *before != endpoint);
        self.store_peer_endpoint(owner, nickname, endpoint);
        // A peer at a new address is not the peer that refused.
        if changed {
            self.graft_backoff.reset(id);
            if self.rendezvous_id == Some(id) {
                self.probe_backoff.reset();
            }
        }
    }

    /// Keep the endpoint of a `PeerInfo` of `key` that bound no dial hint, for the day `key` is
    /// the only live key of its nickname.
    pub(crate) fn retain_refused_endpoint(&mut self, key: AuthorKey, endpoint: EndpointAddr) {
        let id = endpoint.id;
        if !self.refused_endpoints.contains_key(&key) {
            while self.refused_endpoints.len() >= REFUSED_ENDPOINTS_CAP {
                let Some(oldest) = self.refused_order.pop_front() else {
                    break;
                };
                self.release_refused_endpoint(&oldest);
            }
            self.refused_order.push_back(key);
            if self.refused_order.len() > 2 * REFUSED_ENDPOINTS_CAP {
                let held = &self.refused_endpoints;
                self.refused_order
                    .retain(|queued| held.contains_key(queued) || *queued == key);
            }
        }
        let displaced = self.refused_endpoints.insert(key, endpoint);
        if let Some(old) = displaced
            && old.id != id
        {
            self.release_if_unowned(old.id);
        }
    }

    /// Give up the retained endpoint of `key`. Its state goes with it, unless a nickname binds the
    /// endpoint or another retained endpoint names it.
    pub(crate) fn release_refused_endpoint(&mut self, key: &AuthorKey) {
        let Some(address) = self.refused_endpoints.remove(key) else {
            return;
        };
        self.release_if_unowned(address.id);
    }

    /// Drop the state of `endpoint` unless a dial hint or a retained endpoint names it.
    fn release_if_unowned(&mut self, endpoint: EndpointId) {
        if !self.endpoint_is_bound(endpoint) {
            self.release_unbound_endpoint(endpoint);
        }
    }

    /// Place the endpoint that `key` published under `nickname`: as the dial hint of the nickname,
    /// or, when another key holds it, as the endpoint retained for `key`. A key that said
    /// goodbye never speaks again, so what it published is a replay and binds nothing. Another
    /// key under the same nickname binds no hint while the key that made the hint is in the
    /// roster, or while another live key holds the nickname: a directed send must not reach a
    /// node that only borrowed the label. One rule for a `PeerInfo` and for a meta card.
    pub(crate) fn place_endpoint(
        &mut self,
        key: AuthorKey,
        nickname: &Nickname,
        endpoint: EndpointAddr,
    ) {
        if self.key_said_goodbye(key) {
            return;
        }
        let held = self.hint_is_held_by_other(nickname, key)
            || self.nickname_is_taken_by_live_other(nickname, key);
        if held {
            self.retain_refused_endpoint(key, endpoint);
        } else {
            self.bind_peer_endpoint(key, nickname.clone(), endpoint);
            self.release_refused_endpoint(&key);
        }
    }

    /// Bind the endpoint that the meta card of `key` names as its dial hint, as the `PeerInfo` of
    /// the key does, so a send to the key is deliverable before the `PeerInfo` comes. The rule is
    /// the one of a `PeerInfo`: a second live key of a nickname gets the endpoint retained for it,
    /// and a send to that key dials it. A key with no name in the roster, and a key that said
    /// goodbye, bind nothing.
    pub fn note_key_endpoint(&mut self, key: AuthorKey, endpoint: EndpointAddr) {
        let Some(nickname) = self.names.get(&key).cloned() else {
            return;
        };
        self.place_endpoint(key, &nickname, endpoint);
    }

    /// Bind the retained endpoint of each key that is now the only live key of its nickname, with
    /// the flow of a `PeerInfo`, and drop the retained value.
    pub(crate) fn rebind_refused_endpoints(&mut self) {
        let refused = self.refused_endpoints.keys();
        let live = refused.filter(|key| self.peers.contains(*key));
        let waiting: Vec<(AuthorKey, Nickname)> = live
            .filter_map(|key| Some((*key, self.names.get(key)?.clone())))
            .collect();
        for (key, nickname) in waiting {
            if self.nickname_is_ambiguous(&nickname) || self.hint_is_held_by_other(&nickname, key) {
                continue;
            }
            if let Some(address) = self.refused_endpoints.remove(&key) {
                self.bind_peer_endpoint(key, nickname, address);
            }
        }
    }

    /// Write the binding of `nickname` to its endpoint, made by `key`: a `PeerInfo`
    /// (`handle_peer_info`) comes here.
    pub(crate) fn bind_peer_endpoint(
        &mut self,
        key: AuthorKey,
        nickname: Nickname,
        endpoint: EndpointAddr,
    ) {
        self.store_peer_endpoint(Some(key), nickname, endpoint);
    }

    /// The one place that writes a dial hint. `owner` is the key that made it, if known.
    fn store_peer_endpoint(
        &mut self,
        owner: Option<AuthorKey>,
        nickname: Nickname,
        endpoint: EndpointAddr,
    ) {
        let bound_id = endpoint.id;
        match owner {
            Some(key) => self.hint_owner.insert(nickname.clone(), key),
            None => self.hint_owner.remove(&nickname),
        };
        let replaced = self.peer_endpoints.insert(nickname, endpoint);
        // The endpoint that the nickname left has no name now, unless another nickname binds it.
        // The sweep drops only the bindings that it removes, so it never sees this one.
        if let Some(old) = replaced
            && old.id != bound_id
            && !self.endpoint_is_bound(old.id)
        {
            self.release_unbound_endpoint(old.id);
        }
    }

    /// Record that `signer` proved `endpoint`, and feed the vector of `signer` that waited for the
    /// proof, now and not at the next tick.
    pub(crate) fn note_proven_endpoint(
        &mut self,
        signer: AuthorKey,
        endpoint: EndpointId,
        stamp: UnixSecs,
    ) {
        let linked = self.linked_endpoints.clone();
        let roster = &self.peers;
        self.proven_endpoints
            .insert(signer, endpoint, stamp, &linked, |holder| {
                roster.contains(holder)
            });
        // The table can refuse a replay of an older stamp, so the trust follows what it holds.
        self.promote_stored_proof(signer);
    }

    /// Trust the proof that the table holds for `signer`, if `signer` is in the roster, and feed
    /// the vector that waited for it. A proof can come before its signer is admitted, and then no
    /// further `PeerInfo` is due: the admission calls this. Anyone can mint keys, so only a key of
    /// the roster is trusted, and the roster bounds the map.
    pub(crate) fn promote_stored_proof(&mut self, signer: AuthorKey) {
        let in_roster = self.peers.contains(&signer) || self.quiet.contains(&signer);
        if in_roster && let Some(endpoint) = self.proven_endpoints.get(&signer) {
            self.proven_endpoints.trust(signer, endpoint);
        }
        #[cfg(feature = "multihop")]
        self.feed_parked_link_state(&signer);
    }

    /// Feed the link vector that waited for the proof of `signer`, with the check that a vector
    /// that arrives after its proof goes through: the origin must be the proven endpoint. The
    /// underlay is ticked when the vector changed the topology, as at any other receipt.
    #[cfg(feature = "multihop")]
    fn feed_parked_link_state(&mut self, signer: &AuthorKey) {
        // The vector stays parked until the signer is trusted: a proof can come before the roster.
        let Some(proven) = self.proven_endpoints.trusted(signer) else {
            return;
        };
        let Some(vector) = self.parked_link_states.take(signer) else {
            return;
        };
        if vector.origin().get() != proven {
            tracing::debug!(target: "habilis_network::gossip",
                "dropping parked multihop link-state: its origin is not the endpoint its signer proved"
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
        self.standing.remove(&Standing::GossipOpen);
    }

    /// Test only: adversarial feature. Put the document of `channel` in `epoch` at once, as an
    /// adoption does after its wait, and queue the write of the own entry. The Op that calls it
    /// exists only in an app build with the feature on: no frame and no CLI reaches it.
    #[cfg(feature = "adversarial")]
    pub fn force_epoch(&mut self, channel: protocol::Channel, epoch: u64) {
        let own = self.identity.author_key();
        let switch = self.doc_mut(channel).restart_at_epoch(epoch, &own);
        self.note_epoch_switch(switch);
    }

    /// Tests only: the next ask of a fast round fails to start, once.
    #[cfg(test)]
    pub(crate) fn fail_the_next_ask(&mut self) {
        self.fail_next_ask = true;
    }

    /// Tests only: whether the injected failure of an ask is due now. It is spent when it is read.
    #[cfg(test)]
    pub(crate) fn take_injected_ask_failure(&mut self) -> bool {
        let due = self.fail_next_ask;
        self.fail_next_ask = false;
        due
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

    /// Tests only: whether the roster trusts the endpoint that `peer` proved in its `PeerInfo`.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    #[must_use]
    pub fn endpoint_is_proven(&self, peer: &Nickname) -> bool {
        let named = self.names.iter().find(|(_, name)| *name == peer);
        named.is_some_and(|(key, _)| self.proven_endpoints.trusted(key).is_some())
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

/// Roster fixtures for the tests. A nickname names one key: the key that a frame of the test
/// already registered under it, or else the key of [`crate::testing::test_key`].
#[cfg(test)]
impl EventLoopState {
    /// The key that `nickname` names in this state.
    pub(crate) fn key_named(&self, nickname: &str) -> AuthorKey {
        let named = self
            .names
            .iter()
            .find(|(_, name)| name.as_str() == nickname);
        named.map_or_else(|| testing::test_key(nickname), |(key, _)| *key)
    }

    /// [`Self::key_named`], and record the name of the key.
    pub(crate) fn name_key(&mut self, nickname: &str) -> AuthorKey {
        let key = self.key_named(nickname);
        let name = Nickname::try_new(nickname).expect("a test nickname is valid");
        self.names.insert(key, name);
        key
    }

    pub(crate) fn peer_for_test(&mut self, nickname: &str) {
        let key = self.name_key(nickname);
        self.peers.insert(key);
    }

    pub(crate) fn surfaced_for_test(&mut self, nickname: &str) {
        let key = self.name_key(nickname);
        self.surfaced.insert(key);
    }

    pub(crate) fn quiet_for_test(&mut self, nickname: &str) {
        let key = self.name_key(nickname);
        self.quiet.insert(key);
    }

    pub(crate) fn last_seen_for_test(&mut self, nickname: &str, at: Instant) {
        let key = self.name_key(nickname);
        self.last_seen.insert(key, at);
    }

    pub(crate) fn quiet_since_for_test(&mut self, nickname: &str, at: Instant) {
        let key = self.name_key(nickname);
        self.quiet_since.insert(key, at);
    }

    pub(crate) fn peer_stamp_for_test(&mut self, nickname: &str, stamp: UnixSecs) {
        let key = self.name_key(nickname);
        self.peer_stamp.insert(key, stamp);
    }
}
