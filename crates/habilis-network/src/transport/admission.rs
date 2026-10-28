//! Who is allowed to hold a direct-peer slot, and how many at once.
//!
//! One table for both roles. The dialer asks before offering and the
//! answerer asks before answering, so the direct-peer ceiling means the same
//! thing whichever end of a pair you are on — which it did not, when only the
//! dialer checked.
//!
//! # One slot per peer
//!
//! The table is keyed by peer. Under each peer sit the guards of every
//! transport that holds it: today a signalling round, and the QUIC connections
//! the endpoint hook reports (any protocol, gossip included). Only `WebRTC` sessions take a slot
//! against the cap today, but nothing in the shape assumes that: a later cap
//! over UDP, `WebRTC` and gossip counts peers in this same table.
//!
//! # Pruning
//!
//! A sampler visits the table on a timer. It drops the connections that are
//! gone and the peers that nothing holds. It also drops the ledger entries of the sessions
//! that ended. The ceiling refuses no newcomer: a session or a unicast connection that attaches
//! at the ceiling evicts the least valuable peer, see [`super::ceiling`].
//!
//! # Idle sessions
//!
//! The same table says when a session is idle: no round is in flight, no gossip connection holds
//! the peer, and the last use of the peer in the ledger is a window ago. [`SignalAdmission::idle_sessions`]
//! hands back such peers, and the retry pass detaches their sessions
//! (`webrtc::detach_idle_sessions_at`), so a session goes a window after its last use. A gossip
//! neighbor always has its gossip connection, so it never idles out.
//!
//! # What a single table buys
//!
//! **The ceiling becomes real.** The role rule (lower id offers) makes the
//! highest-id peer in a mesh a pure answerer. With the cap on the dial side
//! only, every one of its 24 counterparts passed *its own* check and that peer
//! attached all 24 — eight over a ceiling whose own comment claimed to be
//! enforced. The header rendered `24/16`.
//!
//! **In-flight rounds do not count against the ceiling.** [`Self::try_admit`] keeps one round
//! per peer, and the ceiling counts attached units only: it acts when a session attaches, and
//! evicts then (see [`super::ceiling`]). So a pass of the retry tick may admit a round for every
//! peer, and the count can pass the ceiling by the rounds that attach together. That is by
//! design: a round that fails costs nothing, and one that succeeds evicts the least valuable
//! peer. The lock is never held across an await.
//!
//! **Nothing can be pinned forever.** The slot is released by
//! [`AdmissionGuard`]'s `Drop`, so it survives the task being aborted — at
//! shutdown, or when a future is dropped mid-round. The set this replaced was
//! cleared by a statement at the end of the task, which a task that never
//! finishes never reaches: one stalled peer stayed marked in-flight for the
//! life of the process, and every later retry skipped it. That pair was pinned
//! to the relay permanently, which is the exact failure the retry tick exists
//! to prevent.
//!
//! **One peer cannot flood us.** Admission is keyed by the TLS-proven remote
//! id, and the acceptor admits *before* it spawns, so N connections from one
//! peer produce one task and N-1 immediate closes.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use habilis_network_iroh_webrtc_transport::WebRtcHandle;
use iroh::EndpointId;
use iroh::endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, WeakConnectionHandle};
use n0_future::task::AbortHandle;

use crate::util::clock::Instant;
use crate::util::tuning;

use tokio::sync::mpsc;
/// How long to leave a peer alone after it answered "at my cap", and how that
/// grows.
///
/// Without a wait the retry tick re-offers every 30s and every refused round
/// still costs *us* a full candidate-gathering budget before the refusal
/// arrives. The wait is per peer: the first refusal waits
/// [`tuning::CAP_REFUSAL_COOLDOWN`], each further one in a row doubles it up
/// to [`tuning::CAP_REFUSAL_COOLDOWN_MAX`], and a success resets it. One
/// rule serves both kinds of peer: the rendezvous frees a slot soon after, so
/// the first short wait finds it, while a member whose sessions are all busy
/// gossip links does not, and the wait grows to a size that makes the cost of a
/// refused round small.
#[derive(Debug, Default)]
struct RefusalBackoff {
    by_peer: HashMap<EndpointId, Backoff>,
    /// The peers that turned an offer away as not a neighbor, and when it was last: the first
    /// time in a row is a race that the next offer wins, a second one goes through [`Self::note`].
    #[cfg(any(feature = "multihop", test))]
    strangers: HashMap<EndpointId, Instant>,
}

#[derive(Debug, Clone, Copy)]
struct Backoff {
    until: Instant,
    window: Duration,
}

impl RefusalBackoff {
    fn note(&mut self, peer: EndpointId, now: Instant) {
        let first = tuning::CAP_REFUSAL_COOLDOWN;
        let max = tuning::CAP_REFUSAL_COOLDOWN_MAX;
        // Entries whose wait ended more than a longest wait ago are forgotten, so
        // that the map stays bounded by the peers refused lately.
        self.by_peer
            .retain(|_, backoff| now.saturating_duration_since(backoff.until) < max);
        let window = self
            .by_peer
            .get(&peer)
            .map_or(first, |previous| (previous.window * 2).min(max));
        self.by_peer.insert(
            peer,
            Backoff {
                until: now + window,
                window,
            },
        );
    }

    fn on_cooldown(&self, peer: &EndpointId, now: Instant) -> bool {
        self.by_peer
            .get(peer)
            .is_some_and(|backoff| now < backoff.until)
    }

    fn forget(&mut self, peer: &EndpointId) {
        self.by_peer.remove(peer);
        #[cfg(any(feature = "multihop", test))]
        self.strangers.remove(peer);
    }

    /// Forget every turn-away as not a neighbor, and the wait that a second one earned.
    #[cfg(any(feature = "multihop", test))]
    fn forget_strangers(&mut self) {
        for peer in self.strangers.keys() {
            self.by_peer.remove(peer);
        }
        self.strangers.clear();
    }

    /// `peer` turned an offer away as not a neighbor: its underlay does not hold our link vector
    /// yet. Whether the offer is tried again soon. The first turn-away in a row is a race of two
    /// vectors that cross, and the next offer wins it. A second one in a row (the earlier one is
    /// not older than the longest wait) is a refusal like the cap and waits as one.
    #[cfg(any(feature = "multihop", test))]
    fn note_stranger(&mut self, peer: EndpointId, now: Instant) -> bool {
        let max = tuning::CAP_REFUSAL_COOLDOWN_MAX;
        self.strangers
            .retain(|_, at| now.saturating_duration_since(*at) < max);
        if self.strangers.insert(peer, now).is_none() {
            return true;
        }
        self.note(peer, now);
        false
    }
}

/// Why a negotiation was not admitted. Diagnostic — every arm means "not now".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A round for this peer is already running.
    InFlight,
    /// We already hold a usable session with this peer.
    HaveSession,
    /// This peer refused us at *its* cap recently.
    Cooling,
    /// We evicted this peer lately, and its offer would take the place back.
    Evicted,
    /// The Router is shutting down.
    ShuttingDown,
    /// A test denied this peer: no round with it, offered or answered.
    Denied,
    /// The table of a route edge is at its cap: the units and the rounds in flight reach it, and
    /// nobody is evicted for a newcomer. The offerer waits as for any cap refusal.
    AtCapacity,
}

/// What the table needs from a `WebRTC` hub. A trait so a test can stand in
/// for sessions, which cannot be negotiated inside a unit test.
pub(crate) trait Sessions: Send + Sync + 'static {
    fn has_session(&self, peer: &EndpointId) -> bool;
    /// The peers that hold a live session now.
    fn live_peers(&self) -> Vec<EndpointId>;
    /// End the session of `peer`. `true` if there was one.
    fn detach(&self, peer: &EndpointId) -> bool;
}

impl Sessions for WebRtcHandle {
    fn has_session(&self, peer: &EndpointId) -> bool {
        WebRtcHandle::has_session(self, peer)
    }

    fn live_peers(&self) -> Vec<EndpointId> {
        self.live_peer_ids().collect()
    }

    fn detach(&self, peer: &EndpointId) -> bool {
        WebRtcHandle::detach(self, peer)
    }
}

/// A signalling round holding a peer's negotiation slot.
#[derive(Debug)]
enum Round {
    /// The slot is claimed; the task is not spawned yet.
    Admitted,
    /// The task that holds the slot, which shutdown can cancel.
    Running(AbortHandle),
}

/// Everything held under one peer.
#[derive(Debug)]
struct Slot {
    /// The signalling round that holds the negotiation slot.
    round: Option<Round>,
    /// Every QUIC connection to the peer, whatever its protocol or path.
    conns: Vec<WeakConnectionHandle>,
    /// Which round holds the slot: a guard releases the slot only if its round still does.
    epoch: u64,
    /// The round that holds the slot is an offer of this node, not an answer.
    outgoing: bool,
}

impl Slot {
    fn new() -> Self {
        Self {
            round: None,
            conns: Vec::new(),
            epoch: 0,
            outgoing: false,
        }
    }
}

/// What an eviction ends: the connections, closed with the `EVICTED` code, and the sessions.
#[derive(Default)]
struct Victims {
    conns: Vec<Connection>,
    sessions: Vec<(EndpointId, Arc<dyn Sessions>)>,
}

impl Victims {
    fn end(self) {
        for victim in self.conns {
            tracing::info!(
                target: super::LOG_TARGET,
                peer = %victim.remote_id().fmt_short(),
                "evicting a direct connection at the ceiling"
            );
            victim.close(
                super::webrtc::close_code::EVICTED.into(),
                b"evicted at capacity",
            );
        }
        for (peer, hub) in self.sessions {
            tracing::info!(
                target: super::LOG_TARGET,
                peer = %peer.fmt_short(),
                "evicting a session at the ceiling"
            );
            let _ = hub.detach(&peer);
        }
    }
}

/// How long a pair keeps reading as the gossip rung after the recursion rule closed its gossip
/// connection and no other connection is left to read. The loss of the link, the race for a
/// session and its attach all fit in it.
const RUNG_CLOSE_MEMORY: Duration = Duration::from_secs(15);

struct Inner {
    slots: HashMap<EndpointId, Slot>,
    /// Peers that refused us at their cap, each with its wait.
    refused: RefusalBackoff,
    /// The hub whose sessions the cap counts, learned at the first admission.
    hub: Option<Arc<dyn Sessions>>,
    sampler_running: bool,
    closed: bool,
    /// The direct connections of the node against the ceiling, see [`super::ceiling`].
    ceiling: super::ceiling::Ceiling,
    /// The peers that closed a connection of ours with the `EVICTED` code.
    evicted_by: super::ceiling::EvictionBackoff,
    /// Where an answered session is reported to the event loop, set once the loop has its channel.
    proven_sink: Option<mpsc::UnboundedSender<super::probe::DirectOutcome>>,
    /// Where the relay watch of a dialed gossip link reports to the event loop, set with the sink above.
    path_sink: Option<mpsc::UnboundedSender<super::probe::PathChange>>,
    /// The gossip transport of the endpoint, when the mesh has `gossip`. The table sees every
    /// connection, so it tells the handle which peers are established and which pairs a higher
    /// rung carries (see [`Inner::sync_gossip`]).
    gossip: Option<habilis_network_iroh_gossip_transport::GossipHandle>,
    /// The peers that we evicted. A peer whose session we detach has no connection to read the code
    /// on, so we refuse its offer for the same minute instead.
    we_evicted: super::ceiling::EvictionBackoff,
    /// The peers that a test denied (see [`SignalAdmission::deny`]). Empty in a product build:
    /// only `deny` fills it.
    denied: HashSet<EndpointId>,
    /// When the recursion rule last closed a gossip connection of a peer. The closed connection
    /// leaves the table at once, so this is what keeps the pair reading as the gossip rung while
    /// the event loop handles the loss of the link (see [`SignalAdmission::selected_kind`]).
    closed_on_rung: HashMap<EndpointId, Instant>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Inner")
            .field("peers", &self.slots.len())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl Inner {
    fn slot(&mut self, peer: EndpointId) -> &mut Slot {
        self.slots.entry(peer).or_insert_with(Slot::new)
    }

    fn rounds_in_flight(&self) -> usize {
        self.slots
            .values()
            .filter(|slot| slot.round.is_some())
            .count()
    }

    /// The peers whose session was last used `window` ago or more, each handed back once. The
    /// last use is the one of the ledger, so a session goes a window after its last use, and no
    /// later. A round in flight holds the peer, and so does a live gossip connection: a gossip
    /// neighbor never idles out. A peer that is handed back starts a new window, in case the caller
    /// keeps its session.
    fn take_idle(&mut self, now: Instant, window: Duration) -> Vec<EndpointId> {
        self.sample();
        let Some(hub) = self.hub.clone() else {
            return Vec::new();
        };
        let mut idle = Vec::new();
        for peer in self.ceiling.session_peers() {
            let held = self.slots.get(&peer).is_some_and(|slot| {
                slot.round.is_some()
                    || slot
                        .conns
                        .iter()
                        .filter_map(WeakConnectionHandle::upgrade)
                        .any(|conn| conn.alpn() == iroh_gossip::net::GOSSIP_ALPN)
            });
            if held || !hub.has_session(&peer) {
                continue;
            }
            if self
                .ceiling
                .unused_for(peer, now)
                .is_some_and(|unused| unused >= window)
            {
                self.ceiling.touch(peer, now);
                idle.push(peer);
            }
        }
        idle.sort_unstable();
        idle
    }

    /// The connections and the sessions of the peers that `evictions` names, and the end of
    /// their units in the ledger: the caller ends them once it has dropped the lock.
    fn take_victims(&mut self, evictions: &super::ceiling::Admission) -> Victims {
        let mut victims = Victims::default();
        for peer in &evictions.evict {
            self.ceiling.unregister_quic(*peer);
            self.ceiling.unregister_session(*peer);
            let spread = rand::Rng::random_range(&mut rand::rng(), -1.0..=1.0);
            self.we_evicted.note(*peer, Instant::now(), spread);
            if let Some(hub) = self.hub.as_ref().filter(|hub| hub.has_session(peer)) {
                victims.sessions.push((*peer, Arc::clone(hub)));
            }
            let Some(slot) = self.slots.get(peer) else {
                continue;
            };
            victims.conns.extend(
                slot.conns
                    .iter()
                    .filter_map(WeakConnectionHandle::upgrade)
                    .filter(|conn| {
                        conn.close_reason().is_none() && conn.alpn() == super::UNICAST_ALPN
                    }),
            );
        }
        victims
    }

    /// End the unit of the unicast connections of `peer` in the ledger if it holds none that is
    /// alive.
    fn drop_quic_without_connection(&mut self, peer: EndpointId) {
        let alive = self.slots.get(&peer).is_some_and(|slot| {
            slot.conns
                .iter()
                .filter_map(WeakConnectionHandle::upgrade)
                .any(|conn| conn.close_reason().is_none() && conn.alpn() == super::UNICAST_ALPN)
        });
        if !alive {
            self.ceiling.unregister_quic(peer);
        }
    }

    /// Tell the gossip transport what the table sees, for every peer with a slot: a peer with a
    /// live connection is established, and frames go to a peer only when no higher rung carries
    /// the pair (see [`gossip_view`]). Called when a connection is noted and on every sweep, so
    /// both ids of a pair get it, not only the lower one that has a path watcher. A peer without
    /// a live connection is established no more, and allowed again: a destination that was never
    /// named is allowed, so that a handshake to a new peer is not dropped.
    fn sync_gossip(&self) {
        let Some(gossip) = &self.gossip else {
            return;
        };
        for (peer, slot) in &self.slots {
            let kinds: Vec<super::probe::PathKind> = slot
                .conns
                .iter()
                .filter_map(WeakConnectionHandle::upgrade)
                .filter(|conn| conn.close_reason().is_none())
                .map(|conn| super::probe::selected_kind(&conn))
                .collect();
            let (established, allowed) = gossip_view(&kinds);
            gossip.set_established(*peer, established);
            // A session carries the pair though no connection is left to read: a gossip
            // connection dialed now would be born on the gossip rung and closed by the
            // recursion rule before iroh moves it onto the session. With a live connection its
            // own path decides: a session whose rung is cut carries nothing, and a block would
            // starve the connection that does.
            let carried =
                kinds.is_empty() && self.hub.as_ref().is_some_and(|hub| hub.has_session(peer));
            gossip.allow(*peer, allowed && !carried);
        }
    }

    /// Drop the connections that are gone, and the slots nothing holds.
    fn sample(&mut self) {
        for slot in self.slots.values_mut() {
            slot.conns.retain(|handle| {
                handle
                    .upgrade()
                    .is_some_and(|conn| conn.close_reason().is_none())
            });
        }
        self.sync_gossip();
        let now = Instant::now();
        self.closed_on_rung
            .retain(|_, at| now.saturating_duration_since(*at) < RUNG_CLOSE_MEMORY);
        for peer in self.ceiling.quic_peers() {
            self.drop_quic_without_connection(peer);
        }
        let hub = self.hub.clone();
        if let Some(hub) = &hub {
            let live = hub.live_peers();
            for peer in self.ceiling.session_peers() {
                if !live.contains(&peer) {
                    self.ceiling.unregister_session(peer);
                }
            }
        }
        self.slots.retain(|peer, slot| {
            slot.round.is_some()
                || !slot.conns.is_empty()
                || hub.as_ref().is_some_and(|hub| hub.has_session(peer))
        });
    }
}

/// The one place a direct-peer slot is granted, for both roles.
#[derive(Debug, Clone)]
pub struct SignalAdmission {
    inner: Arc<Mutex<Inner>>,
    cap: usize,
    /// The mesh lets no payload ride the relay, so the hook keeps watch over the
    /// gossip connections that this node dialed (see [`ConnectionHook`]). Set once
    /// the router, which knows the mesh policy, is built.
    watch_dialed_gossip: Arc<AtomicBool>,
    /// Woken when a round ends, offered or answered, so that the event loop can offer the
    /// sessions that the budget kept back (see [`Self::slot_freed`]).
    freed: Arc<tokio::sync::Notify>,
}

impl SignalAdmission {
    /// The table of the sessions of the underlay. A session there is a route edge, not a cache
    /// entry: at the cap it refuses a newcomer and evicts nobody, so a route that other members use
    /// does not end because a node learned of one more. Above the cap a pair has no session and
    /// routes through others.
    #[must_use]
    pub fn new_route_table(cap: usize) -> Self {
        let table = Self::new(cap);
        table.lock().ceiling = super::ceiling::Ceiling::refusing(cap);
        table
    }

    /// How many new rounds the table admits now: the cap less the units and the rounds in flight.
    #[cfg(any(feature = "multihop", test))]
    #[must_use]
    pub(crate) fn room(&self) -> usize {
        let inner = self.lock();
        self.cap
            .saturating_sub(inner.ceiling.units() + inner.rounds_in_flight())
    }

    /// An admission table with a ceiling of `cap` direct connections and none in use.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                slots: HashMap::new(),
                refused: RefusalBackoff::default(),
                hub: None,
                sampler_running: false,
                closed: false,
                ceiling: super::ceiling::Ceiling::new(cap),
                evicted_by: super::ceiling::EvictionBackoff::default(),
                we_evicted: super::ceiling::EvictionBackoff::default(),
                denied: HashSet::new(),
                proven_sink: None,
                path_sink: None,
                gossip: None,
                closed_on_rung: HashMap::new(),
            })),
            cap,
            watch_dialed_gossip: Arc::new(AtomicBool::new(false)),
            freed: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// The cap this table enforces: D, the most `WebRTC` sessions the node holds.
    #[must_use]
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Whether the hook keeps the relay policy on the gossip connections that
    /// this node dials: on when the mesh lets no payload ride the relay.
    pub(crate) fn watch_dialed_gossip(&self, on: bool) {
        self.watch_dialed_gossip.store(on, Ordering::Relaxed);
    }

    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    /// Tests only: whether the hook recorded a live connection to `peer`.
    pub(crate) fn has_live_connection(&self, peer: EndpointId) -> bool {
        self.lock().slots.get(&peer).is_some_and(|slot| {
            slot.conns
                .iter()
                .filter_map(WeakConnectionHandle::upgrade)
                .any(|conn| conn.close_reason().is_none())
        })
    }

    /// The peers whose session nothing has held for `window` (see
    /// [`Inner::take_idle`]). Each is handed back once, and the caller detaches
    /// it.
    pub(crate) fn idle_sessions(&self, now: Instant, window: Duration) -> Vec<EndpointId> {
        self.lock().take_idle(now, window)
    }

    /// The selected path of `peer`, read from the live connections that the hook
    /// recorded for it: the gossip link, the pooled unicast connection, and the inbound
    /// ones. iroh selects a path per connection, so the best of them stands for the pair
    /// (see [`best_kind`](super::probe::best_kind)): a link that is still on the relay
    /// can sit beside one that is already direct. A pair that only gossips has no pooled
    /// connection, and this is how the engine sees it. `None` if the peer has no live
    /// connection with a selected path. On the underlay a peer that has a relay link beside a
    /// session now reads as the session (`[Relay, WebRtc]` reads `WebRtc`), where the first
    /// connection used to decide.
    pub(crate) fn selected_kind(&self, peer: EndpointId) -> Option<super::probe::PathKind> {
        let handles: Vec<WeakConnectionHandle> = self
            .lock()
            .slots
            .get(&peer)
            .map(|slot| slot.conns.clone())
            .unwrap_or_default();
        super::probe::best_kind(
            handles
                .iter()
                .filter_map(WeakConnectionHandle::upgrade)
                .filter(|conn| conn.close_reason().is_none())
                .map(|conn| super::probe::selected_kind(&conn)),
        )
        .or_else(|| self.recently_closed_on_rung(peer))
    }

    /// The recursion rule closed a gossip connection of `peer`: for a while, the pair reads as
    /// the gossip rung though no connection is left to read it from.
    pub(crate) fn note_closed_on_rung(&self, peer: EndpointId) {
        self.lock().closed_on_rung.insert(peer, Instant::now());
    }

    /// The gossip rung, if the recursion rule closed a connection of `peer` lately.
    fn recently_closed_on_rung(&self, peer: EndpointId) -> Option<super::probe::PathKind> {
        let inner = self.lock();
        let at = inner.closed_on_rung.get(&peer)?;
        (Instant::now().saturating_duration_since(*at) < RUNG_CLOSE_MEMORY)
            .then_some(super::probe::PathKind::Gossip)
    }

    /// Whether any live connection of `peer` with a selected path reads below IP: the relay, a
    /// session or a route (see [`any_not_ip`](super::probe::any_not_ip)).
    pub(crate) fn any_connection_not_ip(&self, peer: EndpointId) -> bool {
        let handles: Vec<WeakConnectionHandle> = self
            .lock()
            .slots
            .get(&peer)
            .map(|slot| slot.conns.clone())
            .unwrap_or_default();
        super::probe::any_not_ip(
            handles
                .iter()
                .filter_map(WeakConnectionHandle::upgrade)
                .filter(|conn| conn.close_reason().is_none())
                .map(|conn| super::probe::selected_kind(&conn)),
        )
    }

    /// The endpoint hook that reports every connection to this table. Install
    /// it on the endpoint builder, before bind.
    #[must_use]
    pub fn connection_hook(&self) -> ConnectionHook {
        ConnectionHook {
            admission: self.clone(),
        }
    }

    /// Claim a negotiation slot for `peer`.
    ///
    /// Synchronous by design: the whole decision happens under one lock with
    /// nothing awaited inside, which is what lets in-flight rounds be counted
    /// against the cap without a lock ever crossing a suspension point.
    ///
    /// # Errors
    /// A [`Refusal`] saying which gate closed. All of them are "not now" — none
    /// is a fault, and all but `ShuttingDown` clear on their own.
    pub(crate) fn try_admit<Handle>(
        &self,
        peer: EndpointId,
        handle: &Handle,
    ) -> Result<AdmissionGuard, Refusal>
    where
        Handle: Sessions + Clone,
    {
        self.try_admit_at(peer, handle, Instant::now())
    }

    pub(crate) fn try_admit_at<Handle>(
        &self,
        peer: EndpointId,
        handle: &Handle,
        now: Instant,
    ) -> Result<AdmissionGuard, Refusal>
    where
        Handle: Sessions + Clone,
    {
        self.admit(peer, handle, now, false)
    }

    fn admit<Handle>(
        &self,
        peer: EndpointId,
        handle: &Handle,
        now: Instant,
        outgoing: bool,
    ) -> Result<AdmissionGuard, Refusal>
    where
        Handle: Sessions + Clone,
    {
        let mut inner = self.lock();
        if inner.closed {
            return Err(Refusal::ShuttingDown);
        }
        if inner.denied.contains(&peer) {
            return Err(Refusal::Denied);
        }
        if inner
            .slots
            .get(&peer)
            .is_some_and(|slot| slot.round.is_some())
        {
            return Err(Refusal::InFlight);
        }
        // Nesting the transport's own lock is safe: it is a leaf, with no path
        // back into us.
        if handle.has_session(&peer) {
            return Err(Refusal::HaveSession);
        }
        if inner.refused.on_cooldown(&peer, now) {
            return Err(Refusal::Cooling);
        }
        // Only the offer of the peer: our own offer, from a frame that is held for it, is a send.
        if !outgoing && inner.we_evicted.holds(&peer, now) {
            return Err(Refusal::Evicted);
        }
        if inner.ceiling.refuses()
            && !inner.ceiling.holds(peer)
            && inner.ceiling.units() + inner.rounds_in_flight() >= self.cap
        {
            return Err(Refusal::AtCapacity);
        }
        if inner.hub.is_none() {
            inner.hub = Some(Arc::new(handle.clone()));
        }
        let slot = inner.slot(peer);
        slot.round = Some(Round::Admitted);
        slot.epoch += 1;
        slot.outgoing = outgoing;
        let epoch = slot.epoch;
        drop(inner);
        Ok(AdmissionGuard {
            admission: self.clone(),
            peer,
            epoch,
        })
    }

    /// [`Self::try_admit`] for a round that this node offers, not one that it answers. Only such
    /// a round can be given up for an offer of the peer, see [`Self::preempt_offer`].
    pub(crate) fn try_admit_offer<Handle>(
        &self,
        peer: EndpointId,
        handle: &Handle,
    ) -> Result<AdmissionGuard, Refusal>
    where
        Handle: Sessions + Clone,
    {
        self.try_admit_offer_at(peer, handle, Instant::now())
    }

    fn try_admit_offer_at<Handle>(
        &self,
        peer: EndpointId,
        handle: &Handle,
        now: Instant,
    ) -> Result<AdmissionGuard, Refusal>
    where
        Handle: Sessions + Clone,
    {
        self.admit(peer, handle, now, true)
    }

    /// The peer offers a session while this node's own offer to it runs: give ours up, so that the
    /// peer's offer is answered. Returns whether an offer was given up. A round that answers is
    /// never given up.
    ///
    /// Each round has an epoch, and a guard releases the slot only if its round still holds it.
    /// Without it, the guard of the round that was given up would drop later, and release the slot of
    /// the answer that took its place, so that a third round could start beside the answer.
    pub(crate) fn preempt_offer(&self, peer: EndpointId) -> bool {
        let mut inner = self.lock();
        let Some(slot) = inner
            .slots
            .get_mut(&peer)
            .filter(|slot| slot.outgoing && slot.round.is_some())
        else {
            return false;
        };
        if let Some(Round::Running(abort)) = slot.round.take() {
            abort.abort();
        }
        slot.epoch += 1;
        slot.outgoing = false;
        true
    }

    /// The identity of `peer` has a new holder, or none: a round of this node that was started
    /// against the previous holder cannot find the new one, and holds the slot for the whole round
    /// deadline. End it, so that the next offer is made at once, and forget the wait that the
    /// refusals of the previous holder earned. An aborted round never reaches its error branch, so
    /// this records no wait of its own. Returns whether a round was ended.
    pub(crate) fn cancel_round(&self, peer: EndpointId) -> bool {
        let mut inner = self.lock();
        inner.refused.forget(&peer);
        let Some(slot) = inner
            .slots
            .get_mut(&peer)
            .filter(|slot| slot.round.is_some())
        else {
            return false;
        };
        if let Some(Round::Running(abort)) = slot.round.take() {
            abort.abort();
        }
        slot.epoch += 1;
        slot.outgoing = false;
        drop(inner);
        tracing::debug!(target: super::LOG_TARGET, peer = %peer.fmt_short(), "cancelled the signalling round of a peer whose holder changed");
        self.freed.notify_one();
        true
    }

    /// Record the task holding `peer`'s slot, so shutdown can cancel it.
    ///
    /// Separate from `try_admit` because the slot must be claimed *before* the
    /// task is spawned — that ordering is what bounds the task count — and the
    /// abort handle does not exist until after.
    ///
    /// `epoch` names the round, from [`AdmissionGuard::epoch`]. A round that was given up before
    /// its task was recorded has its task aborted here.
    pub(crate) fn track(&self, peer: EndpointId, epoch: u64, abort: AbortHandle) {
        match self
            .lock()
            .slots
            .get_mut(&peer)
            .filter(|slot| slot.epoch == epoch)
            .and_then(|slot| slot.round.as_mut())
        {
            Some(round) => *round = Round::Running(abort),
            None => abort.abort(),
        }
    }

    /// Note that `peer` refused us at its cap; stop offering for a while, longer
    /// each time in a row.
    pub(crate) fn note_refused(&self, peer: EndpointId) {
        self.lock().refused.note(peer, Instant::now());
    }

    /// Note that the underlay of `peer` turned our offer away as not a neighbor. Whether to offer
    /// again soon: only the first time in a row. A second one waits like a refusal at the cap,
    /// and a success starts the row over.
    #[cfg(any(feature = "multihop", test))]
    pub(crate) fn note_not_a_neighbor(&self, peer: EndpointId) -> bool {
        self.lock().refused.note_stranger(peer, Instant::now())
    }

    /// Forget that peers turned our offers away as not a neighbor, and the wait that a second
    /// turn-away earned: this node just sent its link vector, and the vector is what they lacked.
    #[cfg(any(feature = "multihop", test))]
    pub(crate) fn forget_not_a_neighbor(&self) {
        self.lock().refused.forget_strangers();
    }

    /// A round with `peer` ended in a session: it is no longer refusing us, so
    /// its wait starts over.
    pub(crate) fn note_success(&self, peer: EndpointId) {
        let mut inner = self.lock();
        inner.refused.forget(&peer);
        let evictions = inner.ceiling.register_session(peer, Instant::now());
        let victims = inner.take_victims(&evictions);
        drop(inner);
        victims.end();
    }

    /// Drop the wait that `peer`'s refusals earned, because the peer at that
    /// address is not the one that refused: a new holder of the rendezvous id.
    pub(crate) fn forget_refusal(&self, peer: EndpointId) {
        self.lock().refused.forget(&peer);
    }

    /// Cancel every round in flight and refuse all later admissions.
    ///
    /// Called from `ProtocolHandler::shutdown`, which the Router awaits before
    /// closing the endpoint — so aborting rather than draining is the right
    /// semantic: an in-flight negotiation has nothing left to attach to.
    ///
    /// Each aborted task drops its `AdmissionGuard`, which is what empties the
    /// table; nothing here removes entries itself.
    pub(crate) fn close(&self) {
        let mut inner = self.lock();
        inner.closed = true;
        for slot in inner.slots.values() {
            if let Some(Round::Running(abort)) = &slot.round {
                abort.abort();
            }
        }
    }

    /// Whether a round with `peer` holds a slot right now, in either role.
    pub(crate) fn negotiating(&self, peer: EndpointId) -> bool {
        self.lock()
            .slots
            .get(&peer)
            .is_some_and(|slot| slot.round.is_some())
    }

    /// Woken once, with a stored permit, after any round ended: several ends in a row wake it
    /// once, and the pass that follows spends the whole budget that they freed, so one wake is
    /// enough. The end of a round that failed counts as much as one that attached, and no
    /// `DirectOutcome` is sent for it, because a verdict of `direct: false` would mark a lane peer
    /// relay-only.
    pub(crate) fn slot_freed(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.freed)
    }

    fn release(&self, peer: EndpointId, epoch: u64) {
        let ended = self
            .lock()
            .slots
            .get_mut(&peer)
            .filter(|slot| slot.epoch == epoch)
            .map(|slot| slot.round = None)
            .is_some();
        if ended {
            self.freed.notify_one();
        }
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.lock().rounds_in_flight()
    }

    /// Put a connection under its peer, and start the sampler if it is not
    /// running.
    fn note_connection(&self, conn: &Connection) {
        let peer = conn.remote_id();
        let handle = conn.weak_handle();
        let mut inner = self.lock();
        if inner.closed {
            return;
        }
        inner.slot(peer).conns.push(handle);
        inner.sync_gossip();
        let evictions = if conn.alpn() == super::UNICAST_ALPN {
            inner.ceiling.register_quic(peer, Instant::now())
        } else {
            super::ceiling::Admission::default()
        };
        let victims = inner.take_victims(&evictions);
        if !inner.sampler_running {
            inner.sampler_running = true;
            spawn_sampler(Arc::downgrade(&self.inner), tuning::SLOT_SWEEP);
        }
        drop(inner);
        if conn.alpn() == super::UNICAST_ALPN {
            self.watch_for_eviction(conn.clone());
        }
        victims.end();
    }

    /// When `conn` closes, whatever the reason, the peer leaves the ledger unless it holds another
    /// unicast connection: a unit ends with its last connection. When the peer closes it with the
    /// `EVICTED` code, note that too, so that no proactive dial goes back to that peer for a while.
    fn watch_for_eviction(&self, conn: Connection) {
        let admission = self.clone();
        n0_future::task::spawn(async move {
            let reason = conn.closed().await;
            let peer = conn.remote_id();
            let mut inner = admission.lock();
            inner.drop_quic_without_connection(peer);
            if let iroh::endpoint::ConnectionError::ApplicationClosed(close) = reason
                && close.error_code.into_inner() == u64::from(super::webrtc::close_code::EVICTED)
            {
                let spread = rand::Rng::random_range(&mut rand::rng(), -1.0..=1.0);
                inner.evicted_by.note(peer, Instant::now(), spread);
            }
        });
    }

    /// A send or a stream is in flight on the connection of `peer`: the ledger does not
    /// evict it until the guard is dropped.
    pub(crate) fn busy(&self, peer: EndpointId) -> BusyGuard {
        self.lock().ceiling.busy_begin(peer);
        BusyGuard {
            admission: self.clone(),
            peer,
        }
    }

    /// When the ledger last saw `peer` used, for a test.
    #[cfg(test)]
    pub(crate) fn last_use(&self, peer: EndpointId) -> Option<Instant> {
        self.lock().ceiling.last_use(peer)
    }

    /// Whether a send or a stream is in flight on `peer`, for a test.
    #[cfg(test)]
    pub(crate) fn is_busy(&self, peer: EndpointId) -> bool {
        self.lock()
            .ceiling
            .unused_for(peer, Instant::now())
            .is_none()
    }

    /// Note an eviction by `peer`, for a test that does not run the eviction.
    #[cfg(test)]
    pub(crate) fn note_evicted(&self, peer: EndpointId) {
        self.lock().evicted_by.note(peer, Instant::now(), 0.0);
    }

    /// Tests only: refuse every round with `peer`, the ones this node offers and the ones it
    /// answers, or lift the refusal. A test uses it to keep two members from forming a direct
    /// session, so that their traffic has to take the multihop route. A test that keeps a pair
    /// apart denies each member on the other's node: the refusal is one-sided.
    #[cfg(any(test, feature = "iroh-test-utils"))]
    pub(crate) fn deny(&self, peer: EndpointId, denied: bool) {
        let mut inner = self.lock();
        if denied {
            inner.denied.insert(peer);
        } else {
            inner.denied.remove(&peer);
        }
    }

    /// Whether a test denied `peer`. The underlay tick reads it, so it exists where the
    /// underlay does.
    #[cfg(any(feature = "multihop", test))]
    pub(crate) fn is_denied(&self, peer: EndpointId) -> bool {
        self.lock().denied.contains(&peer)
    }

    /// Whether `peer` evicted our connection lately, so that no proactive dial goes to it.
    pub(crate) fn evicted_recently(&self, peer: EndpointId) -> bool {
        self.lock().evicted_by.holds(&peer, Instant::now())
    }

    /// The gossip neighbors changed. A session counts only while its peer is not one, so a
    /// peer that stops being a neighbor can take the ceiling over.
    pub(crate) fn set_neighbors(&self, neighbors: &HashSet<EndpointId>) {
        let mut inner = self.lock();
        let evictions = inner.ceiling.set_neighbors(neighbors, Instant::now());
        let victims = inner.take_victims(&evictions);
        drop(inner);
        victims.end();
    }

    /// The gossip transport of this endpoint, kept by the table so that it can tell the transport
    /// which peers are established and which pairs a higher rung carries.
    pub(crate) fn set_gossip(&self, handle: habilis_network_iroh_gossip_transport::GossipHandle) {
        self.lock().gossip = Some(handle);
    }

    /// The gossip transport that [`set_gossip`](Self::set_gossip) set, if the mesh has gossip.
    pub(crate) fn gossip_handle(
        &self,
    ) -> Option<habilis_network_iroh_gossip_transport::GossipHandle> {
        self.lock().gossip.clone()
    }

    /// [`Inner::sync_gossip`], now. The sweep and every new connection do it too.
    pub(crate) fn sync_gossip(&self) {
        self.lock().sync_gossip();
    }

    /// The event loop's channel for the sessions that this node answered.
    pub(crate) fn set_proven_sink(&self, sink: mpsc::UnboundedSender<super::probe::DirectOutcome>) {
        self.lock().proven_sink = Some(sink);
    }

    /// The event loop's channel for the dialed gossip links that left a direct path.
    pub(crate) fn set_path_sink(&self, sink: mpsc::UnboundedSender<super::probe::PathChange>) {
        self.lock().path_sink = Some(sink);
    }

    fn path_sink(&self) -> Option<mpsc::UnboundedSender<super::probe::PathChange>> {
        self.lock().path_sink.clone()
    }

    /// A session to `peer` attached on the answering side. The loop flushes the frames held for the
    /// peer, if there are any: the offering side does the same on its own attach.
    pub(crate) fn report_answered(&self, peer: EndpointId) {
        if let Some(sink) = &self.lock().proven_sink {
            let _ = sink.send(super::probe::DirectOutcome {
                peer,
                direct: true,
                answered: true,
            });
        }
    }

    /// How many peers the node holds a direct connection to, against the ceiling.
    pub(crate) fn direct_units(&self) -> usize {
        self.lock().ceiling.units()
    }

    /// How many direct connections the node is over its ceiling by, because every other
    /// candidate was busy when a newcomer came.
    pub(crate) fn over_ceiling(&self) -> usize {
        self.lock().ceiling.over_ceiling()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("signal admission poisoned")
    }
}

/// Marks a connection busy for as long as it lives.
#[derive(Debug)]
#[must_use = "dropping the guard ends the busy mark"]
pub(crate) struct BusyGuard {
    admission: SignalAdmission,
    peer: EndpointId,
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.admission
            .lock()
            .ceiling
            .busy_end(self.peer, Instant::now());
    }
}

/// Pure: what the table tells the gossip transport about a peer whose live connections read as
/// `kinds`: whether it is established (any live connection, on any protocol) and whether frames
/// may go to it (no higher rung carries the pair: see
/// [`allow_for`](super::probe::allow_for), read on the best of the connections). A peer with no
/// connection is not established and is allowed.
///
/// Two ends of one pair may disagree for one sweep, and a multihop path that is dead stays
/// selected until noq abandons it (15 s), so gossip is blocked for that long.
fn gossip_view(kinds: &[super::probe::PathKind]) -> (bool, bool) {
    let best = super::probe::best_kind(kinds.iter().copied());
    (!kinds.is_empty(), best.is_none_or(super::probe::allow_for))
}

/// One timer for the whole table, ending with it.
fn spawn_sampler(table: Weak<Mutex<Inner>>, period: Duration) {
    n0_future::task::spawn(async move {
        loop {
            n0_future::time::sleep(period).await;
            let Some(table) = table.upgrade() else {
                return;
            };
            let mut inner = table.lock().expect("signal admission poisoned");
            if inner.closed {
                return;
            }
            inner.sample();
        }
    });
}

/// Reports every connection of the endpoint it is installed on, in or out and
/// on any protocol, to its [`SignalAdmission`], which keeps them under their
/// peer so that it can close and prune them. It also watches the gossip
/// connections this node dials for the relay policy.
#[derive(Debug, Clone)]
pub struct ConnectionHook {
    admission: SignalAdmission,
}

impl EndpointHooks for ConnectionHook {
    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        self.admission.note_connection(conn);
        // A gossip connection on the gossip rung would carry the gossip that its frames need:
        // both ends close it, whatever the mesh policy says, and before the relay watch, which is
        // policy-gated.
        if conn.alpn() == iroh_gossip::net::GOSSIP_ALPN {
            super::payload_path::watch_gossip_recursion(conn, self.admission.clone());
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            super::payload_path::track_gossip_conn(conn);
        }
        // The accept side watches the gossip connections it holds
        // (`DirectOnlyGossip::accept`). iroh-gossip dials its own, so the
        // watch for those starts here, with the same rule.
        if conn.side().is_client()
            && self.admission.watch_dialed_gossip.load(Ordering::Relaxed)
            && conn.alpn() == iroh_gossip::net::GOSSIP_ALPN
        {
            super::direct_only_gossip::watch_relay_policy(conn, self.admission.path_sink());
        }
        AfterHandshakeOutcome::accept()
    }
}

/// Holds a peer's negotiation slot for as long as the round runs.
///
/// Released on `Drop`, not on a `return`. That is the whole point: a round can
/// end by being aborted — Router shutdown, a dropped future — and a release
/// written as a statement at the end of the task never runs on that path.
#[derive(Debug)]
#[must_use = "dropping the guard releases the peer's negotiation slot"]
pub(crate) struct AdmissionGuard {
    admission: SignalAdmission,
    peer: EndpointId,
    epoch: u64,
}

impl AdmissionGuard {
    /// Which round of the peer this guard holds.
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        self.admission.release(self.peer, self.epoch);
    }
}

// Host-only: the browser hub is a different type, and these need a tokio
// runtime for the abort test. The logic under test is target-independent.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use habilis_network_test_tracing::test;
    use std::collections::HashSet;

    use habilis_network_iroh_webrtc_transport::{WebRtcHandle, WebRtcTransport};

    #[cfg(feature = "iroh-test-utils")]
    use super::ConnectionHook;
    use super::{
        Arc, Connection, Duration, EndpointId, Instant, Mutex, Refusal, RefusalBackoff, Sessions,
        SignalAdmission, gossip_view, tuning,
    };
    #[cfg(feature = "iroh-test-utils")]
    use crate::lookup::test_relay;
    use crate::transport::payload_path;
    use iroh::endpoint::presets;
    #[cfg(feature = "iroh-test-utils")]
    use tokio::sync::mpsc;
    use tokio::sync::oneshot;
    fn peer(byte: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[byte; 32]).public()
    }

    /// The first turn-away as not a neighbor in a row is a race that the next offer wins, so the
    /// peer is offered again at once; a second one in a row is a refusal and waits.
    #[test]
    fn two_turn_aways_in_a_row_make_the_peer_wait_and_one_does_not() {
        let admission = SignalAdmission::new(4);
        let stranger = peer(31);
        assert!(
            admission.note_not_a_neighbor(stranger),
            "the first one: offer again soon"
        );
        assert!(
            !admission
                .lock()
                .refused
                .on_cooldown(&stranger, Instant::now()),
            "one turn-away does not make the peer wait"
        );
        assert!(
            !admission.note_not_a_neighbor(stranger),
            "the second one in a row: wait"
        );
        assert!(
            admission
                .lock()
                .refused
                .on_cooldown(&stranger, Instant::now()),
            "two in a row do"
        );
    }

    #[test]
    fn a_session_with_the_peer_starts_the_row_of_turn_aways_over() {
        let admission = SignalAdmission::new(4);
        let stranger = peer(32);
        assert!(admission.note_not_a_neighbor(stranger));
        admission.note_success(stranger);
        assert!(
            admission.note_not_a_neighbor(stranger),
            "after a success the first one is a first one again"
        );
    }

    /// A vector that this node sends is what a peer that turned its offer away lacked: the wait
    /// that two turn-aways in a row earned ends with it, and the next one is a first again.
    #[test]
    fn a_vector_that_this_node_sent_ends_the_wait_that_two_turn_aways_earned() {
        let admission = SignalAdmission::new(4);
        let stranger = peer(33);
        assert!(admission.note_not_a_neighbor(stranger));
        assert!(!admission.note_not_a_neighbor(stranger));
        assert!(
            admission
                .lock()
                .refused
                .on_cooldown(&stranger, Instant::now()),
            "two in a row wait"
        );

        admission.forget_not_a_neighbor();
        assert!(
            !admission
                .lock()
                .refused
                .on_cooldown(&stranger, Instant::now()),
            "a vector sent ends the wait"
        );
        assert!(
            admission.note_not_a_neighbor(stranger),
            "and the next turn-away is a first one again"
        );
    }

    /// The end of a round wakes the waiter of `slot_freed`, however the round ended, and a round
    /// that was given up for the offer of the peer does not: its guard no longer holds the slot.
    #[test]
    async fn the_end_of_a_round_wakes_the_waiter_of_slot_freed() {
        let admission = SignalAdmission::new(4);
        let freed = admission.slot_freed();
        let guard = admission
            .try_admit_offer(peer(1), &hub())
            .expect("a free slot");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), freed.notified())
                .await
                .is_err(),
            "a round in flight wakes nobody"
        );

        drop(guard);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), freed.notified())
                .await
                .is_ok(),
            "the end of the round wakes the waiter"
        );
    }

    /// An empty hub: `has_session` is always false and `session_count` is 0, so
    /// these tests exercise the admission logic and nothing else.
    fn hub() -> WebRtcHandle {
        WebRtcHandle::new(WebRtcTransport::new(peer(0)))
    }

    /// A round that was started while the identity had no holder never finds the holder that comes
    /// later, and held the slot for the whole round deadline: every later offer was refused
    /// `InFlight`. Cancelling the round frees the slot, and the refusals of the old holder are forgotten.
    #[test]
    async fn a_cancelled_round_frees_the_slot_and_forgets_the_refusals() {
        let admission = SignalAdmission::new(4);
        let hub = hub();
        let guard = admission.try_admit(peer(1), &hub).expect("a free slot");
        let epoch = guard.epoch();
        let task = n0_future::task::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        admission.track(peer(1), epoch, task.abort_handle());
        admission.note_refused(peer(1));
        assert!(matches!(
            admission.try_admit(peer(1), &hub),
            Err(Refusal::InFlight)
        ));

        assert!(admission.cancel_round(peer(1)), "a round was ended");

        assert!(
            admission.try_admit(peer(1), &hub).is_ok(),
            "the slot is free and the old refusals are gone"
        );
    }

    #[test]
    fn a_denied_peer_is_admitted_in_neither_role() {
        let admission = SignalAdmission::new(16);
        let hub = hub();
        admission.deny(peer(1), true);
        assert!(matches!(
            admission.try_admit(peer(1), &hub),
            Err(Refusal::Denied)
        ));
        assert!(matches!(
            admission.try_admit_offer(peer(1), &hub),
            Err(Refusal::Denied)
        ));
        assert!(admission.is_denied(peer(1)));
    }

    /// A guard, not a red test: it cannot fail on a stub that denies nothing. It keeps `deny` from
    /// denying more than the peer it names, and `deny(false)` from leaving the peer denied.
    #[test]
    fn a_deny_leaves_the_other_peers_alone_and_can_be_lifted() {
        let admission = SignalAdmission::new(16);
        let hub = hub();
        admission.deny(peer(1), true);
        assert!(admission.try_admit(peer(2), &hub).is_ok());
        admission.deny(peer(1), false);
        assert!(!admission.is_denied(peer(1)));
        assert!(admission.try_admit(peer(1), &hub).is_ok());
    }

    #[test]
    fn a_peer_being_dialled_is_refused_a_second_slot() {
        let admission = SignalAdmission::new(16);
        let hub = hub();
        let _guard = admission.try_admit(peer(1), &hub).expect("first admit");
        assert_eq!(
            admission.try_admit(peer(1), &hub).unwrap_err(),
            Refusal::InFlight
        );
    }

    #[test]
    fn dropping_the_guard_releases_the_slot() {
        let admission = SignalAdmission::new(16);
        let hub = hub();
        drop(admission.try_admit(peer(1), &hub).expect("first admit"));
        assert_eq!(admission.in_flight(), 0);
        assert!(admission.try_admit(peer(1), &hub).is_ok());
    }

    /// Rounds in flight are not a count against a cap: the ceiling acts when a session
    /// attaches, so the retry tick may admit a round for every peer.
    #[test]
    fn rounds_in_flight_are_not_refused_by_a_ceiling() {
        let admission = SignalAdmission::new(2);
        let hub = hub();
        let _one = admission.try_admit(peer(1), &hub).expect("first admit");
        let _two = admission.try_admit(peer(2), &hub).expect("second admit");
        assert!(admission.try_admit(peer(3), &hub).is_ok());
    }

    /// The table of the underlay is a route table: at its cap it refuses and evicts nobody.
    #[test]
    fn a_route_table_refuses_at_its_cap_and_evicts_nobody() {
        let admission = SignalAdmission::new_route_table(2);
        let hub = hub();
        assert_eq!(admission.room(), 2);
        let one = admission.try_admit(peer(1), &hub).expect("first admit");
        let two = admission.try_admit(peer(2), &hub).expect("second admit");
        assert_eq!(admission.room(), 0, "the rounds in flight count");
        assert_eq!(
            admission.try_admit(peer(3), &hub).unwrap_err(),
            Refusal::AtCapacity
        );
        // The first round ends in a session: its unit counts, and the third peer is still refused.
        admission.note_success(peer(1));
        drop(one);
        assert_eq!(admission.room(), 0, "one unit and one round in flight");
        assert_eq!(
            admission.try_admit(peer(3), &hub).unwrap_err(),
            Refusal::AtCapacity
        );
        // The second round fails: its room is free again, and nobody was evicted.
        drop(two);
        assert_eq!(admission.room(), 1);
        let _three = admission.try_admit(peer(3), &hub).expect("room again");
        assert_eq!(
            admission.try_admit(peer(4), &hub).unwrap_err(),
            Refusal::AtCapacity
        );
        assert_eq!(admission.direct_units(), 1, "nothing was evicted");
    }

    #[test]
    fn a_peer_that_refused_at_its_cap_is_left_alone() {
        let admission = SignalAdmission::new(16);
        let hub = hub();
        admission.note_refused(peer(1));
        assert_eq!(
            admission.try_admit(peer(1), &hub).unwrap_err(),
            Refusal::Cooling
        );
        // Unrelated peers are unaffected.
        assert!(admission.try_admit(peer(2), &hub).is_ok());
    }

    #[test]
    fn close_refuses_everything_afterwards() {
        let admission = SignalAdmission::new(16);
        let hub = hub();
        admission.close();
        assert_eq!(
            admission.try_admit(peer(1), &hub).unwrap_err(),
            Refusal::ShuttingDown
        );
    }

    /// The permanent-pin bug, under test: a task that is aborted rather than
    /// returning must still give its slot back.
    #[test]
    async fn aborting_the_task_releases_the_slot() {
        let admission = SignalAdmission::new(16);
        let hub = hub();
        let guard = admission.try_admit(peer(1), &hub).expect("admit");
        let epoch = guard.epoch();

        let task = n0_future::task::spawn(async move {
            let _guard = guard;
            // Never returns on its own — only an abort ends this.
            std::future::pending::<()>().await;
        });
        admission.track(peer(1), epoch, task.abort_handle());
        assert_eq!(admission.in_flight(), 1);

        admission.close();
        // Let the aborted task's drop glue run.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(
            admission.in_flight(),
            0,
            "an aborted round must release its slot"
        );
    }

    /// Sessions a test can hold without a negotiation. Clones share the set.
    #[derive(Debug, Clone, Default)]
    struct FakeHub(Arc<Mutex<HashSet<EndpointId>>>);

    impl FakeHub {
        fn attach(&self, peer: EndpointId) {
            self.0.lock().expect("fake hub").insert(peer);
        }

        fn detach(&self, peer: &EndpointId) {
            self.0.lock().expect("fake hub").remove(peer);
        }
    }

    impl Sessions for FakeHub {
        fn has_session(&self, peer: &EndpointId) -> bool {
            self.0.lock().expect("fake hub").contains(peer)
        }

        fn live_peers(&self) -> Vec<EndpointId> {
            self.0.lock().expect("fake hub").iter().copied().collect()
        }

        fn detach(&self, peer: &EndpointId) -> bool {
            self.0.lock().expect("fake hub").remove(peer)
        }
    }

    /// **Sessions count against the ceiling, and none is refused for it.** At a ceiling of 2, a
    /// third session is admitted, and the least recently used of the first two is detached.
    #[test]
    fn a_third_session_at_a_ceiling_of_two_detaches_the_least_recently_used() {
        let admission = SignalAdmission::new(2);
        let hub = FakeHub::default();
        for byte in [1, 2, 3] {
            drop(
                admission
                    .try_admit(peer(byte), &hub)
                    .expect("the ceiling refuses no session"),
            );
            hub.attach(peer(byte));
            admission.note_success(peer(byte));
        }

        assert!(!hub.has_session(&peer(1)), "the least recently used goes");
        assert!(hub.has_session(&peer(2)) && hub.has_session(&peer(3)));
        assert_eq!(admission.direct_units(), 2);
    }

    /// The ledger of the underlay leg has G as its ceiling, and the leg holds a session only
    /// to a gossip neighbor, so at most G. Up to G sessions, nothing is evicted.
    #[test]
    fn a_ledger_with_g_as_its_ceiling_never_evicts_while_the_sessions_stay_within_g() {
        let ceiling = 4;
        let admission = SignalAdmission::new(ceiling);
        let hub = FakeHub::default();
        for byte in 1..=4 {
            drop(admission.try_admit(peer(byte), &hub).expect("admit"));
            hub.attach(peer(byte));
            admission.note_success(peer(byte));
        }
        admission.note_success(peer(2));
        admission.lock().sample();

        assert_eq!(hub.live_peers().len(), ceiling, "every session stays");
        assert_eq!(admission.direct_units(), ceiling);
        assert_eq!(admission.over_ceiling(), 0);
    }

    /// Glare: our offer to a peer is given up for the offer of that peer. The guard of the offer
    /// that was given up must not release the round that took its place.
    #[test]
    fn a_preempted_offer_does_not_release_the_round_that_replaced_it() {
        let admission = SignalAdmission::new(8);
        let hub = FakeHub::default();
        let offer = admission.try_admit_offer(peer(1), &hub).expect("offer");
        assert!(admission.preempt_offer(peer(1)), "our offer is given up");
        assert_eq!(admission.in_flight(), 0);

        let answer = admission
            .try_admit(peer(1), &hub)
            .expect("the peer's offer");
        drop(offer);
        assert_eq!(admission.in_flight(), 1, "the answer keeps its slot");
        drop(answer);
        assert_eq!(admission.in_flight(), 0);
    }

    /// A round that answers an offer is never given up for another offer of the same peer.
    #[test]
    fn a_round_that_answers_is_not_preempted() {
        let admission = SignalAdmission::new(8);
        let hub = FakeHub::default();
        let _answer = admission.try_admit(peer(1), &hub).expect("answer");
        assert!(!admission.preempt_offer(peer(1)));
        assert_eq!(admission.in_flight(), 1);
        assert_eq!(
            admission.try_admit(peer(1), &hub).unwrap_err(),
            Refusal::InFlight
        );
    }

    /// A peer that holds no unicast connection has no way to read the `EVICTED` code when its
    /// session is detached. The evictor remembers the peer for the same minute instead, and refuses
    /// its offer, so that two peers at the ceiling do not offer sessions back and forth.
    #[test]
    fn a_peer_whose_session_was_evicted_is_refused_for_a_minute_and_answered_after() {
        let admission = SignalAdmission::new(1);
        let hub = FakeHub::default();
        for byte in [1, 2] {
            drop(admission.try_admit(peer(byte), &hub).expect("admit"));
            hub.attach(peer(byte));
            admission.note_success(peer(byte));
        }
        assert!(!hub.has_session(&peer(1)), "the first session was evicted");
        let now = Instant::now();

        assert_eq!(
            admission
                .try_admit_at(peer(1), &hub, now + Duration::from_secs(30))
                .unwrap_err(),
            Refusal::Evicted,
            "its offer within the minute"
        );
        assert!(
            admission
                .try_admit_offer_at(peer(1), &hub, now + Duration::from_secs(30))
                .is_ok(),
            "our own offer to it is not refused by this"
        );
        assert!(
            admission
                .try_admit_at(peer(1), &hub, now + Duration::from_secs(90))
                .is_ok(),
            "its offer after the minute"
        );
    }

    #[test]
    fn a_slot_nothing_holds_is_dropped() {
        let admission = SignalAdmission::new(2);
        let hub = FakeHub::default();
        for byte in [1, 2] {
            drop(admission.try_admit(peer(byte), &hub).expect("room"));
            hub.attach(peer(byte));
        }
        hub.detach(&peer(1));
        hub.detach(&peer(2));

        admission.lock().sample();

        assert!(admission.lock().slots.is_empty());
    }

    /// A session that nobody used for the window is idle, and is handed back once it has been
    /// unused for the whole window, not before.
    #[test]
    fn a_session_nothing_uses_idles_out_after_the_window() {
        let admission = SignalAdmission::new(4);
        let hub = FakeHub::default();
        drop(admission.try_admit(peer(1), &hub).expect("room"));
        hub.attach(peer(1));
        admission.note_success(peer(1));
        let window = tuning::DIRECT_IDLE_BACKSTOP;
        let start = Instant::now();

        let mut inner = admission.lock();
        assert!(inner.take_idle(start, window).is_empty(), "just used");
        assert!(
            inner
                .take_idle(
                    start + window.saturating_sub(Duration::from_secs(1)),
                    window
                )
                .is_empty(),
            "one second short of the window"
        );
        assert_eq!(inner.take_idle(start + window, window), vec![peer(1)]);
        assert!(
            inner.take_idle(start + window, window).is_empty(),
            "handed back once"
        );
    }

    /// One source of truth for idle: the ledger's last use. A session goes a window after the last
    /// use of its peer, not a window after the first look of the sweep, and not a window after
    /// its connection closed, which would add a second window to the idle close of the connection.
    #[test]
    fn a_session_idles_out_a_window_after_its_last_use_not_after_the_first_look() {
        let admission = SignalAdmission::new(4);
        let hub = FakeHub::default();
        drop(admission.try_admit(peer(1), &hub).expect("room"));
        hub.attach(peer(1));
        admission.note_success(peer(1));
        let window = tuning::DIRECT_IDLE_BACKSTOP;
        let start = Instant::now();

        let mut inner = admission.lock();
        assert!(
            inner.take_idle(start + window / 2, window).is_empty(),
            "half a window after the last use"
        );
        assert_eq!(
            inner.take_idle(start + window, window),
            vec![peer(1)],
            "a window after the last use, not a window after the first look"
        );
    }

    /// A round in flight holds the peer: its session is not idle however long
    /// the round runs.
    #[test]
    fn a_round_in_flight_keeps_a_session_from_idling() {
        let admission = SignalAdmission::new(4);
        let hub = FakeHub::default();
        let _guard = admission.try_admit(peer(1), &hub).expect("room");
        hub.attach(peer(1));
        admission.note_success(peer(1));
        let window = tuning::DIRECT_IDLE_BACKSTOP;
        let start = Instant::now();

        let mut inner = admission.lock();
        assert!(inner.take_idle(start, window).is_empty());
        assert!(inner.take_idle(start + window * 3, window).is_empty());
    }

    /// Only a peer with a session can idle out.
    #[test]
    fn a_peer_with_no_session_is_never_idle() {
        let admission = SignalAdmission::new(4);
        let hub = FakeHub::default();
        drop(admission.try_admit(peer(1), &hub).expect("room"));
        let window = tuning::DIRECT_IDLE_BACKSTOP;
        let start = Instant::now();

        let mut inner = admission.lock();
        assert!(inner.take_idle(start, window).is_empty());
        assert!(inner.take_idle(start + window * 3, window).is_empty());
    }

    /// The wait after a refusal doubles with each one in a row, stops at the
    /// longest, and starts over once the peer has taken a round.
    #[test]
    fn the_wait_after_a_refusal_doubles_up_to_the_longest_and_a_success_resets_it() {
        let mut backoff = RefusalBackoff::default();
        let bob = peer(1);
        let start = Instant::now();
        let first = tuning::CAP_REFUSAL_COOLDOWN;
        let longest = tuning::CAP_REFUSAL_COOLDOWN_MAX;

        backoff.note(bob, start);
        assert!(backoff.on_cooldown(&bob, start + first.saturating_sub(Duration::from_secs(1))));
        assert!(!backoff.on_cooldown(&bob, start + first));

        let mut now = start + first;
        let mut window = first;
        while window < longest {
            backoff.note(bob, now);
            window = (window * 2).min(longest);
            assert!(
                backoff.on_cooldown(&bob, now + window / 2),
                "still waiting inside {window:?}"
            );
            assert!(
                !backoff.on_cooldown(&bob, now + window),
                "done after {window:?}"
            );
            now += window;
        }
        assert_eq!(window, longest);

        backoff.note(bob, now);
        assert!(
            !backoff.on_cooldown(&bob, now + longest),
            "the wait does not grow past the longest"
        );

        backoff.forget(&bob);
        backoff.note(bob, now);
        assert!(
            !backoff.on_cooldown(&bob, now + first),
            "a success started the wait over at the first"
        );
    }

    /// One peer's refusals do not make another peer wait.
    #[test]
    fn a_refusal_makes_only_that_peer_wait() {
        let mut backoff = RefusalBackoff::default();
        let now = Instant::now();
        backoff.note(peer(1), now);
        assert!(backoff.on_cooldown(&peer(1), now));
        assert!(!backoff.on_cooldown(&peer(2), now));
    }

    /// A live gossip connection to the peer holds its session: a gossip neighbor never idles out.
    /// Once the connection is gone, the session is idle a window after its last use, with no second
    /// window added for the connection.
    #[cfg(feature = "iroh-test-utils")]
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_connection_holds_a_session_until_it_closes() {
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                conn.closed().await;
                Ok(())
            }
        }
        let (relay_url, _relay_server) = test_relay::spawn_plain().await.expect("local relay");
        let bind = |hook: Option<ConnectionHook>| {
            let relay_url = relay_url.clone();
            async move {
                let mut builder = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::custom([relay_url]))
                    .clear_ip_transports();
                if let Some(hook) = hook {
                    builder = builder.hooks(hook);
                }
                builder.bind().await.expect("bind an endpoint on the relay")
            }
        };
        let admission = SignalAdmission::new(2);
        let hub = FakeHub::default();
        let server = bind(None).await;
        let router = Router::builder(server.clone())
            .accept(iroh_gossip::net::GOSSIP_ALPN, Hold)
            .spawn();
        let client = bind(Some(admission.connection_hook())).await;
        let neighbor = server.id();
        drop(admission.try_admit(neighbor, &hub).expect("room"));
        hub.attach(neighbor);
        admission.note_success(neighbor);
        let relayed = iroh::EndpointAddr::new(neighbor).with_relay_url(relay_url.clone());
        let conn = client
            .connect(relayed, iroh_gossip::net::GOSSIP_ALPN)
            .await
            .expect("dial over the relay");
        let window = tuning::DIRECT_IDLE_BACKSTOP;
        let start = Instant::now();

        assert!(admission.lock().take_idle(start, window).is_empty());
        assert!(
            admission
                .lock()
                .take_idle(start + window * 3, window)
                .is_empty(),
            "a live connection holds the session"
        );

        conn.close(0u32.into(), b"done");
        conn.closed().await;
        let later = start + window * 3;
        assert_eq!(
            admission.lock().take_idle(later, window),
            vec![neighbor],
            "a window after the last use, whatever the connection did"
        );
        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// The accept side watches every gossip connection it holds, so one that
    /// stays on the relay is closed. A connection that this node dialed needs
    /// the same watch, or a link can stay up on the relay for ever while its
    /// other end believes the policy keeps it off.
    #[cfg(feature = "iroh-test-utils")]
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gossip_connection_this_node_dialed_is_closed_when_it_stays_on_the_relay() {
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                conn.closed().await;
                Ok(())
            }
        }
        let (relay_url, _relay_server) = test_relay::spawn_plain().await.expect("local relay");
        let bind = |hook: Option<ConnectionHook>| {
            let relay_url = relay_url.clone();
            async move {
                let mut builder = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::custom([relay_url]))
                    .clear_ip_transports();
                if let Some(hook) = hook {
                    builder = builder.hooks(hook);
                }
                builder.bind().await.expect("bind an endpoint on the relay")
            }
        };
        let admission = SignalAdmission::new(2);
        admission.watch_dialed_gossip(true);
        let server = bind(None).await;
        let router = Router::builder(server.clone())
            .accept(iroh_gossip::net::GOSSIP_ALPN, Hold)
            .spawn();
        let client = bind(Some(admission.connection_hook())).await;
        let relayed = iroh::EndpointAddr::new(server.id()).with_relay_url(relay_url.clone());
        let conn = client
            .connect(relayed, iroh_gossip::net::GOSSIP_ALPN)
            .await
            .expect("dial over the relay");

        let closed = tokio::time::timeout(Duration::from_secs(25), conn.closed()).await;

        assert!(
            closed.is_ok(),
            "a dialed gossip connection left on the relay must be closed after the deadline"
        );
        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// A node with an admission table at ceiling `cap`, and servers that report how
    /// each of its connections ended.
    #[cfg(feature = "iroh-test-utils")]
    struct Fixture {
        admission: SignalAdmission,
        node: iroh::Endpoint,
        relay_url: iroh::RelayUrl,
        _relay_server: Box<dyn std::any::Any + Send>,
        reports: mpsc::UnboundedSender<(EndpointId, iroh::endpoint::ConnectionError)>,
        closed: mpsc::UnboundedReceiver<(EndpointId, iroh::endpoint::ConnectionError)>,
        servers: Vec<(iroh::Endpoint, iroh::protocol::Router)>,
    }

    #[cfg(feature = "iroh-test-utils")]
    impl Fixture {
        async fn new(cap: usize) -> Self {
            let (relay_url, relay_server) = test_relay::spawn_plain().await.expect("local relay");
            let admission = SignalAdmission::new(cap);
            let (reports, closed) = mpsc::unbounded_channel();
            let mut fixture = Self {
                node: Self::bind(&relay_url, Some(admission.connection_hook())).await,
                admission,
                relay_url,
                _relay_server: Box::new(relay_server),
                reports,
                closed,
                servers: Vec::new(),
            };
            fixture.servers.clear();
            fixture
        }

        async fn bind(relay_url: &iroh::RelayUrl, hook: Option<ConnectionHook>) -> iroh::Endpoint {
            let mut builder = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::custom([relay_url.clone()]))
                .clear_ip_transports();
            if let Some(hook) = hook {
                builder = builder.hooks(hook);
            }
            builder.bind().await.expect("bind an endpoint on the relay")
        }

        /// The node dials a new server on the unicast protocol.
        async fn dial(&mut self) -> (EndpointId, Connection) {
            self.dial_with(None).await
        }

        /// As [`Self::dial`], and the server binds with `hook`.
        async fn dial_with(&mut self, hook: Option<ConnectionHook>) -> (EndpointId, Connection) {
            use iroh::protocol::{AcceptError, ProtocolHandler, Router};

            #[derive(Debug, Clone)]
            struct Report(
                EndpointId,
                mpsc::UnboundedSender<(EndpointId, iroh::endpoint::ConnectionError)>,
            );
            impl ProtocolHandler for Report {
                async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                    let reason = conn.closed().await;
                    let _ = self.1.send((self.0, reason));
                    Ok(())
                }
            }
            let server = Self::bind(&self.relay_url, hook).await;
            let id = server.id();
            let router = Router::builder(server.clone())
                .accept(super::super::UNICAST_ALPN, Report(id, self.reports.clone()))
                .spawn();
            let relayed = iroh::EndpointAddr::new(id).with_relay_url(self.relay_url.clone());
            let conn = self
                .node
                .connect(relayed, super::super::UNICAST_ALPN)
                .await
                .expect("dial over the relay");
            self.servers.push((server, router));
            (id, conn)
        }

        /// The next connection that a server saw close, within `within`.
        async fn next_closed(
            &mut self,
            within: Duration,
        ) -> Option<(EndpointId, iroh::endpoint::ConnectionError)> {
            tokio::time::timeout(within, self.closed.recv())
                .await
                .ok()
                .flatten()
        }

        async fn shutdown(self) {
            for (_, router) in self.servers {
                router.shutdown().await.expect("shutdown");
            }
            self.node.close().await;
        }
    }

    /// **Two live connections of one peer.** A session may be detached only when no connection
    /// of the pair reads below IP. The table reads every live connection, not the first.
    #[cfg(feature = "iroh-test-utils")]
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_table_reads_every_live_connection_of_a_peer() {
        let mut fixture = Fixture::new(4).await;
        let (peer, first) = fixture.dial().await;
        assert!(
            fixture.admission.any_connection_not_ip(peer),
            "one relay connection reads below IP"
        );
        let relayed = iroh::EndpointAddr::new(peer).with_relay_url(fixture.relay_url.clone());
        let second = fixture
            .node
            .connect(relayed, super::super::UNICAST_ALPN)
            .await
            .expect("a second connection over the relay");
        first.close(0u32.into(), b"done");
        first.closed().await;
        assert!(
            fixture.admission.any_connection_not_ip(peer),
            "the second connection is still live and reads below IP"
        );
        second.close(0u32.into(), b"done");
        second.closed().await;
        assert!(
            !fixture.admission.any_connection_not_ip(peer),
            "no live connection is left"
        );
        fixture.shutdown().await;
    }

    /// **The ceiling of direct connections.** A node whose ceiling is 4 dials five peers over
    /// the unicast protocol. The fifth connection is admitted, and the least recently used
    /// one is closed with the `EVICTED` code, which the peer reads.
    #[cfg(feature = "iroh-test-utils")]
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fifth_unicast_connection_at_a_ceiling_of_four_evicts_the_least_recently_used() {
        use super::super::webrtc::close_code::EVICTED;

        let mut fixture = Fixture::new(4).await;
        let mut conns = Vec::new();
        for _ in 0..5 {
            conns.push(fixture.dial().await);
        }
        let first = conns[0].0;

        let (peer, reason) = fixture
            .next_closed(Duration::from_secs(10))
            .await
            .expect("a connection must be evicted");
        assert_eq!(peer, first, "the least recently used goes");
        let iroh::endpoint::ConnectionError::ApplicationClosed(close) = &reason else {
            panic!("expected the EVICTED code, got {reason:?}");
        };
        assert_eq!(close.error_code.into_inner(), u64::from(EVICTED));
        assert!(
            fixture
                .next_closed(Duration::from_millis(500))
                .await
                .is_none(),
            "exactly one eviction"
        );
        for (_, conn) in &conns[1..] {
            assert!(conn.close_reason().is_none(), "the others stay open");
        }
        fixture.shutdown().await;
    }

    /// **The evicted peer backs off.** The node that reads the `EVICTED` code on a connection
    /// holds its proactive dials to the evictor for a while. The node that evicted does not
    /// back off.
    #[cfg(feature = "iroh-test-utils")]
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_peer_that_reads_the_evicted_code_backs_off_from_the_evictor() {
        let mut fixture = Fixture::new(1).await;
        let evicted = SignalAdmission::new(8);
        let (first, _first_conn) = fixture.dial_with(Some(evicted.connection_hook())).await;
        let _second = fixture.dial().await;
        let (peer, _) = fixture
            .next_closed(Duration::from_secs(10))
            .await
            .expect("a connection must be evicted");
        assert_eq!(peer, first, "the first one is evicted");

        let me = fixture.node.id();
        let mut backed_off = false;
        for _ in 0..40 {
            backed_off = evicted.evicted_recently(me);
            if backed_off {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(backed_off, "the evicted peer holds its proactive dials");
        assert!(
            !fixture.admission.evicted_recently(first),
            "the evictor does not back off"
        );
        fixture.shutdown().await;
    }

    /// **A connection that closes leaves the ledger.** Four connections at a ceiling of four; one
    /// closes on its own (an idle close, a reset). The count falls to three, and the next newcomer
    /// evicts nobody. A unit that is a ghost keeps the count at the ceiling for ever, and every newcomer
    /// then evicts a live peer.
    #[cfg(feature = "iroh-test-utils")]
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connection_that_closes_leaves_the_ledger() {
        let mut fixture = Fixture::new(4).await;
        let mut conns = Vec::new();
        for _ in 0..4 {
            conns.push(fixture.dial().await);
        }
        assert_eq!(fixture.admission.direct_units(), 4);

        conns[0].1.close(0u32.into(), b"idle");
        for _ in 0..40 {
            fixture.admission.lock().sample();
            if fixture.admission.direct_units() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            fixture.admission.direct_units(),
            3,
            "the closed connection left the ledger"
        );

        let _fifth = fixture.dial().await;
        // The first server saw its connection close by us, which is not an eviction.
        let mut evicted = Vec::new();
        while let Some((peer, reason)) = fixture.next_closed(Duration::from_millis(700)).await {
            if let iroh::endpoint::ConnectionError::ApplicationClosed(close) = &reason
                && close.error_code.into_inner()
                    == u64::from(super::super::webrtc::close_code::EVICTED)
            {
                evicted.push(peer);
            }
        }
        assert!(
            evicted.is_empty(),
            "a fifth dial at three units evicts nobody: {evicted:?}"
        );
        fixture.shutdown().await;
    }

    /// A connection with a send in flight is never evicted: the next least recently used
    /// one goes instead.
    #[cfg(feature = "iroh-test-utils")]
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_busy_connection_is_not_evicted() {
        let mut fixture = Fixture::new(2).await;
        let (first, first_conn) = fixture.dial().await;
        let (second, _second_conn) = fixture.dial().await;
        let _busy = fixture.admission.busy(first);

        let _third = fixture.dial().await;

        let (peer, _) = fixture
            .next_closed(Duration::from_secs(10))
            .await
            .expect("a connection must be evicted");
        assert_eq!(peer, second, "the busy first connection is skipped");
        assert!(
            first_conn.close_reason().is_none(),
            "the busy one stays open"
        );
        fixture.shutdown().await;
    }

    /// When every candidate is busy the newcomer is still admitted: the count is over the
    /// ceiling by the busy connections, the gauge says so, and nothing is evicted. When the
    /// sends end, the next admission evicts again.
    #[cfg(feature = "iroh-test-utils")]
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn when_every_connection_is_busy_the_newcomer_is_admitted_over_the_ceiling() {
        let mut fixture = Fixture::new(1).await;
        let (first, _first_conn) = fixture.dial().await;
        let busy = fixture.admission.busy(first);

        let (_second, _second_conn) = fixture.dial().await;

        assert!(
            fixture
                .next_closed(Duration::from_millis(1500))
                .await
                .is_none(),
            "nobody is evicted while the only candidate is busy"
        );
        assert_eq!(fixture.admission.over_ceiling(), 1);

        drop(busy);
        let _third = fixture.dial().await;
        assert!(
            fixture.next_closed(Duration::from_secs(10)).await.is_some(),
            "once the send has ended an admission evicts again"
        );
        fixture.shutdown().await;
    }

    /// A gossip connection whose selected path is the gossip rung is closed by the hook, with the
    /// code of the recursion rule, and the other end reads that code. Only the dialer has the hook:
    /// with a hook at both ends each end can close before it reads the close of the other, and
    /// then both read `LocallyClosed`. The rule reads no mesh policy: here the dialed gossip watch
    /// is off, which is its default.
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gossip_connection_on_the_gossip_path_is_closed_by_the_hook() {
        use habilis_network_iroh_gossip_transport::memory::Hub;
        use habilis_network_iroh_gossip_transport::{GossipHandle, gossip_addr};
        use iroh::endpoint::ConnectionError;
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};
        use iroh::{EndpointAddr, RelayMode, SecretKey, TransportAddr};

        #[derive(Debug, Clone)]
        struct Report(Arc<Mutex<Option<oneshot::Sender<ConnectionError>>>>);
        impl ProtocolHandler for Report {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                let reason = conn.closed().await;
                if let Some(tx) = self.0.lock().expect("report lock").take() {
                    let _ = tx.send(reason);
                }
                Ok(())
            }
        }

        let (alice_key, bob_key) = (
            SecretKey::from_bytes(&[11; 32]),
            SecretKey::from_bytes(&[12; 32]),
        );
        let hub = Hub::new();
        let (alice_handle, bob_handle) = (
            GossipHandle::new(alice_key.public()),
            GossipHandle::new(bob_key.public()),
        );
        hub.join(&alice_handle);
        hub.join(&bob_handle);
        let bind = |key: SecretKey, handle: GossipHandle, admission: Option<SignalAdmission>| async move {
            let builder = iroh::Endpoint::builder(presets::Minimal)
                .secret_key(key)
                .relay_mode(RelayMode::Disabled)
                .add_custom_transport(handle.custom_transport())
                .clear_ip_transports()
                .clear_relay_transports();
            let builder = match admission {
                Some(admission) => builder.hooks(admission.connection_hook()),
                None => builder,
            };
            builder.bind().await.expect("bind a gossip-only endpoint")
        };
        let admission = SignalAdmission::new(8);
        let alice = bind(alice_key, alice_handle, Some(admission.clone())).await;
        let bob = bind(bob_key, bob_handle, None).await;
        let (tx, rx) = oneshot::channel();
        let router = Router::builder(bob.clone())
            .accept(
                iroh_gossip::net::GOSSIP_ALPN,
                Report(Arc::new(Mutex::new(Some(tx)))),
            )
            .spawn();
        let before = payload_path::gossip_recursion_closes();

        let connection = alice
            .connect(
                EndpointAddr::from_parts(bob.id(), [TransportAddr::Custom(gossip_addr(bob.id()))]),
                iroh_gossip::net::GOSSIP_ALPN,
            )
            .await
            .expect("connect over the gossip path");

        let at_alice = tokio::time::timeout(Duration::from_secs(5), connection.closed())
            .await
            .expect("the dialed end was not closed");
        let at_bob = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("the accepted end was not closed")
            .expect("the probe reported");
        let code = u64::from(payload_path::GOSSIP_RECURSION_REFUSED_CODE);
        assert!(
            matches!(at_alice, ConnectionError::LocallyClosed),
            "the dialer closed itself: {at_alice:?}"
        );
        assert!(
            matches!(&at_bob, ConnectionError::ApplicationClosed(close) if u64::from(close.error_code) == code),
            "the accepted end reads the code: {at_bob:?}"
        );
        assert!(
            payload_path::gossip_recursion_closes() > before,
            "the close is counted"
        );
        assert_eq!(
            admission.selected_kind(bob.id()),
            Some(super::super::probe::PathKind::Gossip),
            "the pair still reads as the gossip rung once its closed connection left the table"
        );
        router.shutdown().await.expect("shutdown");
        alice.close().await;
    }

    /// What the table tells the gossip transport about a peer: established when it has a live
    /// connection, allowed unless a higher rung carries the pair, on the best of its connections.
    #[test]
    fn the_table_tells_the_gossip_transport_what_it_sees() {
        use super::super::probe::PathKind::{self, Gossip, Ip, Multihop, Relay, WebRtc};
        assert_eq!(
            gossip_view(&[]),
            (false, true),
            "no connection: a handshake"
        );
        assert_eq!(gossip_view(&[Relay]), (true, true));
        assert_eq!(gossip_view(&[Gossip]), (true, true));
        assert_eq!(
            gossip_view(&[PathKind::None]),
            (true, true),
            "no path selected yet"
        );
        assert_eq!(gossip_view(&[Ip]), (true, false));
        assert_eq!(gossip_view(&[WebRtc]), (true, false));
        assert_eq!(gossip_view(&[Multihop, Gossip]), (true, false));
        assert_eq!(
            gossip_view(&[Relay, Ip]),
            (true, false),
            "the best connection stands for the pair"
        );
    }

    /// An endpoint with a loopback UDP socket and the gossip transport, whose connections are
    /// reported to its own table, which keeps the gossip handle.
    async fn ip_and_gossip_node(
        seed: u8,
        hub: &habilis_network_iroh_gossip_transport::memory::Hub,
        with_ip: bool,
    ) -> (
        iroh::Endpoint,
        SignalAdmission,
        habilis_network_iroh_gossip_transport::GossipHandle,
    ) {
        use habilis_network_iroh_gossip_transport::GossipHandle;
        use iroh::{RelayMode, SecretKey};

        let key = SecretKey::from_bytes(&[seed; 32]);
        let handle = GossipHandle::new(key.public());
        hub.join(&handle);
        let admission = SignalAdmission::new(8);
        admission.set_gossip(handle.clone());
        let mut builder = iroh::Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled)
            .add_custom_transport(handle.custom_transport())
            .path_selector(handle.path_selector())
            .hooks(admission.connection_hook());
        builder = if with_ip {
            builder
                .bind_addr(
                    "127.0.0.1:0"
                        .parse::<std::net::SocketAddr>()
                        .expect("loopback"),
                )
                .expect("bind address")
        } else {
            builder.clear_ip_transports().clear_relay_transports()
        };
        (builder.bind().await.expect("bind"), admission, handle)
    }

    /// Accepts and holds every connection on the test ALPN.
    #[derive(Debug, Clone)]
    struct HoldConnections;

    impl iroh::protocol::ProtocolHandler for HoldConnections {
        async fn accept(&self, connection: Connection) -> Result<(), iroh::protocol::AcceptError> {
            connection.closed().await;
            Ok(())
        }
    }

    const GOSSIP_TEST_ALPN: &[u8] = b"habilis-network/test-gossip-view/0";

    /// A pair that rides IP is blocked for gossip at BOTH ends, the dialer and the acceptor, and
    /// both are established: neither end needs a path watcher, which only the lower id has.
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pair_on_ip_is_blocked_for_gossip_at_both_ends() {
        use habilis_network_iroh_gossip_transport::gossip_addr;
        use habilis_network_iroh_gossip_transport::memory::Hub;
        use iroh::{EndpointAddr, TransportAddr};

        let hub = Hub::new();
        let (alice, alice_table, alice_handle) = ip_and_gossip_node(41, &hub, true).await;
        let (bob, bob_table, bob_handle) = ip_and_gossip_node(42, &hub, true).await;
        let router = iroh::protocol::Router::builder(bob.clone())
            .accept(GOSSIP_TEST_ALPN, HoldConnections)
            .spawn();
        let both = bob
            .addr()
            .addrs
            .into_iter()
            .chain([TransportAddr::Custom(gossip_addr(bob.id()))]);
        let _connection = alice
            .connect(EndpointAddr::from_parts(bob.id(), both), GOSSIP_TEST_ALPN)
            .await
            .expect("connect");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            alice_table.sync_gossip();
            bob_table.sync_gossip();
            if !alice_handle.is_allowed(bob.id()) && !bob_handle.is_allowed(alice.id()) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "a pair on IP is blocked at both ends"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(alice_handle.is_established(bob.id()), "the dialer");
        assert!(bob_handle.is_established(alice.id()), "the acceptor");
        let sent = alice_handle.stats().frames_out + bob_handle.stats().frames_out;
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert_eq!(
            alice_handle.stats().frames_out + bob_handle.stats().frames_out,
            sent,
            "a pair on IP puts no frame on the topic"
        );
        router.shutdown().await.expect("shutdown");
        alice.close().await;
    }

    /// A pair that only gossip carries is not blocked, and a peer whose connection is gone is
    /// established no more, and allowed again.
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pair_on_gossip_is_allowed_and_a_gone_peer_is_forgotten() {
        use habilis_network_iroh_gossip_transport::gossip_addr;
        use habilis_network_iroh_gossip_transport::memory::Hub;
        use iroh::{EndpointAddr, TransportAddr};

        let hub = Hub::new();
        let (alice, alice_table, alice_handle) = ip_and_gossip_node(43, &hub, false).await;
        let (bob, _bob_table, _bob_handle) = ip_and_gossip_node(44, &hub, false).await;
        let router = iroh::protocol::Router::builder(bob.clone())
            .accept(GOSSIP_TEST_ALPN, HoldConnections)
            .spawn();
        let connection = alice
            .connect(
                EndpointAddr::from_parts(bob.id(), [TransportAddr::Custom(gossip_addr(bob.id()))]),
                GOSSIP_TEST_ALPN,
            )
            .await
            .expect("connect over gossip");

        alice_table.sync_gossip();
        assert!(alice_handle.is_established(bob.id()));
        assert!(alice_handle.is_allowed(bob.id()), "gossip carries the pair");

        alice_handle.allow(bob.id(), false);
        connection.close(0u32.into(), b"done");
        connection.closed().await;
        alice_table.lock().sample();
        assert!(!alice_handle.is_established(bob.id()), "no connection left");
        assert!(alice_handle.is_allowed(bob.id()), "allowed again");
        router.shutdown().await.expect("shutdown");
        alice.close().await;
    }

    /// A pair that a session carries is blocked for gossip though no connection is left to read.
    /// A gossip connection dialed now would be born on the gossip rung, and the recursion rule
    /// would close it before iroh moves it onto the session.
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pair_with_a_session_is_blocked_for_gossip_without_a_connection() {
        use habilis_network_iroh_gossip_transport::gossip_addr;
        use habilis_network_iroh_gossip_transport::memory::Hub;
        use iroh::{EndpointAddr, TransportAddr};

        let hub = Hub::new();
        let (alice, alice_table, alice_handle) = ip_and_gossip_node(45, &hub, false).await;
        let (bob, _bob_table, _bob_handle) = ip_and_gossip_node(46, &hub, false).await;
        let sessions = FakeHub::default();
        alice_table.lock().hub = Some(Arc::new(sessions.clone()));
        let router = iroh::protocol::Router::builder(bob.clone())
            .accept(GOSSIP_TEST_ALPN, HoldConnections)
            .spawn();
        let connection = alice
            .connect(
                EndpointAddr::from_parts(bob.id(), [TransportAddr::Custom(gossip_addr(bob.id()))]),
                GOSSIP_TEST_ALPN,
            )
            .await
            .expect("connect over gossip");
        connection.close(0u32.into(), b"done");
        connection.closed().await;

        sessions.attach(bob.id());
        alice_table.lock().sample();
        assert!(
            !alice_handle.is_allowed(bob.id()),
            "the session carries the pair: the gossip rung is not allowed"
        );
        assert!(!alice_handle.is_established(bob.id()), "no connection left");
        router.shutdown().await.expect("shutdown");
        alice.close().await;
    }

    /// A session is attached while a live connection still reads the gossip rung: gossip is not
    /// blocked. That connection carries the pair. A block would starve it, and iroh would give it
    /// up for the relay, though the session may carry nothing (its rung is cut).
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pair_with_a_session_and_a_connection_on_the_gossip_rung_is_allowed_for_gossip() {
        use habilis_network_iroh_gossip_transport::gossip_addr;
        use habilis_network_iroh_gossip_transport::memory::Hub;
        use iroh::{EndpointAddr, TransportAddr};

        let hub = Hub::new();
        let (alice, alice_table, alice_handle) = ip_and_gossip_node(47, &hub, false).await;
        let (bob, _bob_table, _bob_handle) = ip_and_gossip_node(48, &hub, false).await;
        let sessions = FakeHub::default();
        alice_table.lock().hub = Some(Arc::new(sessions.clone()));
        let router = iroh::protocol::Router::builder(bob.clone())
            .accept(GOSSIP_TEST_ALPN, HoldConnections)
            .spawn();
        let connection = alice
            .connect(
                EndpointAddr::from_parts(bob.id(), [TransportAddr::Custom(gossip_addr(bob.id()))]),
                GOSSIP_TEST_ALPN,
            )
            .await
            .expect("connect over gossip");

        sessions.attach(bob.id());
        alice_table.lock().sample();
        assert!(
            alice_handle.is_established(bob.id()),
            "a connection is left"
        );
        assert!(
            alice_handle.is_allowed(bob.id()),
            "a live connection reads the gossip rung: the session does not block it"
        );
        connection.close(0u32.into(), b"done");
        connection.closed().await;
        router.shutdown().await.expect("shutdown");
        alice.close().await;
    }
}
