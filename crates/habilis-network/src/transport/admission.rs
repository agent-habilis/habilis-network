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
//! **In-flight rounds count.** [`Self::try_admit`] is a plain `fn` and the
//! retry tick calls it in a loop with nothing awaited between calls, so
//! `session_count()` alone never moves during a pass: twenty dials each read
//! zero and all twenty were spawned. Counting reservations is what makes the
//! loop self-limiting, and doing it in one lock scope is what makes it correct
//! without ever holding a lock across an await.
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

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use habilis_network_iroh_webrtc_transport::WebRtcHandle;
use iroh::EndpointId;
use iroh::endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, WeakConnectionHandle};
use n0_future::task::AbortHandle;

use crate::util::clock::Instant;
use crate::util::tuning;

/// How long to leave a peer alone after it answered "at my cap", and how that
/// grows.
///
/// Without a wait the retry tick re-offers every 30s and every refused round
/// still costs *us* a full candidate-gathering budget before the refusal
/// arrives. The wait is per peer: the first refusal waits
/// [`tuning::CAP_REFUSAL_COOLDOWN_SECS`], each further one in a row doubles it up
/// to [`tuning::CAP_REFUSAL_COOLDOWN_MAX_SECS`], and a success resets it. One
/// rule serves both kinds of peer: the rendezvous frees a slot soon after, so
/// the first short wait finds it, while a member whose sessions are all busy
/// gossip links does not, and the wait grows to a size that makes the cost of a
/// refused round small.
#[derive(Debug, Default)]
struct RefusalBackoff {
    by_peer: HashMap<EndpointId, Backoff>,
}

#[derive(Debug, Clone, Copy)]
struct Backoff {
    until: Instant,
    window: Duration,
}

impl RefusalBackoff {
    fn note(&mut self, peer: EndpointId, now: Instant) {
        let first = Duration::from_secs(tuning::CAP_REFUSAL_COOLDOWN_SECS);
        let max = Duration::from_secs(tuning::CAP_REFUSAL_COOLDOWN_MAX_SECS);
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
        self.live_peer_ids()
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

struct Inner {
    slots: HashMap<EndpointId, Slot>,
    /// Peers that refused us at their cap, each with its wait.
    refused: RefusalBackoff,
    /// The hub whose sessions the cap counts, learned at the first admission.
    hub: Option<Arc<dyn Sessions>>,
    sampler_running: bool,
    closed: bool,
    /// An endpoint hook reports to this table.
    observing: bool,
    /// The direct connections of the node against the ceiling, see [`super::ceiling`].
    ceiling: super::ceiling::Ceiling,
    /// The peers that closed a connection of ours with the `EVICTED` code.
    evicted_by: super::ceiling::EvictionBackoff,
    /// Where an answered session is reported to the event loop, set once the loop has its channel.
    proven_sink: Option<tokio::sync::mpsc::UnboundedSender<super::probe::DirectOutcome>>,
    /// The peers that we evicted. A peer whose session we detach has no connection to read the code
    /// on, so we refuse its offer for the same minute instead.
    we_evicted: super::ceiling::EvictionBackoff,
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

    /// Drop the connections that are gone, and the slots nothing holds.
    fn sample(&mut self) {
        for slot in self.slots.values_mut() {
            slot.conns.retain(|handle| {
                handle
                    .upgrade()
                    .is_some_and(|conn| conn.close_reason().is_none())
            });
        }
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
}

impl SignalAdmission {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                slots: HashMap::new(),
                refused: RefusalBackoff::default(),
                hub: None,
                sampler_running: false,
                closed: false,
                observing: false,
                ceiling: super::ceiling::Ceiling::new(cap),
                evicted_by: super::ceiling::EvictionBackoff::default(),
                we_evicted: super::ceiling::EvictionBackoff::default(),
                proven_sink: None,
            })),
            cap,
            watch_dialed_gossip: Arc::new(AtomicBool::new(false)),
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

    /// The selected path of `peer`, read from any live connection that the hook
    /// recorded for it: the gossip link, the pooled unicast connection, or an
    /// inbound one. iroh selects one path per remote, so any of them answers. A pair
    /// that only gossips has no pooled connection, and this is how the engine sees
    /// it. `None` if the peer has no live connection with a selected path.
    pub(crate) fn selected_kind(&self, peer: EndpointId) -> Option<super::probe::PathKind> {
        let handles: Vec<WeakConnectionHandle> = self.lock().slots.get(&peer)?.conns.clone();
        handles
            .iter()
            .filter_map(WeakConnectionHandle::upgrade)
            .filter(|conn| conn.close_reason().is_none())
            .map(|conn| super::probe::selected_kind(&conn))
            .find(|kind| *kind != super::probe::PathKind::None)
    }

    /// Whether [`connection_hook`](Self::connection_hook) was called on this
    /// table. Without a hook the table sees none of the endpoint's connections:
    /// the relay policy is not kept on the gossip connections that the node
    /// dials, and a slot whose connection is gone is never pruned. It does not
    /// prove that the hook is installed on a given endpoint: an embedder that
    /// calls the method and drops the hook passes this check.
    #[must_use]
    pub fn is_observed(&self) -> bool {
        self.lock().observing
    }

    /// The endpoint hook that reports every connection to this table. Install
    /// it on the endpoint builder, before bind.
    #[must_use]
    pub fn connection_hook(&self) -> ConnectionHook {
        self.lock().observing = true;
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
    pub(crate) fn try_admit<H>(
        &self,
        peer: EndpointId,
        handle: &H,
    ) -> Result<AdmissionGuard, Refusal>
    where
        H: Sessions + Clone,
    {
        self.try_admit_at(peer, handle, Instant::now())
    }

    pub(crate) fn try_admit_at<H>(
        &self,
        peer: EndpointId,
        handle: &H,
        now: Instant,
    ) -> Result<AdmissionGuard, Refusal>
    where
        H: Sessions + Clone,
    {
        self.admit(peer, handle, now, false)
    }

    fn admit<H>(
        &self,
        peer: EndpointId,
        handle: &H,
        now: Instant,
        outgoing: bool,
    ) -> Result<AdmissionGuard, Refusal>
    where
        H: Sessions + Clone,
    {
        let mut inner = self.lock();
        if inner.closed {
            return Err(Refusal::ShuttingDown);
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
    pub(crate) fn try_admit_offer<H>(
        &self,
        peer: EndpointId,
        handle: &H,
    ) -> Result<AdmissionGuard, Refusal>
    where
        H: Sessions + Clone,
    {
        self.try_admit_offer_at(peer, handle, Instant::now())
    }

    fn try_admit_offer_at<H>(
        &self,
        peer: EndpointId,
        handle: &H,
        now: Instant,
    ) -> Result<AdmissionGuard, Refusal>
    where
        H: Sessions + Clone,
    {
        self.admit(peer, handle, now, true)
    }

    /// The peer offers a session while this node's own offer to it runs: give ours up, so that the
    /// peer's offer is answered. Returns whether an offer was given up. A round that answers is
    /// never given up, and the guard of the round that was given up releases nothing later.
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

    fn release(&self, peer: EndpointId, epoch: u64) {
        if let Some(slot) = self.lock().slots.get_mut(&peer)
            && slot.epoch == epoch
        {
            slot.round = None;
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
        let evictions = if conn.alpn() == super::UNICAST_ALPN {
            inner.ceiling.register_quic(peer, Instant::now())
        } else {
            super::ceiling::Admission::default()
        };
        let victims = inner.take_victims(&evictions);
        if !inner.sampler_running {
            inner.sampler_running = true;
            spawn_sampler(
                Arc::downgrade(&self.inner),
                Duration::from_secs(tuning::SLOT_SWEEP_SECS),
            );
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
        tokio::spawn(async move {
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

    /// Note an eviction by `peer`, for a test that does not run the eviction.
    #[cfg(test)]
    pub(crate) fn note_evicted(&self, peer: EndpointId) {
        self.lock().evicted_by.note(peer, Instant::now(), 0.0);
    }

    /// Whether `peer` evicted our connection lately, so that no proactive dial goes to it.
    pub(crate) fn evicted_recently(&self, peer: EndpointId) -> bool {
        self.lock().evicted_by.holds(&peer, Instant::now())
    }

    /// The gossip neighbors changed. A session counts only while its peer is not one, so a
    /// peer that stops being a neighbor can take the ceiling over.
    pub(crate) fn set_neighbors(&self, neighbors: &std::collections::HashSet<EndpointId>) {
        let mut inner = self.lock();
        let evictions = inner.ceiling.set_neighbors(neighbors, Instant::now());
        let victims = inner.take_victims(&evictions);
        drop(inner);
        victims.end();
    }

    /// The event loop's channel for the sessions that this node answered.
    pub(crate) fn set_proven_sink(
        &self,
        sink: tokio::sync::mpsc::UnboundedSender<super::probe::DirectOutcome>,
    ) {
        self.lock().proven_sink = Some(sink);
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
        // The accept side watches the gossip connections it holds
        // (`DirectOnlyGossip::accept`). iroh-gossip dials its own, so the
        // watch for those starts here, with the same rule.
        if conn.side().is_client()
            && self.admission.watch_dialed_gossip.load(Ordering::Relaxed)
            && conn.alpn() == iroh_gossip::net::GOSSIP_ALPN
        {
            super::direct_gossip::watch_relay_policy(conn);
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
    use std::collections::HashSet;

    use habilis_network_iroh_webrtc_transport::{WebRtcHandle, WebRtcTransport};

    use super::*;

    fn peer(byte: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[byte; 32]).public()
    }

    /// An empty hub: `has_session` is always false and `session_count` is 0, so
    /// these tests exercise the admission logic and nothing else.
    fn hub() -> WebRtcHandle {
        WebRtcHandle::new(WebRtcTransport::new(peer(0)))
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
    #[tokio::test]
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
        let window = Duration::from_secs(tuning::DIRECT_IDLE_BACKSTOP_SECS);
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
        let window = Duration::from_secs(tuning::DIRECT_IDLE_BACKSTOP_SECS);
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
        let window = Duration::from_secs(tuning::DIRECT_IDLE_BACKSTOP_SECS);
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
        let window = Duration::from_secs(tuning::DIRECT_IDLE_BACKSTOP_SECS);
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
        let first = Duration::from_secs(tuning::CAP_REFUSAL_COOLDOWN_SECS);
        let longest = Duration::from_secs(tuning::CAP_REFUSAL_COOLDOWN_MAX_SECS);

        backoff.note(bob, start);
        assert!(backoff.on_cooldown(
            &bob,
            start + Duration::from_secs(tuning::CAP_REFUSAL_COOLDOWN_SECS - 1)
        ));
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        let (relay_url, _relay_server) = crate::lookup::test_relay::spawn_plain()
            .await
            .expect("local relay");
        let bind = |hook: Option<ConnectionHook>| {
            let relay_url = relay_url.clone();
            async move {
                let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
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
        let window = Duration::from_secs(tuning::DIRECT_IDLE_BACKSTOP_SECS);
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        let (relay_url, _relay_server) = crate::lookup::test_relay::spawn_plain()
            .await
            .expect("local relay");
        let bind = |hook: Option<ConnectionHook>| {
            let relay_url = relay_url.clone();
            async move {
                let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
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
        reports: tokio::sync::mpsc::UnboundedSender<(EndpointId, iroh::endpoint::ConnectionError)>,
        closed: tokio::sync::mpsc::UnboundedReceiver<(EndpointId, iroh::endpoint::ConnectionError)>,
        servers: Vec<(iroh::Endpoint, iroh::protocol::Router)>,
    }

    #[cfg(feature = "iroh-test-utils")]
    impl Fixture {
        async fn new(cap: usize) -> Self {
            let (relay_url, relay_server) = crate::lookup::test_relay::spawn_plain()
                .await
                .expect("local relay");
            let admission = SignalAdmission::new(cap);
            let (reports, closed) = tokio::sync::mpsc::unbounded_channel();
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
            let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
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
                tokio::sync::mpsc::UnboundedSender<(EndpointId, iroh::endpoint::ConnectionError)>,
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

    /// **The ceiling of direct connections.** A node whose ceiling is 4 dials five peers over
    /// the unicast protocol. The fifth connection is admitted, and the least recently used
    /// one is closed with the `EVICTED` code, which the peer reads.
    #[cfg(feature = "iroh-test-utils")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
}
