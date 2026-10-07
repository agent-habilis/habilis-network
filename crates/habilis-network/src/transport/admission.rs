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
//! gone and the peers that nothing holds. The cap never evicts a peer: at the
//! cap a newcomer is refused, and a slot frees when its session ends.
//!
//! # Idle sessions
//!
//! The same table says when a session is idle: the peer holds no live
//! connection, of any protocol, and no round is in flight. [`SignalAdmission::idle_sessions`]
//! hands back the peers that have been in that state for a window, and the
//! retry pass detaches their sessions (`webrtc::detach_idle_sessions_at`), so a
//! slot frees without a newcomer evicting anyone. A gossip neighbor always has
//! its gossip connection, so it never idles out.
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
    /// At the direct-peer ceiling, counting rounds in flight.
    AtCap,
    /// This peer refused us at *its* cap recently.
    Cooling,
    /// The Router is shutting down.
    ShuttingDown,
}

/// What the table needs from a `WebRTC` hub. A trait so a test can stand in
/// for sessions, which cannot be negotiated inside a unit test.
pub(crate) trait Sessions: Send + Sync + 'static {
    fn has_session(&self, peer: &EndpointId) -> bool;
    fn session_count(&self) -> usize;
    fn local(&self) -> String {
        String::new()
    }
}

impl Sessions for WebRtcHandle {
    fn has_session(&self, peer: &EndpointId) -> bool {
        WebRtcHandle::has_session(self, peer)
    }

    fn session_count(&self) -> usize {
        WebRtcHandle::session_count(self)
    }

    fn local(&self) -> String {
        self.transport().local_id().fmt_short().to_string()
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
}

impl Slot {
    fn new() -> Self {
        Self {
            round: None,
            conns: Vec::new(),
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
    /// Since when each peer with a session has had nothing on it: no live
    /// connection and no round in flight. See [`Self::take_idle`].
    idle_since: HashMap<EndpointId, Instant>,
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

    /// The peers whose session nothing has held for `window`, each handed back
    /// once. Held means a live connection of any protocol, or a round in flight.
    /// The clock of a peer starts the first time it is seen unheld, and starts
    /// over if it is held again, so the window runs from the last use.
    fn take_idle(&mut self, now: Instant, window: Duration) -> Vec<EndpointId> {
        self.sample();
        let Some(hub) = self.hub.clone() else {
            self.idle_since.clear();
            return Vec::new();
        };
        let unheld: Vec<EndpointId> = self
            .slots
            .iter()
            .filter(|(peer, slot)| {
                slot.round.is_none() && slot.conns.is_empty() && hub.has_session(peer)
            })
            .map(|(peer, _)| *peer)
            .collect();
        self.idle_since.retain(|peer, _| unheld.contains(peer));
        let mut idle = Vec::new();
        for peer in unheld {
            let since = *self.idle_since.entry(peer).or_insert(now);
            if now.saturating_duration_since(since) >= window {
                self.idle_since.remove(&peer);
                idle.push(peer);
            }
        }
        idle.sort_unstable();
        idle
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
        let hub = self.hub.clone();
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
                idle_since: HashMap::new(),
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
        if inner.hub.is_none() {
            inner.hub = Some(Arc::new(handle.clone()));
        }
        // Reservations count. A peer can briefly appear in both this and
        // `session_count` — between attach and the guard's drop — which biases
        // toward refusing one dial we could have made. The next tick fixes it.
        if handle.session_count() + inner.rounds_in_flight() >= self.cap {
            tracing::info!(
                target: "habilis_network::transport",
                local = %handle.local(),
                refused = %peer.fmt_short(),
                sessions = handle.session_count(),
                in_flight = inner.rounds_in_flight(),
                cap = self.cap,
                "cap refusal"
            );
            return Err(Refusal::AtCap);
        }
        inner.slot(peer).round = Some(Round::Admitted);
        drop(inner);
        Ok(AdmissionGuard {
            admission: self.clone(),
            peer,
        })
    }

    /// Record the task holding `peer`'s slot, so shutdown can cancel it.
    ///
    /// Separate from `try_admit` because the slot must be claimed *before* the
    /// task is spawned — that ordering is what bounds the task count — and the
    /// abort handle does not exist until after.
    pub(crate) fn track(&self, peer: EndpointId, abort: AbortHandle) {
        if let Some(round) = self
            .lock()
            .slots
            .get_mut(&peer)
            .and_then(|slot| slot.round.as_mut())
        {
            *round = Round::Running(abort);
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
        self.forget_refusal(peer);
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

    fn release(&self, peer: EndpointId) {
        if let Some(slot) = self.lock().slots.get_mut(&peer) {
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
        if !inner.sampler_running {
            inner.sampler_running = true;
            spawn_sampler(
                Arc::downgrade(&self.inner),
                Duration::from_secs(tuning::SLOT_SWEEP_SECS),
            );
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("signal admission poisoned")
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
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        self.admission.release(self.peer);
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

    /// The dial-side half of the cap bug: the retry tick admits in a tight loop
    /// with nothing awaited, so `session_count()` never moves and only the
    /// reservations can hold the line.
    #[test]
    fn rounds_in_flight_count_against_the_cap() {
        let admission = SignalAdmission::new(2);
        let hub = hub();
        let _one = admission.try_admit(peer(1), &hub).expect("first admit");
        let _two = admission.try_admit(peer(2), &hub).expect("second admit");
        assert_eq!(
            admission.try_admit(peer(3), &hub).unwrap_err(),
            Refusal::AtCap
        );
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

        let task = n0_future::task::spawn(async move {
            let _guard = guard;
            // Never returns on its own — only an abort ends this.
            std::future::pending::<()>().await;
        });
        admission.track(peer(1), task.abort_handle());
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

        fn session_count(&self) -> usize {
            self.0.lock().expect("fake hub").len()
        }
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

    /// A session that no connection and no round holds is idle, and is handed
    /// back once it has been idle for the whole window, not before.
    #[test]
    fn a_session_nothing_holds_idles_out_after_the_window() {
        let admission = SignalAdmission::new(4);
        let hub = FakeHub::default();
        drop(admission.try_admit(peer(1), &hub).expect("room"));
        hub.attach(peer(1));
        let window = Duration::from_secs(tuning::WEBRTC_SESSION_IDLE_SECS);
        let start = Instant::now();

        let mut inner = admission.lock();
        assert!(
            inner.take_idle(start, window).is_empty(),
            "the clock starts"
        );
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

    /// A round in flight holds the peer: its session is not idle however long
    /// the round runs.
    #[test]
    fn a_round_in_flight_keeps_a_session_from_idling() {
        let admission = SignalAdmission::new(4);
        let hub = FakeHub::default();
        let _guard = admission.try_admit(peer(1), &hub).expect("room");
        hub.attach(peer(1));
        let window = Duration::from_secs(tuning::WEBRTC_SESSION_IDLE_SECS);
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
        let window = Duration::from_secs(tuning::WEBRTC_SESSION_IDLE_SECS);
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

    /// A live connection to the peer holds its session, whatever the protocol:
    /// a gossip neighbor never idles out. Once the connection is gone, the
    /// session is idle, and the window runs from then.
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
        let relayed = iroh::EndpointAddr::new(neighbor).with_relay_url(relay_url.clone());
        let conn = client
            .connect(relayed, iroh_gossip::net::GOSSIP_ALPN)
            .await
            .expect("dial over the relay");
        let window = Duration::from_secs(tuning::WEBRTC_SESSION_IDLE_SECS);
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
        assert!(
            admission.lock().take_idle(later, window).is_empty(),
            "the clock starts when the connection is gone"
        );
        assert_eq!(
            admission.lock().take_idle(later + window, window),
            vec![neighbor]
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
}
