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
//! the endpoint hook reports (any protocol, gossip included). Next to them sits
//! one last-activity time for the whole peer. Only `WebRTC` sessions take a slot
//! against the cap today, but nothing in the shape assumes that: a later cap
//! over UDP, `WebRTC` and gossip counts peers in this same table.
//!
//! # One eviction rule
//!
//! At the cap, a newcomer takes the slot of the peer that has been idle longest,
//! once that peer has been idle for [`EvictionPolicy::min_idle`] (plus a random
//! per-peer extra). Nobody is exempt: a peer that carries gossip is not idle, so
//! it is not evicted, and a rendezvous session that nothing uses any more is
//! idle, so it is. If no peer qualifies, the newcomer is refused as before.
//!
//! **Activity is payload.** Bytes on a stream or datagram of any connection to
//! the peer count, whatever the protocol. QUIC keep-alive and ack frames, ICE
//! consent checks and STUN do not: they flow on an idle link, and counting them
//! would make no peer ever idle. The hub sees only encrypted datagrams and
//! cannot tell the two apart, so the activity is read where the frames are
//! counted, on the QUIC connection (see [`payload_frames`]).
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
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use habilis_network_iroh_webrtc_transport::WebRtcHandle;
use iroh::EndpointId;
use iroh::endpoint::{
    AfterHandshakeOutcome, Connection, ConnectionStats, EndpointHooks, WeakConnectionHandle,
};
use n0_future::task::AbortHandle;
use rand::Rng;

use super::LOG_TARGET;
use crate::util::clock::Instant;
use crate::util::cooldown::Cooldown;
use crate::util::tuning;

/// How long to leave a peer alone after it answered "at my cap".
///
/// Without it the retry tick re-offers every 30s and every refused round still
/// costs *us* a full candidate-gathering budget before the refusal arrives.
/// The refusal now means no session was idle for a minute, so the window is
/// short: see [`tuning::CAP_REFUSAL_COOLDOWN_SECS`].
const CAP_REFUSAL_COOLDOWN: Duration = Duration::from_secs(tuning::CAP_REFUSAL_COOLDOWN_SECS);

/// Why a negotiation was not admitted. Diagnostic — every arm means "not now".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A round for this peer is already running.
    InFlight,
    /// We already hold a usable session with this peer.
    HaveSession,
    /// At the direct-peer ceiling, counting rounds in flight, and no peer has
    /// been idle long enough to make room.
    AtCap,
    /// This peer refused us at *its* cap recently.
    Cooling,
    /// We evicted this peer recently, so neither role takes it back yet.
    Evicted,
    /// The Router is shutting down.
    ShuttingDown,
}

/// The timings of the eviction rule. Plain data, so a test can shrink them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EvictionPolicy {
    /// How long a peer must have carried no payload before it may be evicted.
    pub(crate) min_idle: Duration,
    /// Random extra idle time, up to this much, fixed per peer.
    pub(crate) jitter: Duration,
    /// How long an evicted peer is refused in both roles.
    pub(crate) cooldown: Duration,
    /// How often the connection counters are read.
    pub(crate) sample: Duration,
}

impl Default for EvictionPolicy {
    fn default() -> Self {
        Self {
            min_idle: Duration::from_secs(tuning::MIN_IDLE_FOR_EVICTION_SECS),
            jitter: Duration::from_secs(tuning::EVICTION_JITTER_SECS),
            cooldown: Duration::from_secs(tuning::EVICTION_COOLDOWN_SECS),
            sample: Duration::from_secs(tuning::ACTIVITY_SAMPLE_SECS),
        }
    }
}

/// What the table needs from a `WebRTC` hub. A trait so a test can stand in
/// for sessions, which cannot be negotiated inside a unit test.
pub(crate) trait Sessions: Send + Sync + 'static {
    fn has_session(&self, peer: &EndpointId) -> bool;
    fn session_count(&self) -> usize;
    fn detach(&self, peer: &EndpointId) -> bool;
}

impl Sessions for WebRtcHandle {
    fn has_session(&self, peer: &EndpointId) -> bool {
        WebRtcHandle::has_session(self, peer)
    }

    fn session_count(&self) -> usize {
        WebRtcHandle::session_count(self)
    }

    fn detach(&self, peer: &EndpointId) -> bool {
        WebRtcHandle::detach(self, peer)
    }
}

/// The payload frames a connection has carried, both directions summed.
///
/// The one definition of activity: stream and datagram frames. Pings, acks and
/// flow-control frames are what an idle connection exchanges, so they are left
/// out on purpose.
fn payload_frames(stats: &ConnectionStats) -> u64 {
    [
        stats.frame_tx.stream,
        stats.frame_tx.datagram,
        stats.frame_rx.stream,
        stats.frame_rx.datagram,
    ]
    .into_iter()
    .fold(0, u64::saturating_add)
}

/// One QUIC connection to a peer, held weakly: the table must never keep a
/// connection open.
#[derive(Debug)]
struct Tracked {
    handle: WeakConnectionHandle,
    /// [`payload_frames`] at the last reading.
    frames: u64,
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
    conns: Vec<Tracked>,
    /// When the peer last carried payload, or was first seen.
    last_activity: Instant,
    /// How long past `last_activity` before this peer may be evicted. Fixed at
    /// creation, so a peer does not become evictable and safe by turns.
    idle_floor: Duration,
}

impl Slot {
    fn new(now: Instant, policy: &EvictionPolicy) -> Self {
        let extra_ms = u64::try_from(policy.jitter.as_millis()).unwrap_or(u64::MAX);
        let extra = Duration::from_millis(rand::rng().random_range(0..=extra_ms));
        Self {
            round: None,
            conns: Vec::new(),
            last_activity: now,
            idle_floor: policy.min_idle + extra,
        }
    }

    fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_activity)
    }
}

struct Inner {
    slots: HashMap<EndpointId, Slot>,
    /// Peers that refused us at their cap; do not re-offer before this instant.
    refused_until: Cooldown<EndpointId>,
    /// Peers we evicted; neither role takes them back before this instant.
    evicted_until: Cooldown<EndpointId>,
    /// The hub whose sessions the cap counts, learned at the first admission.
    hub: Option<Arc<dyn Sessions>>,
    policy: EvictionPolicy,
    /// An endpoint hook feeds this table. Without one nothing can be seen to
    /// be idle, so nothing is evicted: an endpoint the caller built, and
    /// shares with the mesh, has no hook.
    observing: bool,
    sampler_running: bool,
    closed: bool,
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
    fn slot(&mut self, peer: EndpointId, now: Instant) -> &mut Slot {
        let policy = self.policy;
        self.slots
            .entry(peer)
            .or_insert_with(|| Slot::new(now, &policy))
    }

    fn rounds_in_flight(&self) -> usize {
        self.slots
            .values()
            .filter(|slot| slot.round.is_some())
            .count()
    }

    /// Read every connection's counters: a peer whose count moved was active
    /// now. Drops connections that are gone, and the slots nothing holds.
    fn sample(&mut self, now: Instant) {
        for slot in self.slots.values_mut() {
            slot.conns.retain_mut(|tracked| {
                let Some(conn) = tracked.handle.upgrade() else {
                    return false;
                };
                if conn.close_reason().is_some() {
                    return false;
                }
                let frames = payload_frames(&conn.stats());
                if frames != tracked.frames {
                    tracked.frames = frames;
                    slot.last_activity = now;
                }
                true
            });
        }
        let hub = self.hub.clone();
        self.slots.retain(|peer, slot| {
            slot.round.is_some()
                || !slot.conns.is_empty()
                || hub.as_ref().is_some_and(|hub| hub.has_session(peer))
        });
    }

    /// Take the slot of the peer idle longest past its floor, if there is one.
    fn evict_idlest(&mut self, now: Instant) -> Option<EndpointId> {
        if !self.observing {
            return None;
        }
        let hub = self.hub.clone()?;
        let held: Vec<_> = self
            .slots
            .iter()
            .filter(|(peer, slot)| slot.round.is_none() && hub.has_session(peer))
            .map(|(peer, slot)| (*peer, slot.idle_for(now), slot.idle_floor))
            .collect();
        let Some((victim, idle)) = held
            .iter()
            .filter(|(_, idle, floor)| idle >= floor)
            .map(|(peer, idle, _)| (*peer, *idle))
            .max_by_key(|(_, idle)| *idle)
        else {
            tracing::debug!(
                target: LOG_TARGET,
                sessions = held.len(),
                least_idle = ?held.iter().map(|(_, idle, _)| *idle).min(),
                most_idle = ?held.iter().map(|(_, idle, _)| *idle).max(),
                "at the direct-peer cap: nobody idle long enough to make room"
            );
            return None;
        };
        let _ = hub.detach(&victim);
        self.evicted_until.note(victim, now);
        tracing::info!(
            target: LOG_TARGET,
            %victim,
            idle = ?idle,
            "at the direct-peer cap: evicted the idlest peer for a newcomer"
        );
        Some(victim)
    }
}

/// The one place a direct-peer slot is granted, for both roles.
#[derive(Debug, Clone)]
pub struct SignalAdmission {
    inner: Arc<Mutex<Inner>>,
    cap: usize,
}

impl SignalAdmission {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self::with_policy(cap, EvictionPolicy::default())
    }

    pub(crate) fn with_policy(cap: usize, policy: EvictionPolicy) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                slots: HashMap::new(),
                refused_until: Cooldown::new(CAP_REFUSAL_COOLDOWN),
                evicted_until: Cooldown::new(policy.cooldown),
                hub: None,
                policy,
                observing: false,
                sampler_running: false,
                closed: false,
            })),
            cap,
        }
    }

    /// The endpoint hook that reports every connection to this table. Install
    /// it on the endpoint builder, before bind.
    #[must_use]
    pub fn activity_hook(&self) -> ActivityHook {
        self.lock().observing = true;
        ActivityHook {
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
        if inner.refused_until.on_cooldown(&peer, now) {
            return Err(Refusal::Cooling);
        }
        if inner.evicted_until.on_cooldown(&peer, now) {
            return Err(Refusal::Evicted);
        }
        if inner.hub.is_none() {
            inner.hub = Some(Arc::new(handle.clone()));
        }
        // Reservations count. A peer can briefly appear in both this and
        // `session_count` — between attach and the guard's drop — which biases
        // toward refusing one dial we could have made. The next tick fixes it.
        if handle.session_count() + inner.rounds_in_flight() >= self.cap {
            inner.sample(now);
            if inner.evict_idlest(now).is_none() {
                return Err(Refusal::AtCap);
            }
        }
        inner.slot(peer, now).round = Some(Round::Admitted);
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

    /// Treat `peer` as evicted just now, for a test that needs the refusal
    /// without filling a table first.
    #[cfg(test)]
    pub(crate) fn note_evicted(&self, peer: EndpointId) {
        self.lock().evicted_until.note(peer, Instant::now());
    }

    /// Note that `peer` refused us at its cap; stop offering for a while.
    pub(crate) fn note_refused(&self, peer: EndpointId) {
        // `note` prunes expired entries first, so a long-lived node does not
        // accumulate entries for peers it met once.
        self.lock().refused_until.note(peer, Instant::now());
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

    /// Close every QUIC connection the endpoint hook reported for `peer`, with
    /// `code` and `reason`. Returns how many were open. This is how a node lets
    /// go of a peer it did not dial itself: iroh-gossip owns its connections
    /// and has no call to drop one neighbour, but the table holds a handle to
    /// each.
    pub(crate) fn close_peer(&self, peer: EndpointId, code: u32, reason: &[u8]) -> usize {
        let handles: Vec<WeakConnectionHandle> = self
            .lock()
            .slots
            .get(&peer)
            .map(|slot| {
                slot.conns
                    .iter()
                    .map(|tracked| tracked.handle.clone())
                    .collect()
            })
            .unwrap_or_default();
        handles
            .iter()
            .filter_map(WeakConnectionHandle::upgrade)
            .filter(|conn| conn.close_reason().is_none())
            .map(|conn| conn.close(code.into(), reason))
            .count()
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
    /// running. A new connection is itself activity: the peer just spoke.
    fn note_connection(&self, conn: &Connection) {
        let peer = conn.remote_id();
        let tracked = Tracked {
            handle: conn.weak_handle(),
            frames: payload_frames(&conn.stats()),
        };
        let now = Instant::now();
        let mut inner = self.lock();
        if inner.closed {
            return;
        }
        let slot = inner.slot(peer, now);
        slot.conns.push(tracked);
        slot.last_activity = now;
        if !inner.sampler_running {
            inner.sampler_running = true;
            spawn_sampler(Arc::downgrade(&self.inner), inner.policy.sample);
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
            inner.sample(Instant::now());
        }
    });
}

/// Reports every connection of the endpoint it is installed on, in or out and
/// on any protocol, to its [`SignalAdmission`].
#[derive(Debug, Clone)]
pub struct ActivityHook {
    admission: SignalAdmission,
}

impl EndpointHooks for ActivityHook {
    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        self.admission.note_connection(conn);
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
    }

    impl Sessions for FakeHub {
        fn has_session(&self, peer: &EndpointId) -> bool {
            self.0.lock().expect("fake hub").contains(peer)
        }

        fn session_count(&self) -> usize {
            self.0.lock().expect("fake hub").len()
        }

        fn detach(&self, peer: &EndpointId) -> bool {
            self.0.lock().expect("fake hub").remove(peer)
        }
    }

    const MIN_IDLE: Duration = Duration::from_mins(1);

    fn policy() -> EvictionPolicy {
        EvictionPolicy {
            min_idle: MIN_IDLE,
            jitter: Duration::ZERO,
            cooldown: Duration::from_mins(5),
            sample: Duration::from_secs(5),
        }
    }

    /// A node at a cap of two, holding sessions with peers 1 and 2, both first
    /// seen at the returned instant.
    fn full_node() -> (SignalAdmission, FakeHub, Instant) {
        let admission = SignalAdmission::with_policy(2, policy());
        let _hook = admission.activity_hook();
        let hub = FakeHub::default();
        let start = Instant::now();
        for byte in [1, 2] {
            drop(
                admission
                    .try_admit_at(peer(byte), &hub, start)
                    .expect("room"),
            );
            hub.attach(peer(byte));
        }
        (admission, hub, start)
    }

    fn mark_active(admission: &SignalAdmission, who: EndpointId, at: Instant) {
        admission.lock().slot(who, at).last_activity = at;
    }

    #[test]
    fn at_the_cap_a_newcomer_evicts_the_idlest_peer_past_the_floor() {
        let (admission, hub, start) = full_node();
        mark_active(&admission, peer(2), start + Duration::from_secs(30));

        let now = start + MIN_IDLE + Duration::from_secs(1);
        let guard = admission
            .try_admit_at(peer(3), &hub, now)
            .expect("the idlest peer makes room");

        assert!(!hub.has_session(&peer(1)), "peer 1 was idle longest");
        assert!(hub.has_session(&peer(2)), "peer 2 was active more recently");
        drop(guard);
    }

    #[test]
    fn at_the_cap_a_newcomer_is_refused_when_nobody_is_idle_long_enough() {
        let (admission, hub, start) = full_node();

        let now = start + Duration::from_secs(59);
        assert_eq!(
            admission.try_admit_at(peer(3), &hub, now).unwrap_err(),
            Refusal::AtCap
        );
        assert!(hub.has_session(&peer(1)) && hub.has_session(&peer(2)));
    }

    /// Recent activity, from any protocol, keeps a peer off the list. This is
    /// the rule's one definition of "not idle": no peer is named as an
    /// exception.
    #[test]
    fn a_peer_that_carried_payload_recently_is_not_evicted() {
        let (admission, hub, start) = full_node();
        let recent = start + MIN_IDLE;
        let now = recent + Duration::from_secs(1);
        mark_active(&admission, peer(1), recent);
        mark_active(&admission, peer(2), recent);

        assert_eq!(
            admission.try_admit_at(peer(3), &hub, now).unwrap_err(),
            Refusal::AtCap
        );
    }

    #[test]
    fn a_peer_in_a_negotiation_is_not_evicted() {
        let (admission, hub, start) = full_node();
        let _round = admission
            .try_admit_at(peer(1), &FakeHub::default(), start)
            .expect("a round for peer 1 on an empty hub");
        let now = start + MIN_IDLE + Duration::from_secs(1);

        let guard = admission
            .try_admit_at(peer(3), &hub, now)
            .expect("peer 2 makes room");
        assert!(hub.has_session(&peer(1)), "a round in flight is never idle");
        assert!(!hub.has_session(&peer(2)));
        drop(guard);
    }

    #[test]
    fn an_evicted_peer_is_refused_in_both_roles_until_the_cooldown_ends() {
        let (admission, hub, start) = full_node();
        let now = start + MIN_IDLE + Duration::from_secs(1);
        drop(admission.try_admit_at(peer(3), &hub, now).expect("room"));
        hub.attach(peer(3));
        // Peer 1 or 2 went; find which, then ask for it back.
        let evicted = [peer(1), peer(2)]
            .into_iter()
            .find(|candidate| !hub.has_session(candidate))
            .expect("one was evicted");

        assert_eq!(
            admission
                .try_admit_at(evicted, &hub, now + Duration::from_secs(10))
                .unwrap_err(),
            Refusal::Evicted
        );
        assert_ne!(
            admission
                .try_admit_at(evicted, &hub, now + Duration::from_secs(301))
                .err(),
            Some(Refusal::Evicted),
            "the cooldown ends"
        );
    }

    #[test]
    fn a_slot_nothing_holds_is_dropped() {
        let (admission, hub, start) = full_node();
        hub.detach(&peer(1));
        hub.detach(&peer(2));

        admission.lock().sample(start + Duration::from_secs(5));

        assert!(admission.lock().slots.is_empty());
    }

    /// The definition of activity, on counters built by hand: pings, acks and
    /// flow control are what an idle connection exchanges and must read as
    /// nothing; a stream or a datagram, in either direction, must read as
    /// something.
    #[test]
    fn only_stream_and_datagram_frames_count_as_activity() {
        let mut idle = ConnectionStats::default();
        idle.frame_tx.ping = 40;
        idle.frame_rx.ping = 40;
        idle.frame_tx.acks = 90;
        idle.frame_rx.acks = 90;
        idle.frame_rx.max_data = 3;
        assert_eq!(payload_frames(&idle), 0);

        let mut sent = idle.clone();
        sent.frame_tx.stream = 1;
        assert_eq!(payload_frames(&sent), 1);
        let mut received = idle.clone();
        received.frame_rx.datagram = 1;
        assert_eq!(payload_frames(&received), 1);
    }

    /// The same rule on a real connection: a link carrying only its own
    /// keep-alives and acks stays idle, and a stream written on it makes the
    /// peer active at the next reading.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connection_with_only_keepalives_goes_idle_and_one_with_a_stream_stays_active() {
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        const ALPN: &[u8] = b"habilis-mesh/test-activity/0";

        #[derive(Debug, Clone)]
        struct Drain;
        impl ProtocolHandler for Drain {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                while let Ok(mut recv) = conn.accept_uni().await {
                    let _ = recv.read_to_end(1024).await;
                }
                Ok(())
            }
        }
        let bind = |admission: Option<&SignalAdmission>| {
            let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled);
            if let Some(admission) = admission {
                builder = builder.hooks(admission.activity_hook());
            }
            async move { builder.bind().await.expect("bind a loopback endpoint") }
        };
        let admission = SignalAdmission::with_policy(2, policy());
        let server = bind(None).await;
        let router = Router::builder(server.clone()).accept(ALPN, Drain).spawn();
        let client = bind(Some(&admission)).await;
        crate::lookup::add_peer_addr(&client, server.addr()).expect("register the server");

        let conn = client.connect(server.id(), ALPN).await.expect("connect");
        let connected = Instant::now();
        let activity = |table: &SignalAdmission| {
            table
                .lock()
                .slots
                .get(&server.id())
                .expect("the hook reported the connection")
                .last_activity
        };
        let at_connect = activity(&admission);

        // Let the link run quiet until it has sent keep-alives of its own.
        let ping_wait = Instant::now();
        loop {
            let stats = conn.stats();
            if stats.frame_tx.ping + stats.frame_rx.ping > 0 {
                break;
            }
            assert!(
                ping_wait.elapsed() < Duration::from_secs(10),
                "the idle link never sent a keep-alive"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        admission.lock().sample(connected + Duration::from_secs(30));
        assert_eq!(
            activity(&admission),
            at_connect,
            "a link with no payload stays idle"
        );

        let mut stream = conn.open_uni().await.expect("open a stream");
        stream.write_all(b"payload").await.expect("write");
        stream.finish().expect("finish");
        // The counters move when the frame is sent; give the connection a beat.
        let reading = connected + Duration::from_mins(1);
        let stream_wait = Instant::now();
        while activity(&admission) != reading {
            assert!(
                stream_wait.elapsed() < Duration::from_secs(5),
                "a stream on the link never counted as activity"
            );
            admission.lock().sample(reading);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        conn.close(0u32.into(), b"done");
        router.shutdown().await.expect("shutdown");
        client.close().await;
    }
}
