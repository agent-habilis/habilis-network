//! Who is allowed to start a `WebRTC` negotiation, and how many at once.
//!
//! One registry for both roles. The dialer asks before offering and the
//! answerer asks before answering, so the direct-peer ceiling means the same
//! thing whichever end of a pair you are on — which it did not, when only the
//! dialer checked.
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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fofoca_iroh_webrtc_transport::WebRtcHandle;
use iroh::EndpointId;
use n0_future::task::AbortHandle;

use crate::util::clock::Instant;
use crate::util::cooldown::Cooldown;

/// How long to leave a peer alone after it answered "at my cap".
///
/// Without it the retry tick re-offers every 30s and every refused round still
/// costs *us* a full candidate-gathering budget before the refusal arrives.
/// Five minutes is short enough that a peer whose sessions churn is picked up
/// on the next window, and long enough that the cost rounds to nothing.
const CAP_REFUSAL_COOLDOWN: Duration = Duration::from_mins(5);

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

#[derive(Debug)]
struct Inner {
    /// Peer → the abort handle of the task holding the slot, once spawned.
    inflight: HashMap<EndpointId, Option<AbortHandle>>,
    /// Peers that refused us at their cap; do not re-offer before this instant.
    refused_until: Cooldown<EndpointId>,
    closed: bool,
}

/// The one place a `WebRTC` negotiation slot is granted, for both roles.
#[derive(Debug, Clone)]
pub struct SignalAdmission {
    inner: Arc<Mutex<Inner>>,
    cap: usize,
}

impl SignalAdmission {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                inflight: HashMap::new(),
                refused_until: Cooldown::new(CAP_REFUSAL_COOLDOWN),
                closed: false,
            })),
            cap,
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
    pub(crate) fn try_admit(
        &self,
        peer: EndpointId,
        handle: &WebRtcHandle,
    ) -> Result<AdmissionGuard, Refusal> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(Refusal::ShuttingDown);
        }
        if inner.inflight.contains_key(&peer) {
            return Err(Refusal::InFlight);
        }
        // Nesting the transport's own lock is safe: it is a leaf, with no path
        // back into us.
        if handle.has_session(&peer) {
            return Err(Refusal::HaveSession);
        }
        if inner.refused_until.on_cooldown(&peer, Instant::now()) {
            return Err(Refusal::Cooling);
        }
        // Reservations count. A peer can briefly appear in both this and
        // `session_count` — between attach and the guard's drop — which biases
        // toward refusing one dial we could have made. The next tick fixes it.
        if handle.session_count() + inner.inflight.len() >= self.cap {
            return Err(Refusal::AtCap);
        }
        inner.inflight.insert(peer, None);
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
        if let Some(slot) = self.lock().inflight.get_mut(&peer) {
            *slot = Some(abort);
        }
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
        for abort in inner.inflight.values().flatten() {
            abort.abort();
        }
    }

    fn release(&self, peer: EndpointId) {
        self.lock().inflight.remove(&peer);
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.lock().inflight.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("signal admission poisoned")
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
    use fofoca_iroh_webrtc_transport::{WebRtcHandle, WebRtcTransport};

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
}
