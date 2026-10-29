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
//! (`webrtc::retry::detach_idle_sessions_at`), so a session goes a window after its last use. A gossip
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

mod admission_guard;
mod busy_guard;
mod connection_hook;
mod inner;
mod refusal;
mod refusal_backoff;
mod round;
mod sampler;
mod sessions;
mod signal_admission;
mod slot;
mod victims;
pub(crate) use admission_guard::AdmissionGuard;
pub(crate) use busy_guard::BusyGuard;
pub(crate) use connection_hook::ConnectionHook;
pub(crate) use inner::Inner;
pub(crate) use refusal::Refusal;
pub(crate) use refusal_backoff::RefusalBackoff;
pub(crate) use round::Round;
pub(crate) use sessions::Sessions;
pub use signal_admission::SignalAdmission;
pub(crate) use slot::Slot;
pub(crate) use victims::Victims;

// Host-only: the browser hub is a different type, and these need a tokio
// runtime for the abort test. The logic under test is target-independent.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use habilis_network_test_tracing::test;
    use std::collections::HashSet;
    use std::net::SocketAddr;

    use habilis_network_iroh_webrtc_transport::{WebRtcHandle, WebRtcTransport};

    #[cfg(feature = "iroh-test-utils")]
    use super::ConnectionHook;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use iroh::EndpointId;
    use iroh::endpoint::Connection;

    use crate::util::clock::Instant;
    use crate::util::tuning;

    use super::{Refusal, RefusalBackoff, Sessions, SignalAdmission, sampler};
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
        assert!(
            admission.note_not_a_neighbor(stranger),
            "a stranger's first turn-away starts the row"
        );
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
        assert!(
            admission.note_not_a_neighbor(stranger),
            "the vector sent by this node ends the wait the turn-aways earned"
        );
        assert!(
            !admission.note_not_a_neighbor(stranger),
            "the stranger's next turn-away does not start a new row"
        );
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
        assert!(
            matches!(admission.try_admit(peer(1), &hub), Err(Refusal::InFlight)),
            "the peer is refused while its round is in flight"
        );

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
        assert!(
            matches!(admission.try_admit(peer(1), &hub), Err(Refusal::Denied)),
            "a denied peer is refused as a dialler"
        );
        assert!(
            matches!(
                admission.try_admit_offer(peer(1), &hub),
                Err(Refusal::Denied)
            ),
            "a denied peer is refused as an offer"
        );
        assert!(
            admission.is_denied(peer(1)),
            "the peer is recorded as denied"
        );
    }

    /// A guard, not a red test: it cannot fail on a stub that denies nothing. It keeps `deny` from
    /// denying more than the peer it names, and `deny(false)` from leaving the peer denied.
    #[test]
    fn a_deny_leaves_the_other_peers_alone_and_can_be_lifted() {
        let admission = SignalAdmission::new(16);
        let hub = hub();
        admission.deny(peer(1), true);
        assert!(
            admission.try_admit(peer(2), &hub).is_ok(),
            "peer 2 is admitted while peer 1 is denied"
        );
        admission.deny(peer(1), false);
        assert!(
            !admission.is_denied(peer(1)),
            "lifting the deny clears peer 1's denial"
        );
        assert!(
            admission.try_admit(peer(1), &hub).is_ok(),
            "peer 1 is admitted once the denial is lifted"
        );
    }

    #[test]
    fn a_peer_being_dialled_is_refused_a_second_slot() {
        let admission = SignalAdmission::new(16);
        let hub = hub();
        let _guard = admission.try_admit(peer(1), &hub).expect("first admit");
        assert_eq!(
            admission.try_admit(peer(1), &hub).unwrap_err(),
            Refusal::InFlight,
            "the second admit for a dialled peer is refused as in flight"
        );
    }

    #[test]
    fn dropping_the_guard_releases_the_slot() {
        let admission = SignalAdmission::new(16);
        let hub = hub();
        drop(admission.try_admit(peer(1), &hub).expect("first admit"));
        assert_eq!(
            admission.in_flight(),
            0,
            "dropping the guard leaves no slot in flight"
        );
        assert!(
            admission.try_admit(peer(1), &hub).is_ok(),
            "the dropped slot can be taken again"
        );
    }

    /// Rounds in flight are not a count against a cap: the ceiling acts when a session
    /// attaches, so the retry tick may admit a round for every peer.
    #[test]
    fn rounds_in_flight_are_not_refused_by_a_ceiling() {
        let admission = SignalAdmission::new(2);
        let hub = hub();
        let _one = admission.try_admit(peer(1), &hub).expect("first admit");
        let _two = admission.try_admit(peer(2), &hub).expect("second admit");
        assert!(
            admission.try_admit(peer(3), &hub).is_ok(),
            "peer 3 is admitted while rounds are in flight"
        );
    }

    /// The table of the underlay is a route table: at its cap it refuses and evicts nobody.
    #[test]
    fn a_route_table_refuses_at_its_cap_and_evicts_nobody() {
        let admission = SignalAdmission::new_route_table(2);
        let hub = hub();
        assert_eq!(
            admission.room(),
            2,
            "the table has room for two routes at its cap"
        );
        let one = admission.try_admit(peer(1), &hub).expect("first admit");
        let two = admission.try_admit(peer(2), &hub).expect("second admit");
        assert_eq!(admission.room(), 0, "the rounds in flight count");
        assert_eq!(
            admission.try_admit(peer(3), &hub).unwrap_err(),
            Refusal::AtCapacity,
            "a route at the cap is refused and no one is evicted"
        );
        // The first round ends in a session: its unit counts, and the third peer is still refused.
        admission.note_success(peer(1));
        drop(one);
        assert_eq!(admission.room(), 0, "one unit and one round in flight");
        assert_eq!(
            admission.try_admit(peer(3), &hub).unwrap_err(),
            Refusal::AtCapacity,
            "the refusal at the cap holds on a second try"
        );
        // The second round fails: its room is free again, and nobody was evicted.
        drop(two);
        assert_eq!(
            admission.room(),
            1,
            "one route of room is left after one admit"
        );
        let _three = admission.try_admit(peer(3), &hub).expect("room again");
        assert_eq!(
            admission.try_admit(peer(4), &hub).unwrap_err(),
            Refusal::AtCapacity,
            "peer 4 is refused once the table is full"
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
            Refusal::Cooling,
            "a refused peer waits out its cooldown"
        );
        // Unrelated peers are unaffected.
        assert!(
            admission.try_admit(peer(2), &hub).is_ok(),
            "peer 2 is admitted while peer 1 cools down"
        );
    }

    #[test]
    fn close_refuses_everything_afterwards() {
        let admission = SignalAdmission::new(16);
        let hub = hub();
        admission.close();
        assert_eq!(
            admission.try_admit(peer(1), &hub).unwrap_err(),
            Refusal::ShuttingDown,
            "a closed table refuses every peer as shutting down"
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
        assert_eq!(
            admission.in_flight(),
            1,
            "one slot is still held before the task is aborted"
        );

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
    // the fake hub is shared by its handles
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
            let live = self.0.lock().expect("fake hub");
            live.iter().copied().collect()
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
        assert!(
            hub.has_session(&peer(2)) && hub.has_session(&peer(3)),
            "peers 2 and 3 keep their sessions and the least recently used one goes"
        );
        assert_eq!(
            admission.direct_units(),
            2,
            "two direct units remain after the third session"
        );
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
        assert_eq!(
            admission.direct_units(),
            ceiling,
            "the direct units stay at the ceiling"
        );
        assert_eq!(
            admission.over_ceiling(),
            0,
            "no session is over the ceiling"
        );
    }

    /// Glare: our offer to a peer is given up for the offer of that peer. The guard of the offer
    /// that was given up must not release the round that took its place.
    #[test]
    fn a_preempted_offer_does_not_release_the_round_that_replaced_it() {
        let admission = SignalAdmission::new(8);
        let hub = FakeHub::default();
        let offer = admission.try_admit_offer(peer(1), &hub).expect("offer");
        assert!(admission.preempt_offer(peer(1)), "our offer is given up");
        assert_eq!(
            admission.in_flight(),
            0,
            "the slot taken by the replacing round stays in flight"
        );

        let answer = admission
            .try_admit(peer(1), &hub)
            .expect("the peer's offer");
        drop(offer);
        assert_eq!(admission.in_flight(), 1, "the answer keeps its slot");
        drop(answer);
        assert_eq!(
            admission.in_flight(),
            0,
            "no slot is in flight after the preempted offer is released"
        );
    }

    /// A round that answers an offer is never given up for another offer of the same peer.
    #[test]
    fn a_round_that_answers_is_not_preempted() {
        let admission = SignalAdmission::new(8);
        let hub = FakeHub::default();
        let _answer = admission.try_admit(peer(1), &hub).expect("answer");
        assert!(
            !admission.preempt_offer(peer(1)),
            "an answered round is not preempted"
        );
        assert_eq!(
            admission.in_flight(),
            1,
            "one slot is still in flight after the round answers"
        );
        assert_eq!(
            admission.try_admit(peer(1), &hub).unwrap_err(),
            Refusal::InFlight,
            "a peer with an answered round is refused as in flight"
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

        assert!(
            admission.lock().slots.is_empty(),
            "the table holds no slot after the drop"
        );
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
        assert_eq!(
            inner.take_idle(start + window, window),
            vec![peer(1)],
            "peer 1 is the only idle session after the window"
        );
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
        assert!(
            inner.take_idle(start, window).is_empty(),
            "no session idles while a round is in flight"
        );
        assert!(
            inner.take_idle(start + window * 3, window).is_empty(),
            "a round in flight still keeps the session from idling after three windows"
        );
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
        assert!(
            inner.take_idle(start, window).is_empty(),
            "a peer with no session is never idle"
        );
        assert!(
            inner.take_idle(start + window * 3, window).is_empty(),
            "a peer with no session is not idle after three windows"
        );
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
        assert!(
            backoff.on_cooldown(&bob, start + first.saturating_sub(Duration::from_secs(1))),
            "the cooldown is still on one second before its length ends"
        );
        assert!(
            !backoff.on_cooldown(&bob, start + first),
            "the cooldown is over at its length"
        );

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
        assert_eq!(
            window, longest,
            "the wait reaches the longest window after the doubling"
        );

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
        assert!(
            backoff.on_cooldown(&peer(1), now),
            "a refused peer waits on its own cooldown"
        );
        assert!(
            !backoff.on_cooldown(&peer(2), now),
            "a refusal does not make peer 2 wait"
        );
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
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                connection.closed().await;
                Ok(())
            }
        }
        let (relay_url, _relay_server) = test_relay::spawn_plain().await.expect("local relay");
        let bind = |hook: Option<ConnectionHook>| {
            let relay_url = relay_url.clone();
            async move {
                let mut builder: iroh::endpoint::Builder =
                    iroh::Endpoint::builder(presets::Minimal)
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
        let connection = client
            .connect(relayed, iroh_gossip::net::GOSSIP_ALPN)
            .await
            .expect("dial over the relay");
        let window = tuning::DIRECT_IDLE_BACKSTOP;
        let start = Instant::now();

        assert!(
            admission.lock().take_idle(start, window).is_empty(),
            "no session is idle on a fresh table"
        );
        assert!(
            admission
                .lock()
                .take_idle(start + window * 3, window)
                .is_empty(),
            "a live connection holds the session"
        );

        connection.close(0u32.into(), b"done");
        connection.closed().await;
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
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                connection.closed().await;
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
        let connection = client
            .connect(relayed, iroh_gossip::net::GOSSIP_ALPN)
            .await
            .expect("dial over the relay");

        let closed = tokio::time::timeout(Duration::from_secs(25), connection.closed()).await;

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
                async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                    let reason = connection.closed().await;
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
            let connection = self
                .node
                .connect(relayed, super::super::UNICAST_ALPN)
                .await
                .expect("dial over the relay");
            self.servers.push((server, router));
            (id, connection)
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
        assert_eq!(
            close.error_code.into_inner(),
            u64::from(EVICTED),
            "the least recently used connection is closed with the evicted code"
        );
        assert!(
            fixture
                .next_closed(Duration::from_millis(500))
                .await
                .is_none(),
            "exactly one eviction"
        );
        for (_, connection) in &conns[1..] {
            assert!(connection.close_reason().is_none(), "the others stay open");
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
        assert_eq!(
            fixture.admission.direct_units(),
            4,
            "a closed connection leaves the ledger at four units"
        );

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
        assert_eq!(
            fixture.admission.over_ceiling(),
            1,
            "the newcomer is over the ceiling by one"
        );

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
        use habilis_network_iroh_gossip_transport::hub::Hub;
        use habilis_network_iroh_gossip_transport::{GossipHandle, gossip_addr};
        use iroh::endpoint::ConnectionError;
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};
        use iroh::{EndpointAddr, RelayMode, SecretKey, TransportAddr};

        #[derive(Debug, Clone)]
        // the report is shared with the hook, which sends through it
        struct Report(Arc<Mutex<Option<oneshot::Sender<ConnectionError>>>>);
        impl ProtocolHandler for Report {
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                let reason = connection.closed().await;
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
            let builder = iroh::Endpoint::builder(presets::Minimal);
            let builder = builder.secret_key(key);
            let builder = builder.relay_mode(RelayMode::Disabled);
            let builder = builder.add_custom_transport(handle.custom_transport());
            let builder = builder.clear_ip_transports();
            let builder = builder.clear_relay_transports();
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
                // the report is shared with the hook, which sends through it
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
            sampler::gossip_view(&[]),
            (false, true),
            "no connection: a handshake"
        );
        assert_eq!(
            sampler::gossip_view(&[Relay]),
            (true, true),
            "a relay link reads as gossip view (true, true)"
        );
        assert_eq!(
            sampler::gossip_view(&[Gossip]),
            (true, true),
            "a gossip link reads as gossip view (true, true)"
        );
        assert_eq!(
            sampler::gossip_view(&[PathKind::None]),
            (true, true),
            "no path selected yet"
        );
        assert_eq!(
            sampler::gossip_view(&[Ip]),
            (true, false),
            "an ip link reads as gossip view (true, false)"
        );
        assert_eq!(
            sampler::gossip_view(&[WebRtc]),
            (true, false),
            "a webrtc link reads as gossip view (true, false)"
        );
        assert_eq!(
            sampler::gossip_view(&[Multihop, Gossip]),
            (true, false),
            "a multihop link beside gossip reads as gossip view (true, false)"
        );
        assert_eq!(
            sampler::gossip_view(&[Relay, Ip]),
            (true, false),
            "the best connection stands for the pair"
        );
    }

    /// An endpoint with a loopback UDP socket and the gossip transport, whose connections are
    /// reported to its own table, which keeps the gossip handle.
    async fn ip_and_gossip_node(
        seed: u8,
        hub: &habilis_network_iroh_gossip_transport::hub::Hub,
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
        let transport = handle.custom_transport();
        let selector = handle.path_selector();
        let hook = admission.connection_hook();
        let base = iroh::Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled);
        let mut builder: iroh::endpoint::Builder = base
            .add_custom_transport(transport)
            .path_selector(selector)
            .hooks(hook);
        builder = if with_ip {
            builder
                .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
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
        use habilis_network_iroh_gossip_transport;
        use habilis_network_iroh_gossip_transport::hub::Hub;
        use iroh::{EndpointAddr, TransportAddr};

        let hub = Hub::new();
        let (alice, alice_table, alice_handle) = ip_and_gossip_node(41, &hub, true).await;
        let (bob, bob_table, bob_handle) = ip_and_gossip_node(42, &hub, true).await;
        let router = iroh::protocol::Router::builder(bob.clone())
            .accept(GOSSIP_TEST_ALPN, HoldConnections)
            .spawn();
        let both = bob.addr().addrs.into_iter().chain([TransportAddr::Custom(
            habilis_network_iroh_gossip_transport::gossip_addr(bob.id()),
        )]);
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
        use habilis_network_iroh_gossip_transport;
        use habilis_network_iroh_gossip_transport::hub::Hub;
        use iroh::{EndpointAddr, TransportAddr};

        let hub = Hub::new();
        let (alice, alice_table, alice_handle) = ip_and_gossip_node(43, &hub, false).await;
        let (bob, _bob_table, _bob_handle) = ip_and_gossip_node(44, &hub, false).await;
        let router = iroh::protocol::Router::builder(bob.clone())
            .accept(GOSSIP_TEST_ALPN, HoldConnections)
            .spawn();
        let connection = alice
            .connect(
                EndpointAddr::from_parts(
                    bob.id(),
                    [TransportAddr::Custom(
                        habilis_network_iroh_gossip_transport::gossip_addr(bob.id()),
                    )],
                ),
                GOSSIP_TEST_ALPN,
            )
            .await
            .expect("connect over gossip");

        alice_table.sync_gossip();
        assert!(
            alice_handle.is_established(bob.id()),
            "a pair on gossip is allowed to establish and the gone peer is forgotten"
        );
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
        use habilis_network_iroh_gossip_transport;
        use habilis_network_iroh_gossip_transport::hub::Hub;
        use iroh::{EndpointAddr, TransportAddr};

        let hub = Hub::new();
        let (alice, alice_table, alice_handle) = ip_and_gossip_node(45, &hub, false).await;
        let (bob, _bob_table, _bob_handle) = ip_and_gossip_node(46, &hub, false).await;
        let sessions = FakeHub::default();
        // the table keeps the hub as a shared trait object
        alice_table.lock().hub = Some(Arc::new(sessions.clone()));
        let router = iroh::protocol::Router::builder(bob.clone())
            .accept(GOSSIP_TEST_ALPN, HoldConnections)
            .spawn();
        let connection = alice
            .connect(
                EndpointAddr::from_parts(
                    bob.id(),
                    [TransportAddr::Custom(
                        habilis_network_iroh_gossip_transport::gossip_addr(bob.id()),
                    )],
                ),
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
        use habilis_network_iroh_gossip_transport;
        use habilis_network_iroh_gossip_transport::hub::Hub;
        use iroh::{EndpointAddr, TransportAddr};

        let hub = Hub::new();
        let (alice, alice_table, alice_handle) = ip_and_gossip_node(47, &hub, false).await;
        let (bob, _bob_table, _bob_handle) = ip_and_gossip_node(48, &hub, false).await;
        let sessions = FakeHub::default();
        // the table keeps the hub as a shared trait object
        alice_table.lock().hub = Some(Arc::new(sessions.clone()));
        let router = iroh::protocol::Router::builder(bob.clone())
            .accept(GOSSIP_TEST_ALPN, HoldConnections)
            .spawn();
        let connection = alice
            .connect(
                EndpointAddr::from_parts(
                    bob.id(),
                    [TransportAddr::Custom(
                        habilis_network_iroh_gossip_transport::gossip_addr(bob.id()),
                    )],
                ),
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
