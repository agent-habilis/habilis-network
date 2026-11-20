//! A graft request and the peer it targets.

use iroh::EndpointId;

use crate::daemon::state::EventLoopState;
use crate::util::clock::Instant;

use crate::transport;
/// How a graft asks for a link.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum GraftRequest {
    /// Always accepted: a peer with a full view drops a neighbor to make room.
    Join,
    /// Low priority: a peer with a full view refuses and keeps its neighbors.
    Neighbor,
    /// High priority, to this one peer: it makes a peer with a full view drop exactly one neighbor,
    /// and starts no walk. For a node short of G that gained no link for its window.
    Force,
    /// No request: the peer refused lately and its wait runs.
    Skip,
}

/// The peer that a graft asks for, and the rendezvous it is told apart from: the rendezvous is
/// asked with a `Join`, and a swap of the two compiles, since both are an `EndpointId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GraftTarget {
    pub(crate) peer: EndpointId,
    pub(crate) rendezvous: EndpointId,
}

/// The request that grafts `peer`. The rendezvous gets a `Join`, because a low
/// priority request to a peer that holds a tombstone for us is refused for ever.
/// Every other graft only fills a view, and must not make a full one drop a neighbor.
///
/// A peer that refused a `Neighbor` request lately is skipped by a paced graft, for the wait of
/// its backoff (`GraftBackoff`). The `PeerInfo` graft is not held, but its request is recorded
/// too, so that its silence reads as a refusal.
///
/// A node that holds fewer than G links and gained none for its window (`FORCE_NEIGHBOR_AFTER`,
/// doubled for each forced request of its streak up to `STARVED`, then stretched by its jitter, so
/// at most 1.5 times `STARVED`) asks one peer with a `Force` instead, at most once per window: when
/// two members are one link short and linked to each other, every other member is full and refuses
/// every low priority request, and the backoffs of the free peers overlap, so a rule that waits for
/// them all would never fire.
///
/// When the links of all the members add up to an odd number, one member stays one link short and
/// no member can fill it: a forced request only moves that gap to the member that lost a link. The
/// doubling does not stop this, because the node that loses the link has no streak of its own. So
/// the live member with the greatest endpoint does not force when it is one link short
/// (`is_anchor`): the gap walks until it reaches that member, and stays. In the advisor model the
/// walk takes about one forced request per member, 75 to 105 s each. The same rule slows the case
/// of two short members when one of them is the anchor, because only the other can force: by up to
/// 27 min at the worst in that model (a mesh of G plus 2 members). A member that thinks it is the
/// anchor in a split roster, and a member that is silent but listed, do not make a deadlock: a
/// linked pair cannot both be the greatest. With members of different caps the gap is bounded by
/// the doubling, not removed.
///
/// A low priority request evicts nobody, so a node that arrives when every other node is
/// full gets no link from it. A `paced` graft (the fill tick, a proven direct path) asks
/// with a `Join` instead when the node is starved: it held two or more links fewer than G
/// for `STARVED`, at most once per `STARVED`. A `PeerInfo` graft is not paced.
pub(crate) fn graft_request(
    state: &mut EventLoopState,
    target: GraftTarget,
    max_connections: usize,
    now: Instant,
    paced: bool,
) -> GraftRequest {
    let GraftTarget {
        peer,
        rendezvous: rendezvous_id,
    } = target;
    if peer == rendezvous_id {
        return GraftRequest::Join;
    }
    state.note_link_count(state.linked_endpoints.len(), max_connections, now);
    if paced && state.starved_join_due(now) {
        // A `Join` is not refused, so it ignores the backoff of the peer.
        GraftRequest::Join
    } else if paced && state.forced_neighbor_due(now) {
        tracing::info!(target: transport::LOG_TARGET, %peer, linked = state.linked_endpoints.len(), "short of G with no link gained: forcing one neighbor");
        // A forced request that brings no link is read as a refusal, like any other ask.
        state.graft_backoff.asked(peer, now);
        GraftRequest::Force
    } else if paced && state.graft_backoff.is_blocked(&peer, now) {
        tracing::debug!(target: transport::LOG_TARGET, %peer, "graft skipped: the peer refused lately");
        GraftRequest::Skip
    } else {
        state.graft_backoff.asked(peer, now);
        GraftRequest::Neighbor
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{GraftRequest, GraftTarget, graft_request};
    use crate::daemon::state::EventLoopState;
    use crate::testing;
    use crate::util::clock::Instant;
    use crate::util::tuning::{FORCE_NEIGHBOR_AFTER, STARVED};

    const TARGET: usize = 4;

    /// The spread of the backoff jitter, fixed: 0.0 makes the first wait exactly 60 s, where a
    /// random spread makes it 48 to 72 s and a second ask 90 s after the first can find it unexpired.
    const BACKOFF_SPREAD: f64 = 0.0;

    /// A node with `links` links that has been short of G since `start`, and whose window has no
    /// jitter.
    fn short_node(links: usize, start: Instant) -> EventLoopState {
        let mut state = testing::fresh_state();
        for seed in 0..links {
            state.link(testing::endpoint_id(
                u8::try_from(seed).expect("a small seed") + 10,
            ));
        }
        state.force_jitter = 0.0;
        state.note_link_count(links, TARGET, start);
        state
    }

    fn target(peer: u8) -> GraftTarget {
        GraftTarget {
            peer: testing::endpoint_id(peer),
            rendezvous: testing::endpoint_id(99),
        }
    }

    /// `peer` is asked at `at`, and its silence is read as a refusal 21 s later: the peer is left
    /// alone for the first wait of the backoff after that.
    fn refuse_at(state: &mut EventLoopState, peer: u8, at: Instant) {
        assert_eq!(
            graft_request(state, target(peer), TARGET, at, true),
            GraftRequest::Neighbor,
            "an ask of a peer that did not refuse is a low priority request"
        );
        let linked = &state.linked_endpoints;
        state.graft_backoff.settle(
            at + Duration::from_secs(21),
            |endpoint| linked.contains(endpoint),
            BACKOFF_SPREAD,
        );
    }

    #[test]
    fn a_forced_request_is_recorded_so_that_its_silence_reads_as_a_refusal() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET - 1, start);
        let due = start + FORCE_NEIGHBOR_AFTER;
        assert_eq!(
            graft_request(&mut state, target(1), TARGET, due, true),
            GraftRequest::Force,
            "the window ends, so the first request is forced"
        );
        let linked = &state.linked_endpoints;
        state.graft_backoff.settle(
            due + Duration::from_secs(21),
            |endpoint| linked.contains(endpoint),
            BACKOFF_SPREAD,
        );
        assert!(
            state
                .graft_backoff
                .is_blocked(&testing::endpoint_id(1), due + Duration::from_secs(21)),
            "a peer that got no link from a forced request is left alone for the first wait"
        );
    }

    #[test]
    fn each_forced_request_doubles_the_window_up_to_starved_and_a_full_view_resets_it() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET - 1, start);
        let mut now = start + FORCE_NEIGHBOR_AFTER;
        let mut windows = Vec::new();
        for _ in 0..4 {
            windows.push(state.force_window());
            assert!(
                state.forced_neighbor_due(now),
                "the request is due when its window ends"
            );
            now += state.force_window();
        }
        assert_eq!(
            windows,
            [
                FORCE_NEIGHBOR_AFTER,
                FORCE_NEIGHBOR_AFTER * 2,
                FORCE_NEIGHBOR_AFTER * 4,
                STARVED
            ],
            "the window doubles with each forced request and stops at STARVED"
        );
        assert_eq!(state.force_window(), STARVED, "the cap holds");
        state.note_link_count(TARGET, TARGET, now);
        assert_eq!(
            state.force_window(),
            FORCE_NEIGHBOR_AFTER,
            "a view at G starts the window over"
        );
    }

    #[test]
    fn a_second_forced_request_waits_for_the_doubled_window() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET - 1, start);
        let due = start + FORCE_NEIGHBOR_AFTER;
        assert_eq!(
            graft_request(&mut state, target(1), TARGET, due, true),
            GraftRequest::Force,
            "the window ends, so the first request is forced"
        );
        let gained = due + Duration::from_secs(1);
        let held = testing::endpoint_id(12);
        state.unlink(held);
        state.link(held);
        state.note_link_count(TARGET - 1, TARGET, gained);
        let one_window = gained + FORCE_NEIGHBOR_AFTER;
        assert_ne!(
            graft_request(&mut state, target(2), TARGET, one_window, true),
            GraftRequest::Force,
            "one plain window after a forced request is not enough"
        );
        let two_windows = gained + FORCE_NEIGHBOR_AFTER * 2;
        assert_eq!(
            graft_request(&mut state, target(2), TARGET, two_windows, true),
            GraftRequest::Force,
            "the doubled window is"
        );
    }

    #[test]
    fn a_node_one_link_short_forces_one_neighbor_when_the_free_peer_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET - 1, start);
        refuse_at(&mut state, 1, start);
        let due = start + FORCE_NEIGHBOR_AFTER;
        assert!(
            state
                .graft_backoff
                .is_blocked(&testing::endpoint_id(1), due),
            "the peer is still in its wait when the window ends"
        );
        assert_eq!(
            graft_request(&mut state, target(1), TARGET, due, true),
            GraftRequest::Force,
            "a node at TARGET - 1 links, short for the window, asks the refusing peer with a high priority request"
        );
    }

    #[test]
    fn a_starved_node_with_both_due_joins_and_does_not_force() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET - 2, start);
        let due = start + STARVED;
        assert_eq!(
            graft_request(&mut state, target(1), TARGET, due, true),
            GraftRequest::Join,
            "at TARGET - 2 links the starved Join keeps its precedence over the forced request"
        );
        assert!(
            state.forced_neighbor_at.is_none(),
            "a Join does not use up the window of the forced request"
        );
    }

    #[test]
    fn no_forced_neighbor_before_the_window_ends() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET - 1, start);
        refuse_at(&mut state, 1, start);
        let early = start + FORCE_NEIGHBOR_AFTER.saturating_sub(Duration::from_secs(1));
        assert_eq!(
            graft_request(&mut state, target(1), TARGET, early, true),
            GraftRequest::Skip,
            "inside the window the refused peer is left alone"
        );
    }

    #[test]
    fn no_forced_neighbor_at_g_links() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET, start);
        refuse_at(&mut state, 1, start);
        let due = start + FORCE_NEIGHBOR_AFTER;
        assert_eq!(
            graft_request(&mut state, target(1), TARGET, due, true),
            GraftRequest::Skip,
            "a full view asks nobody with a high priority request"
        );
    }

    #[test]
    fn a_free_peer_that_did_not_refuse_gets_the_low_priority_request_before_the_window_ends() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET - 1, start);
        refuse_at(&mut state, 1, start);
        let early = start + FORCE_NEIGHBOR_AFTER.saturating_sub(Duration::from_secs(1));
        assert_eq!(
            graft_request(&mut state, target(2), TARGET, early, true),
            GraftRequest::Neighbor,
            "a peer that did not refuse is asked the soft way while the window runs"
        );
    }

    #[test]
    fn a_node_one_link_short_forces_even_when_a_free_peer_is_out_of_its_wait() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET - 1, start);
        refuse_at(&mut state, 1, start);
        let due = start + FORCE_NEIGHBOR_AFTER;
        assert_eq!(
            graft_request(&mut state, target(2), TARGET, due, true),
            GraftRequest::Force,
            "the window says the soft asks failed, so the peer picked is forced, refused or not"
        );
    }

    #[test]
    fn a_graft_that_is_not_paced_never_forces() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET - 1, start);
        let due = start + FORCE_NEIGHBOR_AFTER;
        assert_eq!(
            graft_request(&mut state, target(1), TARGET, due, false),
            GraftRequest::Neighbor,
            "a PeerInfo graft is not paced"
        );
    }

    #[test]
    fn a_node_forces_one_neighbor_per_window() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET - 1, start);
        refuse_at(&mut state, 1, start);
        let due = start + FORCE_NEIGHBOR_AFTER;
        assert_eq!(
            graft_request(&mut state, target(1), TARGET, due, true),
            GraftRequest::Force,
            "the first call of the window forces"
        );
        assert_eq!(
            graft_request(
                &mut state,
                target(1),
                TARGET,
                due + Duration::from_secs(1),
                true
            ),
            GraftRequest::Skip,
            "a second call inside the window does not"
        );
        let doubled = FORCE_NEIGHBOR_AFTER * 2;
        let next = due + doubled;
        let refused_again = due + doubled.saturating_sub(Duration::from_secs(30));
        refuse_at(&mut state, 1, refused_again);
        assert_eq!(
            graft_request(&mut state, target(1), TARGET, next, true),
            GraftRequest::Force,
            "the next window, doubled, forces again"
        );
    }

    #[test]
    fn a_gained_link_restarts_the_window() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET - 2, start);
        refuse_at(&mut state, 1, start);
        let gained = start + Duration::from_secs(30);
        state.link(testing::endpoint_id(77));
        state.note_link_count(TARGET - 1, TARGET, gained);
        let due = start + FORCE_NEIGHBOR_AFTER;
        assert_eq!(
            graft_request(&mut state, target(1), TARGET, due, true),
            GraftRequest::Skip,
            "the window counts from the last link gained"
        );
    }

    /// Four endpoints in the order of their ids, smallest first: an id is the public half of a key,
    /// so the order of the seeds says nothing about it.
    fn ids_in_order() -> [iroh::EndpointId; 4] {
        let mut ids: Vec<iroh::EndpointId> = (10..14).map(testing::endpoint_id).collect();
        ids.sort_unstable();
        <[iroh::EndpointId; 4]>::try_from(ids).expect("four ids")
    }

    /// A node one link short since `start`, whose endpoint is `own` and whose roster holds the
    /// members `others`, each heard at `start`.
    fn anchor_node(
        start: Instant,
        own: iroh::EndpointId,
        others: &[(&str, iroh::EndpointId)],
    ) -> EventLoopState {
        let mut state = short_node(TARGET - 1, start);
        state.own_endpoint = Some(own);
        for (nickname, endpoint) in others {
            state.live_member_for_test(nickname, *endpoint, start);
        }
        state
    }

    #[test]
    fn the_greatest_live_member_short_by_one_does_not_force() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let [low, middle, high, _] = ids_in_order();
        let late = start + FORCE_NEIGHBOR_AFTER * 2;
        let state = anchor_node(start, high, &[("low-a", low), ("low-b", middle)]);
        assert!(
            !state.forced_neighbor_ready(late),
            "the last gap stays where it is: no member can fill it"
        );
        let mut two_short = anchor_node(start, high, &[("low-a", low), ("low-b", middle)]);
        two_short.note_link_count(TARGET - 2, TARGET, start);
        assert!(
            two_short.forced_neighbor_ready(start + FORCE_NEIGHBOR_AFTER),
            "the same node, short by two, is not holding the last gap"
        );
    }

    #[test]
    fn a_member_that_is_not_the_greatest_forces_when_short_by_one() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let [low, middle, high, _] = ids_in_order();
        let state = anchor_node(start, middle, &[("low-a", low), ("high", high)]);
        assert!(
            state.forced_neighbor_ready(start + FORCE_NEIGHBOR_AFTER),
            "the other of two short members forces, and the anchor keeps its gap"
        );
    }

    #[test]
    fn a_greater_member_that_was_not_seen_alive_lately_is_no_anchor() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let [low, middle, high, _] = ids_in_order();
        let late = start + STARVED + FORCE_NEIGHBOR_AFTER * 2;
        let mut state = anchor_node(start, middle, &[]);
        state.live_member_for_test("low-a", low, start + STARVED);
        state.live_member_for_test("gone", high, start);
        assert!(
            !state.forced_neighbor_ready(late),
            "a member that was silent for STARVED does not make this node a forcing one"
        );
    }

    #[test]
    fn a_new_record_of_links_starts_the_doubling_over_and_a_repeat_does_not() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET - 2, start);
        assert!(
            state.forced_neighbor_due(start + FORCE_NEIGHBOR_AFTER),
            "the first request is due when the window ends"
        );
        assert_eq!(state.force_streak, 1, "a forced request counts");
        state.link(testing::endpoint_id(77));
        assert_eq!(
            state.force_streak, 0,
            "a link beyond the most held starts over"
        );
        state.note_link_count(TARGET - 1, TARGET, start + FORCE_NEIGHBOR_AFTER);
        assert!(
            state.forced_neighbor_due(start + FORCE_NEIGHBOR_AFTER * 4),
            "after the new record the window is the plain one"
        );
        state.unlink(testing::endpoint_id(77));
        state.link(testing::endpoint_id(78));
        assert_eq!(
            state.force_streak, 1,
            "a link that only restores the count held before is no record"
        );
    }

    #[test]
    fn the_cap_comes_before_the_jitter() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut plain = short_node(TARGET - 1, start);
        let mut spread = short_node(TARGET - 1, start);
        spread.force_jitter = 0.5;
        plain.force_streak = 4;
        spread.force_streak = 4;
        assert_eq!(
            plain.force_window(),
            STARVED,
            "a node with no jitter waits for the cap"
        );
        assert_eq!(
            spread.force_window(),
            STARVED.mul_f64(1.5),
            "two nodes at the cap still wait for different times"
        );
    }

    #[test]
    fn the_anchor_short_by_one_sends_no_forced_request_for_three_starved_windows() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let [low, middle, high, _] = ids_in_order();
        let mut state = anchor_node(start, high, &[("low-a", low), ("low-b", middle)]);
        let mut now = start;
        while now < start + STARVED * 3 {
            assert_ne!(
                graft_request(&mut state, target(1), TARGET, now, true),
                GraftRequest::Force,
                "the last gap of an odd mesh does not chase a link"
            );
            now += Duration::from_secs(30);
        }
    }

    #[test]
    fn a_member_that_lost_every_link_starts_the_record_over_when_it_comes_back() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = short_node(TARGET - 1, start);
        assert!(
            state.forced_neighbor_due(start + FORCE_NEIGHBOR_AFTER),
            "the request is due when the window ends"
        );
        assert_eq!(state.force_streak, 1, "a forced request counts");
        for seed in 0..TARGET - 1 {
            state.unlink(testing::endpoint_id(
                u8::try_from(seed).expect("a small seed") + 10,
            ));
        }
        state.link(testing::endpoint_id(10));
        assert_eq!(
            state.force_streak, 0,
            "the first link of a member that lost every link is a new record"
        );
    }
}
