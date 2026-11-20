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
    /// and starts no walk. For a node one link short whose free peers all refused.
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
/// A node that holds fewer than G links and gained none for `FORCE_NEIGHBOR_AFTER` asks one peer
/// with a `Force` instead, at most once per window: when two members are one link short and linked
/// to each other, every other member is full and refuses every low priority request, and the
/// backoffs of the free peers overlap, so a rule that waits for them all would never fire.
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
        state.settle_graft_backoff(at + Duration::from_secs(21));
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
            graft_request(&mut state, target(1), TARGET, due + Duration::from_secs(1), true),
            GraftRequest::Skip,
            "a second call inside the window does not"
        );
        let next = due + FORCE_NEIGHBOR_AFTER;
        let refused_again = due + FORCE_NEIGHBOR_AFTER.saturating_sub(Duration::from_secs(30));
        refuse_at(&mut state, 1, refused_again);
        assert_eq!(
            graft_request(&mut state, target(1), TARGET, next, true),
            GraftRequest::Force,
            "the next window forces again"
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
}
