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
/// A low priority request evicts nobody, so a node that arrives when every other node is
/// full gets no link from it. A `paced` graft (the fill tick, a proven direct path) asks
/// with a `Join` instead when the node is starved, at most once per `STARVED`: it held fewer
/// than G peers for `STARVED`, and it is 2 or more peers short, or 1 short and a peer refused
/// it (`GraftBackoff::has_refusal`). A `PeerInfo` graft is not paced.
///
/// The `Join` ignores the backoff, whose wait can reach `GRAFT_BACKOFF_MAX` (15 minutes) and
/// so outlasts the clock of 5 minutes. When 2 nodes that are 1 peer short each hold a backoff on
/// the other, neither `Neighbor` request goes out during the wait, but each `Join` goes out
/// when its clock runs out. A `Join` to a peer with a free slot evicts nobody and links the 2.
///
/// A `Join` to a full peer evicts one neighbor of it, and the `ForwardJoin` walk that it
/// starts ends in a `Neighbor` request of high priority at up to G - 1 more peers, so a `Join`
/// can make up to 1 + 2(G - 1) peers drop a link. Each peer that dropped one is 1 peer short.
/// A node that is 1 peer short by structure (the sum of the caps is odd, or the 2 nodes that
/// are short are linked to each other) asks 1 `Join` per `STARVED` for ever.
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
    state.note_link_count(max_connections, now);
    if paced && state.starved_join_due(now) {
        // A `Join` is not refused, so it ignores the backoff of the peer.
        GraftRequest::Join
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

    use iroh::EndpointId;

    use super::{GraftRequest, GraftTarget, graft_request};
    use crate::daemon::state::EventLoopState;
    use crate::testing::{endpoint_id, fresh_state};
    use crate::util::clock::Instant;
    use crate::util::tuning::{GRAFT_REFUSED_AFTER, STARVED};

    const MAX_CONNECTIONS: usize = 4;
    const SECOND: Duration = Duration::from_secs(1);

    fn rendezvous() -> EndpointId {
        endpoint_id(1)
    }

    /// A state that holds a link to each of `peers` peers, of the `MAX_CONNECTIONS` that it
    /// wants, and to the rendezvous too when `with_rendezvous`. The rendezvous takes no slot.
    fn state_with_links(peers: u8, with_rendezvous: bool) -> EventLoopState {
        let mut state = fresh_state();
        state.rendezvous_id = Some(rendezvous());
        for seed in 10..10 + peers {
            state.linked_endpoints.insert(endpoint_id(seed));
        }
        if with_rendezvous {
            state.linked_endpoints.insert(rendezvous());
        }
        state
    }

    fn ask(state: &mut EventLoopState, peer: EndpointId, now: Instant) -> GraftRequest {
        let target = GraftTarget {
            peer,
            rendezvous: rendezvous(),
        };
        graft_request(state, target, MAX_CONNECTIONS, now, true)
    }

    /// Every candidate gets a `Neighbor` request at `start`, and none of them links: after
    /// `GRAFT_REFUSED_AFTER` the backoff reads each one as a refusal.
    fn all_candidates_refuse(state: &mut EventLoopState, start: Instant) -> [EndpointId; 3] {
        let candidates = [endpoint_id(2), endpoint_id(3), endpoint_id(4)];
        for candidate in candidates {
            assert_eq!(
                ask(state, candidate, start),
                GraftRequest::Neighbor,
                "a first request to a candidate is a Neighbor request"
            );
        }
        state.settle_graft_backoff(start + GRAFT_REFUSED_AFTER);
        assert_eq!(
            ask(state, candidates[0], start + GRAFT_REFUSED_AFTER + SECOND),
            GraftRequest::Skip,
            "the refusal is read: the candidate waits"
        );
        candidates
    }

    /// A node at G - 1 peers whose every candidate refused it, for `STARVED`, asks 1 `Join`, and
    /// its clock starts again. The 2 nodes that are linked to each other at G - 1 reach no other
    /// link in any other way: each `Neighbor` request goes to a peer with a full view.
    #[test]
    fn a_node_at_g_minus_one_with_all_grafts_refused_for_five_minutes_asks_one_join() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = state_with_links(3, false);
        let start = Instant::now();
        let candidates = all_candidates_refuse(&mut state, start);

        assert_eq!(
            ask(&mut state, candidates[1], start + STARVED),
            GraftRequest::Join,
            "G - 1 peers, every candidate refused, for STARVED: one Join"
        );
        assert_ne!(
            ask(&mut state, candidates[2], start + STARVED + SECOND),
            GraftRequest::Join,
            "the Join restarted the clock: no second Join at once"
        );
        assert_eq!(
            ask(&mut state, candidates[2], start + STARVED * 2),
            GraftRequest::Join,
            "STARVED after the Join, the node is still short and refused: the next Join"
        );
    }

    /// The link to the rendezvous takes no slot of the engine, so a node that holds G - 1 peers
    /// and the rendezvous is at G - 1, not at G.
    #[test]
    fn the_link_to_the_rendezvous_is_not_one_of_the_g_links() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = state_with_links(3, true);
        let start = Instant::now();
        let candidates = all_candidates_refuse(&mut state, start);

        assert_eq!(
            ask(&mut state, candidates[1], start + STARVED),
            GraftRequest::Join,
            "3 peers and the rendezvous is G - 1 peers: starved"
        );
    }

    /// Control: a node at G - 1 that no candidate refused keeps asking with `Neighbor`. It is
    /// not stuck, so it makes no member of a full view drop a neighbor.
    #[test]
    fn a_node_at_g_minus_one_that_no_peer_refused_never_asks_a_join() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = state_with_links(3, false);
        let start = Instant::now();
        let candidate = endpoint_id(2);

        for step in 0..=2_u32 {
            assert_eq!(
                ask(&mut state, candidate, start + STARVED * step),
                GraftRequest::Neighbor,
                "step {step}: no refusal is read, so a Neighbor request goes out"
            );
        }
    }

    /// Control: a node at G - 2 asks 1 `Join` after `STARVED`, with or without a refusal.
    #[test]
    fn a_node_at_g_minus_two_asks_a_join_after_five_minutes_without_a_refusal() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = state_with_links(2, false);
        let start = Instant::now();
        let candidate = endpoint_id(2);

        assert_eq!(
            ask(&mut state, candidate, start),
            GraftRequest::Neighbor,
            "the clock has not run yet"
        );
        assert_eq!(
            ask(&mut state, candidate, start + STARVED),
            GraftRequest::Join,
            "2 peers short for STARVED: one Join, with no refusal read"
        );
    }

    /// Pins the accepted cost of the rule: a node that stays 1 peer short and refused, as the
    /// sum of the caps is odd or the 2 short nodes are linked to each other, asks 1 `Join` per
    /// `STARVED` for ever, and none in between. Nothing in the loop changes its links. A later
    /// fix that ends the chain changes this test on purpose.
    #[test]
    fn a_node_that_stays_at_g_minus_one_asks_one_join_every_five_minutes_for_ever() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = state_with_links(3, false);
        let start = Instant::now();
        let candidates = all_candidates_refuse(&mut state, start);

        for round in 1..=6_u32 {
            let due = start + STARVED * round;
            assert_eq!(
                ask(&mut state, candidates[0], due),
                GraftRequest::Join,
                "round {round}: the node is still 1 peer short and refused, so it asks a Join"
            );
            assert_ne!(
                ask(&mut state, candidates[1], due + SECOND),
                GraftRequest::Join,
                "round {round}: the Join restarted the clock, so a second ask at once is no Join"
            );
        }
    }
}
