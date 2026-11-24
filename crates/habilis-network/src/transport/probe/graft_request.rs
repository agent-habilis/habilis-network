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
/// it within the last `STARVED` (`GraftBackoff::has_refusal`). A `PeerInfo` graft is not paced.
/// A node with no neighbor at all, whose `Neighbor` request was read as refused, is starved at once:
/// its `Join` does not wait for `STARVED`, and the next one waits for it, as for any starved node.
///
/// The `Join` ignores the backoff of the peer, but the guard of a node that is 1 peer short does
/// not: it needs a refusal read within the last `STARVED`, and the wait of the backoff can reach
/// `GRAFT_BACKOFF_MAX` (15 minutes). A node whose refusals are all older asks `Neighbor` again
/// when the wait of a peer ends, and the next refusal makes the `Join` due. When 2 nodes that
/// are 1 peer short hold a backoff on each other, the `Neighbor` request goes out after the wait,
/// and a peer with a free slot accepts it. The `Join` of a short node goes to the peer that
/// `next_fill` picks at random among the free members, not to the other short node, so the
/// 2 short nodes meet by chance: each `Join` to a full peer moves the shortage to the peer that
/// it evicts.
///
/// A `Join` to a full peer evicts one neighbor of it, and the `ForwardJoin` walk that it
/// starts ends in a `Neighbor` request of high priority at up to G - 1 more peers, so a `Join`
/// can make up to 1 + 2(G - 1) peers drop a link. Each peer that dropped one is 1 peer short.
/// A node that is 1 peer short by structure (the sum of the caps is odd, or the 2 nodes that
/// are short are linked to each other) asks at most 1 `Join` per `STARVED` for ever, while a
/// peer keeps refusing it. The wait of a refusing peer grows to 15 minutes. With 1 or 2
/// candidates, such a node asks about once per 15 minutes in the long run. With 3 or more, the
/// refusals of the different peers fall in different windows, and it asks 1 `Join` per `STARVED`.
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
        tracing::debug!(target: transport::LOG_TARGET, %peer, "graft: a Join to the rendezvous");
        return GraftRequest::Join;
    }
    state.note_link_count(max_connections, now);
    if paced && state.starved_join_due(now) {
        // A `Join` is not refused, so it ignores the backoff of the peer.
        tracing::info!(
            target: transport::LOG_TARGET,
            %peer,
            linked = state.linked_endpoints.len(),
            links_short = state.links_short,
            "graft: a starved node asks with a Join"
        );
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

    /// A state that holds a link to each of `peers` peers, of the `MAX_CONNECTIONS` that it wants.
    fn state_with_links(peers: u8) -> EventLoopState {
        let mut state = fresh_state();
        for seed in 10..10 + peers {
            state.linked_endpoints.insert(endpoint_id(seed));
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
        let mut state = state_with_links(3);
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
        assert_ne!(
            ask(&mut state, candidates[2], start + STARVED * 2),
            GraftRequest::Join,
            "STARVED after the Join, the refusal that was read is older than STARVED: no Join"
        );
    }

    /// The state that the at-cap flake reaches (2 of 100 runs): a node with no neighbor, and every
    /// other node full and silent. A retry at each alive tick (15 s) asks each of them with a
    /// `Neighbor` request. The silence is read as a refusal 20 s after the first ask, and the
    /// node, with no neighbor and a refusal read, asks with a `Join` at once. Before the fix the
    /// clock of an ask restarted with each retry, so no refusal was read and the node asked
    /// `Neighbor` for ever.
    #[test]
    fn a_node_with_no_neighbor_that_every_peer_leaves_unanswered_asks_a_join_by_the_second_retry() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = state_with_links(0);
        let start = Instant::now();
        let candidates = [endpoint_id(2), endpoint_id(3)];
        let retry_every = SECOND * 15;

        let mut asked: Vec<GraftRequest> = Vec::new();
        for tick in 0..=2_u32 {
            let now = start + retry_every * tick;
            state.settle_graft_backoff(now);
            for candidate in candidates {
                asked.push(ask(&mut state, candidate, now));
            }
        }
        assert!(
            asked[..4]
                .iter()
                .all(|request| *request == GraftRequest::Neighbor),
            "the first 2 retries, 0 s and 15 s: no refusal is read yet, so every ask is a Neighbor"
        );
        assert!(
            asked[4..].contains(&GraftRequest::Join),
            "the retry at 30 s: the silence of 30 s is a refusal, so the node asks with a Join: {asked:?}"
        );
    }

    /// Control: a node at G - 1 for which no ask stayed unanswered for `GRAFT_REFUSED_AFTER`
    /// keeps asking with `Neighbor`. It is not stuck, so it makes no member of a full view drop a
    /// neighbor. The test does not settle the backoff: `settle_graft_backoff` reads an ask that
    /// no link answered in `GRAFT_REFUSED_AFTER` as a refusal, so a silent peer makes the node
    /// stuck on the next alive tick.
    #[test]
    fn a_node_at_g_minus_one_that_no_peer_refused_never_asks_a_join() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = state_with_links(3);
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
        let mut state = state_with_links(2);
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

    /// A refusal counts for `STARVED` after it was read. A node at G - 1 whose last refusal is
    /// older than that asks no `Join`: the refusal is not a reason any more (the peer may have a
    /// free slot now), and a record that never ended made the guard true for almost every node.
    #[test]
    fn a_refusal_older_than_five_minutes_does_not_make_a_node_at_g_minus_one_ask_a_join() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        // The refusal is read GRAFT_REFUSED_AFTER after the request.
        let read_at = start + GRAFT_REFUSED_AFTER;

        let mut fresh = state_with_links(3);
        let candidates = all_candidates_refuse(&mut fresh, start);
        assert_eq!(
            ask(
                &mut fresh,
                candidates[1],
                read_at + STARVED.saturating_sub(SECOND)
            ),
            GraftRequest::Join,
            "a refusal read just under STARVED ago counts"
        );

        let mut stale = state_with_links(3);
        let stale_candidates = all_candidates_refuse(&mut stale, start);
        assert_ne!(
            ask(&mut stale, stale_candidates[1], read_at + STARVED + SECOND),
            GraftRequest::Join,
            "a refusal read more than STARVED ago does not count"
        );
    }

    /// Pins the accepted cost of the rule: a node that stays 1 peer short, as the sum of the caps
    /// is odd or the 2 short nodes are linked to each other, asks at most 1 `Join` per `STARVED`
    /// for ever, and none in between, while a peer keeps refusing it. Each round resets the backoff
    /// of every candidate (`GraftBackoff::reset`) and reads a new refusal of each, which stands
    /// for a peer that waited its wait out and refuses again. Nothing changes the links of the
    /// node. A later fix that ends the chain changes this test on purpose.
    #[test]
    fn a_node_that_stays_at_g_minus_one_asks_at_most_one_join_per_starved_while_peers_keep_refusing()
     {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = state_with_links(3);
        let start = Instant::now();
        let candidates = all_candidates_refuse(&mut state, start);

        for round in 1..=6_u32 {
            let due = start + STARVED * round;
            if round > 1 {
                // The backoff of each candidate ended, and the new request is refused again.
                for candidate in candidates {
                    state.graft_backoff.reset(candidate);
                }
                let halfway = start + (STARVED * round).saturating_sub(STARVED / 2);
                all_candidates_refuse(&mut state, halfway);
            }
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
