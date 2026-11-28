//! The next hop of a cell: one pure rule that each node applies with its own table.

use std::collections::{HashMap, HashSet};

use crate::app_id::AppId;
use crate::link_metric::LinkMetric;

/// What a node does with a cell that is not for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NextHop {
    /// Send the cell to this neighbor.
    Forward(AppId),
    /// No neighbor can reach the destination now: the cell is dropped.
    Unreachable,
    /// The best neighbor is the hop that the cell came from: the tables disagree, and the cell is dropped.
    TurnedBack,
}

impl NextHop {
    /// This next hop for a cell that came from `from`: a cell never goes back to the hop that it came from.
    pub(crate) fn unless_from(self, from: Option<AppId>) -> Self {
        if let Self::Forward(neighbor) = self
            && from == Some(neighbor)
        {
            Self::TurnedBack
        } else {
            self
        }
    }
}

/// The state of the gate of this node toward each neighbor, as the rule reads it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GateView<'sets> {
    /// Neighbors whose connection has no direct path now, for less than the deadline: they stay candidates, but
    /// behind every neighbor that admits.
    pub(crate) waiting: &'sets HashSet<AppId>,
    /// Neighbors that stayed without a direct path for the whole deadline: they are no candidate.
    pub(crate) stuck: &'sets HashSet<AppId>,
}

/// Pure: the next hop of a cell for `dst`, from the links of this node.
///
/// `neighbors` are the links of this node, and `distances` holds, for each node that can reach `dst`, the
/// total cost of its shortest path to `dst`. The rule, in this order:
///
/// 1. The cost of a neighbor is the cost of its link plus its distance to `dst`. A neighbor with no path to
///    `dst` has no cost and is not a candidate.
/// 2. A neighbor that is stuck (`gate.stuck`) is removed before the choice. It is a fact of this node, and it
///    is certain: the node takes a longer way.
/// 3. No candidate is left: [`NextHop::Unreachable`].
/// 4. A neighbor that admits cells now is taken before a neighbor in wait (`gate.waiting`), whatever the cost.
///    A neighbor in wait is taken only when no neighbor that admits reaches `dst`: its cells wait in the queue
///    of its writer until a direct path is selected.
/// 5. Inside one of the two tiers, the best is the lowest cost, and for an equal cost the lowest app id in byte
///    order.
/// 6. The best is the hop that the cell came from (`from`): [`NextHop::TurnedBack`]. The second best is not
///    taken: a cell that has to go back shows tables that disagree, and the vectors bring them together.
/// 7. Otherwise [`NextHop::Forward`] to the best.
pub(crate) fn next_hop(
    neighbors: &[(AppId, LinkMetric)],
    distances: &HashMap<AppId, LinkMetric>,
    gate: GateView<'_>,
    from: Option<AppId>,
) -> NextHop {
    let mut best: Option<(bool, LinkMetric, AppId)> = None;
    for (neighbor, link) in neighbors {
        if gate.stuck.contains(neighbor) {
            continue;
        }
        let Some(distance) = distances.get(neighbor) else {
            continue;
        };
        let key = (
            gate.waiting.contains(neighbor),
            link.add(*distance),
            *neighbor,
        );
        if best.is_none_or(|known| key < known) {
            best = Some(key);
        }
    }
    match best {
        None => NextHop::Unreachable,
        Some((_, _, neighbor)) => NextHop::Forward(neighbor).unless_from(from),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use iroh::SecretKey;

    use super::{GateView, NextHop, next_hop};
    use crate::app_id::AppId;
    use crate::link_metric::LinkMetric;

    fn id(seed: u8) -> AppId {
        AppId::new(SecretKey::from_bytes(&[seed; 32]).public())
    }

    fn metric(cost: u32) -> LinkMetric {
        LinkMetric::new(cost)
    }

    /// The next hop with the hops in `waiting` and in `stuck` as the gate of the node reads them.
    fn pick(
        neighbors: &[(AppId, LinkMetric)],
        distances: &HashMap<AppId, LinkMetric>,
        waiting: &[AppId],
        stuck: &[AppId],
        from: Option<AppId>,
    ) -> NextHop {
        let waiting: HashSet<AppId> = waiting.iter().copied().collect();
        let stuck: HashSet<AppId> = stuck.iter().copied().collect();
        next_hop(
            neighbors,
            distances,
            GateView {
                waiting: &waiting,
                stuck: &stuck,
            },
            from,
        )
    }

    /// Two neighbors at the same total cost: the lower app id wins, each time, whatever the order of the links.
    #[test]
    fn equal_cost_takes_the_lowest_app_id_each_time() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = {
            let (first, second) = (id(1), id(2));
            if first < second {
                (first, second)
            } else {
                (second, first)
            }
        };
        let distances = HashMap::from([(low, metric(5)), (high, metric(5))]);
        for round in 0..100 {
            let neighbors = if round % 2 == 0 {
                [(low, metric(1)), (high, metric(1))]
            } else {
                [(high, metric(1)), (low, metric(1))]
            };
            assert_eq!(
                pick(&neighbors, &distances, &[], &[], None),
                NextHop::Forward(low),
                "round {round}: the lowest app id"
            );
        }
    }

    /// The neighbor with the lowest total cost is taken, whatever the cost of its link alone.
    #[test]
    fn the_lowest_total_cost_is_taken() {
        let _guard = ::habilis_network_test_tracing::init();
        let (near, far) = (id(1), id(2));
        // near: link 1 + distance 10 = 11. far: link 5 + distance 2 = 7.
        let neighbors = [(near, metric(1)), (far, metric(5))];
        let distances = HashMap::from([(near, metric(10)), (far, metric(2))]);

        assert_eq!(
            pick(&neighbors, &distances, &[], &[], None),
            NextHop::Forward(far),
            "far costs 7 in all, near costs 11"
        );
    }

    /// A neighbor that is stuck is removed before the choice: the node takes a longer way at once. The neighbor
    /// that it takes is not on a shortest path of the node.
    #[test]
    fn a_stuck_neighbor_is_removed_before_the_choice() {
        let _guard = ::habilis_network_test_tracing::init();
        let (refused_best, detour) = (id(1), id(2));
        let neighbors = [(refused_best, metric(1)), (detour, metric(1))];
        let distances = HashMap::from([(refused_best, metric(1)), (detour, metric(7))]);

        assert_eq!(
            pick(&neighbors, &distances, &[], &[], None),
            NextHop::Forward(refused_best),
            "control: with nothing refused the best is taken"
        );
        assert_eq!(
            pick(&neighbors, &distances, &[], &[refused_best], None),
            NextHop::Forward(detour),
            "the stuck neighbor is removed, and the node switches to the longer way"
        );
    }

    /// Every neighbor stuck, or none with a path: no next hop.
    #[test]
    fn no_candidate_gives_no_next_hop() {
        let _guard = ::habilis_network_test_tracing::init();
        let (reaching, lost) = (id(1), id(2));
        let neighbors = [(reaching, metric(1)), (lost, metric(1))];
        // `lost` has no distance: it has no path to the destination.
        let distances = HashMap::from([(reaching, metric(3))]);

        assert_eq!(
            pick(&neighbors, &distances, &[], &[reaching], None),
            NextHop::Unreachable,
            "the only neighbor with a path is stuck"
        );
        assert_eq!(
            pick(&[], &distances, &[], &[], None),
            NextHop::Unreachable,
            "a node with no neighbor"
        );
    }

    /// The best neighbor is the hop that the cell came from: the cell is dropped, and the second best is not
    /// taken.
    #[test]
    fn a_cell_is_not_sent_back_and_the_second_best_is_not_taken() {
        let _guard = ::habilis_network_test_tracing::init();
        let (best, second) = (id(1), id(2));
        let neighbors = [(best, metric(1)), (second, metric(1))];
        let distances = HashMap::from([(best, metric(1)), (second, metric(4))]);

        assert_eq!(
            pick(&neighbors, &distances, &[], &[], Some(best)),
            NextHop::TurnedBack,
            "the best is the hop that the cell came from"
        );
        assert_eq!(
            pick(&neighbors, &distances, &[], &[], Some(second)),
            NextHop::Forward(best),
            "a cell that came from another neighbor goes to the best"
        );
    }

    /// A neighbor that admits is taken before a neighbor in wait, whatever the cost. The node holds cells for a
    /// hop in wait only when no neighbor that admits reaches the destination.
    #[test]
    fn a_neighbor_that_admits_is_taken_before_a_neighbor_in_wait_at_any_cost() {
        let _guard = ::habilis_network_test_tracing::init();
        let (cheap, dear) = (id(1), id(2));
        let neighbors = [(cheap, metric(1)), (dear, metric(1))];
        let distances = HashMap::from([(cheap, metric(1)), (dear, metric(50))]);

        assert_eq!(
            pick(&neighbors, &distances, &[], &[], None),
            NextHop::Forward(cheap),
            "control: nothing waits, the cheap one is taken"
        );
        assert_eq!(
            pick(&neighbors, &distances, &[cheap], &[], None),
            NextHop::Forward(dear),
            "the cheap one waits, the dear one admits: the dear one is taken"
        );
        assert_eq!(
            pick(&neighbors, &distances, &[cheap, dear], &[], None),
            NextHop::Forward(cheap),
            "both wait: the cost decides inside the tier"
        );
    }

    /// A node whose only neighbor is in wait has a next hop: its cells wait in the queue of the writer.
    #[test]
    fn a_node_whose_only_neighbor_is_in_wait_has_a_next_hop() {
        let _guard = ::habilis_network_test_tracing::init();
        let only = id(1);
        let neighbors = [(only, metric(1))];
        let distances = HashMap::from([(only, metric(3))]);

        assert_eq!(
            pick(&neighbors, &distances, &[only], &[], None),
            NextHop::Forward(only),
            "a hop in wait is a candidate"
        );
        assert_eq!(
            pick(&neighbors, &distances, &[], &[only], None),
            NextHop::Unreachable,
            "control: a stuck hop is not"
        );
    }
}
