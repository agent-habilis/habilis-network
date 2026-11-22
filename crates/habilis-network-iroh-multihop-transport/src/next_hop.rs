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

/// Pure: the next hop of a cell for `dst`, from the links of this node.
///
/// `neighbors` are the links of this node, and `distances` holds, for each node that can reach `dst`, the
/// total cost of its shortest path to `dst`. The rule, in this order:
///
/// 1. The cost of a neighbor is the cost of its link plus its distance to `dst`. A neighbor with no path to
///    `dst` has no cost and is not a candidate.
/// 2. A neighbor that the gate of this node refuses now (`refused`) is removed before the choice. The node
///    then takes a longer way: it is a fact of this node, and it is certain.
/// 3. No candidate is left: [`NextHop::Unreachable`].
/// 4. The best is the lowest cost, and for an equal cost the lowest app id in byte order.
/// 5. The best is the hop that the cell came from (`from`): [`NextHop::TurnedBack`]. The second best is not
///    taken: a cell that has to go back shows tables that disagree, and the vectors bring them together.
/// 6. Otherwise [`NextHop::Forward`] to the best.
pub(crate) fn next_hop(
    neighbors: &[(AppId, LinkMetric)],
    distances: &HashMap<AppId, LinkMetric>,
    refused: &HashSet<AppId>,
    from: Option<AppId>,
) -> NextHop {
    let mut best: Option<(LinkMetric, AppId)> = None;
    for (neighbor, link) in neighbors {
        if refused.contains(neighbor) {
            continue;
        }
        let Some(distance) = distances.get(neighbor) else {
            continue;
        };
        let cost = link.add(*distance);
        if best.is_none_or(|(known, known_id)| (cost, *neighbor) < (known, known_id)) {
            best = Some((cost, *neighbor));
        }
    }
    match best {
        None => NextHop::Unreachable,
        Some((_, neighbor)) => NextHop::Forward(neighbor).unless_from(from),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use iroh::SecretKey;

    use super::{NextHop, next_hop};
    use crate::app_id::AppId;
    use crate::link_metric::LinkMetric;

    fn id(seed: u8) -> AppId {
        AppId::new(SecretKey::from_bytes(&[seed; 32]).public())
    }

    fn metric(cost: u32) -> LinkMetric {
        LinkMetric::new(cost)
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
        let refused = HashSet::new();

        for round in 0..100 {
            let neighbors = if round % 2 == 0 {
                [(low, metric(1)), (high, metric(1))]
            } else {
                [(high, metric(1)), (low, metric(1))]
            };
            assert_eq!(
                next_hop(&neighbors, &distances, &refused, None),
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
            next_hop(&neighbors, &distances, &HashSet::new(), None),
            NextHop::Forward(far),
            "far costs 7 in all, near costs 11"
        );
    }

    /// A neighbor that the gate refuses is removed before the choice: the node takes a longer way at once. The
    /// neighbor that it takes is not on a shortest path of the node.
    #[test]
    fn a_refused_neighbor_is_removed_before_the_choice() {
        let _guard = ::habilis_network_test_tracing::init();
        let (refused_best, detour) = (id(1), id(2));
        let neighbors = [(refused_best, metric(1)), (detour, metric(1))];
        let distances = HashMap::from([(refused_best, metric(1)), (detour, metric(7))]);

        assert_eq!(
            next_hop(&neighbors, &distances, &HashSet::new(), None),
            NextHop::Forward(refused_best),
            "control: with nothing refused the best is taken"
        );
        assert_eq!(
            next_hop(&neighbors, &distances, &HashSet::from([refused_best]), None),
            NextHop::Forward(detour),
            "the refused neighbor is removed, and the node switches to the longer way"
        );
    }

    /// Every neighbor refused, or none with a path: no next hop.
    #[test]
    fn no_candidate_gives_no_next_hop() {
        let _guard = ::habilis_network_test_tracing::init();
        let (reaching, lost) = (id(1), id(2));
        let neighbors = [(reaching, metric(1)), (lost, metric(1))];
        // `lost` has no distance: it has no path to the destination.
        let distances = HashMap::from([(reaching, metric(3))]);

        assert_eq!(
            next_hop(&neighbors, &distances, &HashSet::from([reaching]), None),
            NextHop::Unreachable,
            "the only neighbor with a path is refused"
        );
        assert_eq!(
            next_hop(&[], &distances, &HashSet::new(), None),
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
            next_hop(&neighbors, &distances, &HashSet::new(), Some(best)),
            NextHop::TurnedBack,
            "the best is the hop that the cell came from"
        );
        assert_eq!(
            next_hop(&neighbors, &distances, &HashSet::new(), Some(second)),
            NextHop::Forward(best),
            "a cell that came from another neighbor goes to the best"
        );
    }
}
