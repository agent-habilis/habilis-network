//! The link-state graph as a metric-weighted directed graph, assembled from
//! peers' gossiped link-vectors, and the distances over it: the cost of the
//! shortest path from each node to one destination (Dijkstra over the reversed
//! links). A node uses them to pick the next hop of a cell from its own table.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

use crate::app_id::AppId;
use crate::link_metric::LinkMetric;

/// A directed, metric-weighted view of the link-state graph: for each node, its
/// outbound links `(neighbour, cost)`. Nodes are keyed by their stable `AppId`.
#[derive(Debug, Default, Clone)]
pub(crate) struct Graph {
    adj: HashMap<AppId, Vec<(AppId, LinkMetric)>>,
}

/// A directed link `from -> to` and what it costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Link {
    pub(crate) from: AppId,
    pub(crate) to: AppId,
    pub(crate) cost: LinkMetric,
}

impl Graph {
    /// Record a usable directed link `from -> to`. An unusable
    /// ([`LinkMetric::INFINITE`]) cost is dropped — an unusable link is the same
    /// as an absent one.
    pub(crate) fn insert_link(&mut self, link: Link) {
        let Link { from, to, cost } = link;
        if cost.is_usable() {
            self.adj.entry(from).or_default().push((to, cost));
        }
    }

    /// The outbound links of `node`: each neighbor and what the link costs. Empty for a node with none.
    pub(crate) fn links_of(&self, node: AppId) -> &[(AppId, LinkMetric)] {
        self.adj.get(&node).map_or(&[], Vec::as_slice)
    }

    /// For each node that can reach `dst`, the total cost of its shortest path to `dst` (the cost of `dst`
    /// itself is zero). One Dijkstra over the reversed links, so a node that no path leaves toward `dst` is
    /// absent. A directed link `a -> b` makes `a` reach `dst` only when `b` does.
    pub(crate) fn distances_to(&self, dst: AppId) -> HashMap<AppId, LinkMetric> {
        let mut reversed: HashMap<AppId, Vec<(AppId, LinkMetric)>> = HashMap::new();
        for (from, edges) in &self.adj {
            for (to, cost) in edges {
                reversed.entry(*to).or_default().push((*from, *cost));
            }
        }
        let mut best: HashMap<AppId, LinkMetric> = HashMap::from([(dst, LinkMetric::ZERO)]);
        let mut heap: BinaryHeap<Reverse<(LinkMetric, AppId)>> = BinaryHeap::new();
        heap.push(Reverse((LinkMetric::ZERO, dst)));
        while let Some(Reverse((cost, node))) = heap.pop() {
            // Skip a stale heap entry superseded by a cheaper relaxation.
            if best.get(&node).is_some_and(|known| *known < cost) {
                continue;
            }
            let Some(incoming) = reversed.get(&node) else {
                continue;
            };
            for (from, weight) in incoming {
                let through = cost.add(*weight);
                if best.get(from).is_none_or(|known| through < *known) {
                    best.insert(*from, through);
                    heap.push(Reverse((through, *from)));
                }
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use crate::app_id::AppId;

    use super::{Graph, Link, LinkMetric};

    fn eid(seed: u8) -> AppId {
        AppId::new(SecretKey::from_bytes(&[seed; 32]).public())
    }

    /// A bidirectional link `left <-> right` of equal cost each way.
    fn link(graph: &mut Graph, left: AppId, right: AppId, cost: u32) {
        let cost = LinkMetric::new(cost);
        graph.insert_link(Link {
            from: left,
            to: right,
            cost,
        });
        graph.insert_link(Link {
            from: right,
            to: left,
            cost,
        });
    }

    /// The distances to the destination follow the cheaper way, one cost for each node, zero for the destination.
    #[test]
    fn distances_to_a_destination_take_the_cheaper_way() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb, nc, nd) = (eid(1), eid(2), eid(3), eid(4));
        let mut graph = Graph::default();
        // na - nb - nd costs 2 + 3 = 5. na - nc - nd costs 1 + 1 = 2.
        link(&mut graph, na, nb, 2);
        link(&mut graph, nb, nd, 3);
        link(&mut graph, na, nc, 1);
        link(&mut graph, nc, nd, 1);

        let distances = graph.distances_to(nd);

        assert_eq!(
            distances.get(&nd),
            Some(&LinkMetric::ZERO),
            "the destination"
        );
        assert_eq!(
            distances.get(&nc),
            Some(&LinkMetric::new(1)),
            "nc is one link away"
        );
        assert_eq!(
            distances.get(&nb),
            Some(&LinkMetric::new(3)),
            "nb has the one way"
        );
        assert_eq!(
            distances.get(&na),
            Some(&LinkMetric::new(2)),
            "na takes the cheaper way through nc"
        );
    }

    /// The graph is directed: a node that only has a link INTO the way to the destination reaches it, and a node
    /// that only receives a link from it does not.
    #[test]
    fn distances_follow_the_direction_of_the_links() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb, nc) = (eid(1), eid(2), eid(3));
        let mut graph = Graph::default();
        // na -> nb -> nc, and nothing back.
        for (from, to) in [(na, nb), (nb, nc)] {
            graph.insert_link(Link {
                from,
                to,
                cost: LinkMetric::new(1),
            });
        }

        let toward_end = graph.distances_to(nc);
        let toward_start = graph.distances_to(na);

        assert_eq!(
            toward_end.get(&na),
            Some(&LinkMetric::new(2)),
            "na reaches nc over nb"
        );
        assert_eq!(
            toward_end.get(&nb),
            Some(&LinkMetric::new(1)),
            "nb reaches nc"
        );
        assert!(!toward_start.contains_key(&nb), "nb has no link toward na");
        assert!(!toward_start.contains_key(&nc), "nc has no link toward na");
    }

    /// An unusable link is the same as an absent one, and the links of a node are those that leave it.
    #[test]
    fn an_unusable_link_is_no_distance_and_links_of_lists_the_outbound_links() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb) = (eid(1), eid(2));
        let mut graph = Graph::default();
        graph.insert_link(Link {
            from: na,
            to: nb,
            cost: LinkMetric::INFINITE,
        });
        graph.insert_link(Link {
            from: nb,
            to: na,
            cost: LinkMetric::new(4),
        });

        assert!(
            !graph.distances_to(nb).contains_key(&na),
            "the unusable link gives no distance"
        );
        assert_eq!(
            graph.distances_to(na).get(&nb),
            Some(&LinkMetric::new(4)),
            "the usable link gives its cost"
        );
        assert_eq!(
            graph.links_of(nb),
            &[(na, LinkMetric::new(4))],
            "the links of nb leave nb"
        );
        assert!(
            graph.links_of(na).is_empty(),
            "the unusable link is not listed"
        );
    }
}
