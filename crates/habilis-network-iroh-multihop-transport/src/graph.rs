//! The link-state graph as a metric-weighted directed graph, assembled from
//! peers' gossiped link-vectors, and the source-route computation over it:
//! shortest path (Dijkstra) plus node-disjoint backups.
//!
//! The initiator holds this graph and picks the whole hop sequence itself —
//! source routing (each hop only knows its neighbours; only the initiator can
//! reason about a whole path).

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use crate::app_id::AppId;
use crate::link_metric::LinkMetric;

/// A directed, metric-weighted view of the link-state graph: for each node, its
/// outbound links `(neighbour, cost)`. Nodes are keyed by their stable `AppId`.
#[derive(Debug, Default, Clone)]
pub(crate) struct Graph {
    adj: HashMap<AppId, Vec<(AppId, LinkMetric)>>,
}

/// The two ends of a route: the node a cell starts at and the node it must reach.
///
/// One struct for the pair, because both are an `AppId` and a call that swaps
/// them compiles and routes the wrong way.
///
/// # Examples
///
/// A Leg is built by the routing code, and a caller outside the crate cannot build one, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_multihop_transport::{Leg, Topology};
///
/// # fn demo(topology: &Topology, leg: Leg) -> usize {
/// topology.route_to(leg, 2).count()
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Leg {
    /// Where the route starts.
    pub src: AppId,
    /// Where the route must arrive.
    pub dst: AppId,
}

/// A directed link `from -> to` and what it costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Link {
    pub(crate) from: AppId,
    pub(crate) to: AppId,
    pub(crate) cost: LinkMetric,
}

/// A computed source route: the ordered hops **after** the source, up to and
/// including the destination (`[first_hop, …, dst]`), and the path's total cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Path {
    pub(crate) hops: Vec<AppId>,
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

    /// Shortest path from `src` to `dst` by total [`LinkMetric`], or `None` when
    /// `dst` is unreachable.
    #[cfg(test)]
    pub(crate) fn shortest_path(&self, leg: Leg) -> Option<Path> {
        self.shortest_path_avoiding(leg, &HashSet::new())
    }

    /// Up to `k` **node-disjoint** paths from `src` to `dst`, shortest first.
    /// Greedy: take the shortest, block its interior hops, repeat.
    /// Interior-disjoint so one dead hop can't sever two routes at once
    /// (`src`/`dst` are shared by construction). Stops early when no further
    /// disjoint path exists.
    pub(crate) fn disjoint_paths(&self, leg: Leg, max_paths: usize) -> Vec<Path> {
        let mut paths = Vec::new();
        let mut blocked: HashSet<AppId> = HashSet::new();
        for _ in 0..max_paths {
            let Some(path) = self.shortest_path_avoiding(leg, &blocked) else {
                break;
            };
            // Interior hops = every hop except the final destination.
            let trimmed = path.hops.iter().rev().skip(1);
            let interior: Vec<AppId> = trimmed.copied().collect();
            let exhausted = interior.is_empty();
            blocked.extend(interior);
            paths.push(path);
            if exhausted {
                // A direct (interior-less) path has no disjoint alternative.
                break;
            }
        }
        paths
    }

    /// Shortest path from `src` to `dst` that does not leave `src` over a link to
    /// a node in `refused`: the edges `src -> r` are absent. It is a rule on edges
    /// and not on nodes, since `dst` can itself be a refused first hop (a direct
    /// link), and a node rule never blocks `dst`. `None` when every way out of
    /// `src` is refused or leads nowhere.
    pub(crate) fn shortest_path_avoiding_first_hops(
        &self,
        leg: Leg,
        refused: &HashSet<AppId>,
    ) -> Option<Path> {
        self.shortest_path_with(leg, &HashSet::new(), refused)
    }

    /// Dijkstra that treats every node in `blocked` as absent — the primitive
    /// behind node-disjoint search. `dst` is never blocked even if the caller
    /// lists it.
    fn shortest_path_avoiding(&self, leg: Leg, blocked: &HashSet<AppId>) -> Option<Path> {
        self.shortest_path_with(leg, blocked, &HashSet::new())
    }

    /// Dijkstra with both rules: `blocked` nodes are absent, and the links from
    /// `src` to a node in `refused_first` are absent.
    fn shortest_path_with(
        &self,
        leg: Leg,
        blocked: &HashSet<AppId>,
        refused_first: &HashSet<AppId>,
    ) -> Option<Path> {
        let Leg { src, dst } = leg;
        let mut best: HashMap<AppId, LinkMetric> = HashMap::new();
        let mut previous: HashMap<AppId, AppId> = HashMap::new();
        let mut heap: BinaryHeap<Reverse<(LinkMetric, AppId)>> = BinaryHeap::new();

        best.insert(src, LinkMetric::ZERO);
        heap.push(Reverse((LinkMetric::ZERO, src)));

        while let Some(Reverse((cost, node))) = heap.pop() {
            if node == dst {
                return Some(Path {
                    hops: reconstruct(&previous, leg),
                    cost,
                });
            }
            // Skip a stale heap entry superseded by a cheaper relaxation.
            if best.get(&node).is_some_and(|known| *known < cost) {
                continue;
            }
            let Some(edges) = self.adj.get(&node) else {
                continue;
            };
            for (next, edge) in edges {
                if node == src && refused_first.contains(next) {
                    continue;
                }
                let candidate = RelaxEdge {
                    node,
                    cost,
                    next: *next,
                    weight: *edge,
                    dst,
                    blocked,
                };
                relax(&mut best, &mut previous, &mut heap, candidate);
            }
        }
        None
    }
}

/// The edge under consideration by one relaxation step: `node -> next` weighing
/// `weight` atop the already-settled `cost` to `node`, gated by `dst` (never
/// itself blocked) and the `blocked` set.
#[derive(Clone, Copy)]
struct RelaxEdge<'blocked> {
    node: AppId,
    cost: LinkMetric,
    next: AppId,
    weight: LinkMetric,
    dst: AppId,
    blocked: &'blocked HashSet<AppId>,
}

/// Relax `candidate`: skip it when `next` is blocked (unless it's `dst` itself),
/// then update `best`/`prev`/`heap` if the new cost improves on any previously
/// known cost to `next`.
fn relax(
    best: &mut HashMap<AppId, LinkMetric>,
    previous: &mut HashMap<AppId, AppId>,
    heap: &mut BinaryHeap<Reverse<(LinkMetric, AppId)>>,
    candidate: RelaxEdge<'_>,
) {
    let RelaxEdge {
        node,
        cost,
        next,
        weight,
        dst,
        blocked,
    } = candidate;
    if next != dst && blocked.contains(&next) {
        return;
    }
    let next_cost = cost.add(weight);
    let improved = match best.get(&next) {
        Some(known) => next_cost < *known,
        None => true,
    };
    if !improved {
        return;
    }
    best.insert(next, next_cost);
    previous.insert(next, node);
    heap.push(Reverse((next_cost, next)));
}

/// Walk `prev` from `dst` back to `src`, returning the hops after `src` in
/// forward order (`[first_hop, …, dst]`).
fn reconstruct(previous: &HashMap<AppId, AppId>, leg: Leg) -> Vec<AppId> {
    let Leg { src, dst } = leg;
    let mut hops = vec![dst];
    let mut cur = dst;
    while let Some(&parent) = previous.get(&cur) {
        if parent == src {
            break;
        }
        hops.push(parent);
        cur = parent;
    }
    hops.reverse();
    hops
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use crate::app_id::AppId;

    use super::{Graph, Leg, Link, LinkMetric};

    use std::iter;
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

    #[test]
    fn a_link_from_the_source_to_a_refused_node_is_skipped_also_when_it_is_the_destination() {
        let _guard = ::habilis_network_test_tracing::init();
        let (src, via, dst) = (eid(1), eid(2), eid(3));
        let mut graph = Graph::default();
        link(&mut graph, src, dst, 1);
        link(&mut graph, src, via, 1);
        link(&mut graph, via, dst, 1);
        let refusing = |nodes: &[AppId]| nodes.iter().copied().collect();

        let path = |refused| graph.shortest_path_avoiding_first_hops(Leg { src, dst }, &refused);
        assert_eq!(
            path(refusing(&[])).expect("direct").hops,
            vec![dst],
            "a link to a refused node is skipped even when it is the destination"
        );
        assert_eq!(
            path(refusing(&[dst])).expect("through via").hops,
            vec![via, dst],
            "the direct link is a refused first hop: the destination itself"
        );
        assert_eq!(
            path(refusing(&[via])).expect("direct").hops,
            vec![dst],
            "a refused node that is not on the shortest path changes nothing"
        );
        assert_eq!(
            path(refusing(&[dst, via])),
            None,
            "every way out of the source is refused"
        );
    }

    #[test]
    fn a_refused_first_hop_is_still_a_hop_in_the_middle_of_a_route() {
        let _guard = ::habilis_network_test_tracing::init();
        // Only the links from the source are refused: `via` can carry the route
        // on from a later node, since the rule reads the first hop alone.
        let (src, near, via, dst) = (eid(1), eid(2), eid(3), eid(4));
        let mut graph = Graph::default();
        link(&mut graph, src, near, 1);
        link(&mut graph, near, via, 1);
        link(&mut graph, via, dst, 1);
        link(&mut graph, src, via, 5);
        let refused = iter::once(via).collect();
        let path = graph
            .shortest_path_avoiding_first_hops(Leg { src, dst }, &refused)
            .expect("a route");
        assert_eq!(
            path.hops,
            vec![near, via, dst],
            "a refused first hop is still a hop in the middle of a route"
        );
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

    #[test]
    fn shortest_path_traces_a_line() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb, nc) = (eid(1), eid(2), eid(3));
        let mut graph = Graph::default();
        link(&mut graph, na, nb, 5);
        link(&mut graph, nb, nc, 7);
        let path = graph
            .shortest_path(Leg { src: na, dst: nc })
            .expect("reachable");
        assert_eq!(
            path.hops,
            vec![nb, nc],
            "shortest path traces a line of two hops"
        );
        assert_eq!(path.cost, LinkMetric::new(12), "the line costs twelve");
    }

    #[test]
    fn shortest_path_prefers_a_cheaper_direct_over_the_chain() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb, nc, nd) = (eid(1), eid(2), eid(3), eid(4));
        let mut graph = Graph::default();
        link(&mut graph, na, nb, 1);
        link(&mut graph, nb, nc, 1);
        link(&mut graph, nc, nd, 1);
        link(&mut graph, na, nd, 1);
        let path = graph
            .shortest_path(Leg { src: na, dst: nd })
            .expect("reachable");
        assert_eq!(
            path.hops,
            vec![nd],
            "shortest path prefers the cheaper direct hop"
        );
        assert_eq!(
            path.cost,
            LinkMetric::new(1),
            "the cheap direct hop costs one"
        );
    }

    #[test]
    fn shortest_path_prefers_the_chain_when_the_direct_link_is_costlier() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb, nc, nd) = (eid(1), eid(2), eid(3), eid(4));
        let mut graph = Graph::default();
        link(&mut graph, na, nb, 1);
        link(&mut graph, nb, nc, 1);
        link(&mut graph, nc, nd, 1);
        link(&mut graph, na, nd, 10);
        let path = graph
            .shortest_path(Leg { src: na, dst: nd })
            .expect("reachable");
        assert_eq!(
            path.hops,
            vec![nb, nc, nd],
            "shortest path prefers the chain when the direct link costs more"
        );
        assert_eq!(
            path.cost,
            LinkMetric::new(3),
            "the chain costs its link sum"
        );
    }

    #[test]
    fn unreachable_destination_is_none() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb, lonely) = (eid(1), eid(2), eid(9));
        let mut graph = Graph::default();
        link(&mut graph, na, nb, 1);
        assert!(
            graph
                .shortest_path(Leg {
                    src: na,
                    dst: lonely
                })
                .is_none(),
            "an unreachable destination has no path"
        );
    }

    #[test]
    fn infinite_links_are_dropped() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb) = (eid(1), eid(2));
        let mut graph = Graph::default();
        graph.insert_link(Link {
            from: na,
            to: nb,
            cost: LinkMetric::INFINITE,
        });
        assert!(
            graph.shortest_path(Leg { src: na, dst: nb }).is_none(),
            "infinite links are dropped from the path search"
        );
    }

    #[test]
    fn disjoint_paths_are_node_disjoint() {
        let _guard = ::habilis_network_test_tracing::init();
        // Diamond: na -> {nb, nc} -> nd. Two interior-disjoint paths exist.
        let (na, nb, nc, nd) = (eid(1), eid(2), eid(3), eid(4));
        let mut graph = Graph::default();
        link(&mut graph, na, nb, 1);
        link(&mut graph, nb, nd, 1);
        link(&mut graph, na, nc, 1);
        link(&mut graph, nc, nd, 1);
        let paths = graph.disjoint_paths(Leg { src: na, dst: nd }, 2);
        assert_eq!(paths.len(), 2, "both diamond arms are available");
        assert_ne!(
            paths[0].hops[0], paths[1].hops[0],
            "disjoint paths are node-disjoint at their first hop"
        );
        for path in &paths {
            assert_eq!(
                *path
                    .hops
                    .last()
                    .expect("a path built by disjoint_paths has at least one hop"),
                nd,
                "each disjoint path ends at the destination"
            );
        }
    }

    #[test]
    fn disjoint_paths_stops_when_no_alternative_exists() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nr, nd) = (eid(1), eid(5), eid(4));
        let mut graph = Graph::default();
        link(&mut graph, na, nr, 1);
        link(&mut graph, nr, nd, 1);
        let paths = graph.disjoint_paths(Leg { src: na, dst: nd }, 3);
        assert_eq!(
            paths.len(),
            1,
            "the lone hop can't be reused for a 2nd path"
        );
        assert_eq!(
            paths[0].hops,
            vec![nr, nd],
            "disjoint paths stop when no alternative exists"
        );
    }
}
