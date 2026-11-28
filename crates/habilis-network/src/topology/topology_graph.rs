use serde::Serialize;

use super::TopologyLink;

/// The multihop link-state graph from the point of view of this node.
///
/// ```no_run
/// use habilis_network::topology::TopologyGraph;
///
/// # fn demo(graph: &TopologyGraph) -> usize {
/// graph.edges.len()
/// # }
/// ```
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct TopologyGraph {
    /// The multihop id of this node, in hex.
    pub self_id: String,
    /// The links of the graph, one per edge.
    pub edges: Vec<TopologyLink>,
    /// Cells that this node dropped because the best next hop is the hop that they came from. A few are normal while
    /// the vectors travel after a link came or went. A count that keeps rising means that the tables do not agree.
    pub turned_back: u64,
    /// Cells (and sends) that this node dropped because no neighbor reaches the destination. Normal for a moment
    /// after a link went, and a sign of a node with no way out when it keeps rising.
    pub no_next_hop: u64,
    /// Cells that this node dropped because they had no forward left or claimed more than the limit: a loop of
    /// tables, or a node that sends more than it may.
    pub hop_limit: u64,
}
