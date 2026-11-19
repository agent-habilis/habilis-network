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
}
