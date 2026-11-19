use serde::Serialize;

/// One directed, metric-labelled link of the multihop graph.
///
/// ```no_run
/// use habilis_network::topology::TopologyLink;
///
/// # fn demo(link: &TopologyLink) -> u32 {
/// link.metric
/// # }
/// ```
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct TopologyLink {
    /// The endpoint id at one end, in hex.
    pub from: String,
    /// The endpoint id at the other end, in hex.
    pub to: String,
    /// The routing cost of the link.
    pub metric: u32,
}
