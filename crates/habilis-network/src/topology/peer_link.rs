use serde::Serialize;

use super::PathLabel;

/// One peer that the node holds a connection, a session or a gossip link to.
///
/// ```no_run
/// use habilis_network::topology::PeerLink;
///
/// # fn demo(link: &PeerLink) -> bool {
/// link.neighbor
/// # }
/// ```
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct PeerLink {
    /// The endpoint id of the peer, in hex.
    pub endpoint: String,
    /// The nickname of the peer, when the roster knows it.
    pub nickname: Option<String>,
    /// The path in use to the peer.
    pub path: PathLabel,
    /// For a multihop path, the endpoint id of the first hop of the route that the topology gives
    /// now, in hex. It is the route that a send would take, not a reading of the path in use.
    pub via: Option<String>,
    /// Whether the peer is a gossip neighbor (in the active view).
    pub neighbor: bool,
    /// Whether the connection to the peer is pinned to multihop.
    pub pinned: bool,
    /// Whether the connection or the session of the peer took no unit of the ceiling: it counts
    /// toward the total cap only, and it closes after it has been idle.
    pub extra: bool,
}
