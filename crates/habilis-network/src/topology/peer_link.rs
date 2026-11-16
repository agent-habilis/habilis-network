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
    /// For a multihop path, the endpoint id of the first hop, in hex.
    pub via: Option<String>,
    /// Whether the peer is a gossip neighbor (in the active view).
    pub neighbor: bool,
    /// Whether the connection to the peer is pinned to multihop.
    pub pinned: bool,
}
