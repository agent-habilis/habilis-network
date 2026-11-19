use serde::Serialize;

use crate::transport::probe::PathKind;

/// The kind of path a node uses to reach a peer, as the engine sees it.
///
/// ```
/// use habilis_network::topology::PathLabel;
///
/// assert_eq!(serde_json::to_string(&PathLabel::Webrtc).unwrap(), "\"webrtc\"");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum PathLabel {
    /// A direct UDP path.
    Ip,
    /// A `WebRTC` session.
    Webrtc,
    /// A route through other members.
    Multihop,
    /// The relay.
    Relay,
    /// The frames of the gossip topic.
    Gossip,
    /// No reading yet.
    Unknown,
}

impl From<PathKind> for PathLabel {
    fn from(kind: PathKind) -> Self {
        match kind {
            PathKind::Ip => Self::Ip,
            PathKind::WebRtc => Self::Webrtc,
            PathKind::Multihop => Self::Multihop,
            PathKind::Gossip => Self::Gossip,
            PathKind::Relay => Self::Relay,
            PathKind::None => Self::Unknown,
        }
    }
}
