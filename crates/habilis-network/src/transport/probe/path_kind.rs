//! The kind of path a peer's connection is on.

/// Which kind of path iroh has selected to a peer, as the race sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathKind {
    Ip,
    WebRtc,
    /// A multihop route through other members. It is not on the relay, but a
    /// pair on it has no lane of its own: an IP path or a `WebRTC` session ranks
    /// above it.
    Multihop,
    /// The gossip rung: frames of the mesh topic carry the pair's QUIC. It is not on the relay
    /// either, and it ranks below multihop and above the relay.
    Gossip,
    Relay,
    None,
}
