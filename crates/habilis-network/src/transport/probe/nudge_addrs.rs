//! The addresses a nudge uses.

/// What a nudge dials besides the bare id, so that iroh learns the addresses of
/// the paths that a pair can still climb to. One dial can carry both.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct NudgeAddrs {
    /// The pair's `WebRTC` session address.
    pub(crate) session: bool,
    /// The multihop route to the peer, from the topology.
    pub(crate) route: Option<iroh::TransportAddr>,
    /// The gossip address of the peer.
    pub(crate) gossip: bool,
}
