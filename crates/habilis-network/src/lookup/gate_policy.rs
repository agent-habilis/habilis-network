/// How the gossip gate of a node treats an inbound connection.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GatePolicy {
    /// The mesh's `transport.relay_transport`: with it off, every inbound gossip connection is
    /// held until iroh selects a direct path on it.
    pub(crate) relay_transport: bool,
    /// This node has no UDP path, so its gossip gate needs a `WebRTC` session with the dialer (see
    /// `DirectOnlyGossip::accept`).
    pub(crate) needs_session: bool,
}
