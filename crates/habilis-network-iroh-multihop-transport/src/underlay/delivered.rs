use iroh_base::CustomAddr;

/// A packet that reached its destination on this node, ready for the local
/// transport's `poll_recv` to surface to iroh.
#[derive(Debug, Clone)]
pub(crate) struct Delivered {
    /// The sender's address (the application id of the node that made the cell), reported to iroh as the
    /// remote of this packet so replies go back to it.
    pub(crate) remote: CustomAddr,
    pub(crate) packet: Vec<u8>,
}
