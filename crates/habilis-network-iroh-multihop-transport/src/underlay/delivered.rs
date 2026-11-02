use iroh_base::CustomAddr;

/// A packet that reached its destination on this node, ready for the local
/// transport's `poll_recv` to surface to iroh.
#[derive(Debug, Clone)]
pub(crate) struct Delivered {
    /// The sender's return address (a reversed route), reported to iroh as the
    /// remote of this packet so replies route back.
    pub(crate) remote: CustomAddr,
    pub(crate) packet: Vec<u8>,
}
