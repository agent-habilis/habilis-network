//! The UDP transport a WebRTC session runs on.

/// Whether this node has a UDP transport, as its own state knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UdpTransport {
    /// The peer is present.
    Present,
    /// The peer is absent.
    Absent,
}

impl From<bool> for UdpTransport {
    fn from(present: bool) -> Self {
        if present { Self::Present } else { Self::Absent }
    }
}
