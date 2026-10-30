//! The UDP transport a WebRTC session runs on.

/// Whether this node has a UDP transport, as its own state knows it.
///
/// # Examples
///
/// A UDP transport says whether a node has a UDP path to offer. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::net::direct::UdpTransport;
///
/// # fn demo(udp: UdpTransport) {
/// let _ = udp;
/// # }
/// ```
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
        Self::from_bool(present)
    }
}

impl UdpTransport {
    /// Make the UDP transport from a flag.
    #[must_use]
    pub fn from_bool(
        // `true` means the peer is present (`Present`); `false` means it is absent (`Absent`).
        present: bool,
    ) -> Self {
        if present { Self::Present } else { Self::Absent }
    }
}
