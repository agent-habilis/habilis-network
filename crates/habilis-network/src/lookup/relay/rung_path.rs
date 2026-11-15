/// How a rung of the default ladder reaches its relay, and so whether the relay answers QUIC
/// address discovery.
///
/// # Examples
///
/// A tunnel rung has no port for QUIC address discovery.
///
/// ```
/// use habilis_network::RungPath;
///
/// assert_eq!(RungPath::Tunnel.qad_port(), None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RungPath {
    /// The relay faces the internet, and it answers QUIC address discovery on a UDP port.
    Direct {
        /// The UDP port of the QUIC address discovery of the relay.
        qad_port: u16,
    },
    /// The relay is behind an HTTP tunnel. The tunnel carries no UDP, so the relay answers no
    /// QUIC address discovery.
    Tunnel,
}

impl RungPath {
    /// The UDP port of the QUIC address discovery of the relay, or `None` for a tunnel rung.
    #[must_use]
    pub fn qad_port(self) -> Option<u16> {
        match self {
            Self::Direct { qad_port } => Some(qad_port),
            Self::Tunnel => None,
        }
    }
}
