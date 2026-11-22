/// What an endpoint is for. The code that builds the endpoint says it, in its [`TransportHandles`].
/// A role is one value, so an endpoint cannot be a beacon and an underlay at once.
///
/// [`TransportHandles`]: super::TransportHandles
///
/// # Examples
///
/// The default role is a peer. The doc test compiles it and runs it.
///
/// ```
/// use habilis_network::net::{EndpointRole, TransportHandles};
///
/// assert_eq!(TransportHandles::default().role, EndpointRole::Peer);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum EndpointRole {
    /// A member endpoint: it carries the traffic of a node. The key it holds does not make it a beacon.
    #[default]
    Peer,
    /// The endpoint that serves the rendezvous, of a mesh that is configured with a relay lookup. Only the
    /// beacon publishes the rendezvous to the DHT, and this one publishes its relay and no IP address. The beacon
    /// of a public rendezvous carries a `WebRTC` handle, so the handles do not tell it.
    Beacon,
    /// The beacon of a mesh that is configured with no relay lookup. It has no relay URL to publish, so it
    /// publishes every address of the endpoint to the DHT, its private LAN addresses too.
    BeaconWithoutRelay,
    /// An internal forwarding endpoint of the multi-hop transport: not a peer and not a beacon.
    Underlay,
}

impl EndpointRole {
    /// The word that a log line names the role by.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::Beacon | Self::BeaconWithoutRelay => "beacon",
            Self::Underlay => "underlay",
        }
    }
}
