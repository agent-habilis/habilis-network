use super::transport_opts::TransportOpts;

use crate::transport;
/// Build an iroh endpoint for a mesh's lookups.
///
/// - `lookups`: which address-lookups (mDNS / DHT) and relay to wire.
///   When any lookup is on, the builder is composed from
///   `presets::Minimal` plus the selected lookups; the relay maps via
///   `relay::relay_mode`. An all-off (loopback-only) set wires none of
///   them.
/// - `secret_key`: `Some` pins a deterministic identity (used for the
///   shared rendezvous endpoint); `None` lets iroh generate a fresh
///   random key (the normal peer endpoint).
/// - `bind_port`: loopback-only — `Some(port)` binds
///   `127.0.0.1:port` (the deterministic rendezvous port; a bind
///   failure with `AddrInUse` is the claim-if-free signal that another
///   member already holds the beacon). `None` binds an ephemeral port.
///   Ignored when lookups are on (N0 manages binding).
/// # Errors
/// Returns an error if the inputs are invalid or the operation fails.
/// The custom transports to register on an endpoint.
///
/// A struct rather than more positional arguments because the set grows: each
/// transport is independently optional, and several are host-only (they own
/// UDP sockets), so the field list itself differs per target. `Default` is
/// "IP and relay only".
///
/// # Examples
///
/// The transport handles are the handles to each transport that a node builds its endpoint from. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::net::TransportHandles;
///
/// # fn demo(handles: TransportHandles) {
/// let _ = handles;
/// # }
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct TransportHandles {
    /// Source-routed multi-hop: reach a peer with no direct path by relaying
    /// through intermediate peers. Built with the `multihop` feature; the native
    /// underlay builder, `build_peer_multihop_with`, is host-only.
    #[cfg(feature = "multihop")]
    pub multihop: Option<habilis_network_iroh_multihop_transport::MultihopHandle>,
    /// QUIC over a `WebRTC` data channel. The browser's only way onto the
    /// mesh, and an opportunistic extra path for a native peer.
    pub webrtc: Option<habilis_network_iroh_webrtc_transport::WebRtcHandle>,
    /// Gossip as a path: QUIC packets carried as frames on the mesh topic, below every
    /// direct path and above the relay. On the member endpoint only: the beacon, the
    /// blob endpoint and the multihop underlay never carry it.
    pub gossip: Option<habilis_network_iroh_gossip_transport::GossipHandle>,
    /// The table that decides who holds a direct-peer slot. When set, the
    /// endpoint reports every connection to it, so that it can drop the ones
    /// that are gone.
    pub admission: Option<transport::SignalAdmission>,
    /// The endpoint is a multi-hop underlay, an internal forwarding endpoint
    /// and not a peer or a beacon. Changes only the role a log line names.
    pub underlay: bool,
    /// Which transports this instance may carry data on. Lives here rather than
    /// as another positional argument for the same reason the handles do.
    pub options: TransportOpts,
}

impl TransportHandles {
    /// True when no custom transport is registered.
    #[must_use]
    pub(super) fn is_empty(&self) -> bool {
        #[cfg(feature = "multihop")]
        if self.multihop.is_some() {
            return false;
        }
        self.webrtc.is_none() && self.gossip.is_none()
    }
}
