//! The iroh-exposing corner: endpoint construction and reachability probes.
//!
//! Deliberately quarantined. Every other public module is free of `iroh` types
//! so a consumer's own surface can be; a diagnostics command that genuinely
//! needs an `Endpoint` reaches in here and accepts the coupling.

use crate::gossip::PathSummary;
use iroh::endpoint::TransportAddrUsage;
use iroh::{Endpoint, EndpointId, RelayUrl, TransportAddr};

#[cfg(feature = "multihop")]
pub use crate::lookup::multihop_handle_config;
#[cfg(all(
    feature = "host",
    feature = "iroh-test-utils",
    not(target_arch = "wasm32")
))]
pub use crate::lookup::set_underlay_leg_off;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub use crate::lookup::test_relay;
pub use crate::lookup::{
    EndpointError, TransportHandles, TransportOpts, add_peer_addr, address_book, build_endpoint,
    build_peer_endpoint, probe_connect, probe_ladder, relay_ladder,
};
#[cfg(feature = "host")]
pub use crate::lookup::{NetworkCapability, capability_probe};
pub use crate::protocol::peer_addr_error::{endpoint_addr_from_json, endpoint_addr_to_json};
/// The direct-`WebRTC`-session ceiling this engine enforces, so a consumer
/// renders the same denominator the engine checks. It used to be written out
/// once here and again in each frontend, and the UI's copy drifted from the
/// one that was enforced.
pub use crate::transport::MAX_DIRECT_PEERS;
/// The ids of the custom transports, so a consumer that names the path of a
/// peer (`TransportAddr::Custom(addr)` with `addr.id()`) reads the engine's
/// values. A copy in the consumer would drift with no error. They are here
/// with any set of features: a peer can reach this node over multihop even
/// when this build does not register it.
pub use habilis_network_iroh_transport_util::{
    GOSSIP_TRANSPORT_ID, MULTIHOP_TRANSPORT_ID, WEBRTC_TRANSPORT_ID,
};

/// A direct lane to one peer, without a mesh: the `WebRTC` endpoint, both
/// halves of the JSEP round, and the gate that holds payload until iroh
/// selects a non-relay path. The mesh uses the same pieces; `habilis-network-stream`
/// is the second caller.
pub mod direct {
    pub use crate::lookup::build_peer_webrtc;
    pub use crate::transport::payload_path::{
        PROBE_DEADLINE, PayloadPath, refuse_unless_direct, wait_direct,
    };
    pub use crate::transport::webrtc::{
        IceProfile, MESH_WEBRTC_SIGNAL_ALPN, NUDGE_ALPN, NudgeAcceptor, UdpTransport,
        WebRtcSignalAcceptor, dial_signal, pair_needs_lane,
    };
    pub use crate::transport::{MAX_DIRECT_PEERS, SignalAdmission};
    pub use habilis_network_iroh_webrtc_transport::WebRtcHandle;
    /// Tests only: take UDP away from every connection in the process.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub use habilis_network_iroh_webrtc_transport::block_ip_paths;
}

/// Snapshot the active transport paths to `node_id`, plus the relay URL
/// when one is in use. Point-in-time, not a watcher — iroh starts a fresh
/// link relayed and upgrades to direct after hole-punching, so a reading
/// taken right at `NeighborUp` skews toward `relay`; the periodic census
/// reading is the representative one. Diagnostics only; other iroh apps
/// wanted this too (sendme #67/#112, psyche #586).
pub async fn conn_path(
    endpoint: &Endpoint,
    node_id: EndpointId,
) -> (PathSummary, Option<RelayUrl>) {
    let Some(info) = endpoint.remote_info(node_id).await else {
        return (PathSummary::Unknown, None);
    };
    let mut has_direct = false;
    let mut has_relay = false;
    let mut relay_url = None;
    for addr in info.addrs() {
        if !matches!(addr.usage(), TransportAddrUsage::Active) {
            continue;
        }
        // `TransportAddr` is `#[non_exhaustive]`, so a wildcard is
        // mandatory and the match can't be made exhaustive.
        match addr.addr() {
            TransportAddr::Relay(url) => {
                has_relay = true;
                relay_url = Some(url.clone());
            }
            // A custom transport (`WebRTC`, multihop) is a peer-to-peer path
            // as far as the relay is concerned: nothing on it crosses the
            // relay server.
            TransportAddr::Ip(_) | TransportAddr::Custom(_) => has_direct = true,
            _ => {}
        }
    }
    let summary = match (has_direct, has_relay) {
        (true, true) => PathSummary::Mixed,
        (true, false) => PathSummary::Direct,
        (false, true) => PathSummary::Relay,
        (false, false) => PathSummary::Unknown,
    };
    (summary, relay_url)
}
