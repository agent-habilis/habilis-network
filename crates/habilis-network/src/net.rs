//! The iroh-exposing corner: endpoint construction and reachability probes.
//!
//! Deliberately quarantined. Every other public module is free of `iroh` types
//! so a consumer's own surface can be; a diagnostics command that genuinely
//! needs an `Endpoint` reaches in here and accepts the coupling.

use crate::gossip::PathSummary;
use iroh::endpoint::TransportAddrUsage;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, TransportAddr};

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
///
/// # Examples
///
/// It reads the path that a connection to a node uses. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::iroh::{Endpoint, EndpointId};
/// use habilis_network::net::conn_path;
///
/// # async fn demo(endpoint: &Endpoint, node: EndpointId) {
/// let path = conn_path(endpoint, node).await;
/// # let _ = path;
/// # }
/// ```
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
    for address in info.addrs() {
        if !matches!(address.usage(), TransportAddrUsage::Active) {
            continue;
        }
        // `TransportAddr` is `#[non_exhaustive]`, so a wildcard is
        // mandatory and the match can't be made exhaustive.
        match address.addr() {
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

/// The transport addresses that carry traffic to `node_id` right now, or none when the endpoint
/// knows no such peer.
///
/// # Examples
///
/// It lists the transport addresses that a connection to a node is using. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::iroh::{Endpoint, EndpointId};
/// use habilis_network::net::active_transport_addrs;
///
/// # async fn demo(endpoint: &Endpoint, node: EndpointId) {
/// let addrs = active_transport_addrs(endpoint, node).await;
/// # let _ = addrs;
/// # }
/// ```
pub async fn active_transport_addrs(
    endpoint: &Endpoint,
    node_id: EndpointId,
) -> impl Iterator<Item = TransportAddr> + use<> {
    let mut active: Vec<TransportAddr> = Vec::new();
    if let Some(info) = endpoint.remote_info(node_id).await {
        for address in info.addrs() {
            if matches!(address.usage(), TransportAddrUsage::Active) {
                active.push(address.addr().clone());
            }
        }
    }
    active.into_iter()
}

/// The address that other peers dial to reach `endpoint`.
///
/// # Examples
///
/// It gives the address of a local endpoint, which a peer can dial. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::iroh::Endpoint;
/// use habilis_network::net::endpoint_address;
///
/// # fn demo(endpoint: &Endpoint) {
/// let address = endpoint_address(endpoint);
/// # let _ = address;
/// # }
/// ```
#[must_use]
pub fn endpoint_address(endpoint: &Endpoint) -> EndpointAddr {
    endpoint.addr()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use iroh::endpoint::presets;
    use iroh::{Endpoint, RelayMode};

    #[test]
    fn the_address_of_an_endpoint_names_its_id() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let endpoint: Endpoint = Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Disabled)
                .clear_address_lookup()
                .bind()
                .await
                .expect("bind loopback endpoint");
            assert_eq!(
                super::endpoint_address(&endpoint).id,
                endpoint.id(),
                "the address carries the id of the endpoint"
            );
            endpoint.close().await;
        });
    }

    #[test]
    fn an_unknown_peer_has_no_active_addresses() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let endpoint: Endpoint = Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Disabled)
                .clear_address_lookup()
                .bind()
                .await
                .expect("bind loopback endpoint");
            let stranger = iroh::SecretKey::generate().public();
            assert!(
                super::active_transport_addrs(&endpoint, stranger)
                    .await
                    .next()
                    .is_none(),
                "an endpoint that never met a peer reports no active address for it"
            );
            endpoint.close().await;
        });
    }
}
