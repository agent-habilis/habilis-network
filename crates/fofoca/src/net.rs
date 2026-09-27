//! The iroh-exposing corner: endpoint construction and reachability probes.
//!
//! Deliberately quarantined. Every other public module is free of `iroh` types
//! so a consumer's own surface can be; a diagnostics command that genuinely
//! needs an `Endpoint` reaches in here and accepts the coupling.

pub use crate::gossip::conn_path;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub use crate::lookup::test_relay;
#[cfg(feature = "host")]
pub use crate::lookup::{NetworkCapability, capability_probe};
pub use crate::lookup::{
    PathFlags, TransportHandles, TransportOpts, add_peer_addr, build_endpoint, build_peer_endpoint,
    check_injected_identity, probe_connect, probe_ladder, relay_ladder,
};
pub use crate::protocol::peer_addr::{endpoint_addr_from_json, endpoint_addr_to_json};
/// The direct-`WebRTC`-session ceiling this engine enforces, so a consumer
/// renders the same denominator the engine checks. It used to be written out
/// once here and again in each frontend, and the UI's copy drifted from the
/// one that was enforced.
pub use crate::transport::MAX_DIRECT_PEERS;

/// A direct lane to one peer, without a mesh: the `WebRTC` endpoint, both
/// halves of the JSEP round, and the gate that holds payload until iroh
/// selects a non-relay path. The mesh uses the same pieces; `fofoca-stream`
/// is the second caller.
pub mod direct {
    pub use crate::lookup::build_peer_webrtc;
    pub use crate::transport::path::{PROBE_DEADLINE, refuse_unless_direct, wait_direct};
    pub use crate::transport::webrtc::{
        IceProfile, MESH_WEBRTC_SIGNAL_ALPN, WebRtcSignalAcceptor, dial_signal, pair_needs_lane,
    };
    pub use crate::transport::{MAX_DIRECT_PEERS, SignalAdmission};
    pub use fofoca_iroh_webrtc_transport::WebRtcHandle;
}
