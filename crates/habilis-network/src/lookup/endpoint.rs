// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.

use anyhow::Result;
use iroh::{Endpoint, SecretKey};

use crate::protocol::mesh::LookupOpts;

/// Install on `builder` every custom transport and hook a mesh node needs: the
/// multi-hop transport (with its address lookup and backup path selector), the
/// `WebRTC` transport with its selector, and the connection hook that records
/// the endpoint's connections in the admission table.
///
/// The one definition of that wiring. [`build_endpoint`] calls it, and so does
/// [`InjectedEndpoint::bind`](crate::runtime::InjectedEndpoint::bind), so an
/// injected endpoint and an engine-built one cannot drift. Without the hook the
/// table sees none of the endpoint's connections: the relay policy is not kept on
/// the gossip connections that the node dials, and a slot whose connection is gone
/// is never pruned.
///
/// The builder is consumed here, so no caller can add a `path_selector` or a
/// `hooks` call after it: both are single slots, and the last call wins.
#[must_use]
pub(crate) fn install_transports(
    mut builder: iroh::endpoint::Builder,
    transports: &super::TransportHandles,
) -> iroh::endpoint::Builder {
    // Register the multi-hop custom transport (plus its address lookup + backup
    // path selector) so a `connect` to a peer with no direct path rides the
    // multihop path. The handle's app id must match this endpoint's key — the
    // caller (`build_peer_multihop`) pins the same secret.
    #[cfg(feature = "multihop")]
    let mut selector_set = false;
    #[cfg(feature = "multihop")]
    if let Some(handle) = transports.multihop.clone() {
        builder = builder.preset(handle);
        selector_set = true;
    }
    #[cfg(not(feature = "multihop"))]
    let mut selector_set = false;
    // WebRTC is additive: it joins IP and relay as another candidate path
    // rather than replacing them. Two native peers are better served by iroh's
    // own hole-punching; this is the browser's only path, and a fallback for
    // NATs that defeat hole-punching but not ICE.
    if let Some(handle) = transports.webrtc.clone() {
        if transports.opts.webrtc {
            builder = builder.add_custom_transport(handle.transport());
            // MUST come after `builder.preset(handle)` for multihop above: there
            // is a single `path_selector` slot and the last call wins. Safe only
            // because both selectors rank by the same ladder (IP, WebRTC,
            // multihop, relay), whichever one is installed. Do not "tidy" this
            // above the preset.
            builder = builder.path_selector(handle.path_selector());
            selector_set = true;
        } else if cfg!(feature = "iroh-test-utils") {
            // Tests only: a mesh whose list leaves out `webrtc` still takes the
            // selector, without the transport, so that a test can take IP paths
            // away from one node to others (`Request::BlockIpTo`). Without it
            // such a node uses iroh's own selector, which the hook cannot reach.
            builder = builder.path_selector(handle.path_selector());
            selector_set = true;
        }
    }
    // Gossip is the lowest custom rung, and the member endpoint only. The selector of the
    // multihop or the `WebRTC` transport already ranks it; with neither, iroh's default
    // would put gossip above IP, so the ladder of the gossip handle is the selector.
    if let Some(handle) = transports.gossip.clone() {
        builder = builder
            .add_custom_transport(handle.custom_transport())
            .address_lookup(handle.address_lookup());
        if !selector_set {
            builder = builder.path_selector(handle.path_selector());
        }
    }
    if let Some(admission) = &transports.admission {
        builder = builder.hooks(admission.connection_hook());
    }
    builder
}

/// The memory windows of a QUIC connection, on every endpoint of the engine, the multihop underlay
/// and the blob endpoint included (decision D11). They are generous on purpose: the count of direct
/// connections is the real limit, and these only keep one connection from growing without bound.
/// Keep-alive, idle timeout, multipath, stream counts and datagrams stay at the iroh defaults.
pub(crate) fn quic_limits() -> iroh::endpoint::QuicTransportConfig {
    use crate::util::tuning::{
        QUIC_CONNECTION_RECEIVE_WINDOW, QUIC_SEND_WINDOW, QUIC_STREAM_RECEIVE_WINDOW,
    };
    use iroh::endpoint::{QuicTransportConfig, VarInt};

    QuicTransportConfig::builder()
        .stream_receive_window(VarInt::from_u32(QUIC_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(QUIC_CONNECTION_RECEIVE_WINDOW))
        .send_window(QUIC_SEND_WINDOW)
        .build()
}

/// # Errors
/// Returns an error if the inputs are invalid or the operation fails.
pub async fn build_endpoint(
    lookups: &LookupOpts,
    secret_key: Option<SecretKey>,
    bind_port: Option<u16>,
    alpns: Vec<Vec<u8>>,
    transports: super::TransportHandles,
) -> Result<Endpoint, super::EndpointError> {
    build_endpoint_checked(lookups, secret_key, bind_port, alpns, transports)
        .await
        .map_err(super::EndpointError::internal)
}

async fn build_endpoint_checked(
    lookups: &LookupOpts,
    secret_key: Option<SecretKey>,
    bind_port: Option<u16>,
    alpns: Vec<Vec<u8>>,
    transports: super::TransportHandles,
) -> Result<Endpoint> {
    Ok(
        super::build_endpoint_keeping_mdns(lookups, secret_key, bind_port, alpns, transports)
            .await?
            .0,
    )
}
