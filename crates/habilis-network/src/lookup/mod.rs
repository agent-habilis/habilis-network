//! The lookup layer: building the iroh endpoint for a mesh mode and
//! wiring the selected lookups onto it. Each lookup mechanism lives in
//! its own submodule — [`mdns`] (LAN multicast), [`dht`] (mainline DHT),
//! and [`relay`] (the relay ladder + bootstrap-rung selection/failover).

mod address_book;

mod underlay_leg;

mod peer;

mod probe;
mod probe_answer;

mod lan;
mod lan_event;
mod mdns_handle;

mod endpoint;

use crate::transport::webrtc;
use crate::util::tuning;
#[cfg(feature = "host")]
mod capability;
#[cfg(all(feature = "host", feature = "dht"))]
mod dht;
mod error;
#[cfg(all(feature = "host", feature = "mdns"))]
mod mdns;
mod relay;
mod transport_handles;
mod transport_opts;

// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.

use iroh::Endpoint;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::Router;
use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
use iroh_gossip::proto::HyparviewConfig;

use crate::transport::PayloadPath;

/// A local relay server every side of a test can reach: plain HTTP, so the
/// engine dials `ws://` with no TLS — and so can a **browser**, which owns
/// its own trust store and refuses a self-signed certificate with no
/// override (`iroh::test_utils::run_relay_server` is https-only). No QUIC
/// address discovery: a tab has no UDP, and the tests that use this force
/// the relay to be the only path anyway.
#[cfg(all(any(test, feature = "iroh-test-utils"), not(target_arch = "wasm32")))]
#[cfg_attr(
    not(feature = "iroh-test-utils"),
    expect(
        unreachable_pub,
        reason = "`net` re-exports it only with `iroh-test-utils`"
    )
)]
pub mod test_relay;

#[cfg(feature = "host")]
pub use capability::{NetworkCapability, probe as capability_probe};
pub use error::EndpointError;
pub use relay::{RENDEZVOUS_RELAY_LADDER, probe_ladder, relay_ladder};
pub(crate) use relay::{
    RungRefresh, StoppableTask, plan_rung_refresh, select_bootstrap_rung, spawn_relay_monitor,
};
pub use transport_handles::TransportHandles;
pub use transport_opts::TransportOpts;

#[cfg(all(feature = "multihop", not(feature = "host")))]
pub(crate) use peer::browser_handle_config;
#[cfg(all(feature = "host", test))]
pub(crate) use peer::build_peer_multihop;
#[cfg(feature = "multihop")]
pub(crate) use peer::build_peer_multihop_with;
#[cfg(feature = "multihop")]
pub use peer::multihop_handle_config;
pub use peer::{build_peer_endpoint, build_peer_webrtc};
pub(crate) use peer::{build_peer_webrtc_with, check_injected_against_mesh, new_webrtc_handle};

pub use probe::probe_connect;
pub(crate) use probe_answer::{ProbeAnswer, probe_answer};

pub use endpoint::build_endpoint;

pub(crate) use address_book::replace_peer_addr;
pub use address_book::{add_peer_addr, address_book};

#[cfg(all(feature = "host", feature = "iroh-test-utils"))]
pub use underlay_leg::set_underlay_leg_off;
#[cfg(feature = "multihop")]
pub(crate) use underlay_leg::underlay_cap;

pub(crate) use endpoint::install_transports;
pub(crate) use lan::{build_endpoint_keeping_mdns, lan_contacts};
pub(crate) use lan_event::LanEvent;
pub use mdns_handle::MdnsHandle;

/// How many events of a topic the gossip keeps for a task that is not scheduled yet: sixteen full
/// answers to an anti-entropy digest. A late joiner meets the answers of its peers in one burst,
/// and every change is a message of the topic. The default of 256 overflowed on a loaded host
/// (the reader got `Lagged`, and the node logged "gossip event stream lagged").
const TOPIC_EVENT_CAPACITY: usize = 16 * tuning::ANTIENTROPY_MAX_RESEND;

/// Build an iroh-gossip instance and a Router that accepts incoming gossip connections.
///
/// The Router spawns an accept loop that routes incoming QUIC connections
/// with the gossip ALPN to the Gossip protocol handler. Without this,
/// peers cannot accept inbound connections from other peers.
pub(crate) fn build_mesh(
    endpoint: Endpoint,
    active_view_capacity: usize,
    unicast: Option<crate::transport::UnicastAcceptor>,
    // The admission travels with the handle because the acceptor built below
    // has to share it with the dialing side — one ceiling per node, not one
    // per role. The beacon passes `None` and needs neither.
    webrtc: Option<(
        habilis_network_iroh_webrtc_transport::WebRtcHandle,
        crate::transport::SignalAdmission,
        crate::transport::IceProfile,
    )>,
    protocols: Vec<(Vec<u8>, Box<dyn iroh::protocol::DynProtocolHandler>)>,
    // The mesh's `transport.relay_transport`: with it off, every inbound gossip
    // connection is held until iroh selects a direct path on it.
    relay_transport: bool,
    // This node has no UDP path, so its gossip gate needs a `WebRTC` session
    // with the dialer (see `DirectOnlyGossip::accept`).
    needs_session: bool,
) -> (Gossip, Router, MemoryLookup) {
    // `active_view_capacity` is the live direct-neighbor cap (`--max-peers`),
    // raised above iroh-gossip's default (5) so meshes up to it form a full mesh
    // with nothing to shuffle — no membership churn, hence none of the
    // churn-driven per-connection leak. Set it small to reproduce the churn. The
    // passive (healing/shuffle) pool is kept at 2× the active view.
    let membership = HyparviewConfig {
        active_view_capacity: active_view_capacity.max(1),
        passive_view_capacity: (active_view_capacity * 2).max(1),
        ..Default::default()
    };
    let gossip = Gossip::builder()
        .membership_config(membership)
        .topic_event_capacity(TOPIC_EVENT_CAPACITY)
        .spawn(endpoint.clone());
    let local = endpoint.id();
    // The address book of the endpoint, made where the endpoint is wrapped. The caller keeps it,
    // and the signal acceptor registers webrtc transport addresses in it on attach.
    let book = address_book(&endpoint);
    // Cloned before the Router consumes the endpoint.
    let endpoint_for_acceptor = endpoint.clone();
    if let Some((_, admission, _)) = &webrtc {
        admission.watch_dialed_gossip(!relay_transport);
    }
    let session_gate = webrtc
        .as_ref()
        .filter(|_| needs_session)
        .map(|(handle, admission, _)| (handle.clone(), admission.clone(), local));
    // Every router serves the nudge, the beacon's too: a session that attaches to the rendezvous
    // is followed by a nudge, and it does its work only when the connect completes.
    let mut builder = Router::builder(endpoint)
        .accept(
            GOSSIP_ALPN,
            crate::transport::DirectOnlyGossip::new(
                gossip.clone(),
                PayloadPath::from(relay_transport),
                session_gate,
            ),
        )
        .accept(webrtc::NUDGE_ALPN, webrtc::NudgeAcceptor);
    // A peer also accepts inbound unicast; the rendezvous/beacon endpoint
    // passes `None` (it is not a peer and carries no unicast traffic).
    if let Some(acceptor) = unicast {
        builder = builder.accept(crate::transport::UNICAST_ALPN, acceptor);
    }
    // …and answers JSEP offers, so a peer that cannot reach us over IP can
    // still open a direct data channel. Answering is unconditional: the role
    // rule (lower `EndpointId` offers) decides who *dials*, and a peer that
    // never answers can never be dialled by anyone.
    if let Some((handle, admission, ice)) = webrtc {
        builder = builder.accept(
            crate::transport::MESH_WEBRTC_SIGNAL_ALPN,
            crate::transport::WebRtcSignalAcceptor::new(
                handle,
                endpoint_for_acceptor,
                book.clone(),
                local,
                admission,
                ice,
            ),
        );
    }
    // The caller's own protocols, if it shares this endpoint with us.
    //
    // They have to come through here rather than the caller running its own
    // `endpoint.accept()` loop, and the reason is not stylistic: `Router::spawn`
    // calls `endpoint.set_alpns`, whose own documentation says it *overrides*
    // the ALPN list — so a caller that set its ALPNs at build time silently
    // loses them the moment we spawn. And two accept loops on one endpoint are
    // two consumers of one queue, so each inbound connection goes to whichever
    // loop wins the race. One Router owns `accept()`; everyone else registers.
    for (alpn, handler) in protocols {
        builder = builder.accept(alpn, handler);
    }
    let router = builder.spawn();
    (gossip, router, book)
}

#[cfg(test)]
mod tests;
