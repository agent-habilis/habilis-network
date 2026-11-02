use crate::transport::webrtc;
use crate::util::tuning;
// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.

use iroh::Endpoint;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::Router;
use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
use iroh_gossip::proto::HyparviewConfig;

use crate::transport::PayloadPath;

use crate::transport;
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
    unicast: Option<transport::UnicastAcceptor>,
    // The admission travels with the handle because the acceptor built below
    // has to share it with the dialing side — one ceiling per node, not one
    // per role. The beacon passes `None` and needs neither.
    webrtc: Option<(
        habilis_network_iroh_webrtc_transport::WebRtcHandle,
        transport::SignalAdmission,
        transport::IceProfile,
    )>,
    protocols: habilis_network_iroh_transport_util::ProtocolSet,
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
    let gossip_builder = Gossip::builder()
        .membership_config(membership)
        .topic_event_capacity(TOPIC_EVENT_CAPACITY);
    let gossip = gossip_builder.spawn(endpoint.clone());
    let local = endpoint.id();
    // The address book of the endpoint, made where the endpoint is wrapped. The caller keeps it,
    // and the signal acceptor registers webrtc transport addresses in it on attach.
    let book = super::address_book(&endpoint);
    // Cloned before the Router consumes the endpoint.
    let endpoint_for_acceptor = endpoint.clone();
    if let Some((_, admission, _)) = &webrtc {
        admission.watch_dialed_gossip(!relay_transport);
    }
    let gated = webrtc.as_ref().filter(|_| needs_session);
    let session_gate: Option<(
        habilis_network_iroh_webrtc_transport::WebRtcHandle,
        transport::SignalAdmission,
        iroh::PublicKey,
    )> = gated.map(|(handle, admission, _)| (handle.clone(), admission.clone(), local));
    // Every router serves the nudge, the beacon's too: a session that attaches to the rendezvous
    // is followed by a nudge, and it does its work only when the connect completes.
    let mut builder = Router::builder(endpoint)
        .accept(
            GOSSIP_ALPN,
            transport::DirectOnlyGossip::new(
                gossip.clone(),
                PayloadPath::from(relay_transport),
                session_gate,
            ),
        )
        .accept(webrtc::NUDGE_ALPN, webrtc::NudgeAcceptor);
    // A peer also accepts inbound unicast; the rendezvous/beacon endpoint
    // passes `None` (it is not a peer and carries no unicast traffic).
    if let Some(acceptor) = unicast {
        builder = builder.accept(transport::UNICAST_ALPN, acceptor);
    }
    // …and answers JSEP offers, so a peer that cannot reach us over IP can
    // still open a direct data channel. Answering is unconditional: the role
    // rule (lower `EndpointId` offers) decides who *dials*, and a peer that
    // never answers can never be dialled by anyone.
    if let Some((handle, admission, ice)) = webrtc {
        builder = builder.accept(
            transport::MESH_WEBRTC_SIGNAL_ALPN,
            transport::WebRtcSignalAcceptor::new(
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
