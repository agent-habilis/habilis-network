//! The mesh's `WebRTC` signalling plane: how two peers that cannot reach each
//! other over IP still end up holding a direct data channel.
//!
//! The engine already carries a [`WebRtcHandle`] into `build_endpoint`
//! (`lookup::TransportHandles`), but until this module nothing ever *filled*
//! it: the transport was registered and permanently empty, because a session
//! only exists once two peers have exchanged SDP, and nothing exchanged SDP.
//! This is that exchange.
//!
//! **The relay is the rendezvous.** One short-lived connection on
//! [`MESH_WEBRTC_SIGNAL_ALPN`] carries one JSEP envelope each way and closes.
//! Any transport will do, and over the relay is the interesting case — it is a
//! browser's only way to reach a peer behind NAT, and the mesh's own bootstrap
//! already homes every member on a relay rung. No file or gossip payload ever
//! crosses it; it exists to introduce two peers to each other.
//!
//! **Why a session should exist before the peer is grafted.** A live
//! connection gains a newly attached transport's path only when another
//! connection to the peer completes: that is when iroh opens new paths and
//! re-runs selection (the pinned fork's Initial fan-out patch). Grafting on the
//! attach event gives the pair that connection. A connection that stays up
//! across a later attach, as in a re-race, is moved by a [`nudge`].
//!
//! Both roles are written once and split by target only where the JSEP APIs
//! genuinely differ (str0m natively, `RTCPeerConnection` in a tab). The wire
//! format — [`SignalEnvelope`] — is shared, so a browser and a CLI peer
//! negotiate with each other without either knowing which it is talking to.

// Per-target JSEP: only these two helpers differ by backend. Everything above — the ALPN, the
// envelope framing, the identity rule, the logging — is written once.
#[cfg(not(target_arch = "wasm32"))]
mod backend_native;
#[cfg(target_arch = "wasm32")]
mod backend_web;
pub(crate) mod close_code;
pub(crate) mod consts;
pub(crate) mod dial_signal;
pub(crate) mod ice_profile;
pub(crate) mod lane_needs;
pub(crate) mod negotiate_session;
pub(crate) mod nudge_acceptor;
pub(crate) mod offer;
pub(crate) mod rendezvous;
pub(crate) mod retry;
pub(crate) mod session_policy;
pub(crate) mod signal_deadlines;
pub(crate) mod udp_transport;
pub(crate) mod web_rtc_signal_acceptor;

pub use consts::{MAX_DIRECT_PEERS, MESH_WEBRTC_SIGNAL_ALPN, NUDGE_ALPN};
pub use dial_signal::dial_signal;
pub use ice_profile::IceProfile;
pub use nudge_acceptor::NudgeAcceptor;
pub use session_policy::pair_needs_lane;
pub use udp_transport::UdpTransport;
pub use web_rtc_signal_acceptor::WebRtcSignalAcceptor;

#[cfg(not(target_arch = "wasm32"))]
use backend_native::{build_answer, build_offer};
#[cfg(target_arch = "wasm32")]
use backend_web::{build_answer, build_offer};

// Host-only: two real loopback endpoints and a tokio runtime. The logic under
// test is written once for both targets, but a browser cannot bind an endpoint.
//
// These are in-src rather than in `tests/` because `WebRtcSignalAcceptor` is
// `pub(crate)` — and it should stay that way. Before them this whole plane
// (the ALPN, the acceptor, the dialer, the retry tick) had no coverage
// anywhere in the workspace: `habilis-network-iroh-webrtc-transport`'s loopback test
// hands envelopes over in memory, and `agent-share`'s tests exercise the
// *share's* signal ALPN, not this one.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::time::Duration;

    use habilis_network_iroh_webrtc_transport::WebRtcTransport;
    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::{RelayMode, SecretKey};

    #[cfg(feature = "iroh-test-utils")]
    use super::nudge_acceptor;
    use super::signal_deadlines::SignalDeadlines;
    use super::{
        IceProfile, MAX_DIRECT_PEERS, MESH_WEBRTC_SIGNAL_ALPN, NUDGE_ALPN, NudgeAcceptor,
        UdpTransport, WebRtcSignalAcceptor, dial_signal, lane_needs, negotiate_session, rendezvous,
        retry, session_policy, web_rtc_signal_acceptor,
    };
    use crate::daemon::handler_ctx;
    use crate::lookup::EndpointError;
    use crate::transport::admission::SignalAdmission;
    use crate::transport::probe::PathKind;
    use habilis_network_iroh_webrtc_transport::{MAX_ENVELOPE_BYTES, WebRtcHandle};
    use iroh::address_lookup::memory::MemoryLookup;
    use iroh::endpoint::Connection;
    use iroh::protocol::{AcceptError, ProtocolHandler};
    use iroh::{Endpoint, EndpointAddr, EndpointId};

    use crate::daemon::state;
    use crate::gossip::event;
    #[cfg(feature = "iroh-test-utils")]
    use crate::lookup::test_relay;
    use crate::transport::probe;
    use crate::util::{clock, tuning};
    use tokio::sync::mpsc;
    fn relay_addr() -> iroh::TransportAddr {
        iroh::TransportAddr::Relay("https://relay.example".parse().expect("a relay url"))
    }

    /// A browser: relay only, because wasm has no IP stack.
    fn browser_shaped(id: EndpointId) -> EndpointAddr {
        EndpointAddr::from_parts(id, [relay_addr()])
    }

    /// A native peer: always advertises at least one IP transport.
    fn native_shaped(id: EndpointId) -> EndpointAddr {
        EndpointAddr::from_parts(
            id,
            [
                iroh::TransportAddr::Ip("127.0.0.1:4433".parse().expect("a socket address")),
                relay_addr(),
            ],
        )
    }

    /// The lane is for peers that cannot be reached any other way.
    ///
    /// A regression guard, not a unit test of a one-liner: without this gate the
    /// mesh negotiated a data channel with *every* peer, so two native peers ran
    /// gossip over a transport measured at 6× less throughput and 36× the
    /// latency of the QUIC path they already had.
    #[test]
    fn a_udp_pair_races_until_udp_is_selected() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            session_policy::wants_session(false, None, false),
            "a udp pair races the punch"
        );
        assert!(
            !session_policy::wants_session(false, Some(PathKind::Ip), false),
            "udp won; no round"
        );
        assert!(
            session_policy::wants_session(true, None, false),
            "a lane pair always negotiates"
        );
        assert!(
            session_policy::wants_session(true, Some(PathKind::Ip), true),
            "a lane pair's session is its only direct path"
        );
    }

    // A pair proven direct with no session proved its UDP path; a cold or
    // idled-out pool must not start the race again on every alive tick.
    #[test]
    fn a_proven_udp_pair_is_not_raced_again() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            !session_policy::wants_session(false, None, true),
            "proven direct, no live connection to read"
        );
        assert!(
            !session_policy::wants_session(false, Some(PathKind::WebRtc), true),
            "proven direct, riding a session"
        );
    }

    // The proof of a direct path is a state of the engine, and only a watcher on a
    // pooled connection takes it back. When the admission table reads the relay as the
    // selected path, the proof is stale: the pair offers, as one that was never proven.
    #[test]
    fn a_proven_pair_that_reads_as_relay_is_offered_a_session() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            session_policy::wants_session(false, Some(PathKind::Relay), true),
            "a proven pair that reads as relay is offered a session"
        );
    }

    // Only the lower id watches a pooled connection, so when the higher id is the one
    // that sends, the lower id never sees the direct path go. The higher id then offers
    // by itself, once its own reading contradicts the proof; the lower id wins a crossing.
    #[test]
    fn the_higher_id_offers_when_the_proof_of_a_direct_path_is_stale() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            session_policy::waits_for_the_offer(true, false, None, false),
            "nothing to say"
        );
        assert!(
            session_policy::waits_for_the_offer(true, false, Some(PathKind::Ip), true),
            "the proof holds"
        );
        assert!(
            !session_policy::waits_for_the_offer(true, true, None, false),
            "a frame is held for the peer"
        );
        assert!(
            !session_policy::waits_for_the_offer(true, false, Some(PathKind::Relay), true),
            "the pair reads as relay although it was proven"
        );
        assert!(
            session_policy::waits_for_the_offer(true, false, Some(PathKind::Relay), false),
            "never proven: the lower id offers"
        );
        assert!(
            !session_policy::waits_for_the_offer(false, false, Some(PathKind::Ip), true),
            "the lower id never waits"
        );
    }

    // The recursion rule closes a gossip link on the gossip rung, so a pair that reads as the
    // gossip rung is raced as one that reads as the relay: its proof is taken back and the
    // session round reports at once, not after it judges the connection for UDP.
    #[test]
    fn a_proven_pair_on_gossip_is_demoted_as_one_on_the_relay() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            session_policy::reads_below_a_session(Some(PathKind::Relay), true),
            "a proven pair on gossip is demoted as one on the relay"
        );
        assert!(
            session_policy::reads_below_a_session(Some(PathKind::Gossip), true),
            "a proven pair on gossip reads below a session"
        );
        assert!(
            !session_policy::reads_below_a_session(Some(PathKind::Gossip), false),
            "a proven pair on gossip is not demoted further"
        );
        for kind in [Some(PathKind::Ip), Some(PathKind::WebRtc), None] {
            assert!(
                !session_policy::reads_below_a_session(kind, true),
                "{kind:?}"
            );
        }
    }

    // A pair on gossip is below a session as a pair on multihop is: its proof of a direct path is
    // stale, and it asks for a session.
    #[test]
    fn a_pair_on_gossip_is_offered_a_session_even_when_proven_direct() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            session_policy::proof_is_stale(Some(PathKind::Gossip), true),
            "the proof of a pair on gossip is stale"
        );
        assert!(
            session_policy::wants_session(false, Some(PathKind::Gossip), true),
            "a pair on gossip is offered a session even when proven direct"
        );
    }

    // A pair that multihop carries is off the relay, so it is proven direct, but a
    // session ranks above multihop. The pair offers whether or not a pooled
    // connection exists: the kind comes from the watcher, or from the admission
    // table when the pool has closed an idle connection.
    #[test]
    fn a_pair_on_multihop_is_offered_a_session_even_when_proven_direct() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            session_policy::wants_session(false, Some(PathKind::Multihop), true),
            "a pair on multihop is offered a session even when proven direct"
        );
        let watched_after_the_pool_closed_it = None;
        let read_from_the_admission_table = Some(PathKind::Multihop);
        let kind = probe::pair_kind(
            watched_after_the_pool_closed_it,
            read_from_the_admission_table,
        );
        assert!(
            session_policy::wants_session(false, kind, true),
            "an idle pair on multihop still offers"
        );
    }

    #[test]
    fn only_a_peer_without_ip_needs_the_webrtc_lane() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = SecretKey::from_bytes(&[5u8; 32]).public();
        assert!(
            lane_needs::needs_webrtc_lane(&browser_shaped(id)),
            "a browser-shaped peer needs the webrtc lane"
        );
        assert!(
            !lane_needs::needs_webrtc_lane(&native_shaped(id)),
            "a native-shaped peer does not need the webrtc lane"
        );

        // Nothing advertised at all used to be treated as browser-shaped, on
        // the grounds that a native peer with its IP transports cleared looks
        // the same. It does not: that peer keeps its relay transport, which is
        // `browser_shaped` above. An address with no transports at all only
        // ever means "not known yet", and reading it as a browser is what let
        // the retry pass open a lane with every native peer. See
        // `an_address_with_no_transports_is_unknown_not_a_browser`.
        assert!(
            !lane_needs::needs_webrtc_lane(&EndpointAddr::new(id)),
            "a peer with an ip address does not need the webrtc lane"
        );
    }

    /// A mixed pair needs the lane **whichever end is looking**.
    ///
    /// This is the case the first version of the gate got wrong. The lower
    /// `EndpointId` dials, so when a browser is the lower id it is the browser
    /// that evaluates the gate — and it sees the *native* peer's IP. Testing
    /// only the remote made it skip, while the native peer sat waiting to be
    /// dialled, and the pair silently never got a channel.
    /// **An address we know nothing about is not a browser.**
    ///
    /// The retry pass had no address to hand and built a bare one, which has no
    /// transports at all. That reads as "advertises no IP", so every native peer
    /// looked like a browser and the pass opened a data channel with all of
    /// them, spending the direct-peer slots that browsers actually need.
    #[test]
    fn an_address_with_no_transports_is_unknown_not_a_browser() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = SecretKey::from_bytes(&[7u8; 32]).public();
        assert!(
            !lane_needs::needs_webrtc_lane(&EndpointAddr::new(id)),
            "an address carrying no transports says nothing about the peer"
        );
        // The real relay-only shape still must.
        assert!(
            lane_needs::needs_webrtc_lane(&browser_shaped(id)),
            "an address with no transports is unknown, not a browser"
        );
    }

    #[test]
    fn a_mixed_pair_needs_the_lane_from_either_side() {
        let _guard = ::habilis_network_test_tracing::init();
        let browser = browser_shaped(SecretKey::from_bytes(&[6u8; 32]).public());
        let native = native_shaped(SecretKey::from_bytes(&[7u8; 32]).public());

        let pair_needs_lane = |local: &EndpointAddr, remote: &EndpointAddr| {
            lane_needs::needs_webrtc_lane(remote) || lane_needs::needs_webrtc_lane(local)
        };

        assert!(
            pair_needs_lane(&browser, &native),
            "browser looking at a native peer must still offer"
        );
        assert!(
            pair_needs_lane(&native, &browser),
            "native looking at a browser must still offer"
        );
        assert!(
            pair_needs_lane(&browser, &browser),
            "two browsers have no other transport"
        );
        assert!(
            !pair_needs_lane(&native, &native),
            "two native peers must stay on iroh's own transports"
        );
    }

    /// **A node's own lane is a fact about the node, not about its address
    /// snapshot.** A browser whose relay link just dropped has an empty
    /// endpoint address for a moment; read through `needs_webrtc_lane` that
    /// is "unknown", and a pair with a native peer was left on iroh's own
    /// transports — which a browser does not have. Observed in Safari: every
    /// probe timed out and the peer stayed relay-only for good.
    #[test]
    fn a_node_without_ip_needs_the_lane_even_while_its_own_address_is_empty() {
        let _guard = ::habilis_network_test_tracing::init();
        let native = native_shaped(SecretKey::from_bytes(&[7u8; 32]).public());
        // The address is not consulted at all for the local end; a node
        // without IP transports needs the lane, full stop.
        assert!(
            session_policy::pair_needs_lane(&native, UdpTransport::Absent),
            "a node with no IP transport must offer whatever its address says"
        );
        assert!(
            lane_needs::local_needs_webrtc_lane(UdpTransport::Absent),
            "a node without ip needs the lane even while its own address is empty"
        );
        assert!(
            !session_policy::pair_needs_lane(&native, UdpTransport::Present),
            "two IP-capable peers stay on iroh's own transports"
        );
    }

    /// Short enough that a test finishes, long enough that a loopback dial and
    /// a QUIC handshake comfortably fit inside it.
    fn quick() -> SignalDeadlines {
        SignalDeadlines {
            exchange: Duration::from_millis(400),
            round: Duration::from_millis(900),
        }
    }

    /// Offline: loopback only, no relay, no address lookup.
    async fn endpoint() -> (Endpoint, WebRtcHandle) {
        let key = SecretKey::generate();
        let handle = WebRtcHandle::new(WebRtcTransport::new(key.public()));
        let transport = handle.transport();
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled);
        let builder = builder
            .clear_address_lookup()
            .add_custom_transport(transport);
        let endpoint: Endpoint = builder.bind().await.expect("bind loopback endpoint");
        (endpoint, handle)
    }

    /// [`endpoint`] with the key given.
    async fn endpoint_with(key: SecretKey) -> (Endpoint, WebRtcHandle) {
        let handle = WebRtcHandle::new(WebRtcTransport::new(key.public()));
        let transport = handle.transport();
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled);
        let builder = builder
            .clear_address_lookup()
            .add_custom_transport(transport);
        let endpoint: Endpoint = builder.bind().await.expect("bind loopback endpoint");
        (endpoint, handle)
    }

    fn serve(endpoint: &Endpoint, handle: &WebRtcHandle, admission: &SignalAdmission) -> Router {
        let book = crate::lookup::address_book(&endpoint.clone());
        let signal: WebRtcSignalAcceptor = WebRtcSignalAcceptor::new(
            handle.clone(),
            endpoint.clone(),
            book,
            endpoint.id(),
            admission.clone(),
            // Host candidates only: these tests must not touch STUN.
            IceProfile { host_only: true },
        );
        let signal = signal.with_deadlines(quick());
        let router = Router::builder(endpoint.clone());
        let router = router.accept(NUDGE_ALPN, NudgeAcceptor);
        let router = router.accept(MESH_WEBRTC_SIGNAL_ALPN, signal);
        router.spawn()
    }

    /// Wait for `check` to hold, or give up. Polling beats a fixed sleep: the
    /// release happens on a spawned task's drop, which has no completion signal
    /// to await.
    async fn until(mut check: impl FnMut() -> bool) -> bool {
        for _ in 0..100 {
            if check() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        check()
    }

    /// A peer that connects and never opens a stream must not pin the answer
    /// task, and must not pin its admission slot either.
    ///
    /// Before the deadline and the guard, `answer_one` blocked on `accept_bi`
    /// forever — the peer's QUIC keep-alives meant the connection never idled
    /// out — and the task was detached from the Router's `JoinSet`, so nothing
    /// reaped it.
    #[test]
    fn a_connection_that_never_opens_a_stream_is_released() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (server, server_hub) = endpoint().await;
                let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
                let router = serve(&server, &server_hub, &admission);

                let (client, _client_hub) = endpoint().await;
                let connection = client
                    .connect(server.addr(), MESH_WEBRTC_SIGNAL_ALPN)
                    .await
                    .expect("dial the signal ALPN");
                assert!(
                    until(|| admission.in_flight() == 1).await,
                    "the offer should have been admitted"
                );

                // Never open a bi-stream; just hold the connection open.
                assert!(
                    until(|| admission.in_flight() == 0).await,
                    "a stalled offer must release its slot on the exchange deadline"
                );
                assert_eq!(
                    server_hub.session_count(),
                    0,
                    "a connection that never opens a stream holds no session"
                );

                connection.close(0u32.into(), b"done");
                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    /// One peer, many connections, one task.
    ///
    /// Admission is keyed by the TLS-proven remote id and happens *before* the
    /// spawn, so a peer cannot multiply our task count by reconnecting. It used
    /// to be able to: every connection spawned its own detached task holding
    /// its own `Connection`, with nothing bounding either.
    #[test]
    fn many_connections_from_one_peer_yield_one_task() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (server, server_hub) = endpoint().await;
                let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
                let router = serve(&server, &server_hub, &admission);

                let (client, _client_hub) = endpoint().await;
                let mut conns = Vec::new();
                for _ in 0..5 {
                    conns.push(
                        client
                            .connect(server.addr(), MESH_WEBRTC_SIGNAL_ALPN)
                            .await
                            .expect("dial the signal ALPN"),
                    );
                }

                // Give every accept a chance to run, then assert the ceiling held
                // throughout rather than only at the end.
                for _ in 0..12 {
                    assert!(
                        admission.in_flight() <= 1,
                        "one peer must never hold more than one slot"
                    );
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }

                for connection in conns {
                    connection.close(0u32.into(), b"done");
                }
                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    /// **A node with a ceiling of two holds two sessions, and the third offer is answered.**
    ///
    /// The ceiling is the setting of the node (C). No offer is refused for it. The session
    /// that was used least recently is detached when the third attaches, so the node keeps
    /// two sessions.
    #[test]
    fn a_node_with_a_ceiling_of_two_answers_a_third_offer_and_detaches_the_oldest() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            4,
            async {
                let (server, server_hub) = endpoint().await;
                let admission = SignalAdmission::new(2);
                let router = serve(&server, &server_hub, &admission);

                let mut clients = Vec::new();
                for _ in 0..3 {
                    let (client, client_hub) = endpoint().await;
                    dial_signal::dial_signal_with(
                        &client,
                        &crate::lookup::address_book(&client),
                        server.addr(),
                        &client_hub,
                        quick(),
                        IceProfile { host_only: true },
                    )
                    .await
                    .expect("every offer attaches");
                    clients.push((client, client_hub));
                }

                assert!(
                    until(|| !server_hub.has_session(&clients[0].0.id())).await,
                    "the least recently used session is detached"
                );
                assert!(
                    server_hub.has_session(&clients[1].0.id()),
                    "the first offer's session is still attached at a ceiling of two"
                );
                assert!(
                    server_hub.has_session(&clients[2].0.id()),
                    "the second offer's session is still attached at a ceiling of two"
                );
                assert_eq!(server_hub.session_count(), 2, "the node holds two sessions");

                router.shutdown().await.expect("shutdown");
                for (client, _) in clients {
                    client.close().await;
                }
                server.close().await;
            },
        );
    }

    /// **The evicted peer reads code 11 on its offer.** At a ceiling of one, the second session
    /// evicts the first. The first peer offers again at once, and the dialer reads the refusal as the
    /// `EVICTED` code, so it can wait instead of taking the place back.
    #[test]
    fn a_peer_whose_session_was_evicted_reads_the_evicted_code_on_its_next_offer() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            4,
            async {
                let (server, server_hub) = endpoint().await;
                let admission = SignalAdmission::new(1);
                let router = serve(&server, &server_hub, &admission);

                let (first, first_hub) = endpoint().await;
                let (second, second_hub) = endpoint().await;
                for (client, hub) in [(&first, &first_hub), (&second, &second_hub)] {
                    dial_signal::dial_signal_with(
                        client,
                        &crate::lookup::address_book(client),
                        server.addr(),
                        hub,
                        quick(),
                        IceProfile { host_only: true },
                    )
                    .await
                    .expect("an offer attaches");
                }
                assert!(
                    until(|| !server_hub.has_session(&first.id())).await,
                    "the first session was evicted"
                );

                let error = dial_signal::dial_signal_with(
                    &first,
                    &crate::lookup::address_book(&first),
                    server.addr(),
                    &first_hub,
                    quick(),
                    IceProfile { host_only: true },
                )
                .await
                .expect_err("the evicted peer is refused for a minute");
                assert!(
                    matches!(error, EndpointError::CapRefused { .. }),
                    "the dialer reads the refusal as a code to wait on: {error:#}"
                );
                assert!(
                    server_hub.has_session(&second.id()),
                    "the newcomer keeps its place"
                );

                router.shutdown().await.expect("shutdown");
                first.close().await;
                second.close().await;
                server.close().await;
            },
        );
    }

    /// `Router::shutdown` must reach the spawned answer tasks.
    ///
    /// They are not in the Router's own `JoinSet` — spawning is deliberate, so
    /// a multi-second negotiation does not serialize inbound offers, and so the
    /// browser's `!Send` JSEP future has somewhere to live. `ProtocolHandler`'s
    /// `shutdown` hook is what replaces that reachability.
    /// Like [`endpoint`], but with the address-lookup store intact, so
    /// `add_peer_addr` has somewhere to register and a bare-id dial has
    /// something to resolve through.
    async fn endpoint_with_lookup() -> (Endpoint, WebRtcHandle) {
        let key = SecretKey::generate();
        let handle = WebRtcHandle::new(WebRtcTransport::new(key.public()));
        let transport = handle.transport();
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled)
            .add_custom_transport(transport);
        let endpoint: Endpoint = builder.bind().await.expect("bind loopback endpoint");
        (endpoint, handle)
    }

    /// **The load-bearing assumption of the whole `WebRTC` lane**: after a
    /// session is attached and [`register_session_addr`] has run, a dial by
    /// *bare id* — which is all iroh-gossip's actor ever dials with — must
    /// resolve to the custom-transport path and connect over the data
    /// channel. No relay and no IP address exist in this test, so a success
    /// here is that resolution working and nothing else.
    #[test]
    fn a_bare_id_dial_resolves_to_the_attached_session() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (server, server_hub) = endpoint_with_lookup().await;
                let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
                let router = serve(&server, &server_hub, &admission);

                let (client, client_hub) = endpoint_with_lookup().await;
                dial_signal::dial_signal_with(
                    &client,
                    &crate::lookup::address_book(&client),
                    server.addr(),
                    &client_hub,
                    quick(),
                    IceProfile { host_only: true },
                )
                .await
                .expect("the signal round must attach a session");
                assert!(
                    client_hub.has_session(&server.id()),
                    "a bare id dial resolves to the attached session"
                );

                web_rtc_signal_acceptor::register_session_addr(
                    &crate::lookup::address_book(&client),
                    server.id(),
                );

                let connection: Connection = tokio::time::timeout(
                    Duration::from_secs(10),
                    client.connect(EndpointAddr::new(server.id()), MESH_WEBRTC_SIGNAL_ALPN),
                )
                .await
                .expect("a bare-id dial must not hang")
                .expect("a bare-id dial must resolve through the registered custom address");
                let direct = super::super::payload_path::selected_is_direct(&connection);
                connection.close(0u32.into(), b"done");
                assert!(direct, "the connection's selected path must be the session");

                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    /// The **reverse** of [`a_bare_id_dial_resolves_to_the_attached_session`],
    /// and the direction the native/web matrix caught missing: the *answerer*
    /// dialing the *offerer* by bare id. The production acceptor registers the
    /// offerer's custom address on attach, and a data channel is symmetric —
    /// so this dial must ride the session exactly like the forward one. In the
    /// matrix, every conn dialed in this direction sat on the relay until the
    /// accept gate refused it.
    #[test]
    fn a_bare_id_dial_rides_the_session_from_the_answerer_too() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (server, server_hub) = endpoint_with_lookup().await;
                let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
                let router = serve(&server, &server_hub, &admission);

                let (client, client_hub) = endpoint_with_lookup().await;
                let client_admission = SignalAdmission::new(MAX_DIRECT_PEERS);
                let client_router = serve(&client, &client_hub, &client_admission);
                dial_signal::dial_signal_with(
                    &client,
                    &crate::lookup::address_book(&client),
                    server.addr(),
                    &client_hub,
                    quick(),
                    IceProfile { host_only: true },
                )
                .await
                .expect("the signal round must attach a session");
                assert!(
                    until(|| server_hub.has_session(&client.id())).await,
                    "the answerer's hub must hold the session"
                );
                // `register_session_addr` runs in the acceptor task right after the
                // attach the poll above observed; give it a beat to land.
                tokio::time::sleep(Duration::from_millis(200)).await;

                let connection: Connection = tokio::time::timeout(
                    Duration::from_secs(10),
                    server.connect(EndpointAddr::new(client.id()), MESH_WEBRTC_SIGNAL_ALPN),
                )
                .await
                .expect("an answerer's bare-id dial must not hang")
                .expect(
                    "an answerer's bare-id dial must resolve through the registered custom address",
                );
                let direct = super::super::payload_path::selected_is_direct(&connection);
                connection.close(0u32.into(), b"done");
                assert!(direct, "the connection's selected path must be the session");

                router.shutdown().await.expect("shutdown");
                client_router.shutdown().await.expect("shutdown");
                server.close().await;
                client.close().await;
            },
        );
    }

    /// The whole lookup-only browser story in one offline test: with a
    /// session attached and its address registered, an **iroh-gossip graft
    /// by bare id** must connect over the session and pass the lookup-only
    /// accept gate. This is the layer above [`a_bare_id_dial_resolves_to_the_attached_session`]:
    /// the gossip actor does its own dialing, and it is the actor's dial —
    /// not ours — that the rendezvous link depends on.
    #[test]
    fn a_gossip_graft_by_bare_id_rides_the_attached_session() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use futures_util::StreamExt as _;
                use iroh_gossip::net::{GOSSIP_ALPN, Gossip};

                let (server, server_hub) = endpoint_with_lookup().await;
                let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
                let server_gossip = Gossip::builder().spawn(server.clone());
                // One Router for both ALPNs: `Router::spawn` overrides the endpoint's
                // ALPN list, so a second Router silently unregisters the first's.
                let book = crate::lookup::address_book(&server.clone());
                let signal: WebRtcSignalAcceptor = WebRtcSignalAcceptor::new(
                    server_hub.clone(),
                    server.clone(),
                    book,
                    server.id(),
                    admission.clone(),
                    IceProfile { host_only: true },
                );
                let signal = signal.with_deadlines(quick());
                let router = Router::builder(server.clone());
                let router = router.accept(NUDGE_ALPN, NudgeAcceptor);
                let router = router.accept(MESH_WEBRTC_SIGNAL_ALPN, signal);
                let router = router.accept(
                    GOSSIP_ALPN,
                    super::super::DirectOnlyGossip::new(
                        server_gossip.clone(),
                        crate::transport::PayloadPath::DirectOnly,
                        None,
                    ),
                );
                let router: Router = router.spawn();

                let (client, client_hub) = endpoint_with_lookup().await;
                let client_gossip = Gossip::builder().spawn(client.clone());

                dial_signal::dial_signal_with(
                    &client,
                    &crate::lookup::address_book(&client),
                    server.addr(),
                    &client_hub,
                    quick(),
                    IceProfile { host_only: true },
                )
                .await
                .expect("the signal round must attach a session");
                web_rtc_signal_acceptor::register_session_addr(
                    &crate::lookup::address_book(&client),
                    server.id(),
                );

                let topic = iroh_gossip::proto::TopicId::from_bytes([9u8; 32]);
                let mut server_topic = server_gossip
                    .subscribe(topic, vec![])
                    .await
                    .expect("server subscribes");
                let mut client_topic = client_gossip
                    .subscribe(topic, vec![server.id()])
                    .await
                    .expect("client subscribes and grafts by bare id");

                let linked = tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    tokio::select! {
                        event = client_topic.next() => {
                            if matches!(
                                event,
                                Some(Ok(iroh_gossip::api::Event::NeighborUp(id))) if id == server.id()
                            ) {
                                return;
                            }
                        }
                        event = server_topic.next() => {
                            let _ = event;
                        }
                    }
                }
            })
            .await;
                assert!(
                    linked.is_ok(),
                    "the graft dial must ride the attached session through the lookup-only gate"
                );

                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    /// The failing browser topology, natively: both ends also hold a relay
    /// path. The graft's connection then opens over the relay first, and the
    /// lookup-only gate passes only if selection *migrates* to the attached
    /// session within the hold. This is the exact cell the matrix kept
    /// failing; everything below the relay's presence is covered by
    /// [`a_gossip_graft_by_bare_id_rides_the_attached_session`].
    #[cfg(feature = "iroh-test-utils")]
    #[test]
    fn a_gossip_graft_prefers_the_session_over_the_relay() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use futures_util::StreamExt as _;
                use iroh_gossip::net::{GOSSIP_ALPN, Gossip};

                let _ = tracing_subscriber::fmt()
                    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                    .with_test_writer()
                    .try_init();

                let (relay_url, _relay_server) =
                    test_relay::spawn_plain().await.expect("local relay");
                let with_relay = |key: SecretKey, handle: &WebRtcHandle, browser_shaped: bool| {
                    let relay_url = relay_url.clone();
                    let transport = handle.transport();
                    let selector = handle.path_selector();
                    async move {
                        let builder = Endpoint::builder(presets::Minimal)
                            .secret_key(key)
                            .relay_mode(RelayMode::custom([relay_url]));
                        let builder = builder
                            .add_custom_transport(transport)
                            .path_selector(selector);
                        // A browser has no IP stack: without this, localhost punches
                        // a UDP path inside the held connection and the gate passes
                        // on a path a tab could never have.
                        let builder = if browser_shaped {
                            builder.clear_ip_transports()
                        } else {
                            builder
                        };
                        builder.bind().await.expect("bind endpoint with relay")
                    }
                };
                let server_key = SecretKey::generate();
                let server_hub = WebRtcHandle::new(WebRtcTransport::new(server_key.public()));
                let server = with_relay(server_key, &server_hub, false).await;
                let client_key = SecretKey::generate();
                let client_hub = WebRtcHandle::new(WebRtcTransport::new(client_key.public()));
                let client = with_relay(client_key, &client_hub, true).await;

                let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
                let server_gossip = Gossip::builder().spawn(server.clone());
                let book = crate::lookup::address_book(&server.clone());
                let signal: WebRtcSignalAcceptor = WebRtcSignalAcceptor::new(
                    server_hub.clone(),
                    server.clone(),
                    book,
                    server.id(),
                    admission.clone(),
                    IceProfile { host_only: true },
                );
                let router = Router::builder(server.clone());
                let router = router.accept(NUDGE_ALPN, NudgeAcceptor);
                let router = router.accept(MESH_WEBRTC_SIGNAL_ALPN, signal);
                let router = router.accept(
                    GOSSIP_ALPN,
                    super::super::DirectOnlyGossip::new(
                        server_gossip.clone(),
                        crate::transport::PayloadPath::DirectOnly,
                        None,
                    ),
                );
                let router: Router = router.spawn();

                let client_gossip = Gossip::builder().spawn(client.clone());
                // The relay-homed address, as `register_rendezvous` hands a joiner.
                let relay_addr = EndpointAddr::new(server.id()).with_relay_url(relay_url.clone());
                dial_signal::dial_signal_with(
                    &client,
                    &crate::lookup::address_book(&client),
                    relay_addr,
                    &client_hub,
                    SignalDeadlines::DEFAULT,
                    IceProfile { host_only: true },
                )
                .await
                .expect("the signal round must attach a session over the relay");
                web_rtc_signal_acceptor::register_session_addr(
                    &crate::lookup::address_book(&client),
                    server.id(),
                );

                let topic = iroh_gossip::proto::TopicId::from_bytes([11u8; 32]);
                let mut server_topic = server_gossip
                    .subscribe(topic, vec![])
                    .await
                    .expect("server subscribes");
                let mut client_topic = client_gossip
                    .subscribe(topic, vec![server.id()])
                    .await
                    .expect("client subscribes and grafts by bare id");

                let linked = tokio::time::timeout(Duration::from_secs(40), async {
                loop {
                    tokio::select! {
                        event = client_topic.next() => {
                            if matches!(
                                event,
                                Some(Ok(iroh_gossip::api::Event::NeighborUp(id))) if id == server.id()
                            ) {
                                return;
                            }
                        }
                        event = server_topic.next() => {
                            let _ = event;
                        }
                    }
                }
            })
            .await;
                assert!(
                    linked.is_ok(),
                    "with a session attached, the graft must not stay pinned to the relay"
                );

                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    /// A pair with no UDP: the higher id (the answerer of the session round)
    /// dials a connection over the relay, and the lower id offers a session
    /// while that connection is still held. iroh opens a new path only from the
    /// client side of a connection, and only on a path event of its own
    /// endpoint. The offerer's nudge reaches the answerer's endpoint as an
    /// inbound connect, which gives it no event for the connection it dialed, so
    /// the answerer must nudge once after its attach. Without it the accepted
    /// connection stays on the relay and the relay policy closes it.
    #[cfg(feature = "iroh-test-utils")]
    #[test]
    fn a_connection_dialed_by_the_answerer_leaves_the_relay_when_the_session_attaches() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use iroh::protocol::{AcceptError, ProtocolHandler};

                const HOLD_ALPN: &[u8] = b"habilis-mesh/test-hold/0";

                #[derive(Debug, Clone)]
                struct Hold(mpsc::Sender<bool>);
                impl ProtocolHandler for Hold {
                    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                        let direct = super::super::payload_path::wait_direct(
                            &connection,
                            Duration::from_secs(12),
                        )
                        .await;
                        let _ = self.0.send(direct).await;
                        connection.closed().await;
                        Ok(())
                    }
                }

                let (relay_url, _relay_server) =
                    test_relay::spawn_plain().await.expect("local relay");
                let bind = |key: SecretKey, handle: &WebRtcHandle| {
                    let relay_url = relay_url.clone();
                    let transport = handle.transport();
                    let selector = handle.path_selector();
                    async move {
                        let builder = Endpoint::builder(presets::Minimal)
                            .secret_key(key)
                            .relay_mode(RelayMode::custom([relay_url]))
                            .add_custom_transport(transport);
                        builder
                            .path_selector(selector)
                            .clear_ip_transports()
                            .bind()
                            .await
                            .expect("bind endpoint with relay")
                    }
                };
                let (mut low_key, mut high_key) = (SecretKey::generate(), SecretKey::generate());
                if low_key.public() > high_key.public() {
                    std::mem::swap(&mut low_key, &mut high_key);
                }
                let low_hub = WebRtcHandle::new(WebRtcTransport::new(low_key.public()));
                let low = bind(low_key, &low_hub).await;
                let high_hub = WebRtcHandle::new(WebRtcTransport::new(high_key.public()));
                let high = bind(high_key, &high_hub).await;

                let (held_tx, mut held_rx) = mpsc::channel(1);
                let low_router: Router = Router::builder(low.clone())
                    .accept(NUDGE_ALPN, NudgeAcceptor)
                    .accept(HOLD_ALPN, Hold(held_tx))
                    .spawn();
                let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
                let book = crate::lookup::address_book(&high.clone());
                let signal: WebRtcSignalAcceptor = WebRtcSignalAcceptor::new(
                    high_hub.clone(),
                    high.clone(),
                    book,
                    high.id(),
                    admission,
                    IceProfile { host_only: true },
                );
                let router = Router::builder(high.clone());
                let router = router.accept(NUDGE_ALPN, NudgeAcceptor);
                let router = router.accept(MESH_WEBRTC_SIGNAL_ALPN, signal);
                let high_router: Router = router.spawn();

                let low_on_relay = EndpointAddr::new(low.id()).with_relay_url(relay_url.clone());
                let high_on_relay = EndpointAddr::new(high.id()).with_relay_url(relay_url.clone());
                let held = high
                    .connect(low_on_relay, HOLD_ALPN)
                    .await
                    .expect("the answerer dials the offerer over the relay");

                dial_signal::dial_signal_with(
                    &low,
                    &crate::lookup::address_book(&low),
                    high_on_relay,
                    &low_hub,
                    SignalDeadlines::DEFAULT,
                    IceProfile { host_only: true },
                )
                .await
                .expect("the offerer attaches a session");
                web_rtc_signal_acceptor::register_session_addr(
                    &crate::lookup::address_book(&low),
                    high.id(),
                );
                nudge_acceptor::nudge(&low, high.id()).await;

                let direct = tokio::time::timeout(Duration::from_secs(20), held_rx.recv())
                    .await
                    .expect("the held connection reports in time")
                    .expect("the channel is open");
                assert!(
                    direct,
                    "the connection that the answerer dialed must leave the relay once the session is attached"
                );

                held.close(0u32.into(), b"done");
                high_router.shutdown().await.expect("shutdown");
                low_router.shutdown().await.expect("shutdown");
                low.close().await;
                high.close().await;
            },
        );
    }

    /// A relayed connection still open when the session attaches, which is
    /// what the beacon's accept gate does to a graft for up to its deadline:
    /// iroh then holds a selected relay path to the remote and consults no
    /// address lookup for it, so registering the session address in a lookup
    /// alone left every later bare-id dial on the relay. Observed as a
    /// browser-first mesh cell that never linked.
    #[cfg(feature = "iroh-test-utils")]
    #[test]
    fn a_bare_id_dial_rides_the_session_past_a_held_relay_link() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use iroh::endpoint::Connection;
                use iroh::protocol::{AcceptError, ProtocolHandler};

                /// Keeps every accepted connection open until the dialer closes it.
                #[derive(Debug, Clone)]
                struct Hold;
                impl ProtocolHandler for Hold {
                    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                        connection.closed().await;
                        Ok(())
                    }
                }
                const HOLD_ALPN: &[u8] = b"habilis-network/test-hold";

                let (relay_url, _relay_server) =
                    test_relay::spawn_plain().await.expect("local relay");
                // No IP on either side, as between a tab and a tab-held beacon: the
                // relay and the session are the only paths there are.
                let relay_only = |key: SecretKey, handle: &WebRtcHandle| {
                    let builder = Endpoint::builder(presets::Minimal);
                    let builder = builder.secret_key(key);
                    let builder = builder.relay_mode(RelayMode::custom([relay_url.clone()]));
                    let builder = builder.add_custom_transport(handle.transport());
                    let builder = builder.path_selector(handle.path_selector());
                    let builder = builder.clear_ip_transports();
                    async move { builder.bind().await.expect("bind relay-only endpoint") }
                };
                let server_key = SecretKey::generate();
                let server_hub = WebRtcHandle::new(WebRtcTransport::new(server_key.public()));
                let server = relay_only(server_key, &server_hub).await;
                let client_key = SecretKey::generate();
                let client_hub = WebRtcHandle::new(WebRtcTransport::new(client_key.public()));
                let client = relay_only(client_key, &client_hub).await;

                let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
                let book = crate::lookup::address_book(&server.clone());
                let signal: WebRtcSignalAcceptor = WebRtcSignalAcceptor::new(
                    server_hub.clone(),
                    server.clone(),
                    book,
                    server.id(),
                    admission.clone(),
                    IceProfile { host_only: true },
                );
                let router = Router::builder(server.clone());
                let router = router.accept(NUDGE_ALPN, NudgeAcceptor);
                let router = router.accept(MESH_WEBRTC_SIGNAL_ALPN, signal);
                let router = router.accept(HOLD_ALPN, Hold);
                let router: Router = router.spawn();

                let relay_addr = EndpointAddr::new(server.id()).with_relay_url(relay_url.clone());
                let held = client
                    .connect(relay_addr.clone(), HOLD_ALPN)
                    .await
                    .expect("a relayed connection before any session");
                dial_signal::dial_signal_with(
                    &client,
                    &crate::lookup::address_book(&client),
                    relay_addr,
                    &client_hub,
                    quick(),
                    IceProfile { host_only: true },
                )
                .await
                .expect("the signal round must attach a session");

                let connection: Connection = tokio::time::timeout(
                    Duration::from_secs(10),
                    client.connect(EndpointAddr::new(server.id()), HOLD_ALPN),
                )
                .await
                .expect("a bare-id dial must not hang")
                .expect("a bare-id dial must connect");
                let direct =
                    super::super::payload_path::wait_direct(&connection, Duration::from_secs(10))
                        .await;
                connection.close(0u32.into(), b"done");
                held.close(0u32.into(), b"done");
                assert!(
                    direct,
                    "a dial after the attach must reach the session, not only the relay"
                );

                router.shutdown().await.expect("shutdown");
                client.close().await;
                server.close().await;
            },
        );
    }

    /// The real join order: the graft is attempted *before* any session
    /// exists — the gate holds the relayed connection for its deadline and
    /// closes it — and only then does the session attach. The re-graft after
    /// the refusal must still link; if a refused connection poisons later
    /// dials to the same peer, this is the test that says so.
    /// An endpoint on the local relay, with its transports from `handle`. A browser-shaped one has
    /// no IP stack: without `clear_ip_transports`, localhost punches a UDP path inside the held
    /// connection and the gate passes on a path a tab could never have.
    async fn bind_with_relay(
        relay_url: iroh::RelayUrl,
        key: SecretKey,
        handle: &WebRtcHandle,
        browser_shaped: bool,
    ) -> Endpoint {
        let transport = handle.transport();
        let selector = handle.path_selector();
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::custom([relay_url]));
        let builder = builder
            .add_custom_transport(transport)
            .path_selector(selector);
        let builder = if browser_shaped {
            builder.clear_ip_transports()
        } else {
            builder
        };
        builder.bind().await.expect("bind endpoint with relay")
    }

    #[cfg(feature = "iroh-test-utils")]
    #[test]
    fn a_graft_recovers_after_a_refused_relay_attempt() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use futures_util::StreamExt as _;
                use iroh_gossip::net::{GOSSIP_ALPN, Gossip};

                let _ = tracing_subscriber::fmt()
                    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                    .with_test_writer()
                    .try_init();

                let (relay_url, _relay_server) =
                    test_relay::spawn_plain().await.expect("local relay");
                let server_key = SecretKey::generate();
                let server_hub = WebRtcHandle::new(WebRtcTransport::new(server_key.public()));
                let server =
                    bind_with_relay(relay_url.clone(), server_key, &server_hub, false).await;
                let client_key = SecretKey::generate();
                let client_hub = WebRtcHandle::new(WebRtcTransport::new(client_key.public()));
                let client =
                    bind_with_relay(relay_url.clone(), client_key, &client_hub, true).await;

                let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
                let server_gossip = Gossip::builder().spawn(server.clone());
                let book = crate::lookup::address_book(&server.clone());
                let signal: WebRtcSignalAcceptor = WebRtcSignalAcceptor::new(
                    server_hub.clone(),
                    server.clone(),
                    book,
                    server.id(),
                    admission.clone(),
                    IceProfile { host_only: true },
                );
                let router = Router::builder(server.clone());
                let router = router.accept(NUDGE_ALPN, NudgeAcceptor);
                let router = router.accept(MESH_WEBRTC_SIGNAL_ALPN, signal);
                let router = router.accept(
                    GOSSIP_ALPN,
                    super::super::DirectOnlyGossip::new(
                        server_gossip.clone(),
                        crate::transport::PayloadPath::DirectOnly,
                        None,
                    ),
                );
                let router: Router = router.spawn();

                let client_gossip = Gossip::builder().spawn(client.clone());
                // What register_rendezvous does for a joiner: the relay-homed
                // address, registered before the first graft dial.
                crate::lookup::add_peer_addr(
                    &crate::lookup::address_book(&client),
                    EndpointAddr::new(server.id()).with_relay_url(relay_url.clone()),
                );
                let topic = iroh_gossip::proto::TopicId::from_bytes([13u8; 32]);
                let mut server_topic = server_gossip
                    .subscribe(topic, vec![])
                    .await
                    .expect("server subscribes");
                // The graft attempt with nothing but the relay: held, then refused.
                let (client_sender, mut client_rx) = client_gossip
                    .subscribe(topic, vec![server.id()])
                    .await
                    .expect("client subscribes")
                    .split();

                // Outlast the gate's hold (15 s) so the refusal has happened.
                tokio::time::sleep(Duration::from_secs(17)).await;

                // Now the session, as the heal tick would drive it.
                let relay_addr = EndpointAddr::new(server.id()).with_relay_url(relay_url.clone());
                dial_signal::dial_signal_with(
                    &client,
                    &crate::lookup::address_book(&client),
                    relay_addr,
                    &client_hub,
                    SignalDeadlines::DEFAULT,
                    IceProfile { host_only: true },
                )
                .await
                .expect("the signal round must attach a session over the relay");
                web_rtc_signal_acceptor::register_session_addr(
                    &crate::lookup::address_book(&client),
                    server.id(),
                );

                let linked = tokio::time::timeout(Duration::from_secs(40), async {
                loop {
                    client_sender
                        .join_peers(vec![server.id()])
                        .await
                        .expect("re-graft");
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                    loop {
                        tokio::select! {
                            event = client_rx.next() => {
                                if matches!(
                                    event,
                                    Some(Ok(iroh_gossip::api::Event::NeighborUp(id))) if id == server.id()
                                ) {
                                    return;
                                }
                            }
                            event = server_topic.next() => {
                                let _ = event;
                            }
                            () = tokio::time::sleep_until(deadline) => {
                                break;
                            }
                        }
                    }
                }
            })
            .await;
                assert!(
                    linked.is_ok(),
                    "a refused relay-only graft must not poison the re-graft over the session"
                );

                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    #[test]
    fn router_shutdown_cancels_rounds_in_flight() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (server, server_hub) = endpoint().await;
                let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
                let router = serve(&server, &server_hub, &admission);

                let (client, _client_hub) = endpoint().await;
                let connection = client
                    .connect(server.addr(), MESH_WEBRTC_SIGNAL_ALPN)
                    .await
                    .expect("dial the signal ALPN");
                assert!(
                    until(|| admission.in_flight() == 1).await,
                    "the offer should have been admitted"
                );

                // Well inside the round deadline, so a pass here is the abort working
                // and not the timeout firing.
                tokio::time::timeout(Duration::from_millis(500), router.shutdown())
                    .await
                    .expect("shutdown must not wait out the round deadline")
                    .expect("shutdown");
                assert!(
                    until(|| admission.in_flight() == 0).await,
                    "an aborted round must give its slot back"
                );

                connection.close(0u32.into(), b"done");
                client.close().await;
            },
        );
    }

    /// The dialer's half: a peer that accepts the connection and reads the
    /// offer but never answers must not hold the round open forever.
    ///
    /// This is the shape that pinned a pair to the relay permanently. Nothing
    /// in `dial_signal` was bounded — `JSEP_DEADLINE` wrapped only `complete()`,
    /// which runs after the answer arrives — so the in-flight marker was never
    /// cleared and every later retry skipped that peer.
    #[test]
    fn a_dial_gives_up_when_the_answer_never_comes() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                /// Reads the offer and then says nothing, keeping the connection alive.
                #[derive(Debug, Clone)]
                struct BlackHole;

                impl ProtocolHandler for BlackHole {
                    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                        let (_send, mut recv) = connection.accept_bi().await?;
                        let _ = recv.read_to_end(MAX_ENVELOPE_BYTES).await;
                        // Hold the connection open, answering nothing.
                        connection.closed().await;
                        Ok(())
                    }
                }

                let (server, _server_hub) = endpoint().await;
                let router: Router = Router::builder(server.clone())
                    .accept(NUDGE_ALPN, NudgeAcceptor)
                    .accept(MESH_WEBRTC_SIGNAL_ALPN, BlackHole)
                    .spawn();

                let (client, client_hub) = endpoint().await;
                let started = std::time::Instant::now();
                let outcome = dial_signal::dial_signal_with(
                    &client,
                    &crate::lookup::address_book(&client),
                    server.addr(),
                    &client_hub,
                    quick(),
                    IceProfile { host_only: true },
                )
                .await;

                assert!(outcome.is_err(), "a silent peer must not succeed");
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "the dial must give up on its own deadline, not hang: took {:?}",
                    started.elapsed()
                );
                assert_eq!(
                    client_hub.session_count(),
                    0,
                    "the client hub holds no session after close"
                );

                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    /// A dial by the bare id carries no ip address, so the connection waits for the first retransmit
    /// onto the ip path iroh learns meanwhile. The offer to the rendezvous dials with the addresses of
    /// the book: the ip addresses and the relay of the entry, and only those of the beacon that holds
    /// the id now (a claim replaces the entry, a shed removes it).
    #[test]
    fn the_offer_to_the_rendezvous_dials_with_the_addresses_of_the_book() {
        let _guard = ::habilis_network_test_tracing::init();
        let book = MemoryLookup::new();
        let id = SecretKey::generate().public();
        let at = |port: u16| std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
        assert_eq!(
            rendezvous::rendezvous_dial_target(&book, id)
                .ip_addrs()
                .count(),
            0,
            "no entry in the book: the bare id"
        );

        // A claim of the first beacon, its shed, a claim of the second beacon: the dial carries
        // the second beacon's address only.
        crate::lookup::replace_peer_addr(&book, EndpointAddr::new(id).with_ip_addr(at(4000)));
        book.remove_endpoint_info(id);
        crate::lookup::replace_peer_addr(&book, EndpointAddr::new(id).with_ip_addr(at(5000)));

        let target = rendezvous::rendezvous_dial_target(&book, id);
        assert_eq!(
            target.id, id,
            "the offer to the rendezvous dials with the id from the book"
        );
        let ips: Vec<_> = target.ip_addrs().copied().collect();
        assert_eq!(
            ips,
            vec![at(5000)],
            "the dial carries the ip address of the beacon that holds the id now, and only that one"
        );

        // An entry with a relay (a relay-homed rendezvous, as `register_rendezvous` writes it).
        let relay: iroh::RelayUrl = "https://relay.invalid".parse().expect("relay url");
        book.set_endpoint_info(EndpointAddr::new(id).with_relay_url(relay.clone()));
        let relays: Vec<_> = rendezvous::rendezvous_dial_target(&book, id)
            .relay_urls()
            .cloned()
            .collect();
        assert_eq!(
            relays,
            vec![relay],
            "the dial carries the relay of the entry"
        );
    }

    /// An id that nobody serves never answers the connect, and the connect had no bound of its own:
    /// the round held the slot of the peer for the whole round deadline, and every later offer was
    /// refused `InFlight`. The connect now ends at the exchange deadline.
    #[test]
    fn a_dial_to_an_id_that_nobody_serves_ends_at_the_exchange_deadline() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                // Bound, and never read: packets to it vanish, and nothing answers.
                let silent = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                    .expect("a socket");
                let nobody: EndpointAddr = EndpointAddr::new(SecretKey::generate().public())
                    .with_ip_addr(silent.local_addr().expect("its address"));
                let (client, client_hub) = endpoint().await;
                let deadlines = SignalDeadlines {
                    exchange: Duration::from_millis(400),
                    round: Duration::from_secs(8),
                };
                let started = n0_future::time::Instant::now();
                let outcome = dial_signal::dial_signal_with(
                    &client,
                    &crate::lookup::address_book(&client),
                    nobody,
                    &client_hub,
                    deadlines,
                    IceProfile { host_only: true },
                )
                .await;

                assert!(outcome.is_err(), "nobody answers");
                assert!(
                    started.elapsed() < Duration::from_secs(3),
                    "the connect must end at the exchange deadline, not the round deadline: took {:?}",
                    started.elapsed()
                );
                client.close().await;
            },
        );
    }

    /// Off the heal tick, only a node that already offers offers again: a
    /// lane-needing node on every call, as before, and an IP-capable node only
    /// once the heal tick armed its fallback.
    #[test]
    fn only_a_node_that_already_offers_offers_off_the_heal_tick() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = crate::testing::fresh_state();
        state.local_udp_transport = UdpTransport::Absent;
        assert!(rendezvous::offers_off_tick(&state), "a lane-needing node");
        state.local_udp_transport = UdpTransport::Present;
        assert!(
            !rendezvous::offers_off_tick(&state),
            "an IP-capable node before its fallback"
        );
        state.rendezvous_offer_fallback = true;
        assert!(
            rendezvous::offers_off_tick(&state),
            "an IP-capable node after its fallback"
        );
    }

    /// An IP-capable node that fell back to offering the rendezvous a
    /// session — the beacon is a tab, with no UDP to punch to — grafts on the
    /// attach, never on a timer. A timer graft dials before the session
    /// exists, so its connection has only the relay path; the tab's accept
    /// gate holds it and refuses it after `PROBE_DEADLINE`, and the attach
    /// that follows does not replace it. Observed every 30 s for a whole
    /// browser-first cell.
    /// A pair waits for a send before it is offered a session when it is no gossip neighbor
    /// and holds no pooled connection. A pair that needs the lane waits too, unless a frame is
    /// held for it: that frame is the send.
    #[test]
    fn a_cold_non_neighbor_pair_waits_for_a_send_unless_a_frame_is_held_for_a_lane_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let peer = crate::testing::endpoint_id(7);
        let ip_pair = EndpointAddr::new(peer).with_ip_addr("127.0.0.1:4000".parse().expect("addr"));
        let lane_pair = EndpointAddr::new(peer)
            .with_relay_url("https://relay.invalid".parse().expect("relay url"));
        let mut state = crate::testing::fresh_state();
        state.local_udp_transport = UdpTransport::Present;

        assert!(
            retry::held_back(&state, &ip_pair),
            "cold, no neighbor, an IP path"
        );
        assert!(
            retry::held_back(&state, &lane_pair),
            "a lane pair with no held frame waits as well"
        );
        state.want_lane_session(peer, clock::Instant::now());
        assert!(
            !retry::held_back(&state, &lane_pair),
            "a frame held for a lane peer opens its session"
        );
        state.clear_lane_wanted(peer);
        assert!(
            retry::held_back(&state, &lane_pair),
            "the want ends with the attach"
        );
        state.linked_endpoints.insert(peer);
        assert!(
            !retry::held_back(&state, &ip_pair),
            "a gossip neighbor is never held back"
        );
    }

    /// A pair behind NAT has IP addresses but no direct path. On a mesh whose relay
    /// is lookup only, a directed frame to it is parked, so nothing is ever sent and
    /// no connection opens, and the probe that proves a direct path fails. Waiting
    /// for a send would wait for ever. Once the probe has failed and the pair is
    /// `RelayOnly`, a session is the way out, so the pair is no longer held back.
    #[test]
    fn a_pair_whose_probe_failed_on_a_lookup_only_relay_is_offered_a_session() {
        use crate::daemon::state::DirectState;

        let _guard = ::habilis_network_test_tracing::init();
        let peer = crate::testing::endpoint_id(7);
        let ip_pair = EndpointAddr::new(peer).with_ip_addr("127.0.0.1:4000".parse().expect("addr"));
        let mut state = crate::testing::fresh_state();
        state.local_udp_transport = UdpTransport::Present;
        state.relay_transport = crate::transport::PayloadPath::DirectOnly;

        for (known, held) in [
            (None, true),
            (Some(DirectState::Pending), true),
            (Some(DirectState::Direct), true),
            (Some(DirectState::RelayOnly), false),
        ] {
            match known {
                Some(known) => {
                    state.direct.insert(peer, known);
                }
                None => {
                    state.direct.remove(&peer);
                }
            }
            assert_eq!(
                retry::held_back(&state, &ip_pair),
                held,
                "lookup-only relay, direct state {known:?}"
            );
        }

        // With the relay carrying payload the pair can talk without a session, so
        // a failed probe is no reason to open one before a send.
        state.relay_transport = crate::transport::PayloadPath::RelayAllowed;
        state.direct.insert(peer, DirectState::RelayOnly);
        assert!(
            retry::held_back(&state, &ip_pair),
            "the relay carries payload: wait for a send"
        );
    }

    /// A peer that evicted our connection is not offered a session by the retry pass for a while:
    /// the offer is a proactive dial, and it would take the place that the peer just freed. A frame
    /// that is held for the peer still passes, because a send dials at once.
    #[test]
    fn a_peer_that_evicted_us_is_not_offered_a_session_unless_a_frame_is_held() {
        use crate::daemon::state::DirectState;

        let _guard = ::habilis_network_test_tracing::init();
        let peer = crate::testing::endpoint_id(7);
        let pair = EndpointAddr::new(peer).with_ip_addr("127.0.0.1:4000".parse().expect("addr"));
        let mut state = crate::testing::fresh_state();
        state.local_udp_transport = UdpTransport::Present;
        state.relay_transport = crate::transport::PayloadPath::DirectOnly;
        state.direct.insert(peer, DirectState::RelayOnly);
        assert!(
            !retry::held_back(&state, &pair),
            "a failed probe offers a session"
        );

        state.webrtc_admission.note_evicted(peer);
        assert!(
            retry::held_back(&state, &pair),
            "the peer evicted us lately"
        );

        state.want_lane_session(peer, clock::Instant::now());
        assert!(!retry::held_back(&state, &pair), "a held frame is a send");
    }

    /// A session nothing uses is detached once the idle window has passed, and
    /// the pair then waits for a send.
    #[test]
    fn a_session_nothing_uses_is_detached_and_its_pair_waits_for_a_send() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                idle_session_detaches(|id| {
                    EndpointAddr::new(id).with_ip_addr("127.0.0.1:4000".parse().expect("addr"))
                })
                .await;
            },
        );
    }

    /// The same for a lane peer: its session is no longer kept for ever. It goes at the backstop
    /// like any other, and the pair waits for a held frame to be offered one again.
    #[test]
    fn a_lane_session_nothing_uses_is_detached_at_the_backstop() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                idle_session_detaches(|id| {
                    EndpointAddr::new(id)
                        .with_relay_url("https://relay.invalid".parse().expect("relay url"))
                })
                .await;
            },
        );
    }

    async fn idle_session_detaches(bob_addr: fn(EndpointId) -> EndpointAddr) {
        use crate::util::clock::Instant;

        let (server, server_hub) = endpoint_with_lookup().await;
        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let router = serve(&server, &server_hub, &admission);

        let (client, client_hub) = endpoint_with_lookup().await;
        let client_admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        // The round holds the slot as in production, and teaches the table its hub.
        let round = client_admission
            .try_admit(server.id(), &client_hub)
            .expect("room");
        dial_signal::dial_signal_with(
            &client,
            &crate::lookup::address_book(&client),
            server.addr(),
            &client_hub,
            quick(),
            IceProfile { host_only: true },
        )
        .await
        .expect("the signal round must attach a session");
        drop(round);
        // Both roles tell the table of the attach, as `spawn_offer_round` does.
        client_admission.note_success(server.id());
        assert!(
            client_hub.has_session(&server.id()),
            "the client has a session with the server"
        );

        let mut state = crate::testing::fresh_state();
        state.webrtc = Some(client_hub.clone());
        state.webrtc_admission = client_admission.clone();
        state.local_udp_transport = UdpTransport::Present;
        state
            .peer_endpoints
            .insert(crate::testing::nick("bob"), bob_addr(server.id()));
        let window = tuning::DIRECT_IDLE_BACKSTOP;
        let start = Instant::now();

        assert!(
            retry::detach_idle_sessions_at(&mut state, start).is_empty(),
            "no idle session is detached before its window passes"
        );
        assert!(
            retry::detach_idle_sessions_at(
                &mut state,
                start + window.saturating_sub(Duration::from_secs(1))
            )
            .is_empty(),
            "no idle session is detached one second before its window closes"
        );
        assert!(client_hub.has_session(&server.id()), "not yet");
        assert_eq!(
            retry::detach_idle_sessions_at(&mut state, start + window),
            vec![server.id()],
            "the idle session is detached when its window closes"
        );
        assert!(!client_hub.has_session(&server.id()), "the session is gone");
        assert!(
            retry::held_back(
                &state,
                &state.peer_endpoints.values().next().expect("bob").clone()
            ),
            "the pair waits for a send again"
        );

        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// The retry pass offers a session to a cold pair with an IP path only after
    /// a send: while no pooled connection exists, the pair is left alone.
    #[test]
    fn the_retry_pass_offers_a_session_only_to_a_pair_that_sent() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::protocol::MeshId;
                use crate::protocol::identity::Identity;
                use iroh::endpoint::Connection;
                use iroh::protocol::{AcceptError, ProtocolHandler};

                #[derive(Debug, Clone)]
                struct Hold;
                impl ProtocolHandler for Hold {
                    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                        connection.closed().await;
                        Ok(())
                    }
                }

                let (endpoint, handle) = endpoint().await;
                // Only the lower id offers, so the peer's key must be above ours.
                // The id of our endpoint is random: with 255 seeds, one run in 256 found no key above it.
                let key = (1u16..=u16::MAX)
                    .map(|seed| {
                        let mut bytes = [0u8; 32];
                        bytes[..2].copy_from_slice(&seed.to_le_bytes());
                        SecretKey::from_bytes(&bytes)
                    })
                    .find(|key| key.public() > endpoint.id())
                    .expect("a key above ours");
                let builder = Endpoint::builder(presets::Minimal)
                    .secret_key(key)
                    .relay_mode(RelayMode::Disabled)
                    .clear_address_lookup();
                let server: Endpoint = builder.bind().await.expect("bind a loopback server");
                let router: Router = Router::builder(server.clone())
                    .accept(NUDGE_ALPN, NudgeAcceptor)
                    .accept(crate::transport::UNICAST_ALPN, Hold)
                    .spawn();
                crate::lookup::add_peer_addr(
                    &crate::lookup::address_book(&endpoint),
                    server.addr(),
                );

                let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
                let topic = gossip
                    .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
                    .await
                    .expect("subscribe to a peerless topic");
                let (gossip_sender, _receiver) = topic.split();
                let sender = crate::transport::MeshSender::new(gossip_sender);
                let mesh = MeshId::from("test");
                let identity = Identity::generate();
                let our_pubkey = identity.author_key();
                let author = crate::testing::nick("alice");
                let sink = event::SilentSink;
                let context = handler_ctx::HandlerCtx {
                    sender: &sender,
                    endpoint: &endpoint,
                    mesh: &mesh,
                    author: &author,
                    identity: &identity,
                    our_pubkey,
                    max_peers: 16,
                    rendezvous_id: crate::testing::endpoint_id(9),
                    external_msg_tx: None,
                    sink: &sink,
                };
                let mut state = crate::testing::fresh_state();
                state.webrtc = Some(handle);
                state.local_udp_transport = UdpTransport::Present;
                state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
                state
                    .peer_endpoints
                    .insert(crate::testing::nick("bob"), server.addr());

                retry::retry_sessions(&mut state, &context);
                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    0,
                    "a cold pair is not offered a session"
                );

                state
                    .unicast_pool
                    .warm_or_dial(server.id())
                    .await
                    .expect("a send dials the peer");
                retry::retry_sessions(&mut state, &context);
                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    1,
                    "after a send, the pair is offered a session"
                );

                // The dial to a closed signal port would hold its slot for a long deadline.
                state.webrtc_admission.close();
                assert!(
                    until(|| state.webrtc_admission.in_flight() == 0).await,
                    "closing the table cancels the round"
                );
                router.shutdown().await.expect("shutdown");
                endpoint.close().await;
            },
        );
    }

    /// Only the lower id has a path watcher, so a pair that loses IP while the higher id sends
    /// is seen by nobody but the higher id, and by its admission table alone: the proof of a
    /// direct path is stale where the selected path reads as the relay. The higher id then
    /// offers by itself and takes the proof back, so that a frame is parked for the session
    /// instead of being refused on the relay. A pair that reads as UDP keeps its proof and gets
    /// no offer.
    #[test]
    fn the_higher_id_offers_and_demotes_a_proven_pair_that_reads_as_relay() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::daemon::state::DirectState;
                use crate::protocol::MeshId;
                use crate::protocol::identity::Identity;
                use crate::transport::probe::PathKind;
                use iroh::endpoint::Connection;
                use iroh::protocol::{AcceptError, ProtocolHandler};

                #[derive(Debug, Clone)]
                struct Hold;
                impl ProtocolHandler for Hold {
                    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                        connection.closed().await;
                        Ok(())
                    }
                }

                let (endpoint, handle) = endpoint().await;
                // The peer's key must be below ours, so that we are the higher id and wait to be dialled.
                let key = (1u16..=u16::MAX)
                    .map(|seed| {
                        let mut bytes = [0u8; 32];
                        bytes[..2].copy_from_slice(&seed.to_le_bytes());
                        SecretKey::from_bytes(&bytes)
                    })
                    .find(|key| key.public() < endpoint.id())
                    .expect("a key below ours");
                let builder = Endpoint::builder(presets::Minimal)
                    .secret_key(key)
                    .relay_mode(RelayMode::Disabled)
                    .clear_address_lookup();
                let server: Endpoint = builder.bind().await.expect("bind a loopback server");
                let router: Router = Router::builder(server.clone())
                    .accept(NUDGE_ALPN, NudgeAcceptor)
                    .accept(crate::transport::UNICAST_ALPN, Hold)
                    .spawn();
                crate::lookup::add_peer_addr(
                    &crate::lookup::address_book(&endpoint),
                    server.addr(),
                );

                let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
                let topic = gossip
                    .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
                    .await
                    .expect("subscribe to a peerless topic");
                let (gossip_sender, _receiver) = topic.split();
                let sender = crate::transport::MeshSender::new(gossip_sender);
                let mesh = MeshId::from("test");
                let identity = Identity::generate();
                let our_pubkey = identity.author_key();
                let author = crate::testing::nick("alice");
                let sink = event::SilentSink;
                let context = handler_ctx::HandlerCtx {
                    sender: &sender,
                    endpoint: &endpoint,
                    mesh: &mesh,
                    author: &author,
                    identity: &identity,
                    our_pubkey,
                    max_peers: 16,
                    rendezvous_id: crate::testing::endpoint_id(9),
                    external_msg_tx: None,
                    sink: &sink,
                };
                let mut state = crate::testing::fresh_state();
                state.webrtc = Some(handle);
                state.local_udp_transport = UdpTransport::Present;
                state.relay_transport = crate::transport::PayloadPath::DirectOnly;
                state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
                state
                    .peer_endpoints
                    .insert(crate::testing::nick("bob"), server.addr());
                let bob = server.id();
                state
                    .unicast_pool
                    .warm_or_dial(bob)
                    .await
                    .expect("a send dials the peer");
                state.direct.insert(bob, DirectState::Direct);

                state.path_kinds.insert(bob, PathKind::Ip);
                retry::retry_sessions(&mut state, &context);
                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    0,
                    "UDP is selected: no offer"
                );
                assert_eq!(
                    state.direct.get(&bob),
                    Some(&DirectState::Direct),
                    "bob is direct in the state after the verdict"
                );

                state.path_kinds.insert(bob, PathKind::Relay);
                retry::retry_sessions(&mut state, &context);
                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    1,
                    "the proof is stale: the higher id offers"
                );
                assert_eq!(
                    state.direct.get(&bob),
                    Some(&DirectState::RelayOnly),
                    "and takes the proof back, so that a frame is parked"
                );

                state.webrtc_admission.close();
                assert!(
                    until(|| state.webrtc_admission.in_flight() == 0).await,
                    "closing the table cancels the round"
                );
                router.shutdown().await.expect("shutdown");
                endpoint.close().await;
            },
        );
    }

    /// The retry pass offers a session to an idle lane peer only when a frame is held for it
    /// (decision D11): without one, the pair is left alone.
    #[test]
    fn the_retry_pass_offers_a_session_to_an_idle_lane_peer_only_for_a_held_frame() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::protocol::MeshId;
                use crate::protocol::identity::Identity;
                use iroh::endpoint::Connection;
                use iroh::protocol::{AcceptError, ProtocolHandler};

                #[derive(Debug, Clone)]
                struct Hold;
                impl ProtocolHandler for Hold {
                    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                        connection.closed().await;
                        Ok(())
                    }
                }

                let (endpoint, handle) = endpoint().await;
                // Only the lower id offers, so the peer's key must be above ours.
                // The id of our endpoint is random: with 255 seeds, one run in 256 found no key above it.
                let key = (1u16..=u16::MAX)
                    .map(|seed| {
                        let mut bytes = [0u8; 32];
                        bytes[..2].copy_from_slice(&seed.to_le_bytes());
                        SecretKey::from_bytes(&bytes)
                    })
                    .find(|key| key.public() > endpoint.id())
                    .expect("a key above ours");
                let builder = Endpoint::builder(presets::Minimal)
                    .secret_key(key)
                    .relay_mode(RelayMode::Disabled)
                    .clear_address_lookup();
                let server: Endpoint = builder.bind().await.expect("bind a loopback server");
                let router: Router = Router::builder(server.clone())
                    .accept(NUDGE_ALPN, NudgeAcceptor)
                    .accept(crate::transport::UNICAST_ALPN, Hold)
                    .spawn();
                crate::lookup::add_peer_addr(
                    &crate::lookup::address_book(&endpoint),
                    server.addr(),
                );

                let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
                let topic = gossip
                    .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
                    .await
                    .expect("subscribe to a peerless topic");
                let (gossip_sender, _receiver) = topic.split();
                let sender = crate::transport::MeshSender::new(gossip_sender);
                let mesh = MeshId::from("test");
                let identity = Identity::generate();
                let our_pubkey = identity.author_key();
                let author = crate::testing::nick("alice");
                let sink = event::SilentSink;
                let context = handler_ctx::HandlerCtx {
                    sender: &sender,
                    endpoint: &endpoint,
                    mesh: &mesh,
                    author: &author,
                    identity: &identity,
                    our_pubkey,
                    max_peers: 16,
                    rendezvous_id: crate::testing::endpoint_id(9),
                    external_msg_tx: None,
                    sink: &sink,
                };
                let mut state = crate::testing::fresh_state();
                state.webrtc = Some(handle);
                state.local_udp_transport = UdpTransport::Present;
                state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
                let relay_url: iroh::RelayUrl = "https://relay.invalid".parse().expect("relay url");
                state.peer_endpoints.insert(
                    crate::testing::nick("bob"),
                    EndpointAddr::new(server.id()).with_relay_url(relay_url),
                );

                retry::retry_sessions(&mut state, &context);
                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    0,
                    "an idle lane peer is not offered a session"
                );

                state.want_lane_session(server.id(), clock::Instant::now());
                retry::retry_sessions(&mut state, &context);
                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    1,
                    "a frame is held for the peer: it is offered a session"
                );

                // The dial to a closed signal port would hold its slot for a long deadline.
                state.webrtc_admission.close();
                assert!(
                    until(|| state.webrtc_admission.in_flight() == 0).await,
                    "closing the table cancels the round"
                );
                router.shutdown().await.expect("shutdown");
                endpoint.close().await;
            },
        );
    }

    /// **A graft that this node asks for opens the session of a lane peer.** In a mesh where every
    /// pair needs the lane and nothing is sent, no frame is held. The graft of a member is the
    /// reason for its session: without it the pair stays `Pending` for ever and no member links
    /// to another member.
    #[test]
    fn a_graft_of_a_cold_lane_peer_opens_its_session() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::protocol::MeshId;
                use crate::protocol::identity::Identity;

                let (endpoint, handle) = endpoint().await;
                // Only the lower id offers, so the peer's key must be above ours.
                let key = (1u16..=u16::MAX)
                    .map(|seed| {
                        let mut bytes = [0u8; 32];
                        bytes[..2].copy_from_slice(&seed.to_le_bytes());
                        SecretKey::from_bytes(&bytes)
                    })
                    .find(|key| key.public() > endpoint.id())
                    .expect("a key above ours");
                let (server, _server_hub) = endpoint_with(key).await;
                let peer = server.id();

                let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
                let topic = gossip
                    .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
                    .await
                    .expect("subscribe to a peerless topic");
                let (gossip_sender, _receiver) = topic.split();
                let sender = crate::transport::MeshSender::new(gossip_sender);
                let mesh = MeshId::from("test");
                let identity = Identity::generate();
                let our_pubkey = identity.author_key();
                let author = crate::testing::nick("alice");
                let sink = event::SilentSink;
                let context = handler_ctx::HandlerCtx {
                    sender: &sender,
                    endpoint: &endpoint,
                    mesh: &mesh,
                    author: &author,
                    identity: &identity,
                    our_pubkey,
                    max_peers: 16,
                    rendezvous_id: crate::testing::endpoint_id(9),
                    external_msg_tx: None,
                    sink: &sink,
                };
                let mut state = crate::testing::fresh_state();
                state.webrtc = Some(handle);
                state.local_udp_transport = UdpTransport::Present;
                state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
                let address = EndpointAddr::new(peer)
                    .with_relay_url("https://relay.invalid".parse().expect("relay url"));
                state
                    .peer_endpoints
                    .insert(crate::testing::nick("bob"), address.clone());
                assert!(
                    retry::held_back(&state, &address),
                    "cold: nothing asks for the session yet"
                );

                let grafted = probe::ensure_direct(&mut state, &context, peer, &address);
                assert!(!grafted, "the graft waits for the session");
                assert!(
                    !retry::held_back(&state, &address),
                    "the graft asks for the session of the lane peer"
                );
                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    1,
                    "the session is offered at once"
                );

                // The dial to a closed signal port would hold its slot for a long deadline.
                state.webrtc_admission.close();
                server.close().await;
                endpoint.close().await;
            },
        );
    }

    /// **A frame held on the higher-id node opens the session.** The lower id has no reason to
    /// offer, so the higher id offers when a frame is held for the peer, and the session attaches
    /// on both nodes.
    #[test]
    fn a_frame_held_on_the_higher_id_node_opens_the_session() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::protocol::MeshId;
                use crate::protocol::identity::Identity;

                let (endpoint, handle) = endpoint().await;
                // Only the lower id offers unless a frame is held, and here the peer is the lower id.
                // The id of our endpoint is random, so many seeds are tried.
                let key = (1u16..=u16::MAX)
                    .map(|seed| {
                        let mut bytes = [0u8; 32];
                        bytes[..2].copy_from_slice(&seed.to_le_bytes());
                        SecretKey::from_bytes(&bytes)
                    })
                    .find(|key| key.public() < endpoint.id())
                    .expect("a key below ours");
                let (server, server_hub) = endpoint_with(key).await;
                let server_admission = SignalAdmission::new(8);
                let router = serve(&server, &server_hub, &server_admission);

                let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
                let topic = gossip
                    .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
                    .await
                    .expect("subscribe to a peerless topic");
                let (gossip_sender, _receiver) = topic.split();
                let sender = crate::transport::MeshSender::new(gossip_sender);
                let mesh = MeshId::from("test");
                let identity = Identity::generate();
                let our_pubkey = identity.author_key();
                let author = crate::testing::nick("alice");
                let sink = event::SilentSink;
                let context = handler_ctx::HandlerCtx {
                    sender: &sender,
                    endpoint: &endpoint,
                    mesh: &mesh,
                    author: &author,
                    identity: &identity,
                    our_pubkey,
                    max_peers: 16,
                    rendezvous_id: crate::testing::endpoint_id(9),
                    external_msg_tx: None,
                    sink: &sink,
                };
                let mut state = crate::testing::fresh_state();
                state.webrtc = Some(handle.clone());
                state.local_udp_transport = UdpTransport::Absent;
                state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
                state
                    .peer_endpoints
                    .insert(crate::testing::nick("bob"), server.addr());

                retry::retry_sessions(&mut state, &context);
                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    0,
                    "an idle lane peer is not offered a session"
                );

                state.want_lane_session(server.id(), clock::Instant::now());
                retry::retry_sessions(&mut state, &context);
                assert!(
                    until(|| handle.has_session(&server.id())
                        && server_hub.has_session(&endpoint.id()))
                    .await,
                    "a frame is held for the lower id: the higher id offers, and the session attaches"
                );

                router.shutdown().await.expect("shutdown");
                server.close().await;
                endpoint.close().await;
            },
        );
    }

    /// A session carries the pair whatever one connection reads: a connection opened before the
    /// attach reads `Relay` until a path event moves it. With a session attached the proof stands:
    /// no demotion, no offer.
    #[test]
    fn a_pair_with_a_session_keeps_its_proof_when_a_connection_reads_as_relay() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::daemon::state::DirectState;
                use crate::protocol::MeshId;
                use crate::protocol::identity::Identity;
                use crate::transport::probe::PathKind;

                let (endpoint, handle) = endpoint().await;
                // The answerer of the session nudges this endpoint, the offerer, on the nudge ALPN.
                let nudge_router = Router::builder(endpoint.clone())
                    .accept(NUDGE_ALPN, NudgeAcceptor)
                    .spawn();
                // The peer's key must be below ours: we are the higher id, so a session is offered here
                // only for a held frame, which the test uses to attach one.
                let key = (1u16..=u16::MAX)
                    .map(|seed| {
                        let mut bytes = [0u8; 32];
                        bytes[..2].copy_from_slice(&seed.to_le_bytes());
                        SecretKey::from_bytes(&bytes)
                    })
                    .find(|key| key.public() < endpoint.id())
                    .expect("a key below ours");
                let (server, server_hub) = endpoint_with(key).await;
                let server_admission = SignalAdmission::new(8);
                let router = serve(&server, &server_hub, &server_admission);

                let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
                let topic = gossip
                    .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
                    .await
                    .expect("subscribe to a peerless topic");
                let (gossip_sender, _receiver) = topic.split();
                let sender = crate::transport::MeshSender::new(gossip_sender);
                let mesh = MeshId::from("test");
                let identity = Identity::generate();
                let our_pubkey = identity.author_key();
                let author = crate::testing::nick("alice");
                let sink = event::SilentSink;
                let context = handler_ctx::HandlerCtx {
                    sender: &sender,
                    endpoint: &endpoint,
                    mesh: &mesh,
                    author: &author,
                    identity: &identity,
                    our_pubkey,
                    max_peers: 16,
                    rendezvous_id: crate::testing::endpoint_id(9),
                    external_msg_tx: None,
                    sink: &sink,
                };
                let mut state = crate::testing::fresh_state();
                state.webrtc = Some(handle.clone());
                state.local_udp_transport = UdpTransport::Present;
                state.relay_transport = crate::transport::PayloadPath::DirectOnly;
                state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
                state
                    .peer_endpoints
                    .insert(crate::testing::nick("bob"), server.addr());
                let bob = server.id();

                // Attach a session: a frame is held for the peer, and the higher id offers for it.
                state.want_lane_session(bob, clock::Instant::now());
                state.direct.insert(bob, DirectState::RelayOnly);
                state.path_kinds.insert(bob, PathKind::Relay);
                // The server serves no unicast ALPN: a cooldown stands for the failed dial that keeps UDP
                // from winning the race, without the WARN of a refused ALPN.
                state.unicast_pool.note_dial_failure(bob).await;
                retry::retry_sessions(&mut state, &context);
                assert!(
                    until(|| handle.has_session(&bob) && server_hub.has_session(&endpoint.id()))
                        .await,
                    "the session attaches"
                );

                // The session is up and the proof is back, but a connection still reads as the relay. The
                // frame is still held, so that the pair is not left alone for want of a send.
                state.direct.insert(bob, DirectState::Direct);
                state.path_kinds.insert(bob, PathKind::Relay);
                let address = server.addr();
                negotiate_session::negotiate_session(&mut state, &context, bob, address);
                assert_eq!(
                    state.direct.get(&bob),
                    Some(&DirectState::Direct),
                    "a session carries the pair: the reading of one connection does not take the proof back"
                );

                // The same for a connection that reads the gossip rung: the graft is not skipped, as the
                // gossip link will ride the session and not the rung.
                state.path_kinds.insert(bob, PathKind::Gossip);
                assert!(
                    !state.rides_gossip_rung(bob),
                    "a session carries the pair: a connection on the gossip rung does not stop the graft"
                );

                router.shutdown().await.expect("shutdown");
                server.close().await;
                nudge_router
                    .shutdown()
                    .await
                    .expect("shutdown the nudge router");
                endpoint.close().await;
            },
        );
    }

    /// **UDP returns on a pair that only gossips.** Such a pair has no path watcher, so the session
    /// that the race attached would stay until the backstop. The reading of the admission table
    /// detaches it, on the fast ticker: a relay reading keeps it, an IP reading drops it.
    #[test]
    fn a_session_is_detached_once_udp_is_selected_again() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::daemon::state::DirectState;
                use crate::protocol::MeshId;
                use crate::protocol::identity::Identity;
                use crate::transport::probe::PathKind;

                let (endpoint, handle) = endpoint().await;
                // The answerer of the session nudges this endpoint, the offerer, on the nudge ALPN.
                let nudge_router = Router::builder(endpoint.clone())
                    .accept(NUDGE_ALPN, NudgeAcceptor)
                    .spawn();
                let key = (1u16..=u16::MAX)
                    .map(|seed| {
                        let mut bytes = [0u8; 32];
                        bytes[..2].copy_from_slice(&seed.to_le_bytes());
                        SecretKey::from_bytes(&bytes)
                    })
                    .find(|key| key.public() < endpoint.id())
                    .expect("a key below ours");
                let (server, server_hub) = endpoint_with(key).await;
                let server_admission = SignalAdmission::new(8);
                let router = serve(&server, &server_hub, &server_admission);

                let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
                let topic = gossip
                    .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
                    .await
                    .expect("subscribe to a peerless topic");
                let (gossip_sender, _receiver) = topic.split();
                let sender = crate::transport::MeshSender::new(gossip_sender);
                let mesh = MeshId::from("test");
                let identity = Identity::generate();
                let our_pubkey = identity.author_key();
                let author = crate::testing::nick("alice");
                let sink = event::SilentSink;
                let context = handler_ctx::HandlerCtx {
                    sender: &sender,
                    endpoint: &endpoint,
                    mesh: &mesh,
                    author: &author,
                    identity: &identity,
                    our_pubkey,
                    max_peers: 16,
                    rendezvous_id: crate::testing::endpoint_id(9),
                    external_msg_tx: None,
                    sink: &sink,
                };
                let mut state = crate::testing::fresh_state();
                state.webrtc = Some(handle.clone());
                state.local_udp_transport = UdpTransport::Present;
                state.relay_transport = crate::transport::PayloadPath::DirectOnly;
                state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
                state
                    .peer_endpoints
                    .insert(crate::testing::nick("bob"), server.addr());
                let bob = server.id();

                state.want_lane_session(bob, clock::Instant::now());
                state.direct.insert(bob, DirectState::RelayOnly);
                state.path_kinds.insert(bob, PathKind::Relay);
                // The server serves no unicast ALPN: a cooldown stands for the failed dial that keeps UDP
                // from winning the race, without the WARN of a refused ALPN.
                state.unicast_pool.note_dial_failure(bob).await;
                retry::retry_sessions(&mut state, &context);
                assert!(
                    until(|| handle.has_session(&bob) && server_hub.has_session(&endpoint.id()))
                        .await,
                    "the session attaches"
                );

                state.path_kinds.insert(bob, PathKind::Relay);
                session_policy::detach_sessions_under_udp(&mut state, &context).await;
                assert!(
                    handle.has_session(&bob),
                    "the pair still reads as the relay"
                );

                state.path_kinds.insert(bob, PathKind::Ip);
                session_policy::detach_sessions_under_udp(&mut state, &context).await;
                assert!(!handle.has_session(&bob), "UDP is selected again");
                assert_eq!(
                    state.direct.get(&bob),
                    Some(&DirectState::Direct),
                    "the pair is proven direct again"
                );

                router.shutdown().await.expect("shutdown");
                server.close().await;
                nudge_router
                    .shutdown()
                    .await
                    .expect("shutdown the nudge router");
                endpoint.close().await;
            },
        );
    }

    /// **A pass paces the lane offers.** Six lane members, none linked: the pass offers a session
    /// to `LANE_OFFERS_IN_FLIGHT` of them. The others are not touched: no `Pending` mark, so the
    /// next pass picks them.
    #[test]
    fn a_retry_pass_offers_to_the_budget_of_lane_members_and_leaves_the_others_alone() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::protocol::MeshId;
                use crate::protocol::identity::Identity;
                use crate::util::tuning::LANE_OFFERS_IN_FLIGHT;

                let (endpoint, handle) = endpoint().await;
                let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
                let topic = gossip
                    .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
                    .await
                    .expect("subscribe to a peerless topic");
                let (gossip_sender, _receiver) = topic.split();
                let sender = crate::transport::MeshSender::new(gossip_sender);
                let mesh = MeshId::from("test");
                let identity = Identity::generate();
                let our_pubkey = identity.author_key();
                let author = crate::testing::nick("alice");
                let sink = event::SilentSink;
                let context = handler_ctx::HandlerCtx {
                    sender: &sender,
                    endpoint: &endpoint,
                    mesh: &mesh,
                    author: &author,
                    identity: &identity,
                    our_pubkey,
                    max_peers: 16,
                    rendezvous_id: crate::testing::endpoint_id(99),
                    external_msg_tx: None,
                    sink: &sink,
                };
                let mut state = crate::testing::fresh_state();
                state.webrtc = Some(handle);
                state.local_udp_transport = UdpTransport::Present;
                state.relay_transport = crate::transport::PayloadPath::DirectOnly;
                state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
                let members: Vec<EndpointId> = (1..=6).map(crate::testing::endpoint_id).collect();
                for (index, id) in members.iter().enumerate() {
                    let address = EndpointAddr::new(*id)
                        .with_relay_url("https://relay.invalid".parse().expect("relay url"));
                    state
                        .peer_endpoints
                        .insert(crate::testing::nick(&format!("member{index}")), address);
                }

                probe::retry_direct(&mut state, &context, false).await;

                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    LANE_OFFERS_IN_FLIGHT,
                    "the budget of rounds, not one per member"
                );
                let touched: usize = members
                    .iter()
                    .filter(|id| state.direct.contains_key(*id))
                    .count();
                assert_eq!(
                    touched, LANE_OFFERS_IN_FLIGHT,
                    "the members left out have no mark"
                );

                // The dials to a closed signal port would hold their slots for a long deadline.
                state.webrtc_admission.close();
                endpoint.close().await;
            },
        );
    }

    /// **A freed slot is filled.** With the budget spent, the top-up offers nothing. When one
    /// round ends, it offers to exactly one more of the members that were left out.
    #[test]
    fn the_top_up_fills_the_slot_that_a_round_freed() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::protocol::MeshId;
                use crate::protocol::identity::Identity;
                use crate::util::tuning::LANE_OFFERS_IN_FLIGHT;

                let (endpoint, handle) = endpoint().await;
                let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
                let topic = gossip
                    .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
                    .await
                    .expect("subscribe to a peerless topic");
                let (gossip_sender, _receiver) = topic.split();
                let sender = crate::transport::MeshSender::new(gossip_sender);
                let mesh = MeshId::from("test");
                let identity = Identity::generate();
                let our_pubkey = identity.author_key();
                let author = crate::testing::nick("alice");
                let sink = event::SilentSink;
                let context = handler_ctx::HandlerCtx {
                    sender: &sender,
                    endpoint: &endpoint,
                    mesh: &mesh,
                    author: &author,
                    identity: &identity,
                    our_pubkey,
                    max_peers: 16,
                    rendezvous_id: crate::testing::endpoint_id(99),
                    external_msg_tx: None,
                    sink: &sink,
                };
                let mut state = crate::testing::fresh_state();
                state.webrtc = Some(handle);
                state.local_udp_transport = UdpTransport::Present;
                state.relay_transport = crate::transport::PayloadPath::DirectOnly;
                state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
                let members: Vec<EndpointId> = (1..=6).map(crate::testing::endpoint_id).collect();
                for (index, id) in members.iter().enumerate() {
                    let address = EndpointAddr::new(*id)
                        .with_relay_url("https://relay.invalid".parse().expect("relay url"));
                    state
                        .peer_endpoints
                        .insert(crate::testing::nick(&format!("member{index}")), address);
                }

                probe::retry_direct(&mut state, &context, false).await;
                let touched = |node: &state::EventLoopState| {
                    let direct = &node.direct;
                    members.iter().filter(|id| direct.contains_key(*id)).count()
                };
                assert_eq!(touched(&state), LANE_OFFERS_IN_FLIGHT, "the first pass");

                probe::top_up_lane_offers(&mut state, &context).await;
                assert_eq!(
                    touched(&state),
                    LANE_OFFERS_IN_FLIGHT,
                    "the budget is spent: the top-up offers nothing"
                );

                // One round ends: its slot is free.
                let offered: EndpointId = *members
                    .iter()
                    .find(|id| state.direct.contains_key(*id))
                    .expect("an offered member");
                assert!(
                    state.webrtc_admission.preempt_offer(offered),
                    "a round to end"
                );
                probe::top_up_lane_offers(&mut state, &context).await;
                assert_eq!(
                    touched(&state),
                    LANE_OFFERS_IN_FLIGHT + 1,
                    "one more member is offered"
                );
                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    LANE_OFFERS_IN_FLIGHT,
                    "the budget is spent again"
                );

                state.webrtc_admission.close();
                endpoint.close().await;
            },
        );
    }

    /// **Glare.** Both nodes of a pair offer at once. The lower id wins: the higher id gives its
    /// offer up when the offer of the lower id arrives, and answers it. The pair ends with exactly
    /// one session, and the offer that was given up is cancelled.
    #[test]
    fn a_crossed_pair_ends_with_one_session_and_the_lower_id_wins() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            4,
            async {
                let (first, first_hub) = endpoint().await;
                let (second, second_hub) = endpoint().await;
                let ((lower, lower_hub), (higher, higher_hub)) = if first.id() < second.id() {
                    ((first, first_hub), (second, second_hub))
                } else {
                    ((second, second_hub), (first, first_hub))
                };
                let lower_admission = SignalAdmission::new(8);
                let higher_admission = SignalAdmission::new(8);
                let lower_router = serve(&lower, &lower_hub, &lower_admission);
                let higher_router = serve(&higher, &higher_hub, &higher_admission);

                // The higher id has an offer to the lower id in flight that never ends on its own.
                let offer = higher_admission
                    .try_admit_offer(lower.id(), &higher_hub)
                    .expect("the higher id offers");
                let epoch = offer.epoch();
                let offering = tokio::spawn(async move {
                    let _offer = offer;
                    std::future::pending::<()>().await;
                });
                higher_admission.track(lower.id(), epoch, offering.abort_handle());

                dial_signal::dial_signal_with(
                    &lower,
                    &crate::lookup::address_book(&lower),
                    higher.addr(),
                    &lower_hub,
                    quick(),
                    IceProfile { host_only: true },
                )
                .await
                .expect("the offer of the lower id is answered");

                assert!(
                    until(|| higher_hub.has_session(&lower.id())).await,
                    "the higher id answered"
                );
                assert!(
                    lower_hub.has_session(&higher.id()),
                    "the lower hub keeps the session with the higher peer"
                );
                assert_eq!(
                    lower_hub.session_count(),
                    1,
                    "the lower hub holds exactly one session"
                );
                assert_eq!(
                    higher_hub.session_count(),
                    1,
                    "the higher hub holds exactly one session"
                );
                assert!(
                    offering
                        .await
                        .expect_err("the offer is cancelled")
                        .is_cancelled(),
                    "the higher id gave its offer up"
                );

                higher_router.shutdown().await.expect("shutdown");
                lower_router.shutdown().await.expect("shutdown");
                higher.close().await;
                lower.close().await;
            },
        );
    }

    /// **The answering side reports the attach.** A frame parked on the higher id of a crossed pair
    /// is flushed when the session attaches, although the node answered and did not offer: the
    /// answerer tells the event loop, through the table, which flushes what is held for the peer.
    #[test]
    fn the_answering_side_reports_the_attach_to_the_event_loop() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            4,
            async {
                let (first, first_hub) = endpoint().await;
                let (second, second_hub) = endpoint().await;
                let ((lower, lower_hub), (higher, higher_hub)) = if first.id() < second.id() {
                    ((first, first_hub), (second, second_hub))
                } else {
                    ((second, second_hub), (first, first_hub))
                };
                let higher_admission = SignalAdmission::new(8);
                let (sink, mut attached) = mpsc::unbounded_channel();
                higher_admission.set_proven_sink(sink);
                let higher_router = serve(&higher, &higher_hub, &higher_admission);

                dial_signal::dial_signal_with(
                    &lower,
                    &crate::lookup::address_book(&lower),
                    higher.addr(),
                    &lower_hub,
                    quick(),
                    IceProfile { host_only: true },
                )
                .await
                .expect("the offer of the lower id is answered");

                let outcome = tokio::time::timeout(Duration::from_secs(5), attached.recv())
                    .await
                    .expect("the answerer reports the attach")
                    .expect("the sink stays open");
                assert_eq!(
                    outcome.peer,
                    lower.id(),
                    "the answering side reports the attach with the lower peer's id"
                );
                assert!(
                    outcome.direct && outcome.answered,
                    "the answering side reports a direct, answered attach"
                );

                higher_router.shutdown().await.expect("shutdown");
                higher.close().await;
                lower.close().await;
            },
        );
    }

    /// The loop acts on an answered session only when a frame is held for the peer.
    #[test]
    fn an_answered_session_is_applied_only_when_a_frame_is_held_for_the_peer() {
        use crate::transport::probe::DirectOutcome;

        let _guard = ::habilis_network_test_tracing::init();
        let peer = crate::testing::endpoint_id(7);
        let now = clock::Instant::now();
        let mut state = crate::testing::fresh_state();
        let answered = DirectOutcome {
            peer,
            direct: true,
            answered: true,
        };
        let offered = DirectOutcome {
            answered: false,
            ..answered
        };

        assert!(
            !answered.applies(&state, now),
            "nothing is held for the peer"
        );
        assert!(
            offered.applies(&state, now),
            "our own verdict always applies"
        );
        state.want_lane_session(peer, now);
        assert!(
            answered.applies(&state, now),
            "a frame is held for the peer"
        );
    }

    /// The offer of the lower id is refused as before when the round that runs is an answer, not
    /// an offer of the higher id.
    #[test]
    fn the_lower_id_still_refuses_a_crossed_offer() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            4,
            async {
                let (first, first_hub) = endpoint().await;
                let (second, second_hub) = endpoint().await;
                let ((lower, lower_hub), (higher, higher_hub)) = if first.id() < second.id() {
                    ((first, first_hub), (second, second_hub))
                } else {
                    ((second, second_hub), (first, first_hub))
                };
                let lower_admission = SignalAdmission::new(8);
                let lower_router = serve(&lower, &lower_hub, &lower_admission);

                // The lower id has its own offer to the higher id in flight.
                let _offer = lower_admission
                    .try_admit_offer(higher.id(), &lower_hub)
                    .expect("the lower id offers");

                let outcome = dial_signal::dial_signal_with(
                    &higher,
                    &crate::lookup::address_book(&higher),
                    lower.addr(),
                    &higher_hub,
                    quick(),
                    IceProfile { host_only: true },
                )
                .await;

                assert!(outcome.is_err(), "the lower id keeps its own offer");
                assert_eq!(
                    lower_hub.session_count(),
                    0,
                    "the lower id holds no session after refusing a crossed offer"
                );

                lower_router.shutdown().await.expect("shutdown");
                higher.close().await;
                lower.close().await;
            },
        );
    }

    #[test]
    fn an_offer_fallback_holds_the_timer_graft() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = crate::testing::fresh_state();
        assert!(
            rendezvous::rendezvous_graftable(&state),
            "an IP-capable node grafts on its timer until it falls back"
        );
        state.rendezvous_offer_fallback = true;
        assert!(
            !rendezvous::rendezvous_graftable(&state),
            "the rendezvous is not graftable while the fallback holds"
        );
    }
}
