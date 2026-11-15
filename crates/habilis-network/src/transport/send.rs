//! The single send decision. Every outbound message funnels through
//! [`deliver()`]: a broadcast (no sole addressee) rides gossip, structurally; a
//! directed message goes over the unicast connection only — warm pooled
//! connection first, a dial on a task of its own otherwise — and gossip never carries it. The
//! bytes are the same canonical wire `Message` on both planes, so the
//! receiver's path is identical either way.

mod delivered;
pub use delivered::Delivered;
mod deliver;
mod route;
#[cfg(any(test, all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
pub(crate) use deliver::resolve;
pub(crate) use deliver::{
    can_unicast, lane_for, note_held, note_unproven, send_best_effort, send_dialing_back,
};
pub use deliver::{deliver, deliver_in_background, deliver_to, deliver_to_in_background};
pub(crate) use route::directed_endpoint;
#[cfg(test)]
use route::{Route, route};
mod lane;
pub use lane::Lane;
mod pending_send;
pub use pending_send::PendingSend;
mod send_error;
pub use send_error::SendError;
#[cfg(test)]
#[cfg(test)]
#[cfg(test)]
#[cfg(test)]
mod tests {
    use crate::daemon::state::Standing;
    use crate::testing::{endpoint_id, fresh_state, nick, test_key};
    use crate::transport::UdpTransport;

    use iroh::EndpointId;

    use super::{
        Lane, Route, SendError, can_unicast, deliver, lane_for, note_held, note_unproven, resolve,
        route,
    };
    use crate::daemon::state::EventLoopState;
    use crate::protocol::messages::{AppFrameParams, Verified};
    use crate::protocol::{
        AppTag, AuthorKey, CorrId, Identity, MeshId, Message, MessageBody, MessageId, UnixSecs,
    };

    use super::Delivered;
    use crate::daemon::state::DirectState;
    use crate::lookup::test_relay;
    use crate::protocol::messages::WireFrame;
    use crate::transport::{PayloadPath, payload_path};
    use crate::util::clock;
    use crate::{lookup, transport};
    use iroh::endpoint::{Connection, presets};
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};
    use iroh_gossip::net::Gossip;
    use iroh_gossip::proto;
    use iroh_relay::server::Server;
    use std::net::{UdpSocket, UdpSocket as std_UdpSocket};
    use std::time::{Duration as std_Duration, Instant as std_Instant};
    use tokio::sync::mpsc;
    use tokio::{task, time as tokio_time};
    fn mesh() -> MeshId {
        MeshId::from("test")
    }

    fn body() -> MessageBody {
        MessageBody::from("hi")
    }

    /// A meshed state that knows `bob`'s endpoint — the happy path for unicast.
    /// Bob is known and has a proven direct path: the state a peer is in
    /// once linked on a lookup-only mesh, so a directed frame is sendable.
    fn state_knowing_bob() -> (EventLoopState, EndpointId) {
        let mut state = fresh_state();
        state.standing.insert(Standing::Meshed);
        let bob = endpoint_id(1);
        state.names.insert(test_key("bob"), nick("bob"));
        state.bind_peer_endpoint(test_key("bob"), nick("bob"), iroh::EndpointAddr::new(bob));
        state.direct.insert(bob, DirectState::Direct);
        (state, bob)
    }

    /// A directed frame addressed to `bob` — a `Pong` is the simplest one.
    fn directed_msg() -> Verified {
        Message::new_pong(
            &mesh(),
            &nick("alice"),
            test_key("bob"),
            &MessageId::random(),
        )
        .sign(&Identity::generate())
    }

    fn open_broadcast() -> Verified {
        Message::new_app(
            &mesh(),
            &nick("alice"),
            AppFrameParams::new(
                AppTag::try_new("app_msg").expect("a valid app tag"),
                None,
                None,
                body(),
            ),
        )
        .sign(&Identity::generate())
    }

    // ── lane peers ────────────────────────────────────────────────────

    /// A lane peer: no IP address, only a relay. On a mesh whose relay is lookup only, a frame to
    /// it is held once a probe reads its path as the relay, and holding it is what asks for its
    /// session. Before that reading it is unproven, and the send asks for the session itself.
    fn state_knowing_a_lane_bob() -> (EventLoopState, EndpointId) {
        let mut state = fresh_state();
        state.standing.insert(Standing::Meshed);
        state.local_udp_transport = UdpTransport::Present;
        let bob = endpoint_id(1);
        state.names.insert(test_key("bob"), nick("bob"));
        state.bind_peer_endpoint(
            test_key("bob"),
            nick("bob"),
            iroh::EndpointAddr::new(bob)
                .with_relay_url("https://relay.invalid".parse().expect("relay url")),
        );
        (state, bob)
    }

    /// A cold send to a lane peer with no session holds the frame and marks the session wanted.
    #[test]
    fn a_frame_held_for_a_lane_peer_marks_its_session_wanted() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_a_lane_bob();
        state.direct.insert(bob, DirectState::RelayOnly);
        let now = clock::Instant::now();
        assert!(!state.lane_session_wanted(bob, now), "nothing is held yet");

        let error = resolve(
            &directed_msg(),
            directed_msg().serialize().expect("serialize"),
            &state,
        )
        .expect_err("a lookup-only relay holds the frame");
        note_held(&mut state, &error);

        assert!(state.lane_session_wanted(bob, now), "the held frame asks");
    }

    /// Two live keys use one nickname, and the second is a lane peer whose endpoint the roster
    /// keeps by key. A frame held for the second key asks for the session of the second key: the
    /// member list of the transport plane has one row for each key, not one for each nickname.
    #[test]
    fn a_frame_held_for_the_second_key_of_a_nickname_marks_its_session_wanted() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.standing.insert(Standing::Meshed);
        state.local_udp_transport = UdpTransport::Present;
        let (first, second) = (test_key("bob#first"), test_key("bob#second"));
        let (first_endpoint, second_endpoint) = (endpoint_id(1), endpoint_id(2));
        for key in [first, second] {
            state.names.insert(key, nick("bob"));
            state.peers.insert(key);
        }
        let lane = |id: EndpointId| {
            iroh::EndpointAddr::new(id)
                .with_relay_url("https://relay.invalid".parse().expect("relay url"))
        };
        state.bind_peer_endpoint(first, nick("bob"), lane(first_endpoint));
        state.retain_refused_endpoint(second, lane(second_endpoint));
        state.direct.insert(second_endpoint, DirectState::RelayOnly);

        let error = resolve(
            &directed_msg_to(second),
            directed_msg_to(second).serialize().expect("serialize"),
            &state,
        )
        .expect_err("a lookup-only relay holds the frame");
        note_held(&mut state, &error);

        assert!(
            state.lane_session_wanted(second_endpoint, clock::Instant::now()),
            "the held frame of the second key did not ask for its session"
        );
    }

    /// A peer with an IP path is held too on a lookup-only relay once a probe reads its path as
    /// the relay, but its direct path comes from the probe, so no session is wanted for it.
    #[test]
    fn a_frame_held_for_a_peer_with_an_ip_path_does_not_want_a_session() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_bob();
        state.direct.insert(bob, DirectState::RelayOnly);
        state.names.insert(test_key("bob"), nick("bob"));
        state.bind_peer_endpoint(
            test_key("bob"),
            nick("bob"),
            iroh::EndpointAddr::new(bob).with_ip_addr("127.0.0.1:4000".parse().expect("addr")),
        );
        state.local_udp_transport = UdpTransport::Present;

        let error = resolve(
            &directed_msg(),
            directed_msg().serialize().expect("serialize"),
            &state,
        )
        .expect_err("a lookup-only relay holds the frame");
        note_held(&mut state, &error);

        assert!(
            !state.lane_session_wanted(bob, clock::Instant::now()),
            "a held frame for a peer on an ip path wants no session"
        );
    }

    /// A pair that had a direct path and lost it reads as the relay. Its parked frame asks for a
    /// session even though the pair has an IP address: a failed offer leaves the pair on the
    /// relay with nobody to offer again, and the next parked frame renews the want.
    #[test]
    fn a_frame_held_for_a_pair_that_reads_as_relay_wants_a_session() {
        use crate::daemon::state::DirectState;
        use crate::transport::probe::PathKind;

        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_bob();
        state.names.insert(test_key("bob"), nick("bob"));
        state.bind_peer_endpoint(
            test_key("bob"),
            nick("bob"),
            iroh::EndpointAddr::new(bob).with_ip_addr("127.0.0.1:4000".parse().expect("addr")),
        );
        state.local_udp_transport = UdpTransport::Present;
        state.direct.insert(bob, DirectState::RelayOnly);
        state.path_kinds.insert(bob, PathKind::Relay);

        let error = resolve(
            &directed_msg(),
            directed_msg().serialize().expect("serialize"),
            &state,
        )
        .expect_err("a lookup-only relay holds the frame");
        note_held(&mut state, &error);

        assert!(
            state.lane_session_wanted(bob, clock::Instant::now()),
            "a held frame for a relay pair wants a session"
        );
    }

    /// On a mesh whose relay carries payload, the cold send to a lane peer is not held: it goes
    /// over the relay, and the climb opens the session later.
    #[test]
    fn on_a_payload_relay_the_cold_send_to_a_lane_peer_is_not_held() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_a_lane_bob();
        state.relay_transport = PayloadPath::RelayAllowed;

        assert_eq!(
            route(&directed_msg(), &state),
            Route::Unicast(bob),
            "a cold send to a lane peer is routed unicast, not held"
        );
    }

    // ── the p2p path ──────────────────────────────────────────────────

    /// **The receive path must not dial.**
    ///
    /// The daemon is one `select!`, so an inline dial from a receive arm stalls
    /// every other arm with it — timers, IPC, and every other peer's traffic.
    /// The auto-pong replies to whoever pinged us, so a peer that advertises an
    /// address nothing answers on buys a full dial timeout of daemon silence,
    /// once per identity it cares to mint.
    #[test]
    fn a_courtesy_reply_to_a_cold_peer_does_not_dial() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (state, bob) = state_knowing_bob();
            let sent = super::send_best_effort(
                bob,
                directed_msg().serialize().expect("serialize"),
                &state,
            )
            .await;

            assert!(!sent, "there is no warm path to this peer");
            assert_eq!(
                state.unicast_pool.dial_attempts(),
                0,
                "the receive path entered the inline-dial path; on a live peer that \
                 is a full dial timeout with the whole event loop waiting on it"
            );
        });
    }

    /// **A linked neighbor is still answered, off the loop.**
    ///
    /// A gossip link can come up with neither side holding a unicast
    /// connection, so a warm-only reply left a peer linked only by gossip
    /// unanswerable. The link proves its address, so it gets a dial — spawned,
    /// never awaited by the receive path.
    #[test]
    fn a_courtesy_reply_to_a_cold_linked_neighbor_dials_off_the_loop() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (mut state, bob) = state_knowing_bob();
            state.linked_endpoints.insert(bob);
            let sent = super::send_best_effort(
                bob,
                directed_msg().serialize().expect("serialize"),
                &state,
            )
            .await;

            assert!(sent, "a linked neighbor is answered even with a cold pool");
            assert_eq!(
                state.unicast_pool.dial_attempts(),
                0,
                "the receive path entered the inline-dial path itself"
            );
            task::yield_now().await;
            assert_eq!(
                state.unicast_pool.dial_attempts(),
                1,
                "the dial runs in the background"
            );
        });
    }

    /// A loopback endpoint with no relay, and a gossip sender on a peerless
    /// topic: the real pieces a directed send needs, and nothing reachable.
    async fn loopback_node() -> (iroh::Endpoint, transport::MeshSender) {
        let alpns = vec![transport::UNICAST_ALPN.to_vec()];
        let endpoint: iroh::Endpoint = iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(alpns)
            .bind()
            .await
            .expect("bind a loopback endpoint");
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        (endpoint, transport::MeshSender::new(gossip_sender))
    }

    /// A state that knows `bob` at `bob_addr`, with a proven direct path and a
    /// pool wired to `endpoint`.
    fn state_with_pool(endpoint: &iroh::Endpoint, bob_addr: iroh::EndpointAddr) -> EventLoopState {
        let mut state = fresh_state();
        state.standing.insert(Standing::Meshed);
        state.unicast_pool = transport::UnicastPool::new(endpoint.clone(), false);
        state.direct.insert(bob_addr.id, DirectState::Direct);
        lookup::add_peer_addr(&lookup::address_book(endpoint), bob_addr.clone());
        state.names.insert(test_key("bob"), nick("bob"));
        state.bind_peer_endpoint(test_key("bob"), nick("bob"), bob_addr);
        state
    }

    /// A pool on a real endpoint that knows `bob` at a UDP socket that never
    /// answers, so a dial to him stays in flight for the full dial budget.
    async fn state_with_silent_bob() -> (
        EventLoopState,
        iroh::Endpoint,
        transport::MeshSender,
        std_UdpSocket,
    ) {
        let (endpoint, sender) = loopback_node().await;
        let silent = UdpSocket::bind("127.0.0.1:0").expect("bind a silent socket");
        let bob = iroh::SecretKey::generate().public();
        let bob_addr = iroh::EndpointAddr::from_parts(
            bob,
            [iroh::TransportAddr::Ip(
                silent.local_addr().expect("silent addr"),
            )],
        );
        let state = state_with_pool(&endpoint, bob_addr);
        (state, endpoint, sender, silent)
    }

    /// **A background send to a cold peer returns at once.**
    ///
    /// An app hook on the tick runs inside the event loop's `select!`, so a
    /// send that dials inline stops the whole node for up to the dial budget
    /// plus the path-select budget. Bob's address never answers: the worst
    /// case, where a dial happens. He is not a linked neighbour, because a
    /// directed-message peer is often outside the active view.
    #[test]
    fn a_background_send_to_a_cold_peer_returns_at_once() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (state, endpoint, sender, _silent) = state_with_silent_bob().await;
            let message = directed_msg();
            let bytes = message.serialize().expect("serialize");

            let started = std_Instant::now();
            let sent = super::deliver_in_background(&message, bytes, &state, &sender).await;
            let elapsed = started.elapsed();

            assert!(
                elapsed < std_Duration::from_millis(500),
                "the send held its caller for {elapsed:?}; on the event loop that is the whole node"
            );
            assert!(sent, "a known peer gets a background dial");
            assert_eq!(
                state.unicast_pool.dial_attempts(),
                0,
                "the caller entered the inline-dial path itself"
            );
            task::yield_now().await;
            assert_eq!(
                state.unicast_pool.dial_attempts(),
                1,
                "the dial runs in the background"
            );
            endpoint.close().await;
        });
    }

    /// A peer on the dial-failure cooldown gets no dial, so nothing was
    /// started and the caller must not count the send.
    #[test]
    fn a_background_send_to_a_peer_on_dial_cooldown_is_not_sent() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (state, bob) = state_knowing_bob();
            state.unicast_pool.note_dial_failure(bob).await;
            let (endpoint, sender) = loopback_node().await;
            let message = directed_msg();
            let bytes = message.serialize().expect("serialize");

            let sent = super::deliver_in_background(&message, bytes, &state, &sender).await;

            assert!(
                !sent,
                "the cooldown refuses the dial, so nothing was started"
            );
            task::yield_now().await;
            assert_eq!(
                state.unicast_pool.dial_attempts(),
                0,
                "a background send on dial cooldown makes no dial"
            );
            endpoint.close().await;
        });
    }

    /// Two cold sends to one peer share one dial: each dial is a handshake
    /// and a connection, and the pool keeps only the last one. The second
    /// send comes after a yield, while the first dial is really in flight.
    #[test]
    fn two_background_sends_to_one_cold_peer_share_one_dial() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (state, endpoint, sender, _silent) = state_with_silent_bob().await;
            let message = directed_msg();
            let bytes = message.serialize().expect("serialize");

            let first =
                super::deliver_in_background(&message, bytes.clone(), &state, &sender).await;
            task::yield_now().await;
            let second = super::deliver_in_background(&message, bytes, &state, &sender).await;
            task::yield_now().await;

            assert!(first, "the first send starts the dial");
            assert!(second, "the second send waits for the dial in flight");
            assert_eq!(
                state.unicast_pool.dial_attempts(),
                1,
                "two background sends to one cold peer make one dial"
            );
            endpoint.close().await;
        });
    }

    /// A courtesy reply and a background send to one cold linked neighbour
    /// share one dial, the same as two background sends do.
    #[test]
    fn a_courtesy_reply_shares_a_background_dial_in_flight() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (mut state, bob) = state_knowing_bob();
            state.linked_endpoints.insert(bob);
            let (endpoint, sender) = loopback_node().await;
            let message = directed_msg();
            let bytes = message.serialize().expect("serialize");

            let sent = super::deliver_in_background(&message, bytes.clone(), &state, &sender).await;
            let replied = super::send_best_effort(bob, bytes, &state).await;
            task::yield_now().await;

            assert!(sent, "the background send starts the dial");
            assert!(replied, "the reply waits for the dial in flight");
            assert_eq!(
                state.unicast_pool.dial_attempts(),
                1,
                "a courtesy reply shares the background dial in flight"
            );
            endpoint.close().await;
        });
    }

    /// No known endpoint: nothing to dial, and the caller learns that
    /// nothing went out.
    #[test]
    fn a_background_send_to_an_unknown_peer_is_not_sent() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let state = fresh_state();
            let (endpoint, sender) = loopback_node().await;
            let message = directed_msg();
            let bytes = message.serialize().expect("serialize");

            let sent = super::deliver_in_background(&message, bytes, &state, &sender).await;

            assert!(!sent, "bob has no known endpoint");
            task::yield_now().await;
            assert_eq!(
                state.unicast_pool.dial_attempts(),
                0,
                "a background send to an unknown peer makes no dial"
            );
            endpoint.close().await;
        });
    }

    /// A warm peer gets the frame, whole.
    #[test]
    fn a_background_send_to_a_warm_peer_delivers() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (endpoint, sender) = loopback_node().await;
            let state = state_with_pool(&endpoint, bob_endpoint.addr());
            let received = tokio::spawn(async move {
                let connection = bob_endpoint
                    .accept()
                    .await
                    .expect("an incoming connection")
                    .await
                    .expect("accept the connection");
                let mut stream = connection.accept_uni().await.expect("a uni stream");
                let bytes = stream.read_to_end(64 * 1024).await.expect("read the frame");
                (bytes, bob_endpoint, connection)
            });
            let connection = state
                .unicast_pool
                .warm_or_dial(endpoint_of_bob(&state))
                .await
                .expect("warm the pool");
            assert!(
                payload_path::wait_direct(&connection, std_Duration::from_secs(5)).await,
                "loopback selects a direct path"
            );
            let message = directed_msg();
            let bytes = message.serialize().expect("serialize");

            let sent = super::deliver_in_background(&message, bytes.clone(), &state, &sender).await;

            assert!(sent, "a warm peer is sent to");
            let (got, returned_endpoint, _conn) =
                tokio_time::timeout(std_Duration::from_secs(5), received)
                    .await
                    .expect("bob reads the frame in time")
                    .expect("reader task");
            assert_eq!(
                got,
                bytes.as_bytes().to_vec(),
                "a background send to a warm peer delivers the bytes"
            );
            assert_eq!(
                state.unicast_pool.dial_attempts(),
                0,
                "the warm send entered the dial path"
            );
            returned_endpoint.close().await;
            endpoint.close().await;
        });
    }

    /// A protocol handler that holds each unicast connection open and passes on every frame it
    /// reads.
    #[derive(Debug, Clone)]
    struct Collect(mpsc::UnboundedSender<Vec<u8>>);

    impl ProtocolHandler for Collect {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            while let Ok(mut stream) = connection.accept_uni().await {
                if let Ok(bytes) = stream.read_to_end(64 * 1024).await {
                    let _ = self.0.send(bytes);
                }
            }
            Ok(())
        }
    }

    /// A pool on an endpoint with no IP socket, and a server on the same local relay that
    /// collects the frames it reads: the only path between them is the relay, and it stays so.
    /// The router keeps the server up.
    async fn relay_only_pair() -> (
        transport::UnicastPool,
        iroh::Endpoint,
        EndpointId,
        mpsc::UnboundedReceiver<Vec<u8>>,
        Router,
        Server,
    ) {
        let (relay_url, relay) = test_relay::spawn_plain().await.expect("a local relay");
        let bind = || async {
            let builder = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::custom([relay_url.clone()]))
                .clear_ip_transports();
            builder.bind().await.expect("bind an endpoint on the relay")
        };
        let (frames, received) = mpsc::unbounded_channel();
        let server = bind().await;
        let router = Router::builder(server.clone())
            .accept(transport::UNICAST_ALPN, Collect(frames))
            .spawn();
        let client = bind().await;
        lookup::add_peer_addr(
            &lookup::address_book(&client),
            iroh::EndpointAddr::new(server.id()).with_relay_url(relay_url),
        );
        let pool = transport::UnicastPool::new(client.clone(), false);
        (pool, client, server.id(), received, router, relay)
    }

    /// **A send on a warm connection that reads relay waits one path budget, then fails.**
    ///
    /// A connection that is young reads relay until its direct path is selected, so the check of
    /// a warm send cannot tell a path that is forming from a path that never comes. The send
    /// waits for the path on a task of its own, like the send to a cold peer. A second send
    /// shares that wait. Here no direct path can come, so both sends end with the relay refusal
    /// within one budget, and the server reads no frame.
    #[test]
    fn a_send_on_a_relay_selected_warm_connection_waits_one_budget_then_fails() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (pool, client, server_id, mut received, router, _relay) =
                    relay_only_pair().await;
                let connection = pool
                    .probe_connection(server_id)
                    .await
                    .expect("pool the relay connection");
                assert!(
                    !payload_path::selected_is_direct(&connection),
                    "the premise: the selected path is the relay"
                );

                let frame = || WireFrame::fixture_raw(bytes::Bytes::from_static(b"hello"));
                let mut handles = Vec::new();
                for _ in 0..2 {
                    let delivered = deliver::send_unicast(server_id, frame(), &pool)
                        .await
                        .expect("a refused path is not an error before the wait ends");
                    let Delivered::Pending(handle) = delivered else {
                        panic!("the send waits for a path on a task of its own");
                    };
                    handles.push(handle);
                }
                assert!(pool.is_dialing(server_id), "the wait is registered");
                // The budget to select a path (5 s) and one second more, for both sends together.
                tokio_time::timeout(std_Duration::from_secs(6), async {
                    for handle in handles {
                        let ended = handle.await.expect("the task reports");
                        let error = ended.expect_err("no direct path comes");
                        assert!(
                            format!("{error:#}").contains(transport::RELAY_REFUSED),
                            "the refusal names the relay: {error:#}"
                        );
                    }
                })
                .await
                .expect("both sends end within one path budget");
                assert_eq!(pool.dial_attempts(), 1, "the two sends share one wait");
                assert!(received.try_recv().is_err(), "no frame went over the relay");

                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    /// **A send to a peer on the dial-failure cooldown fails with the cooldown text.**
    ///
    /// The refusal carries the context "unicast dial to X failed" and the cause below it. A caller
    /// that prints only the outer message reads no reason, so the text of the whole chain must
    /// hold the cooldown, also after `SendError::internal` wrapped the error. The text that a user
    /// reads, the `Messaging::Send` reply, is pinned by a test of its own in the loopback tests.
    #[test]
    fn a_send_to_a_peer_on_the_dial_failure_cooldown_fails_with_the_cooldown_text() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (pool, client, server_id, _received, router, _relay) = relay_only_pair().await;
                pool.note_dial_failure(server_id).await;

                let frame = WireFrame::fixture_raw(bytes::Bytes::from_static(b"hello"));
                let error = deliver::send_unicast(server_id, frame, &pool)
                    .await
                    .expect_err("the cooldown refuses the send at once");
                assert!(
                    format!("{error:#}").contains(transport::pool::COOLDOWN_REFUSED),
                    "the chain names the cooldown: {error:#}"
                );
                let error = SendError::internal(error);
                assert!(
                    format!("{error:#}").contains(transport::pool::COOLDOWN_REFUSED),
                    "a SendError keeps the cooldown text: {error:#}"
                );

                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    /// **A warm connection that reads relay is waited on, also on the dial-failure cooldown.**
    ///
    /// The cooldown guards a new dial. A warm connection needs none, and its path can still be
    /// forming, so the send waits on it and ends with the relay refusal, not the cooldown one.
    #[test]
    fn a_warm_connection_that_reads_relay_is_waited_on_also_on_the_dial_failure_cooldown() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (pool, client, server_id, _received, router, _relay) = relay_only_pair().await;
                pool.probe_connection(server_id)
                    .await
                    .expect("pool the relay connection");
                pool.note_dial_failure(server_id).await;

                let frame = WireFrame::fixture_raw(bytes::Bytes::from_static(b"hello"));
                let delivered = deliver::send_unicast(server_id, frame, &pool)
                    .await
                    .expect("a warm connection is not refused by the cooldown");
                let Delivered::Pending(handle) = delivered else {
                    panic!("the send waits for a path on a task of its own");
                };
                let waited = tokio_time::timeout(std_Duration::from_secs(6), handle)
                    .await
                    .expect("the send ends within one path budget");
                let ended = waited.expect("the task reports");
                let error = ended.expect_err("no direct path comes");
                assert!(
                    format!("{error:#}").contains(transport::RELAY_REFUSED),
                    "the refusal names the relay: {error:#}"
                );

                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    fn endpoint_of_bob(state: &EventLoopState) -> EndpointId {
        state
            .peer_endpoints
            .get(&nick("bob"))
            .expect("bob is known")
            .id
    }

    #[test]
    fn directed_message_with_known_endpoint_takes_unicast() {
        let _guard = ::habilis_network_test_tracing::init();
        let (state, bob) = state_knowing_bob();
        assert_eq!(
            route(&directed_msg(), &state),
            Route::Unicast(bob),
            "a directed message with a known endpoint takes unicast"
        );
    }

    #[test]
    fn directed_rpc_and_pong_also_take_unicast() {
        let _guard = ::habilis_network_test_tracing::init();
        let (state, bob) = state_knowing_bob();
        let request = Message::new_app(
            &mesh(),
            &nick("alice"),
            AppFrameParams::new(
                AppTag::try_new("app_req").expect("a valid app tag"),
                Some(test_key("bob")),
                Some(
                    CorrId::try_new("00000000-0000-0000-0000-0000000000aa")
                        .expect("a valid correlation id"),
                ),
                body(),
            ),
        )
        .sign(&Identity::generate());
        let pong = Message::new_pong(
            &mesh(),
            &nick("alice"),
            test_key("bob"),
            &MessageId::random(),
        )
        .sign(&Identity::generate());
        assert_eq!(
            route(&request, &state),
            Route::Unicast(bob),
            "a directed request takes unicast"
        );
        assert_eq!(
            route(&pong, &state),
            Route::Unicast(bob),
            "a directed pong takes unicast"
        );
    }

    /// A known peer we're not yet meshed with is still reached by a unicast
    /// connect — iroh's path selection uses the multihop transport when no direct
    /// path exists, so mesh membership doesn't gate the directed send.
    #[test]
    fn known_peer_while_unmeshed_still_takes_unicast() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_bob();
        state.standing.remove(&Standing::Meshed);
        assert_eq!(
            route(&directed_msg(), &state),
            Route::Unicast(bob),
            "a known peer takes unicast even while unmeshed"
        );
    }

    // ── addressee by key ──────────────────────────────────────────────

    /// The frame that these tests send to a key: a `Pong`, the simplest directed kind.
    fn directed_msg_to(key: AuthorKey) -> Verified {
        Message::new_pong(&mesh(), &nick("alice"), key, &MessageId::random())
            .sign(&Identity::generate())
    }

    /// Two live keys use one nickname. A frame names its recipient by key, so each key has its
    /// own route: the first to the dial hint that it owns, the second to the endpoint that it
    /// retained. The engine does not refuse either, and does not mix them up.
    #[test]
    fn a_directed_message_to_either_key_of_a_nickname_of_two_live_keys_takes_its_own_route() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.standing.insert(Standing::Meshed);
        let (first, second) = (test_key("bob#first"), test_key("bob#second"));
        let (first_endpoint, second_endpoint) = (endpoint_id(1), endpoint_id(2));
        for key in [first, second] {
            state.names.insert(key, nick("bob"));
            state.peers.insert(key);
        }
        state.names.insert(first, nick("bob"));
        state.bind_peer_endpoint(first, nick("bob"), iroh::EndpointAddr::new(first_endpoint));
        state.retain_refused_endpoint(second, iroh::EndpointAddr::new(second_endpoint));
        state.direct.insert(first_endpoint, DirectState::Direct);
        state.direct.insert(second_endpoint, DirectState::Direct);

        assert_eq!(
            route(&directed_msg_to(first), &state),
            Route::Unicast(first_endpoint),
            "the key that owns the hint follows the hint"
        );
        assert_eq!(
            route(&directed_msg_to(second), &state),
            Route::Unicast(second_endpoint),
            "the other key follows the endpoint that it retained"
        );
        assert_eq!(
            lane_for(&second, &state),
            Lane::Unicast,
            "the roster offers the lane of the retained endpoint to the second key"
        );
    }

    /// The proof of a key is a route when no hint is its own: the second key of a nickname has
    /// proved its endpoint, and kept no hint.
    #[test]
    fn a_key_with_no_hint_of_its_own_follows_the_endpoint_that_it_proved() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.standing.insert(Standing::Meshed);
        let (first, second) = (test_key("bob#first"), test_key("bob#second"));
        let proven = endpoint_id(3);
        for key in [first, second] {
            state.names.insert(key, nick("bob"));
            state.peers.insert(key);
        }
        state.names.insert(first, nick("bob"));
        state.bind_peer_endpoint(first, nick("bob"), iroh::EndpointAddr::new(endpoint_id(1)));
        state.note_proven_endpoint(second, proven, UnixSecs::from(1));
        state.direct.insert(proven, DirectState::Direct);

        assert_eq!(
            route(&directed_msg_to(second), &state),
            Route::Unicast(proven),
            "the key with no hint did not follow its proof"
        );
    }

    /// A quiet key that shares the nickname of a live key does not change the route of the live
    /// key, because the route is read from the key and not from the nickname.
    #[test]
    fn a_quiet_key_of_the_nickname_does_not_change_the_route_of_the_live_key() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_bob();
        let (live, quiet) = (test_key("bob#live"), test_key("bob#quiet"));
        for key in [live, quiet] {
            state.names.insert(key, nick("bob"));
        }
        state.peers.insert(live);
        state.quiet.insert(quiet);
        state.names.insert(live, nick("bob"));
        state.bind_peer_endpoint(live, nick("bob"), iroh::EndpointAddr::new(bob));

        assert_eq!(
            route(&directed_msg_to(live), &state),
            Route::Unicast(bob),
            "one live key and one quiet key is one member"
        );
    }

    /// The dial hint of a nickname belongs to one key. When that key is quiet and another key is
    /// live under the nickname, the live key does not follow the hint of the quiet one: its frame
    /// waits for an endpoint of its own. The quiet key keeps its hint, because it may return.
    #[test]
    fn a_key_does_not_follow_the_hint_of_another_key_of_its_nickname() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.standing.insert(Standing::Meshed);
        let dead = endpoint_id(1);
        let (owner, live) = (test_key("bob#owner"), test_key("bob#live"));
        for key in [owner, live] {
            state.names.insert(key, nick("bob"));
        }
        state.quiet.insert(owner);
        state.peers.insert(live);
        state.names.insert(owner, nick("bob"));
        state.bind_peer_endpoint(owner, nick("bob"), iroh::EndpointAddr::new(dead));
        state.direct.insert(dead, DirectState::Direct);

        assert_eq!(
            route(&directed_msg_to(live), &state),
            Route::Undeliverable,
            "the live key followed the hint of a quiet key to a dead endpoint"
        );
        assert_eq!(
            route(&directed_msg_to(owner), &state),
            Route::Unicast(dead),
            "a quiet peer that may return keeps its hint"
        );
    }

    /// A process that restarts keeps its endpoint and mints a new author key. Until the silence
    /// timeout the old key is still live, and its hint still names the endpoint. The new key has
    /// proved that endpoint with a newer stamp, so the endpoint is the new key's: a send to the old
    /// key must not reach the new process.
    #[test]
    fn a_send_to_the_old_key_of_a_restarted_process_does_not_reach_the_new_key() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.standing.insert(Standing::Meshed);
        let (old, new) = (test_key("bob#old"), test_key("bob#new"));
        let endpoint = endpoint_id(7);
        for key in [old, new] {
            state.names.insert(key, nick("bob"));
            state.peers.insert(key);
        }
        state.bind_peer_endpoint(old, nick("bob"), iroh::EndpointAddr::new(endpoint));
        state.note_proven_endpoint(old, endpoint, UnixSecs::from(1));
        state.note_proven_endpoint(new, endpoint, UnixSecs::from(2));
        state.retain_refused_endpoint(new, iroh::EndpointAddr::new(endpoint));
        state.direct.insert(endpoint, DirectState::Direct);

        assert_eq!(
            route(&directed_msg_to(old), &state),
            Route::Undeliverable,
            "the send to the old key reached the process of the new key"
        );
        assert_eq!(
            route(&directed_msg_to(new), &state),
            Route::Unicast(endpoint),
            "the new key lost its own endpoint"
        );
    }

    // ── the gossip plane (broadcasts only) ────────────────────────────

    #[test]
    fn broadcast_message_always_takes_gossip() {
        let _guard = ::habilis_network_test_tracing::init();
        let (state, _) = state_knowing_bob();
        // Even with a known peer, a non-directed kind is a broadcast.
        assert_eq!(
            route(&open_broadcast(), &state),
            Route::Broadcast,
            "a broadcast message takes the gossip route"
        );
    }

    // ── undeliverable ─────────────────────────────────────────────────

    #[test]
    fn directed_message_with_unknown_endpoint_is_undeliverable() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.standing.insert(Standing::Meshed); // meshed, but we hold no endpoint for bob
        assert_eq!(
            route(&directed_msg(), &state),
            Route::Undeliverable,
            "a directed message to an unknown endpoint is undeliverable"
        );
    }

    #[test]
    fn rendezvous_addressee_is_never_a_directed_target() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.standing.insert(Standing::Meshed);
        let rendezvous = endpoint_id(9);
        state.rendezvous_id = Some(rendezvous);
        // bob's advertised endpoint *is* the rendezvous pseudo-node.
        state.names.insert(test_key("bob"), nick("bob"));
        state.names.insert(test_key("bob"), nick("bob"));
        state.bind_peer_endpoint(
            test_key("bob"),
            nick("bob"),
            iroh::EndpointAddr::new(rendezvous),
        );
        assert_eq!(
            route(&directed_msg(), &state),
            Route::Undeliverable,
            "the rendezvous addressee is never a directed target"
        );
    }

    /// A reply goes back on the connection that an unicast frame came by, though no direct path is
    /// proven for that endpoint yet: the unicast acceptor admits a connection only on a selected
    /// path that is not the relay when the relay is lookup-only, so the arrival proves what a probe
    /// would. The exception is for the frame at hand: outside the handling of an unicast frame, and
    /// for any other endpoint, an unproven path is held as before.
    #[test]
    fn a_reply_may_go_back_on_an_admitted_direct_arrival_and_nothing_else_is_let_through() {
        use crate::daemon::state::DirectState;
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_bob();
        let carol = endpoint_id(2);
        state.relay_transport = PayloadPath::DirectOnly;
        state.direct.remove(&bob);
        assert!(
            !can_unicast(bob, &state),
            "the premise: no direct path is proven"
        );

        state.unicast_arrival = Some(bob);
        assert!(
            can_unicast(bob, &state),
            "the frame at hand came by unicast from bob"
        );
        assert!(
            !can_unicast(carol, &state),
            "the arrival of bob opens no path to another endpoint"
        );

        state.unicast_arrival = None;
        assert!(
            !can_unicast(bob, &state),
            "outside the handling of a unicast frame the path is held again"
        );
        state.direct.insert(bob, DirectState::Direct);
        assert!(can_unicast(bob, &state), "a proven direct path still goes");
    }

    /// With the relay lookup only, a directed frame is refused only for a pair that a probe proved
    /// relay-only. A pair that no probe has read, or whose probe is in flight, goes by unicast: the
    /// dial waits for a direct path, and the live path of the connection refuses the relay. The
    /// state lags the connection by a few milliseconds after a join, so it must not refuse alone.
    #[test]
    fn a_directed_frame_is_held_only_for_a_pair_that_a_probe_proved_relay_only() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_bob();
        state.direct.insert(bob, DirectState::RelayOnly);
        state.relay_transport = PayloadPath::RelayAllowed;
        assert_eq!(
            route(&directed_msg(), &state),
            Route::Unicast(bob),
            "a relay-only pair is sent to when the relay carries payload"
        );
        state.relay_transport = PayloadPath::DirectOnly;
        for (reading, expected) in [
            (None, Route::Unicast(bob)),
            (Some(DirectState::Pending), Route::Unicast(bob)),
            (Some(DirectState::RelayOnly), Route::Held(bob)),
            (Some(DirectState::Direct), Route::Unicast(bob)),
        ] {
            match reading {
                Some(proved) => {
                    state.direct.insert(bob, proved);
                }
                None => {
                    state.direct.remove(&bob);
                }
            }
            assert_eq!(
                route(&directed_msg(), &state),
                expected,
                "the route for the reading {reading:?}"
            );
        }
    }

    /// A send that is not held still asks for the lane session of an unproven peer that needs
    /// one: the send dials it and waits for a direct path, and a lane peer has none to wait for.
    /// A proven peer, and a mesh whose relay carries payload, ask for nothing.
    #[test]
    fn an_unproven_lane_peer_asks_for_its_session_at_the_send_and_a_proven_peer_does_not() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_a_lane_bob();
        state.relay_transport = PayloadPath::DirectOnly;
        let now = clock::Instant::now();

        state.direct.insert(bob, DirectState::Direct);
        assert!(
            !note_unproven(&mut state, &directed_msg()),
            "a proven peer is not unproven"
        );
        assert!(
            !state.lane_session_wanted(bob, now),
            "a proven peer asked for a session"
        );

        state.direct.remove(&bob);
        state.relay_transport = PayloadPath::RelayAllowed;
        assert!(
            !note_unproven(&mut state, &directed_msg()),
            "a mesh whose relay carries payload has no unproven peer"
        );
        assert!(
            !state.lane_session_wanted(bob, now),
            "a relay mesh asked for a session"
        );

        state.relay_transport = PayloadPath::DirectOnly;
        assert!(
            note_unproven(&mut state, &directed_msg()),
            "an unread peer on a lookup-only relay is unproven"
        );
        assert_eq!(
            route(&directed_msg(), &state),
            Route::Unicast(bob),
            "the unproven peer is sent to, not held"
        );
        assert!(
            state.lane_session_wanted(bob, now),
            "the unproven lane peer did not ask for its session"
        );
        assert!(
            !note_unproven(&mut state, &open_broadcast()),
            "a broadcast has no addressee to prove"
        );
    }

    /// **A peer with no path watcher is proven by its multihop route when a send needs it.**
    ///
    /// Only the lower id of a pair has a path watcher. The higher id got `Direct` back only from
    /// the sweep tick, so for up to one sweep its directed sends were held though the pair rode a
    /// multihop route. The proof of the addressee runs at the send now.
    #[test]
    fn a_directed_send_to_an_unwatched_peer_on_a_multihop_route_is_proven_and_not_held() {
        use crate::daemon::state::DirectState;
        use crate::transport::probe::{PathKind, prove_addressee};
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_bob();
        state.relay_transport = PayloadPath::DirectOnly;
        state.direct.insert(bob, DirectState::RelayOnly);
        state.path_kinds.insert(bob, PathKind::Multihop);
        let frame = directed_msg();
        assert_eq!(
            route(&frame, &state),
            Route::Held(bob),
            "the premise: before the proof the send is held"
        );

        assert_eq!(
            prove_addressee(&mut state, &frame),
            Some(bob),
            "the route proves the unwatched peer"
        );

        assert_eq!(
            state.direct.get(&bob),
            Some(&DirectState::Direct),
            "the proof marks the peer direct"
        );
        assert_eq!(
            route(&frame, &state),
            Route::Unicast(bob),
            "the proven pair takes unicast"
        );
    }

    /// **A peer with a path watcher is left to its watcher.** The watcher is the only writer of the
    /// proof of a watched peer, and it also revokes it.
    #[test]
    fn a_directed_send_to_a_watched_peer_on_a_multihop_route_stays_held_for_its_watcher() {
        use crate::daemon::state::DirectState;
        use crate::transport::probe::{PathKind, prove_addressee};
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_bob();
        state.relay_transport = PayloadPath::DirectOnly;
        state.direct.insert(bob, DirectState::RelayOnly);
        state.path_kinds.insert(bob, PathKind::Multihop);
        state.path_watchers.insert(bob, None);
        let frame = directed_msg();

        assert_eq!(
            prove_addressee(&mut state, &frame),
            None,
            "the route proves no watched peer"
        );

        assert_eq!(
            state.direct.get(&bob),
            Some(&DirectState::RelayOnly),
            "the watcher is the only writer of the proof"
        );
        assert_eq!(
            route(&frame, &state),
            Route::Held(bob),
            "a watched peer stays held until its watcher proves it"
        );
    }

    // ── the roster lane ───────────────────────────────────────────────

    #[test]
    fn lane_is_unicast_for_a_meshed_known_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let (state, _) = state_knowing_bob();
        assert_eq!(
            lane_for(&test_key("bob"), &state),
            Lane::Unicast,
            "a meshed known peer takes the unicast lane"
        );
    }

    #[test]
    fn lane_is_multihop_for_a_known_but_unmeshed_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, _) = state_knowing_bob();
        state.standing.remove(&Standing::Meshed);
        assert_eq!(
            lane_for(&test_key("bob"), &state),
            Lane::Multihop,
            "a known but unmeshed peer takes the multihop lane"
        );
    }

    /// When the relay is lookup only, a link whose only path is the relay
    /// carries no payload, and the roster says so. Elsewhere the same reading
    /// is just a relayed unicast.
    #[test]
    fn lane_is_relay_only_when_the_relay_is_lookup_only() {
        use crate::daemon::state::DirectState;
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_bob();
        state.direct.insert(bob, DirectState::RelayOnly);
        state.relay_transport = PayloadPath::RelayAllowed;
        assert_eq!(
            lane_for(&test_key("bob"), &state),
            Lane::Unicast,
            "a peer on a lookup-only relay starts on the unicast lane"
        );
        state.relay_transport = PayloadPath::DirectOnly;
        assert_eq!(
            lane_for(&test_key("bob"), &state),
            Lane::RelayOnly,
            "a lookup-only relay peer takes the relay-only lane"
        );
        state.direct.insert(bob, DirectState::Direct);
        assert_eq!(
            lane_for(&test_key("bob"), &state),
            Lane::Unicast,
            "a peer that proves a direct path returns to the unicast lane"
        );
    }

    #[test]
    fn lane_is_unreachable_for_an_unknown_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let (state, _) = state_knowing_bob();
        assert_eq!(
            lane_for(&test_key("carol"), &state),
            Lane::Unreachable,
            "an unknown peer is unreachable"
        );
    }

    // ── a frame of this node, to one key ──────────────────────────────

    /// A broadcast frame that this node signed.
    fn own_broadcast(state: &EventLoopState) -> Verified {
        Message::new_app(
            &mesh(),
            &nick("alice"),
            AppFrameParams::new(
                AppTag::try_new("app_msg").expect("a valid app tag"),
                None,
                None,
                body(),
            ),
        )
        .sign(&state.identity)
    }

    /// A frame that this node signed, directed to `key`.
    fn own_directed(state: &EventLoopState, key: AuthorKey) -> Verified {
        Message::new_pong(&mesh(), &nick("alice"), key, &MessageId::random()).sign(&state.identity)
    }

    fn resolved_to(
        to: &AuthorKey,
        message: &Verified,
        state: &EventLoopState,
    ) -> Result<(EndpointId, WireFrame), SendError> {
        deliver::resolve_to(to, message, state)
    }

    #[test]
    fn an_own_broadcast_frame_sent_to_one_key_takes_unicast_never_gossip() {
        let _guard = ::habilis_network_test_tracing::init();
        let (state, bob) = state_knowing_bob();
        let message = own_broadcast(&state);

        let (eid, _) = resolved_to(&test_key("bob"), &message, &state).expect("a route to bob");

        assert_eq!(
            eid, bob,
            "an own broadcast frame goes to bob's endpoint, not to gossip"
        );
    }

    #[test]
    fn the_frame_that_goes_out_is_the_serialization_of_the_message_that_was_checked() {
        let _guard = ::habilis_network_test_tracing::init();
        let (state, _) = state_knowing_bob();
        let message = own_broadcast(&state);

        let (_, bytes) = resolved_to(&test_key("bob"), &message, &state).expect("a route to bob");

        assert_eq!(
            bytes.into_bytes(),
            message
                .serialize()
                .expect("a frame serializes")
                .into_bytes(),
            "the caller passes no bytes, so none can differ from the checked frame"
        );
    }

    #[test]
    fn a_frame_directed_to_the_key_takes_unicast() {
        let _guard = ::habilis_network_test_tracing::init();
        let (state, bob) = state_knowing_bob();
        let message = own_directed(&state, test_key("bob"));

        let (eid, _) = resolved_to(&test_key("bob"), &message, &state).expect("a route to bob");

        assert_eq!(eid, bob, "a frame directed to bob goes to bob's endpoint");
    }

    #[test]
    fn a_frame_that_another_key_signed_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let (state, _) = state_knowing_bob();

        let error = resolved_to(&test_key("bob"), &open_broadcast(), &state)
            .expect_err("a frame of another key");

        assert!(
            matches!(error, SendError::ForeignFrame),
            "a node is no unicast relay for a frame it did not sign: {error:?}"
        );
    }

    #[test]
    fn a_frame_directed_to_another_key_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let (state, _) = state_knowing_bob();
        let message = own_directed(&state, test_key("carol"));

        let error =
            resolved_to(&test_key("bob"), &message, &state).expect_err("a frame directed to carol");

        assert!(
            matches!(error, SendError::OtherAddressee),
            "its body is sealed to carol, and bob cannot open it: {error:?}"
        );
    }

    #[test]
    fn the_signer_is_checked_before_the_addressee() {
        let _guard = ::habilis_network_test_tracing::init();
        let (state, _) = state_knowing_bob();
        let message = directed_msg_to(test_key("carol"));

        let error =
            resolved_to(&test_key("bob"), &message, &state).expect_err("a foreign directed frame");

        assert!(
            matches!(error, SendError::ForeignFrame),
            "the check of the signer comes first: {error:?}"
        );
    }

    #[test]
    fn an_own_frame_to_a_key_without_an_endpoint_is_undeliverable() {
        let _guard = ::habilis_network_test_tracing::init();
        let (state, _) = state_knowing_bob();
        let message = own_broadcast(&state);

        let error =
            resolved_to(&test_key("carol"), &message, &state).expect_err("carol has no endpoint");

        assert!(
            matches!(&error, SendError::Undeliverable(text) if text.contains("no known endpoint")),
            "a key with no endpoint is undeliverable, never gossip: {error:?}"
        );
    }

    #[test]
    fn an_own_frame_to_a_relay_only_pair_is_held() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_bob();
        state.direct.insert(bob, DirectState::RelayOnly);
        let message = own_broadcast(&state);

        let error = resolved_to(&test_key("bob"), &message, &state).expect_err("a held pair");

        assert!(
            matches!(error, SendError::Held { eid } if eid == bob),
            "the directed rules hold the frame for a direct path: {error:?}"
        );
    }
}

#[cfg(test)]
mod chain_tests {

    use super::SendError;

    use std::io;
    use std::io::ErrorKind;
    #[test]
    fn an_internal_cause_keeps_its_chain() {
        let _guard = ::habilis_network_test_tracing::init();
        let io = io::Error::new(ErrorKind::AddrInUse, "Address already in use");
        let cause = anyhow::Error::new(io).context("bind the endpoint");
        let error = anyhow::Error::new(SendError::internal(cause));
        let text = format!("{error:#}");
        assert!(
            text.contains("Address already in use"),
            "the io cause of SendError is lost: {text}"
        );
    }
}

#[cfg(test)]
mod leave_tests {

    use super::SendError;
    use crate::daemon::event_loop::EventLoopError;

    use std::io;
    use std::io::ErrorKind;
    /// A leave that fails because the loop ended with an error keeps that error's text.
    #[test]
    fn a_leave_failure_keeps_the_event_loop_error() {
        let _guard = ::habilis_network_test_tracing::init();
        let io = io::Error::new(ErrorKind::AddrInUse, "Address already in use");
        let error = SendError::EventLoop(EventLoopError::Internal(Box::new(io)));
        let text = format!("{:#}", anyhow::Error::new(error));
        assert!(text.starts_with("the mesh event loop failed"), "{text}");
        assert_eq!(text.matches("Address already in use").count(), 1, "{text}");
    }
}
