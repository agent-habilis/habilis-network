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
pub(crate) use deliver::{
    can_unicast, lane_for, note_held, resolve, send_best_effort, unicast_answer_target,
    unicast_peers,
};
pub use deliver::{deliver, deliver_in_background};
#[cfg(test)]
use route::{Route, route};
mod lane;
pub use lane::Lane;
mod pending_send;
pub use pending_send::PendingSend;
mod send_error;
pub use send_error::{SendError, StateRefusal};
#[cfg(test)]
#[cfg(test)]
#[cfg(test)]
#[cfg(test)]
mod tests {
    use crate::daemon::state::Standing;
    use std::iter;
    use std::sync::Arc;

    use crate::testing::{endpoint_id, fresh_state, nick, test_key};
    use crate::transport::UdpTransport;

    use iroh::EndpointId;

    use super::{Lane, Route, can_unicast, lane_for, note_held, resolve, route};
    use crate::daemon::state::EventLoopState;
    use crate::protocol::messages::{AppFrameParams, Verified, WireFrame};
    use crate::protocol::{
        AppTag, AuthorKey, CorrId, Identity, MeshId, Message, MessageBody, MessageId, UnixSecs,
    };

    use crate::daemon::handler_ctx;
    use crate::daemon::state::DirectState;
    use crate::gossip::{antientropy, event};
    use crate::protocol::identity;
    use crate::transport::{PayloadPath, payload_path};
    use crate::util::{clock, tuning};
    use crate::{lookup, protocol, transport};
    use iroh::endpoint::presets;
    use iroh_gossip::net::Gossip;
    use iroh_gossip::proto;
    use std::net::{UdpSocket, UdpSocket as std_UdpSocket};
    use std::time::{Duration, Duration as std_Duration, Instant as std_Instant};
    use tokio::sync::oneshot;
    use tokio::{task, time, time as tokio_time};
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
    /// it is held, and holding it is what asks for its session.
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

    /// A peer with an IP path is held too on a lookup-only relay, but its direct path comes
    /// from the probe, so no session is wanted for it.
    #[test]
    fn a_frame_held_for_a_peer_with_an_ip_path_does_not_want_a_session() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_bob();
        state.direct.remove(&bob);
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

        state.state_digest_serves.unicast.arrived_from = Some(bob);
        assert!(
            can_unicast(bob, &state),
            "the frame at hand came by unicast from bob"
        );
        assert!(
            !can_unicast(carol, &state),
            "the arrival of bob opens no path to another endpoint"
        );

        state.state_digest_serves.unicast.arrived_from = None;
        assert!(
            !can_unicast(bob, &state),
            "outside the handling of a unicast frame the path is held again"
        );
        state.direct.insert(bob, DirectState::Direct);
        assert!(can_unicast(bob, &state), "a proven direct path still goes");
    }

    /// With the relay lookup only, a directed frame is parked until a direct
    /// path to the peer is proven — unprobed, pending and relay-only alike;
    /// once proven it takes unicast like any other.
    #[test]
    fn directed_frame_is_held_until_a_direct_path_is_proven_when_the_relay_is_lookup_only() {
        use crate::daemon::state::DirectState;
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, bob) = state_knowing_bob();
        state.direct.insert(bob, DirectState::RelayOnly);
        state.relay_transport = PayloadPath::RelayAllowed;
        assert_eq!(
            route(&directed_msg(), &state),
            Route::Unicast(bob),
            "a directed frame is held while the relay is lookup-only and no direct path is proven"
        );
        state.relay_transport = PayloadPath::DirectOnly;
        for unproven in [
            None,
            Some(DirectState::Pending),
            Some(DirectState::RelayOnly),
        ] {
            match unproven {
                Some(reading) => {
                    state.direct.insert(bob, reading);
                }
                None => {
                    state.direct.remove(&bob);
                }
            }
            assert_eq!(
                route(&directed_msg(), &state),
                Route::Held(bob),
                "{unproven:?}"
            );
        }
        state.direct.insert(bob, DirectState::Direct);
        assert_eq!(
            route(&directed_msg(), &state),
            Route::Unicast(bob),
            "the held directed frame is delivered once a direct path is proven"
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

    /// Linked with a usable path: the answer goes point-to-point. Every other
    /// case answers on gossip as before.
    #[test]
    fn a_digest_answer_goes_point_to_point_only_to_a_linked_neighbor() {
        let _guard = ::habilis_network_test_tracing::init();
        let bob = endpoint_id(1);
        let bob_key = "bb".repeat(32);
        let carol_key = "cc".repeat(32);
        let bob_signer = AuthorKey::decode_hex(&bob_key).expect("a key");
        let carol_signer = AuthorKey::decode_hex(&carol_key).expect("a key");
        let linked = || {
            let mut state = fresh_state();
            prove(&mut state, &bob_key, bob);
            state.direct.insert(bob, DirectState::Direct);
            state.linked_endpoints.insert(bob);
            state
        };

        assert_eq!(
            super::unicast_answer_target(&bob_signer, &linked()),
            Some(bob),
            "a digest answer goes to the linked neighbor only"
        );
        assert_eq!(
            super::unicast_answer_target(&carol_signer, &linked()),
            None,
            "no known endpoint"
        );
        let mut rendezvous = linked();
        rendezvous.rendezvous_id = Some(bob);
        assert_eq!(
            super::unicast_answer_target(&bob_signer, &rendezvous),
            None,
            "the rendezvous pseudo-node"
        );
        let mut held = linked();
        held.direct.remove(&bob);
        assert_eq!(
            super::unicast_answer_target(&bob_signer, &held),
            None,
            "no proven direct path on a lookup-only relay"
        );
        let mut unlinked = linked();
        unlinked.linked_endpoints.remove(&bob);
        assert_eq!(
            super::unicast_answer_target(&bob_signer, &unlinked),
            None,
            "known but not a gossip neighbor"
        );
    }

    /// Record, as a verified `PeerInfo` proof would, that the signing key
    /// `pubkey` (hex) owns `endpoint`.
    fn prove(state: &mut EventLoopState, pubkey: &str, endpoint: EndpointId) {
        let signer = AuthorKey::decode_hex(pubkey).expect("a 32-byte key");
        let linked = state.linked_endpoints.clone();
        state
            .proven_endpoints
            .insert(signer, endpoint, UnixSecs::from(1), &linked, |_| true);
    }

    /// [`prove`] for the key of `identity`.
    fn prove_identity(state: &mut EventLoopState, identity: &Identity, endpoint: EndpointId) {
        let pubkey = identity::encode_pubkey(&identity.public());
        prove(state, &pubkey, endpoint);
    }

    /// What a `HandlerCtx` borrows, kept apart from the state so a test can
    /// hold a context and a `&mut EventLoopState` at once. The state digest
    /// answer tests live here, not in `antientropy`, for the loopback helpers.
    struct Net {
        endpoint: iroh::Endpoint,
        sender: transport::MeshSender,
        mesh: MeshId,
        identity: Identity,
        our_pubkey: AuthorKey,
        author: protocol::Nickname,
        sink: event::SilentSink,
    }

    impl Net {
        fn context(&self) -> handler_ctx::HandlerCtx<'_> {
            handler_ctx::HandlerCtx {
                sender: &self.sender,
                endpoint: &self.endpoint,
                mesh: &self.mesh,
                author: &self.author,
                identity: &self.identity,
                our_pubkey: self.our_pubkey,
                max_peers: 16,
                rendezvous_id: endpoint_id(9),
                external_msg_tx: None,
                sink: &self.sink,
            }
        }
    }

    /// A holder of `changes` changes in each of the state and meta documents
    /// that knows `bob` at `bob_addr` with a proven direct path, and the wire
    /// bytes of each state change.
    async fn holder(
        bob_addr: iroh::EndpointAddr,
        changes: usize,
    ) -> (Net, EventLoopState, Vec<WireFrame>) {
        use crate::protocol::Channel;
        use Identity;

        let (endpoint, sender) = loopback_node().await;
        let mut state = state_with_pool(&endpoint, bob_addr);
        let mesh = MeshId::from("test");
        let seed = *state.identity.public().as_bytes();
        let mut write = |channel: Channel| -> Vec<WireFrame> {
            (0..changes)
                .map(|step| {
                    let change = state
                        .doc(channel)
                        .build_change(&serde_json::json!({ format!("k{step}"): step }), &seed);
                    let change = change
                        .expect("a JSON object merges")
                        .expect("a non-empty merge yields a change");
                    let (wire, _plain) = state
                        .doc(channel)
                        .compose_wire_body(&change, None)
                        .expect("compose the wire body");
                    let frame = Message::new_channel_event(&mesh, &nick("alice"), wire, channel)
                        .sign(&state.identity);
                    let _ = state.doc_mut(channel).ingest(&frame);
                    frame.serialize().expect("serialize")
                })
                .collect()
        };
        let frames = write(Channel::State);
        write(Channel::Meta);
        let identity = Identity::generate();
        let our_pubkey = identity.author_key();
        let net = Net {
            endpoint,
            sender,
            mesh,
            identity,
            our_pubkey,
            author: nick("alice"),
            sink: event::SilentSink,
        };
        (net, state, frames)
    }

    /// `bob`'s digest on `channel`, advertising `heads`, signed by `asker`.
    fn digest(
        mesh: &MeshId,
        channel: protocol::Channel,
        heads: &serde_json::Value,
        asker: &Identity,
    ) -> Verified {
        let body = MessageBody::try_new(&serde_json::json!({ "heads": heads }).to_string())
            .expect("a JSON body");
        Message::new_channel_digest(mesh, &nick("bob"), body, channel).sign(asker)
    }

    /// A state digest from a linked neighbor with a direct path is answered
    /// on the unicast plane, every frame, in order: on gossip every other
    /// member already holds these frames, so a hop drops them as seen.
    #[test]
    fn a_linked_neighbors_state_digest_is_answered_point_to_point_in_order() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, frames) = holder(bob_endpoint.addr(), 3).await;
            state.linked_endpoints.insert(bob_endpoint.id());
            let bob_id = bob_endpoint.id();
            let received = tokio::spawn(async move {
                let connection = bob_endpoint
                    .accept()
                    .await
                    .expect("an incoming connection")
                    .await
                    .expect("accept the connection");
                let mut got = Vec::new();
                for _ in 0..3 {
                    let mut stream = connection.accept_uni().await.expect("a uni stream");
                    got.push(stream.read_to_end(64 * 1024).await.expect("read the frame"));
                }
                (got, bob_endpoint, connection)
            });
            let asker = Identity::generate();
            prove_identity(&mut state, &asker, bob_id);
            let digest = digest(&net.mesh, Channel::State, &serde_json::json!([]), &asker);

            let answered = antientropy::handle_state_digest(
                Channel::State,
                &digest,
                &mut state,
                &net.context(),
            )
            .await;

            assert_eq!(answered.broadcast, 0, "nothing went on gossip");
            assert_eq!(
                answered.unicast, 3,
                "all three answers to the linked neighbor go point to point"
            );
            let (got, returned_endpoint, _conn) =
                tokio_time::timeout(std_Duration::from_secs(5), received)
                    .await
                    .expect("bob reads the answer in time")
                    .expect("reader task");
            let as_bytes = frames.iter().map(WireFrame::as_bytes);
            let expected: Vec<Vec<u8>> = as_bytes.map(<[u8]>::to_vec).collect();
            assert_eq!(got, expected, "every frame, in order");
            returned_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// The heads that close a point-to-point answer tell the receiver how far
    /// the holder is; they are not a request. Answering them sent the holder
    /// frames it had, and that answer closed with heads of its own: a loop
    /// that cost a serve at each turn. The receiver only asks back.
    #[test]
    fn the_heads_that_close_an_answer_draw_no_answer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::gossip::antientropy;
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
            state.linked_endpoints.insert(bob_endpoint.id());
            let bob = Identity::generate();
            prove_identity(&mut state, &bob, bob_endpoint.id());
            let body = MessageBody::try_new(
                &serde_json::json!({ "heads": ["heads-we-do-not-hold"], "closing": true })
                    .to_string(),
            )
            .expect("a JSON body");
            let closing =
                Message::new_channel_digest(&net.mesh, &nick("bob"), body, Channel::State)
                    .sign(&bob);

            let answered = antientropy::handle_state_digest(
                Channel::State,
                &closing,
                &mut state,
                &net.context(),
            )
            .await;
            assert_eq!(
                answered.unicast + answered.broadcast,
                0,
                "no frames for closing heads"
            );
            assert!(
                state.fast_rounds.asked_heads(Channel::State).is_some(),
                "bob is ahead, so we ask him back"
            );
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// The closing digest of a peer ends the first-sync wait only when it came point-to-point: on
    /// gossip it is the answer of no request of this node.
    #[test]
    fn a_closing_digest_ends_the_first_sync_wait_only_when_it_came_on_unicast() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::doc::MeshDoc;
            use crate::gossip::antientropy;
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
            state.state_doc = MeshDoc::new_state(None);
            let bob = Identity::generate();
            let body = MessageBody::try_new(
                &serde_json::json!({ "heads": [], "closing": true }).to_string(),
            )
            .expect("a JSON body");
            let closing =
                Message::new_channel_digest(&net.mesh, &nick("bob"), body, Channel::State)
                    .sign(&bob);

            antientropy::handle_state_digest(Channel::State, &closing, &mut state, &net.context())
                .await;
            assert!(
                state.doc(Channel::State).is_awaiting_first_sync(),
                "a closing digest on gossip is no answer to the request of this node"
            );
            state.state_digest_serves.unicast.arrived_from = Some(bob_endpoint.id());
            state.first_asked_at = Some(clock::Instant::now());
            antientropy::handle_state_digest(Channel::State, &closing, &mut state, &net.context())
                .await;
            assert!(
                !state.doc(Channel::State).is_awaiting_first_sync(),
                "on unicast, soon after this node asked, it is the answer"
            );
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// Any member can unicast a closing digest with no heads. It answers no request of this node,
    /// so it must not end the wait for the first sync: the node would write with a clock that has
    /// not heard of the writes before its restart.
    #[test]
    fn a_closing_digest_when_this_node_asked_nobody_does_not_end_the_wait() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::doc::MeshDoc;
            use crate::gossip::antientropy;
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
            state.state_doc = MeshDoc::new_state(None);
            let bob = Identity::generate();
            let body = MessageBody::try_new(
                &serde_json::json!({ "heads": [], "closing": true }).to_string(),
            )
            .expect("a JSON body");
            let closing =
                Message::new_channel_digest(&net.mesh, &nick("bob"), body, Channel::State)
                    .sign(&bob);
            state.state_digest_serves.unicast.arrived_from = Some(bob_endpoint.id());

            antientropy::handle_state_digest(Channel::State, &closing, &mut state, &net.context())
                .await;

            assert!(
                state.doc(Channel::State).is_awaiting_first_sync(),
                "this node asked nobody, so the closing digest is the answer of no request"
            );
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// A peer holds every change it signed, since a change's actor is its
    /// signer's key and a session key lives no longer than its document. So
    /// its own changes are never missing from it, even when it advertises
    /// heads we do not hold, where we cannot tell what it has.
    #[test]
    fn a_peer_is_not_sent_its_own_changes() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::gossip::antientropy;
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
            state.linked_endpoints.insert(bob_endpoint.id());
            let author = Arc::clone(&state.identity);
            prove_identity(&mut state, &author, bob_endpoint.id());
            let unknown = serde_json::json!(["heads-we-do-not-hold"]);
            let from_the_author = digest(&net.mesh, Channel::State, &unknown, &author);

            let answered = antientropy::handle_state_digest(
                Channel::State,
                &from_the_author,
                &mut state,
                &net.context(),
            )
            .await;
            assert_eq!(
                answered.unicast + answered.broadcast,
                0,
                "all 3 changes are its own"
            );
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// Unknown heads from anyone else still draw every change: we cannot tell
    /// what that peer lacks, so we over-serve rather than under-serve.
    #[test]
    fn a_third_peer_with_unknown_heads_gets_every_change() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::gossip::antientropy;
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
            state.linked_endpoints.insert(bob_endpoint.id());
            let third = Identity::generate();
            prove_identity(&mut state, &third, bob_endpoint.id());
            let unknown = serde_json::json!(["heads-we-do-not-hold"]);
            let request = digest(&net.mesh, Channel::State, &unknown, &third);

            // The plane does not matter here: our ask back to the peer is still
            // dialing, so the answer may take gossip.
            let answered = antientropy::handle_state_digest(
                Channel::State,
                &request,
                &mut state,
                &net.context(),
            )
            .await;
            assert_eq!(
                answered.unicast + answered.broadcast,
                3,
                "three answers reach the third peer"
            );
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// A nickname is a label any signer can put on a digest, so it must not
    /// pick the point-to-point target: a digest signed by a key that proved no
    /// endpoint is answered on gossip, even when a linked peer has that
    /// nickname. Otherwise any member could aim answers at a victim.
    #[test]
    fn a_digest_from_a_key_with_no_proven_endpoint_is_answered_on_gossip() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::gossip::antientropy::{Answered, handle_state_digest};
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
            state.linked_endpoints.insert(bob_endpoint.id());
            let stranger = Identity::generate();
            let posing_as_bob =
                digest(&net.mesh, Channel::State, &serde_json::json!([]), &stranger);

            let answered =
                handle_state_digest(Channel::State, &posing_as_bob, &mut state, &net.context())
                    .await;
            assert_eq!(
                answered,
                Answered {
                    unicast: 0,
                    broadcast: 3
                },
                "a digest from a key with no proven endpoint is answered on gossip"
            );
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// One serve per asker, channel and plane per window: a new node sends a
    /// digest pair for every peer it sees, all with the same heads, and every
    /// holder hears each one. The re-ask at the asker's first real-peer link
    /// switches it to the unicast plane, so it is still answered.
    #[test]
    fn a_state_digest_is_served_once_per_asker_channel_and_plane_per_window() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::gossip::antientropy::{Answered, handle_state_digest};
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
            let context = net.context();
            let asker = Identity::generate();
            prove_identity(&mut state, &asker, bob_endpoint.id());
            let empty = serde_json::json!([]);
            let state_digest = digest(&net.mesh, Channel::State, &empty, &asker);
            let meta_digest = digest(&net.mesh, Channel::Meta, &empty, &asker);
            let gossip = Answered {
                unicast: 0,
                broadcast: 3,
            };
            let refused = Answered::default();

            assert_eq!(
                handle_state_digest(Channel::State, &state_digest, &mut state, &context).await,
                gossip,
                "an unlinked asker is answered on gossip"
            );
            assert_eq!(
                handle_state_digest(Channel::State, &state_digest, &mut state, &context).await,
                refused,
                "a second gossip answer inside the window"
            );
            assert_eq!(
                handle_state_digest(Channel::Meta, &meta_digest, &mut state, &context).await,
                gossip,
                "the meta digest right after is its own serve"
            );

            state.linked_endpoints.insert(bob_endpoint.id());
            assert_eq!(
                handle_state_digest(Channel::State, &state_digest, &mut state, &context).await,
                Answered {
                    unicast: 3,
                    broadcast: 0
                },
                "the re-ask once linked goes on the other plane"
            );
            assert_eq!(
                handle_state_digest(Channel::State, &state_digest, &mut state, &context).await,
                refused,
                "a second unicast answer inside the window"
            );
            assert_eq!(state.idle.state_answers, 3, "the 3 answers that went out");
            assert_eq!(state.idle.state_frames_broadcast, 6, "2 answers on gossip");
            assert_eq!(
                state.idle.state_frames_unicast, 3,
                "1 answer to the linked asker"
            );
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// Two answers in flight at once each end with the holder's heads, and our
    /// heads move with every frame of either. Asking again on each of them
    /// ran two chains of asks, and each round cost the holder two of its
    /// serves, so a long backfill ran out of them. The holder is asked again
    /// at once only after a full answer landed since the last ask.
    #[test]
    fn a_partial_answer_does_not_ask_the_round_peer_again_at_once() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::gossip::antientropy;
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let bob_addr = bob_endpoint.addr();
            let (connected_tx, connected_rx) = oneshot::channel();
            let bob_task = tokio::spawn(async move {
                let connection = bob_endpoint
                    .accept()
                    .await
                    .expect("an incoming connection")
                    .await
                    .expect("accept the connection");
                let _ = connected_tx.send(());
                while let Ok(mut stream) = connection.accept_uni().await {
                    let _ = stream.read_to_end(1 << 20).await;
                }
                bob_endpoint.close().await;
            });
            let (net, mut state, _frames) = holder(bob_addr.clone(), 3).await;
            state.linked_endpoints.insert(bob_addr.id);
            let context = net.context();
            let bob = Identity::generate();
            prove_identity(&mut state, &bob, bob_addr.id);
            let ahead = digest(
                &net.mesh,
                Channel::State,
                &serde_json::json!(["ahead"]),
                &bob,
            );
            // Warm first: the second digest must come inside the 200 ms interval,
            // with no dial in between.
            assert!(
                state
                    .unicast_pool
                    .send_batch_in_background(bob_addr.id, Vec::new())
                    .await,
                "a partial answer does not ask the round peer again at once"
            );
            tokio_time::timeout(std_Duration::from_secs(5), connected_rx)
                .await
                .expect("the dial to bob completes")
                .expect("bob's task reports the connection");

            antientropy::handle_state_digest(Channel::State, &ahead, &mut state, &context).await;
            let first = state.fast_rounds.asked_heads(Channel::State);
            assert!(first.is_some(), "bob is ahead, so we ask him");
            assert_eq!(state.idle.fr_asks, 1, "the ask is counted");
            assert_eq!(state.idle.fr_retries, 0, "a digest, not the tick, made it");
            assert_eq!(
                state.fast_rounds.ahead_count(),
                1,
                "bob is remembered as ahead"
            );

            apply_one(&mut state, &net.mesh, 100);
            antientropy::handle_state_digest(Channel::State, &ahead, &mut state, &context).await;
            assert_eq!(
                state.fast_rounds.asked_heads(Channel::State),
                first,
                "one change landed since the ask: not a full answer, so no new ask"
            );

            for step in 101..101 + tuning::antientropy_max_resend() {
                apply_one(&mut state, &net.mesh, step);
            }
            antientropy::handle_state_digest(Channel::State, &ahead, &mut state, &context).await;
            assert_ne!(
                state.fast_rounds.asked_heads(Channel::State),
                first,
                "a full answer landed since the ask, so we ask again at once"
            );
            net.endpoint.close().await;
            tokio_time::timeout(std_Duration::from_secs(5), bob_task)
                .await
                .expect("bob sees the connection close")
                .expect("bob task");
        });
    }

    /// A serve is counted when the batch is handed to the pool, not when it is
    /// delivered, so a failed batch still costs one, but it does not strand
    /// the asker: the same digest after the repeat interval is answered
    /// again. Here the pool refuses the second send, because the dial failed
    /// (a cooldown) or is still in flight, so the second answer goes on
    /// gossip; the same-plane repeat is
    /// `budget_tests::the_serve_budget_takes_new_heads_up_to_its_count`.
    #[test]
    fn after_a_failed_batch_the_asker_is_answered_again_on_gossip() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::gossip::antientropy;
            use crate::protocol::Channel;

            // Linked and known by nickname, but with no address to dial: the
            // batch's dial fails at once.
            let unreachable = iroh::EndpointAddr::new(iroh::SecretKey::generate().public());
            let (net, mut state, _frames) = holder(unreachable.clone(), 3).await;
            state.linked_endpoints.insert(unreachable.id);
            let context = net.context();
            let asker = Identity::generate();
            prove_identity(&mut state, &asker, unreachable.id);
            let behind = digest(&net.mesh, Channel::State, &serde_json::json!([]), &asker);

            let first =
                antientropy::handle_state_digest(Channel::State, &behind, &mut state, &context)
                    .await;
            assert_eq!(
                first.unicast, 3,
                "handed to the pool as a point-to-point batch"
            );

            tokio_time::sleep(tuning::FAST_ROUND_MIN_INTERVAL + std_Duration::from_millis(50))
                .await;
            let again =
                antientropy::handle_state_digest(Channel::State, &behind, &mut state, &context)
                    .await;
            assert_eq!(
                again,
                antientropy::Answered {
                    unicast: 0,
                    broadcast: 3
                },
                "answered again, on gossip: the pool refuses the send, the dial failed or is in flight"
            );
            net.endpoint.close().await;
        });
    }

    /// Apply one local state change, as a frame from the network would land.
    fn apply_one(state: &mut EventLoopState, mesh: &MeshId, step: usize) {
        use crate::protocol::Channel;

        let seed = *state.identity.public().as_bytes();
        let doc = state.doc(Channel::State);
        let change = doc
            .build_change(&serde_json::json!({ format!("k{step}"): step }), &seed)
            .expect("a JSON object merges")
            .expect("a non-empty merge yields a change");
        let (wire, _plain) = state
            .doc(Channel::State)
            .compose_wire_body(&change, None)
            .expect("compose the wire body");
        let frame = Message::new_channel_event(mesh, &nick("alice"), wire, Channel::State)
            .sign(&state.identity);
        let _ = state.doc_mut(Channel::State).ingest(&frame);
    }

    /// A digest with nothing to answer must not use up the window: the
    /// asker's next digest, with a real gap, is still served. (The gate is
    /// checked before the missing-frames query, which this test cannot see.)
    #[test]
    fn a_digest_with_nothing_missing_does_not_use_the_serve() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::gossip::antientropy;
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
            let context = net.context();
            let asker = Identity::generate();
            let heads: Vec<_> = state.doc(Channel::State).heads().collect();
            let current = serde_json::to_value(heads).expect("heads");
            let up_to_date = digest(&net.mesh, Channel::State, &current, &asker);
            let behind = digest(&net.mesh, Channel::State, &serde_json::json!([]), &asker);

            let nothing =
                antientropy::handle_state_digest(Channel::State, &up_to_date, &mut state, &context)
                    .await;
            assert_eq!(nothing.broadcast + nothing.unicast, 0, "nothing is missing");
            let gap =
                antientropy::handle_state_digest(Channel::State, &behind, &mut state, &context)
                    .await;
            assert_eq!(gap.broadcast, 3, "the gap is served inside the window");
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// Each peer has its share of answer batches in flight, and a batch past it is refused, so the
    /// frames of a batch that a peer does not read are not piled up without a bound. The caller of
    /// a refusal answers on gossip. A finished batch frees its slot.
    #[test]
    fn a_peer_that_holds_its_share_of_batches_is_refused_the_next_one() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (endpoint, _sender) = loopback_node().await;
            let state = state_with_pool(&endpoint, bob_endpoint.addr());
            let bob = bob_endpoint.id();
            let held: Vec<_> = iter::from_fn(|| state.unicast_pool.take_batch_slot(bob)).collect();
            let frame = || {
                vec![
                    Message::new_digest(
                        &MeshId::from("test"),
                        &nick("alice"),
                        MessageBody::from("{}"),
                    )
                    .sign(&state.identity)
                    .serialize()
                    .expect("serialize"),
                ]
            };

            let refused = state
                .unicast_pool
                .send_batch_in_background(bob, frame())
                .await;

            assert!(!held.is_empty(), "the test filled the slots of the peer");
            assert!(
                !refused,
                "a peer with its share of batches in flight is refused"
            );
            drop(held);
            let sent = state
                .unicast_pool
                .send_batch_in_background(bob, frame())
                .await;
            assert!(sent, "a peer whose batches are done is sent the next one");
            bob_endpoint.close().await;
            endpoint.close().await;
        });
    }

    /// A node sends its state and meta digests back to back, so a holder
    /// answers the same warm peer twice at once. The in-flight guard exists
    /// for a cold peer's dial; a warm connection must take both batches.
    #[test]
    fn two_batches_to_a_warm_peer_both_go_out() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (endpoint, _sender) = loopback_node().await;
            let state = state_with_pool(&endpoint, bob_endpoint.addr());
            let received = tokio::spawn(async move {
                let connection = bob_endpoint
                    .accept()
                    .await
                    .expect("an incoming connection")
                    .await
                    .expect("accept the connection");
                let mut got = Vec::new();
                for _ in 0..4 {
                    let mut stream = connection.accept_uni().await.expect("a uni stream");
                    got.push(stream.read_to_end(64 * 1024).await.expect("read the frame"));
                }
                (got, bob_endpoint, connection)
            });
            let bob = endpoint_of_bob(&state);
            let connection = state
                .unicast_pool
                .warm_or_dial(bob)
                .await
                .expect("warm the pool");
            assert!(
                payload_path::wait_direct(&connection, std_Duration::from_secs(5)).await,
                "loopback selects a direct path"
            );
            // Two batches of signed frames, each frame with its own id, so the reader sees four distinct
            // frames in whatever order the batches land.
            let batch = || -> Vec<WireFrame> {
                let frames = (0..2).map(|_| directed_msg().serialize().expect("serialize"));
                frames.collect()
            };
            let state_batch = batch();
            let meta_batch = batch();

            let first = state
                .unicast_pool
                .send_batch_in_background(bob, state_batch.clone())
                .await;
            let second = state
                .unicast_pool
                .send_batch_in_background(bob, meta_batch.clone())
                .await;

            assert!(first, "the first batch starts");
            assert!(second, "the second batch to the same warm peer starts too");
            let (mut got, returned_endpoint, _conn) =
                tokio_time::timeout(std_Duration::from_secs(5), received)
                    .await
                    .expect("bob reads both batches in time")
                    .expect("reader task");
            got.sort();
            let batches = state_batch
                .iter()
                .chain(&meta_batch)
                .map(WireFrame::as_bytes);
            let mut expected: Vec<Vec<u8>> = batches.map(<[u8]>::to_vec).collect();
            expected.sort();
            assert_eq!(
                got, expected,
                "both batches to the warm peer are delivered in order"
            );
            returned_endpoint.close().await;
            endpoint.close().await;
        });
    }

    /// Bob's side of a loopback link: the next `count` frames he reads.
    fn read_frames(
        bob_endpoint: iroh::Endpoint,
        count: usize,
    ) -> task::JoinHandle<(Vec<Vec<u8>>, iroh::Endpoint)> {
        tokio::spawn(async move {
            let connection = bob_endpoint
                .accept()
                .await
                .expect("an incoming connection")
                .await
                .expect("accept the connection");
            let mut got = Vec::new();
            for _ in 0..count {
                let mut stream = connection.accept_uni().await.expect("a uni stream");
                got.push(stream.read_to_end(64 * 1024).await.expect("read the frame"));
            }
            (got, bob_endpoint)
        })
    }

    /// A state digest that came by unicast is answered to its connection, even when the asker is
    /// neither linked nor proven: the connection is the address. On gossip it would be a re-broadcast
    /// of every frame to the whole mesh.
    #[test]
    fn a_state_digest_that_came_by_unicast_is_answered_to_its_connection() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::gossip::antientropy::Answered;
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, frames) = holder(bob_endpoint.addr(), 3).await;
            state.state_digest_serves.unicast.arrived_from = Some(bob_endpoint.id());
            let received = read_frames(bob_endpoint, 4);
            let asker = Identity::generate();
            let digest = digest(&net.mesh, Channel::State, &serde_json::json!([]), &asker);

            let answered = antientropy::handle_state_digest(
                Channel::State,
                &digest,
                &mut state,
                &net.context(),
            )
            .await;

            assert_eq!(
                answered,
                Answered {
                    unicast: 3,
                    broadcast: 0
                },
                "the three frames go to the connection of the digest, none on gossip"
            );
            let (got, returned_endpoint) =
                tokio_time::timeout(std_Duration::from_secs(5), received)
                    .await
                    .expect("bob reads the answer in time")
                    .expect("reader task");
            let bytes_of = |frame: &WireFrame| frame.as_bytes().to_vec();
            let expected: Vec<Vec<u8>> = frames.iter().map(bytes_of).collect();
            assert_eq!(
                got[..3],
                expected[..],
                "the frames as they were signed, in order"
            );
            returned_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// A member mints author keys for free, so the unicast budget cannot be keyed by the author key:
    /// every fresh key would draw a full budget and a batch of its own. The connection that the
    /// digests come on is the asker. Twenty fresh keys on one connection draw the budget of that
    /// connection, not twenty budgets.
    #[test]
    fn many_fresh_keys_on_one_connection_draw_one_unicast_budget() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::gossip::antientropy::Answered;
            use crate::protocol::Channel;
            use crate::util::tuning::ANTIENTROPY_SERVES_PER_WINDOW;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
            state.state_digest_serves.unicast.arrived_from = Some(bob_endpoint.id());
            let context = net.context();

            let mut batches = 0;
            for _ in 0..20 {
                let fresh = Identity::generate();
                let digest = digest(&net.mesh, Channel::State, &serde_json::json!([]), &fresh);
                let answered =
                    antientropy::handle_state_digest(Channel::State, &digest, &mut state, &context)
                        .await;
                if answered != Answered::default() {
                    batches += 1;
                }
            }

            assert!(
                batches <= ANTIENTROPY_SERVES_PER_WINDOW,
                "20 fresh keys on one connection drew {batches} answers, more than the budget of {ANTIENTROPY_SERVES_PER_WINDOW}"
            );
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// The answers that fall back to gossip count against the connection too: a member that rotates author
    /// keys on one connection, while the unicast send cannot start, would otherwise draw a broadcast of
    /// every frame for each key, since each key has a gossip budget of its own.
    #[test]
    fn answers_that_fall_back_to_gossip_count_against_the_connection_budget() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::Channel;
            use crate::util::tuning::ANTIENTROPY_SERVES_PER_WINDOW;

            let silent = UdpSocket::bind("127.0.0.1:0").expect("bind a silent socket");
            let bob = iroh::SecretKey::generate().public();
            let silent_addr = iroh::EndpointAddr::from_parts(
                bob,
                [iroh::TransportAddr::Ip(
                    silent.local_addr().expect("silent addr"),
                )],
            );
            let (net, mut state, _frames) = holder(silent_addr, 3).await;
            state.state_digest_serves.unicast.arrived_from = Some(bob);

            let mut broadcasts = 0;
            for round in 0..20 {
                // Other heads each time: the same heads on one connection are answered once at a time.
                let heads = serde_json::json!([format!("{round:064x}")]);
                let fresh = Identity::generate();
                let digest = digest(&net.mesh, Channel::State, &heads, &fresh);
                let answered = antientropy::handle_state_digest(
                    Channel::State,
                    &digest,
                    &mut state,
                    &net.context(),
                )
                .await;
                if answered.broadcast > 0 {
                    broadcasts += 1;
                }
            }

            assert!(
                broadcasts <= ANTIENTROPY_SERVES_PER_WINDOW,
                "20 fresh keys on one connection drew {broadcasts} broadcasts, more than the budget of {ANTIENTROPY_SERVES_PER_WINDOW}"
            );
            net.endpoint.close().await;
        });
    }

    /// A state digest that came by unicast is answered to the connection it came on, also when the
    /// signer proved another endpoint earlier: a chat answer takes the same choice.
    #[test]
    fn a_state_digest_is_answered_to_its_connection_not_to_an_older_proven_endpoint() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::gossip::antientropy::Answered;
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
            let asker = Identity::generate();
            let older = endpoint_id(9);
            state.linked_endpoints.insert(older);
            state.direct.insert(older, DirectState::Direct);
            state.note_proven_endpoint(asker.author_key(), older, UnixSecs::from(1));
            state.state_digest_serves.unicast.arrived_from = Some(bob_endpoint.id());
            let received = read_frames(bob_endpoint, 4);
            let digest = digest(&net.mesh, Channel::State, &serde_json::json!([]), &asker);

            let answered = antientropy::handle_state_digest(
                Channel::State,
                &digest,
                &mut state,
                &net.context(),
            )
            .await;

            assert_eq!(
                answered,
                Answered {
                    unicast: 3,
                    broadcast: 0
                },
                "the frames go to the connection of the digest"
            );
            let (got, returned_endpoint) =
                tokio_time::timeout(std_Duration::from_secs(5), received)
                    .await
                    .expect("bob reads the answer in time")
                    .expect("reader task");
            assert!(got.len() >= 3, "bob holds the 3 frames");
            returned_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// A unicast digest that is ahead of us is asked back on its connection, though its signer has
    /// proved no endpoint yet: the ask-back does not wait for the next exchange.
    #[test]
    fn a_unicast_digest_that_is_ahead_is_asked_back_on_its_connection() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 1).await;
            state.state_digest_serves.unicast.arrived_from = Some(bob_endpoint.id());
            let asker = Identity::generate();
            let ahead = serde_json::json!(["ab".repeat(32)]);
            let digest = digest(&net.mesh, Channel::State, &ahead, &asker);

            let _ = antientropy::handle_state_digest(
                Channel::State,
                &digest,
                &mut state,
                &net.context(),
            )
            .await;

            assert_eq!(state.idle.fr_asks, 1, "one ask-back, on the connection");
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// The ask-back goes on the connection that the digest came on at once, though no direct path is
    /// proven for it yet (the arrival proves it), and its signer proved no endpoint. A send that
    /// comes later, outside the handling of the frame, waits for the proof of the path as before.
    /// (The retry of an ask-back that could not start, on the connection of the digest, is reached
    /// only when the send itself fails: a held path no longer stops the first ask-back.)
    #[test]
    fn the_ask_back_goes_on_the_connection_of_the_digest_at_once() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 1).await;
            let bob = bob_endpoint.id();
            let asker = Identity::generate();
            let ahead = serde_json::json!(["ab".repeat(32)]);
            let digest = digest(&net.mesh, Channel::State, &ahead, &asker);
            // The path of the connection is not proven when the digest arrives, but the digest came
            // by that connection: the ask-back starts on it.
            state.direct.remove(&bob);
            state.state_digest_serves.unicast.arrived_from = Some(bob);
            let _ = antientropy::handle_state_digest(
                Channel::State,
                &digest,
                &mut state,
                &net.context(),
            )
            .await;
            assert_eq!(
                state.idle.fr_asks, 1,
                "the ask-back goes on the connection of the digest at once"
            );

            // Outside the handling of the frame the path is held again: the retry, when the round
            // has been quiet for FAST_ROUND_RETRY, waits for the proof.
            state.state_digest_serves.unicast.arrived_from = None;
            tokio_time::sleep(std_Duration::from_millis(500)).await;
            antientropy::resume_fast_rounds(&mut state, &net.context()).await;
            assert_eq!(state.idle.fr_retries, 0, "no proof of the path, no retry");
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// The retry of an ask-back uses the connection that the digest came on, when its signer proved no
    /// endpoint yet: the first ask-back could not start (the send failed), and the retry must not
    /// wait for the proof of the signer. The old form of this test used a held path for the first
    /// failure; a held path no longer stops the ask-back on an admitted arrival, so the failure of
    /// the send is injected.
    #[test]
    fn the_retry_of_an_ask_back_that_could_not_start_uses_the_connection_of_the_digest() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            // A holder with nothing to answer: the first send to bob is the retry itself, and no dial of
            // an answer is in flight when it goes.
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 0).await;
            let bob = bob_endpoint.id();
            let asker = Identity::generate();
            let ahead = serde_json::json!(["ab".repeat(32)]);
            let digest = digest(&net.mesh, Channel::State, &ahead, &asker);
            // The first ask-back cannot start: the send fails.
            state.fail_the_next_ask();
            state.state_digest_serves.unicast.arrived_from = Some(bob);
            let _ = antientropy::handle_state_digest(
                Channel::State,
                &digest,
                &mut state,
                &net.context(),
            )
            .await;
            assert_eq!(state.idle.fr_asks, 0, "the first ask-back could not start");

            state.state_digest_serves.unicast.arrived_from = None;
            state.direct.insert(bob, DirectState::Direct);
            antientropy::resume_fast_rounds(&mut state, &net.context()).await;

            assert_eq!(
                state.idle.fr_retries, 1,
                "the retry goes on the connection of the digest"
            );
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// A digest that came by gossip is answered by a few members, as a chat digest is, when the
    /// unicast form is on. Here the k rule leaves this holder out: it sends nothing.
    #[test]
    fn a_state_digest_that_came_by_gossip_is_left_to_the_answerers_when_the_form_is_on() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::gossip::antientropy::Answered;
            use crate::protocol::Channel;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
            let members: Vec<_> = (0..30)
                .map(|index| test_key(&format!("member-{index}")))
                .collect();
            state.peers.extend(members.iter().copied());
            let asker = Identity::generate();
            // the key that the handler ranks: the one of its context
            let our_key = net.our_pubkey;
            let mut digests =
                (0..200).map(|_| digest(&net.mesh, Channel::State, &serde_json::json!([]), &asker));
            let leaves_holder_out = |digest: &Verified| {
                let exchange = antientropy::Exchange {
                    answerer: &our_key,
                    asker: &asker.author_key(),
                };
                !antientropy::answers_digest(exchange, digest.id.as_str(), members.iter())
            };
            let skipped = digests
                .find(leaves_holder_out)
                .expect("a digest id that skips the holder among 30 members");

            let answered = antientropy::handle_state_digest(
                Channel::State,
                &skipped,
                &mut state,
                &net.context(),
            )
            .await;

            assert_eq!(
                answered,
                Answered::default(),
                "the holder is not an answerer"
            );
            bob_endpoint_close(bob_endpoint).await;
            net.endpoint.close().await;
        });
    }

    async fn bob_endpoint_close(bob: iroh::Endpoint) {
        bob.close().await;
    }

    /// A node with a linked peer sends its three digests to that one peer, in one unicast batch, and
    /// broadcasts none.
    #[test]
    fn the_tick_sends_the_digests_to_one_linked_peer_and_broadcasts_none() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::MessageKind;

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 2).await;
            state.linked_endpoints.insert(bob_endpoint.id());
            state.standing.insert(Standing::Meshed);
            state.message_log.push(directed_msg());
            let received = read_frames(bob_endpoint, 3);

            antientropy::tick_digests(&mut state, &net.context()).await;

            let (got, returned_endpoint) =
                tokio_time::timeout(std_Duration::from_secs(5), received)
                    .await
                    .expect("bob reads the digests in time")
                    .expect("reader task");
            let mut kinds: Vec<String> = got
                .iter()
                .map(|bytes| {
                    Message::parse(bytes)
                        .expect("a digest parses")
                        .kind
                        .to_string()
                })
                .collect();
            kinds.sort();
            assert_eq!(
                kinds,
                [
                    MessageKind::Digest.to_string(),
                    MessageKind::MetaDigest.to_string(),
                    MessageKind::StateDigest.to_string()
                ],
                "the chat, state and meta digests"
            );
            assert_eq!(state.idle.broadcasts, 0, "none is broadcast");
            assert!(
                state.state_digest_serves.unicast.chat_ask.is_some(),
                "the chat ask is remembered for the retry"
            );
            returned_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// With no linked peer to ask, the tick broadcasts as before: a node that is linked only to the
    /// rendezvous would otherwise never ask.
    #[test]
    fn with_no_linked_peer_the_tick_broadcasts_the_digests() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 2).await;
            state.standing.insert(Standing::Meshed);
            state.message_log.push(directed_msg());

            antientropy::tick_digests(&mut state, &net.context()).await;

            assert!(state.idle.broadcasts >= 1, "the digests are broadcast");
            assert!(
                state.state_digest_serves.unicast.chat_ask.is_none(),
                "a digest that went by gossip leaves no pending chat ask"
            );
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// A chat ask whose answer was full (the log grew by the resend cap) is repeated to the same peer,
    /// and it is not repeated once its own cap is reached: the retry cannot loop.
    #[test]
    fn the_chat_retry_repeats_a_full_answer_and_stops_at_its_cap() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::gossip::antientropy::{ChatAsk, retry_chat_ask};

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 1).await;
            state.standing.insert(Standing::Meshed);
            state.message_log.push(directed_msg());
            let long_ago = clock::Instant::now()
                .checked_sub(std_Duration::from_secs(60))
                .expect("the clock is older than 60 s");
            let full_answer = ChatAsk {
                peer: bob_endpoint.id(),
                accepted: 0,
                at: long_ago,
                retries: 0,
            };
            // The log holds 1 message and the cap is 64: this answer was not full.
            state.state_digest_serves.unicast.chat_ask = Some(full_answer);
            retry_chat_ask(&mut state, &net.context()).await;
            assert!(
                state.state_digest_serves.unicast.chat_ask.is_none(),
                "a short answer ends the ask: nothing is left to ask again"
            );

            // A full answer at the cap ends the ask without a send.
            for _ in 0..tuning::antientropy_max_resend() {
                state.message_log.push(directed_msg());
            }
            state.state_digest_serves.unicast.chat_ask = Some(ChatAsk {
                retries: tuning::CHAT_RETRIES_MAX,
                ..full_answer
            });
            retry_chat_ask(&mut state, &net.context()).await;
            assert!(
                state.state_digest_serves.unicast.chat_ask.is_none(),
                "at the cap the retry stops"
            );

            // A full answer below the cap is asked again, once more counted.
            state.state_digest_serves.unicast.chat_ask = Some(full_answer);
            retry_chat_ask(&mut state, &net.context()).await;
            assert_eq!(
                state
                    .state_digest_serves
                    .unicast
                    .chat_ask
                    .map(|ask| ask.retries),
                Some(1),
                "a full answer is asked again"
            );
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// The progress of a chat answer is the count of the messages that the log took, not its length:
    /// a full log keeps its length while an answer replaces its entries.
    #[test]
    fn the_chat_retry_sees_an_answer_that_a_full_log_took_without_growing() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::daemon::message_log::MessageLog;
            use crate::gossip::antientropy::{ChatAsk, retry_chat_ask};

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _frames) = holder(bob_endpoint.addr(), 1).await;
            state.standing.insert(Standing::Meshed);
            state.message_log = MessageLog::new(2);
            state.message_log.push(directed_msg());
            state.message_log.push(directed_msg());
            let long_ago = clock::Instant::now()
                .checked_sub(std_Duration::from_secs(60))
                .expect("the clock is older than 60 s");
            state.state_digest_serves.unicast.chat_ask = Some(ChatAsk {
                peer: bob_endpoint.id(),
                accepted: state.message_log.accepted(),
                at: long_ago,
                retries: 0,
            });
            for _ in 0..tuning::antientropy_max_resend() {
                state.message_log.push(directed_msg());
            }
            assert_eq!(
                state.message_log.len(),
                2,
                "the log is full and did not grow"
            );

            retry_chat_ask(&mut state, &net.context()).await;

            assert_eq!(
                state
                    .state_digest_serves
                    .unicast
                    .chat_ask
                    .map(|ask| ask.retries),
                Some(1),
                "a full answer into a full log is asked again"
            );
            bob_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// A point-to-point answer ends with the holder's own heads, so the asker
    /// can tell whether it is still behind and ask again.
    #[test]
    fn a_point_to_point_answer_ends_with_the_holders_heads() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::{Channel, MessageKind};

            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, frames) = holder(bob_endpoint.addr(), 3).await;
            state.linked_endpoints.insert(bob_endpoint.id());
            let bob_id = bob_endpoint.id();
            let received = read_frames(bob_endpoint, 4);
            let asker = Identity::generate();
            prove_identity(&mut state, &asker, bob_id);
            let digest = digest(&net.mesh, Channel::State, &serde_json::json!([]), &asker);

            antientropy::handle_state_digest(Channel::State, &digest, &mut state, &net.context())
                .await;

            let (got, returned_endpoint) =
                tokio_time::timeout(std_Duration::from_secs(5), received)
                    .await
                    .expect("bob reads the answer in time")
                    .expect("reader task");
            let as_bytes = frames.iter().map(WireFrame::as_bytes);
            let expected: Vec<Vec<u8>> = as_bytes.map(<[u8]>::to_vec).collect();
            assert_eq!(got[..3], expected[..], "the three frames first, in order");
            let last = Message::parse(&got[3]).expect("the last frame parses");
            assert_eq!(last.kind, MessageKind::StateDigest, "then a state digest");
            let closing_heads: Vec<_> = state.doc(Channel::State).heads().collect();
            assert_eq!(
                last.body.as_str(),
                format!(
                    r#"{{"heads":{},"closing":true}}"#,
                    serde_json::json!(closing_heads)
                ),
                "carrying the holder's heads"
            );
            returned_endpoint.close().await;
            net.endpoint.close().await;
        });
    }

    /// A linked neighbor's digest with heads we do not hold makes us ask that
    /// neighbor directly; heads we hold, or a sender that is not linked, do
    /// not.
    #[test]
    fn a_digest_from_a_neighbor_that_is_ahead_is_asked_back_directly() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::{Channel, MessageKind};

            let (other_endpoint, _other_sender) = loopback_node().await;
            let (other_net, ahead, _frames) = holder(other_endpoint.addr(), 3).await;
            let ahead_list: Vec<_> = ahead.doc(Channel::State).heads().collect();
            let ahead_heads = serde_json::json!(ahead_list);
            let (bob_endpoint, _bob_sender) = loopback_node().await;
            let (net, mut state, _none) = holder(bob_endpoint.addr(), 0).await;
            let bob = Identity::generate();
            prove_identity(&mut state, &bob, bob_endpoint.id());
            let now = clock::Instant::now();

            let own_list: Vec<_> = state.doc(Channel::State).heads().collect();
            let own = serde_json::json!(own_list);
            let up_to_date = digest(&net.mesh, Channel::State, &own, &bob);
            antientropy::handle_state_digest(
                Channel::State,
                &up_to_date,
                &mut state,
                &net.context(),
            )
            .await;
            assert!(
                !state.fast_rounds.active(Channel::State, now),
                "heads we hold"
            );

            let from_ahead = digest(&net.mesh, Channel::State, &ahead_heads, &bob);
            antientropy::handle_state_digest(
                Channel::State,
                &from_ahead,
                &mut state,
                &net.context(),
            )
            .await;
            assert!(
                !state.fast_rounds.active(Channel::State, now),
                "bob is not linked"
            );

            state.linked_endpoints.insert(bob_endpoint.id());
            let received = read_frames(bob_endpoint, 1);
            antientropy::handle_state_digest(
                Channel::State,
                &from_ahead,
                &mut state,
                &net.context(),
            )
            .await;
            assert!(state.fast_rounds.active(Channel::State, now), "asked bob");
            let (got, returned_endpoint) = time::timeout(Duration::from_secs(5), received)
                .await
                .expect("bob reads the ask in time")
                .expect("reader task");
            let ask = Message::parse(&got[0]).expect("the ask parses");
            assert_eq!(
                ask.kind,
                MessageKind::StateDigest,
                "the neighbor that is ahead is asked back directly"
            );
            assert_eq!(
                ask.body.as_str(),
                serde_json::json!({ "heads": own }).to_string(),
                "the ask carries the digest body the neighbor needs"
            );
            other_endpoint.close().await;
            returned_endpoint.close().await;
            other_net.endpoint.close().await;
            net.endpoint.close().await;
        });
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
