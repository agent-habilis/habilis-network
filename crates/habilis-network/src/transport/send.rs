//! The single send decision. Every outbound message funnels through
//! [`deliver`]: a broadcast (no sole addressee) rides gossip, structurally; a
//! directed message goes over the unicast connection only — warm pooled
//! connection first, a dial on a task of its own otherwise — and gossip never carries it. The
//! bytes are the same canonical wire `Message` on both planes, so the
//! receiver's path is identical either way.

mod delivered;
pub use delivered::Delivered;
mod deliver;
mod route;
pub use deliver::{deliver, deliver_in_background};
pub(crate) use deliver::{lane_for, note_held, resolve, send_best_effort, unicast_answer_target};
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
    use std::sync::Arc;

    use crate::testing::{endpoint_id, fresh_state, nick};
    use crate::transport::UdpTransport;
    use habilis_network_test_tracing::test;

    use iroh::EndpointId;

    use super::{Lane, Route, lane_for, note_held, resolve, route};
    use crate::daemon::state::EventLoopState;
    use crate::protocol::message::{AppFrameParams, Verified, WireFrame};
    use crate::protocol::{AppTag, CorrId, Identity, MeshId, Message, MessageBody, MessageId};

    use crate::daemon::handler_ctx;
    use crate::daemon::state::DirectState;
    use crate::gossip::{antientropy, event};
    use crate::protocol::identity;
    use crate::transport::payload_path;
    use crate::util::{clock, tuning};
    use iroh::endpoint::presets;
    use tokio::sync::oneshot;
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
        state.meshed = true;
        let bob = endpoint_id(1);
        state
            .peer_endpoints
            .insert(nick("bob"), iroh::EndpointAddr::new(bob));
        state.direct.insert(bob, DirectState::Direct);
        (state, bob)
    }

    /// A directed frame addressed to `bob` — a `Pong` is the simplest one.
    fn directed_msg() -> Verified {
        Message::new_pong(&mesh(), &nick("alice"), nick("bob"), &MessageId::random())
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
        state.meshed = true;
        state.local_udp_transport = UdpTransport::Present;
        let bob = endpoint_id(1);
        state.peer_endpoints.insert(
            nick("bob"),
            iroh::EndpointAddr::new(bob)
                .with_relay_url("https://relay.invalid".parse().expect("relay url")),
        );
        (state, bob)
    }

    /// A cold send to a lane peer with no session holds the frame and marks the session wanted.
    #[test]
    fn a_frame_held_for_a_lane_peer_marks_its_session_wanted() {
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

    /// A peer with an IP path is held too on a lookup-only relay, but its direct path comes
    /// from the probe, so no session is wanted for it.
    #[test]
    fn a_frame_held_for_a_peer_with_an_ip_path_does_not_want_a_session() {
        let (mut state, bob) = state_knowing_bob();
        state.direct.remove(&bob);
        state.peer_endpoints.insert(
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

        let (mut state, bob) = state_knowing_bob();
        state.peer_endpoints.insert(
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
        let (mut state, bob) = state_knowing_a_lane_bob();
        state.relay_transport = crate::transport::PayloadPath::RelayAllowed;

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
    async fn a_courtesy_reply_to_a_cold_peer_does_not_dial() {
        let (state, bob) = state_knowing_bob();
        let sent =
            super::send_best_effort(bob, directed_msg().serialize().expect("serialize"), &state)
                .await;

        assert!(!sent, "there is no warm path to this peer");
        assert_eq!(
            state.unicast_pool.dial_attempts(),
            0,
            "the receive path entered the inline-dial path; on a live peer that \
             is a full dial timeout with the whole event loop waiting on it"
        );
    }

    /// **A linked neighbor is still answered, off the loop.**
    ///
    /// A gossip link can come up with neither side holding a unicast
    /// connection, so a warm-only reply left a peer linked only by gossip
    /// unanswerable. The link proves its address, so it gets a dial — spawned,
    /// never awaited by the receive path.
    #[test]
    async fn a_courtesy_reply_to_a_cold_linked_neighbor_dials_off_the_loop() {
        let (mut state, bob) = state_knowing_bob();
        state.linked_endpoints.insert(bob);
        let sent =
            super::send_best_effort(bob, directed_msg().serialize().expect("serialize"), &state)
                .await;

        assert!(sent, "a linked neighbor is answered even with a cold pool");
        assert_eq!(
            state.unicast_pool.dial_attempts(),
            0,
            "the receive path entered the inline-dial path itself"
        );
        tokio::task::yield_now().await;
        assert_eq!(
            state.unicast_pool.dial_attempts(),
            1,
            "the dial runs in the background"
        );
    }

    /// A loopback endpoint with no relay, and a gossip sender on a peerless
    /// topic: the real pieces a directed send needs, and nothing reachable.
    async fn loopback_node() -> (iroh::Endpoint, crate::transport::MeshSender) {
        let endpoint = iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(vec![crate::transport::UNICAST_ALPN.to_vec()])
            .bind()
            .await
            .expect("bind a loopback endpoint");
        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        (endpoint, crate::transport::MeshSender::new(gossip_sender))
    }

    /// A state that knows `bob` at `bob_addr`, with a proven direct path and a
    /// pool wired to `endpoint`.
    fn state_with_pool(endpoint: &iroh::Endpoint, bob_addr: iroh::EndpointAddr) -> EventLoopState {
        let mut state = fresh_state();
        state.meshed = true;
        state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
        state.direct.insert(bob_addr.id, DirectState::Direct);
        crate::lookup::add_peer_addr(&crate::lookup::address_book(endpoint), bob_addr.clone());
        state.peer_endpoints.insert(nick("bob"), bob_addr);
        state
    }

    /// A pool on a real endpoint that knows `bob` at a UDP socket that never
    /// answers, so a dial to him stays in flight for the full dial budget.
    async fn state_with_silent_bob() -> (
        EventLoopState,
        iroh::Endpoint,
        crate::transport::MeshSender,
        std::net::UdpSocket,
    ) {
        let (endpoint, sender) = loopback_node().await;
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a silent socket");
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
    async fn a_background_send_to_a_cold_peer_returns_at_once() {
        let (state, endpoint, sender, _silent) = state_with_silent_bob().await;
        let message = directed_msg();
        let bytes = message.serialize().expect("serialize");

        let started = std::time::Instant::now();
        let sent = super::deliver_in_background(&message, bytes, &state, &sender).await;
        let elapsed = started.elapsed();

        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "the send held its caller for {elapsed:?}; on the event loop that is the whole node"
        );
        assert!(sent, "a known peer gets a background dial");
        assert_eq!(
            state.unicast_pool.dial_attempts(),
            0,
            "the caller entered the inline-dial path itself"
        );
        tokio::task::yield_now().await;
        assert_eq!(
            state.unicast_pool.dial_attempts(),
            1,
            "the dial runs in the background"
        );
        endpoint.close().await;
    }

    /// A peer on the dial-failure cooldown gets no dial, so nothing was
    /// started and the caller must not count the send.
    #[test]
    async fn a_background_send_to_a_peer_on_dial_cooldown_is_not_sent() {
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
        tokio::task::yield_now().await;
        assert_eq!(
            state.unicast_pool.dial_attempts(),
            0,
            "a background send on dial cooldown makes no dial"
        );
        endpoint.close().await;
    }

    /// Two cold sends to one peer share one dial: each dial is a handshake
    /// and a connection, and the pool keeps only the last one. The second
    /// send comes after a yield, while the first dial is really in flight.
    #[test]
    async fn two_background_sends_to_one_cold_peer_share_one_dial() {
        let (state, endpoint, sender, _silent) = state_with_silent_bob().await;
        let message = directed_msg();
        let bytes = message.serialize().expect("serialize");

        let first = super::deliver_in_background(&message, bytes.clone(), &state, &sender).await;
        tokio::task::yield_now().await;
        let second = super::deliver_in_background(&message, bytes, &state, &sender).await;
        tokio::task::yield_now().await;

        assert!(first, "the first send starts the dial");
        assert!(second, "the second send waits for the dial in flight");
        assert_eq!(
            state.unicast_pool.dial_attempts(),
            1,
            "two background sends to one cold peer make one dial"
        );
        endpoint.close().await;
    }

    /// A courtesy reply and a background send to one cold linked neighbour
    /// share one dial, the same as two background sends do.
    #[test]
    async fn a_courtesy_reply_shares_a_background_dial_in_flight() {
        let (mut state, bob) = state_knowing_bob();
        state.linked_endpoints.insert(bob);
        let (endpoint, sender) = loopback_node().await;
        let message = directed_msg();
        let bytes = message.serialize().expect("serialize");

        let sent = super::deliver_in_background(&message, bytes.clone(), &state, &sender).await;
        let replied = super::send_best_effort(bob, bytes, &state).await;
        tokio::task::yield_now().await;

        assert!(sent, "the background send starts the dial");
        assert!(replied, "the reply waits for the dial in flight");
        assert_eq!(
            state.unicast_pool.dial_attempts(),
            1,
            "a courtesy reply shares the background dial in flight"
        );
        endpoint.close().await;
    }

    /// No known endpoint: nothing to dial, and the caller learns that
    /// nothing went out.
    #[test]
    async fn a_background_send_to_an_unknown_peer_is_not_sent() {
        let state = fresh_state();
        let (endpoint, sender) = loopback_node().await;
        let message = directed_msg();
        let bytes = message.serialize().expect("serialize");

        let sent = super::deliver_in_background(&message, bytes, &state, &sender).await;

        assert!(!sent, "bob has no known endpoint");
        tokio::task::yield_now().await;
        assert_eq!(
            state.unicast_pool.dial_attempts(),
            0,
            "a background send to an unknown peer makes no dial"
        );
        endpoint.close().await;
    }

    /// A warm peer gets the frame, whole.
    #[test]
    async fn a_background_send_to_a_warm_peer_delivers() {
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
            payload_path::wait_direct(&connection, std::time::Duration::from_secs(5)).await,
            "loopback selects a direct path"
        );
        let message = directed_msg();
        let bytes = message.serialize().expect("serialize");

        let sent = super::deliver_in_background(&message, bytes.clone(), &state, &sender).await;

        assert!(sent, "a warm peer is sent to");
        let (got, returned_endpoint, _conn) =
            tokio::time::timeout(std::time::Duration::from_secs(5), received)
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
        let (state, bob) = state_knowing_bob();
        assert_eq!(
            route(&directed_msg(), &state),
            Route::Unicast(bob),
            "a directed message with a known endpoint takes unicast"
        );
    }

    #[test]
    fn directed_rpc_and_pong_also_take_unicast() {
        let (state, bob) = state_knowing_bob();
        let request = Message::new_app(
            &mesh(),
            &nick("alice"),
            AppFrameParams::new(
                AppTag::try_new("app_req").expect("a valid app tag"),
                Some(nick("bob")),
                Some(
                    CorrId::try_new("00000000-0000-0000-0000-0000000000aa")
                        .expect("a valid correlation id"),
                ),
                body(),
            ),
        )
        .sign(&Identity::generate());
        let pong = Message::new_pong(&mesh(), &nick("alice"), nick("bob"), &MessageId::random())
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
        let (mut state, bob) = state_knowing_bob();
        state.meshed = false;
        assert_eq!(
            route(&directed_msg(), &state),
            Route::Unicast(bob),
            "a known peer takes unicast even while unmeshed"
        );
    }

    // ── the gossip plane (broadcasts only) ────────────────────────────

    #[test]
    fn broadcast_message_always_takes_gossip() {
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
        let mut state = fresh_state();
        state.meshed = true; // meshed, but we hold no endpoint for bob
        assert_eq!(
            route(&directed_msg(), &state),
            Route::Undeliverable,
            "a directed message to an unknown endpoint is undeliverable"
        );
    }

    #[test]
    fn rendezvous_addressee_is_never_a_directed_target() {
        let mut state = fresh_state();
        state.meshed = true;
        let rendezvous = endpoint_id(9);
        state.rendezvous_id = Some(rendezvous);
        // bob's advertised endpoint *is* the rendezvous pseudo-node.
        state
            .peer_endpoints
            .insert(nick("bob"), iroh::EndpointAddr::new(rendezvous));
        assert_eq!(
            route(&directed_msg(), &state),
            Route::Undeliverable,
            "the rendezvous addressee is never a directed target"
        );
    }

    /// With the relay lookup only, a directed frame is parked until a direct
    /// path to the peer is proven — unprobed, pending and relay-only alike;
    /// once proven it takes unicast like any other.
    #[test]
    fn directed_frame_is_held_until_a_direct_path_is_proven_when_the_relay_is_lookup_only() {
        use crate::daemon::state::DirectState;
        let (mut state, bob) = state_knowing_bob();
        state.direct.insert(bob, DirectState::RelayOnly);
        state.relay_transport = crate::transport::PayloadPath::RelayAllowed;
        assert_eq!(
            route(&directed_msg(), &state),
            Route::Unicast(bob),
            "a directed frame is held while the relay is lookup-only and no direct path is proven"
        );
        state.relay_transport = crate::transport::PayloadPath::DirectOnly;
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
        let (state, _) = state_knowing_bob();
        assert_eq!(
            lane_for(&nick("bob"), &state),
            Lane::Unicast,
            "a meshed known peer takes the unicast lane"
        );
    }

    #[test]
    fn lane_is_multihop_for_a_known_but_unmeshed_peer() {
        let (mut state, _) = state_knowing_bob();
        state.meshed = false;
        assert_eq!(
            lane_for(&nick("bob"), &state),
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
        let (mut state, bob) = state_knowing_bob();
        state.direct.insert(bob, DirectState::RelayOnly);
        state.relay_transport = crate::transport::PayloadPath::RelayAllowed;
        assert_eq!(
            lane_for(&nick("bob"), &state),
            Lane::Unicast,
            "a peer on a lookup-only relay starts on the unicast lane"
        );
        state.relay_transport = crate::transport::PayloadPath::DirectOnly;
        assert_eq!(
            lane_for(&nick("bob"), &state),
            Lane::RelayOnly,
            "a lookup-only relay peer takes the relay-only lane"
        );
        state.direct.insert(bob, DirectState::Direct);
        assert_eq!(
            lane_for(&nick("bob"), &state),
            Lane::Unicast,
            "a peer that proves a direct path returns to the unicast lane"
        );
    }

    #[test]
    fn lane_is_unreachable_for_an_unknown_peer() {
        let (state, _) = state_knowing_bob();
        assert_eq!(
            lane_for(&nick("carol"), &state),
            Lane::Unreachable,
            "an unknown peer is unreachable"
        );
    }

    /// Linked with a usable path: the answer goes point-to-point. Every other
    /// case answers on gossip as before.
    #[test]
    fn a_digest_answer_goes_point_to_point_only_to_a_linked_neighbor() {
        let bob = endpoint_id(1);
        let bob_key = "bb".repeat(32);
        let carol_key = "cc".repeat(32);
        let bob_signer = crate::protocol::AuthorKey::decode_hex(&bob_key).expect("a key");
        let carol_signer = crate::protocol::AuthorKey::decode_hex(&carol_key).expect("a key");
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
        let signer = crate::protocol::AuthorKey::decode_hex(pubkey).expect("a 32-byte key");
        let linked = state.linked_endpoints.clone();
        state.proven_endpoints.insert(signer, endpoint, &linked);
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
        sender: crate::transport::MeshSender,
        mesh: MeshId,
        identity: Identity,
        our_pubkey: crate::protocol::AuthorKey,
        author: crate::protocol::Nickname,
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
                        .build_change(&serde_json::json!({ format!("k{step}"): step }), &seed)
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
        channel: crate::protocol::Channel,
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
    async fn a_linked_neighbors_state_digest_is_answered_point_to_point_in_order() {
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

        let answered =
            antientropy::handle_state_digest(Channel::State, &digest, &mut state, &net.context())
                .await;

        assert_eq!(answered.broadcast, 0, "nothing went on gossip");
        assert_eq!(
            answered.unicast, 3,
            "all three answers to the linked neighbor go point to point"
        );
        let (got, returned_endpoint, _conn) =
            tokio::time::timeout(std::time::Duration::from_secs(5), received)
                .await
                .expect("bob reads the answer in time")
                .expect("reader task");
        let expected: Vec<Vec<u8>> = frames
            .iter()
            .map(|bytes| bytes.as_bytes().to_vec())
            .collect();
        assert_eq!(got, expected, "every frame, in order");
        returned_endpoint.close().await;
        net.endpoint.close().await;
    }

    /// The heads that close a point-to-point answer tell the receiver how far
    /// the holder is; they are not a request. Answering them sent the holder
    /// frames it had, and that answer closed with heads of its own: a loop
    /// that cost a serve at each turn. The receiver only asks back.
    #[test]
    async fn the_heads_that_close_an_answer_draw_no_answer() {
        use crate::gossip::antientropy;
        use crate::protocol::Channel;

        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
        state.linked_endpoints.insert(bob_endpoint.id());
        let bob = Identity::generate();
        prove_identity(&mut state, &bob, bob_endpoint.id());
        let body = MessageBody::try_new(
            &serde_json::json!({ "heads": ["heads-we-do-not-hold"], "closing": true }).to_string(),
        )
        .expect("a JSON body");
        let closing =
            Message::new_channel_digest(&net.mesh, &nick("bob"), body, Channel::State).sign(&bob);

        let answered =
            antientropy::handle_state_digest(Channel::State, &closing, &mut state, &net.context())
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
    }

    /// A peer holds every change it signed, since a change's actor is its
    /// signer's key and a session key lives no longer than its document. So
    /// its own changes are never missing from it, even when it advertises
    /// heads we do not hold, where we cannot tell what it has.
    #[test]
    async fn a_peer_is_not_sent_its_own_changes() {
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
    }

    /// Unknown heads from anyone else still draw every change: we cannot tell
    /// what that peer lacks, so we over-serve rather than under-serve.
    #[test]
    async fn a_third_peer_with_unknown_heads_gets_every_change() {
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
        let answered =
            antientropy::handle_state_digest(Channel::State, &request, &mut state, &net.context())
                .await;
        assert_eq!(
            answered.unicast + answered.broadcast,
            3,
            "three answers reach the third peer"
        );
        bob_endpoint.close().await;
        net.endpoint.close().await;
    }

    /// A nickname is a label any signer can put on a digest, so it must not
    /// pick the point-to-point target: a digest signed by a key that proved no
    /// endpoint is answered on gossip, even when a linked peer has that
    /// nickname. Otherwise any member could aim answers at a victim.
    #[test]
    async fn a_digest_from_a_key_with_no_proven_endpoint_is_answered_on_gossip() {
        use crate::gossip::antientropy::{Answered, handle_state_digest};
        use crate::protocol::Channel;

        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
        state.linked_endpoints.insert(bob_endpoint.id());
        let stranger = Identity::generate();
        let posing_as_bob = digest(&net.mesh, Channel::State, &serde_json::json!([]), &stranger);

        let answered =
            handle_state_digest(Channel::State, &posing_as_bob, &mut state, &net.context()).await;
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
    }

    /// One serve per asker, channel and plane per window: a new node sends a
    /// digest pair for every peer it sees, all with the same heads, and every
    /// holder hears each one. The re-ask at the asker's first real-peer link
    /// switches it to the unicast plane, so it is still answered.
    #[test]
    async fn a_state_digest_is_served_once_per_asker_channel_and_plane_per_window() {
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
        bob_endpoint.close().await;
        net.endpoint.close().await;
    }

    /// Two answers in flight at once each end with the holder's heads, and our
    /// heads move with every frame of either. Asking again on each of them
    /// ran two chains of asks, and each round cost the holder two of its
    /// serves, so a long backfill ran out of them. The holder is asked again
    /// at once only after a full answer landed since the last ask.
    #[test]
    async fn a_partial_answer_does_not_ask_the_round_peer_again_at_once() {
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
        tokio::time::timeout(std::time::Duration::from_secs(5), connected_rx)
            .await
            .expect("the dial to bob completes")
            .expect("bob's task reports the connection");

        antientropy::handle_state_digest(Channel::State, &ahead, &mut state, &context).await;
        let first = state.fast_rounds.asked_heads(Channel::State);
        assert!(first.is_some(), "bob is ahead, so we ask him");

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
        tokio::time::timeout(std::time::Duration::from_secs(5), bob_task)
            .await
            .expect("bob sees the connection close")
            .expect("bob task");
    }

    /// A serve is counted when the batch is handed to the pool, not when it is
    /// delivered, so a failed batch still costs one, but it does not strand
    /// the asker: the same digest after the repeat interval is answered
    /// again. Here the pool refuses the second send, because the dial failed
    /// (a cooldown) or is still in flight, so the second answer goes on
    /// gossip; the same-plane repeat is
    /// `budget_tests::the_serve_budget_takes_new_heads_up_to_its_count`.
    #[test]
    async fn after_a_failed_batch_the_asker_is_answered_again_on_gossip() {
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
            antientropy::handle_state_digest(Channel::State, &behind, &mut state, &context).await;
        assert_eq!(
            first.unicast, 3,
            "handed to the pool as a point-to-point batch"
        );

        tokio::time::sleep(tuning::FAST_ROUND_MIN_INTERVAL + std::time::Duration::from_millis(50))
            .await;
        let again =
            antientropy::handle_state_digest(Channel::State, &behind, &mut state, &context).await;
        assert_eq!(
            again,
            antientropy::Answered {
                unicast: 0,
                broadcast: 3
            },
            "answered again, on gossip: the pool refuses the send, the dial failed or is in flight"
        );
        net.endpoint.close().await;
    }

    /// Apply one local state change, as a frame from the network would land.
    fn apply_one(state: &mut EventLoopState, mesh: &MeshId, step: usize) {
        use crate::protocol::Channel;

        let seed = *state.identity.public().as_bytes();
        let change = state
            .doc(Channel::State)
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
    async fn a_digest_with_nothing_missing_does_not_use_the_serve() {
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
            antientropy::handle_state_digest(Channel::State, &behind, &mut state, &context).await;
        assert_eq!(gap.broadcast, 3, "the gap is served inside the window");
        bob_endpoint.close().await;
        net.endpoint.close().await;
    }

    /// A node sends its state and meta digests back to back, so a holder
    /// answers the same warm peer twice at once. The in-flight guard exists
    /// for a cold peer's dial; a warm connection must take both batches.
    #[test]
    async fn two_batches_to_a_warm_peer_both_go_out() {
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
            payload_path::wait_direct(&connection, std::time::Duration::from_secs(5)).await,
            "loopback selects a direct path"
        );
        // Two batches of signed frames, each frame with its own id, so the reader sees four distinct
        // frames in whatever order the batches land.
        let batch = || -> Vec<WireFrame> {
            (0..2)
                .map(|_| directed_msg().serialize().expect("serialize"))
                .collect()
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
            tokio::time::timeout(std::time::Duration::from_secs(5), received)
                .await
                .expect("bob reads both batches in time")
                .expect("reader task");
        got.sort();
        let mut expected: Vec<Vec<u8>> = state_batch
            .iter()
            .chain(&meta_batch)
            .map(|frame| frame.as_bytes().to_vec())
            .collect();
        expected.sort();
        assert_eq!(
            got, expected,
            "both batches to the warm peer are delivered in order"
        );
        returned_endpoint.close().await;
        endpoint.close().await;
    }

    /// Bob's side of a loopback link: the next `count` frames he reads.
    fn read_frames(
        bob_endpoint: iroh::Endpoint,
        count: usize,
    ) -> tokio::task::JoinHandle<(Vec<Vec<u8>>, iroh::Endpoint)> {
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

    /// A point-to-point answer ends with the holder's own heads, so the asker
    /// can tell whether it is still behind and ask again.
    #[test]
    async fn a_point_to_point_answer_ends_with_the_holders_heads() {
        use crate::protocol::{Channel, MessageKind};

        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (net, mut state, frames) = holder(bob_endpoint.addr(), 3).await;
        state.linked_endpoints.insert(bob_endpoint.id());
        let bob_id = bob_endpoint.id();
        let received = read_frames(bob_endpoint, 4);
        let asker = Identity::generate();
        prove_identity(&mut state, &asker, bob_id);
        let digest = digest(&net.mesh, Channel::State, &serde_json::json!([]), &asker);

        antientropy::handle_state_digest(Channel::State, &digest, &mut state, &net.context()).await;

        let (got, returned_endpoint) =
            tokio::time::timeout(std::time::Duration::from_secs(5), received)
                .await
                .expect("bob reads the answer in time")
                .expect("reader task");
        let expected: Vec<Vec<u8>> = frames
            .iter()
            .map(|bytes| bytes.as_bytes().to_vec())
            .collect();
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
    }

    /// A linked neighbor's digest with heads we do not hold makes us ask that
    /// neighbor directly; heads we hold, or a sender that is not linked, do
    /// not.
    #[test]
    async fn a_digest_from_a_neighbor_that_is_ahead_is_asked_back_directly() {
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
        antientropy::handle_state_digest(Channel::State, &up_to_date, &mut state, &net.context())
            .await;
        assert!(
            !state.fast_rounds.active(Channel::State, now),
            "heads we hold"
        );

        let from_ahead = digest(&net.mesh, Channel::State, &ahead_heads, &bob);
        antientropy::handle_state_digest(Channel::State, &from_ahead, &mut state, &net.context())
            .await;
        assert!(
            !state.fast_rounds.active(Channel::State, now),
            "bob is not linked"
        );

        state.linked_endpoints.insert(bob_endpoint.id());
        let received = read_frames(bob_endpoint, 1);
        antientropy::handle_state_digest(Channel::State, &from_ahead, &mut state, &net.context())
            .await;
        assert!(state.fast_rounds.active(Channel::State, now), "asked bob");
        let (got, returned_endpoint) =
            tokio::time::timeout(std::time::Duration::from_secs(5), received)
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
    }
}

#[cfg(test)]
mod chain_tests {
    use habilis_network_test_tracing::test;

    use super::SendError;

    #[test]
    fn an_internal_cause_keeps_its_chain() {
        let io = std::io::Error::new(std::io::ErrorKind::AddrInUse, "Address already in use");
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
    use habilis_network_test_tracing::test;

    use super::SendError;
    use crate::daemon::event_loop::EventLoopError;

    /// A leave that fails because the loop ended with an error keeps that error's text.
    #[test]
    fn a_leave_failure_keeps_the_event_loop_error() {
        let io = std::io::Error::new(std::io::ErrorKind::AddrInUse, "Address already in use");
        let error = SendError::EventLoop(EventLoopError::Internal(Box::new(io)));
        let text = format!("{:#}", anyhow::Error::new(error));
        assert!(text.starts_with("the mesh event loop failed"), "{text}");
        assert_eq!(text.matches("Address already in use").count(), 1, "{text}");
    }
}
