//! The single send decision. Every outbound message funnels through
//! [`deliver`]: a broadcast (no sole addressee) rides gossip, structurally; a
//! directed message goes over the unicast connection only — warm pooled
//! connection first, inline dial otherwise — and gossip never carries it. The
//! bytes are the same canonical wire `Message` on both planes, so the
//! receiver's path is identical either way.

use anyhow::{Context, Result};
use bytes::Bytes;
use iroh::EndpointId;

use super::outbox::Resend;
use super::pool::WarmSend;
use crate::daemon::state::EventLoopState;
use crate::protocol::message::sole_addressee;
use crate::protocol::{Message, Nickname};
use crate::transport::MeshSender;

/// Route one already-signed, already-serialized message. `bytes` MUST be
/// `msg.serialize()` — the same wire form gossip uses.
///
/// # Errors
/// Propagates a gossip broadcast failure or a unicast dial/send failure. A
/// directed message whose addressee has no dialable endpoint (its `PeerInfo`
/// hasn't arrived, or its advertised endpoint is the rendezvous pseudo-node)
/// is undeliverable — the error names which; callers retry once a real
/// endpoint is learned.
pub async fn deliver(
    msg: &Message,
    bytes: Bytes,
    state: &EventLoopState,
    sender: &MeshSender,
) -> Result<()> {
    match resolve(msg, bytes, state)? {
        Resend::Broadcast(bytes) => broadcast(sender, bytes).await,
        Resend::Unicast(eid, bytes) => send_unicast(eid, bytes, state).await,
    }
}

/// The routing decision of [`deliver`], without the send: which plane carries
/// `msg`, so that a caller that must not wait can queue it for another task.
///
/// # Errors
/// The same as [`deliver`] for a message that has no path now: held for a
/// direct path, or its addressee has no known endpoint.
pub(crate) fn resolve(msg: &Message, bytes: Bytes, state: &EventLoopState) -> Result<Resend> {
    match route(msg, state) {
        Route::Broadcast => Ok(Resend::Broadcast(bytes)),
        Route::Unicast(eid) => Ok(Resend::Unicast(eid, bytes)),
        Route::Held(eid) => Err(HeldForDirect { eid }.into()),
        Route::Undeliverable => {
            let addressee = sole_addressee(&msg.kind);
            let name = addressee.map_or("<none>", Nickname::as_str);
            // Two distinct causes hide behind one route: waiting on PeerInfo
            // is retryable, an addressee advertising the rendezvous is not.
            let via_rendezvous = addressee
                .and_then(|nick| state.peer_endpoints.get(nick))
                .is_some_and(|addr| state.rendezvous_id == Some(addr.id));
            let cause = if via_rendezvous {
                "its advertised endpoint is the rendezvous pseudo-node, never a directed target"
            } else {
                "no known endpoint (PeerInfo not yet received)"
            };
            Err(anyhow::anyhow!(
                "directed message to {name} undeliverable: {cause}"
            ))
        }
    }
}

/// Route like [`deliver`], but never wait on a dial or a stream write: for a
/// caller on the event loop (an app hook on the tick), where an inline dial
/// stops the whole node for the dial and path-select budgets.
///
/// A directed message to a warm peer is handed to the connection, the same as
/// [`deliver`]. A cold peer with a known endpoint is dialed in the background.
/// A broadcast rides gossip, which never dials.
///
/// Returns whether the send was started. `false` when:
/// - the addressee has no known endpoint yet, or advertises the rendezvous
///   pseudo-node. The first can change once its `PeerInfo` arrives. The
///   second never does, so a retry budget must not rely on it.
/// - its only path is a relay that carries no payload. A connection dialed
///   moments ago reads the same way until its path is selected, for up to
///   the path-select budget.
/// - it is cold and on the per-peer dial-failure cooldown.
/// - it is cold and a background dial or batch send to it is already in
///   flight.
/// - the gossip broadcast failed.
///
/// A `false` send is not queued: the caller tries again later.
///
/// `true` does not prove delivery: a background dial or write can still fail,
/// and is only logged. It is also optimistic in one case: an inline dial to
/// the same peer can fail between the cooldown check and the background dial,
/// and the background dial then stops on the new cooldown.
///
/// A background dial can outlive its peer's `Left`. If the peer rejoins at a
/// new address while a stale dial is still running, that dial's failure puts
/// the peer on the cooldown, and directed sends to it return `false` for up
/// to the dial budget plus the cooldown.
pub async fn deliver_in_background(
    msg: &Message,
    bytes: Bytes,
    state: &EventLoopState,
    sender: &MeshSender,
) -> bool {
    match route(msg, state) {
        Route::Broadcast => broadcast(sender, bytes).await.is_ok(),
        Route::Unicast(eid) => match state.unicast_pool.send_if_warm(eid, bytes.clone()).await {
            WarmSend::Sent => true,
            WarmSend::Cold => {
                state
                    .unicast_pool
                    .dial_and_send_in_background(eid, bytes)
                    .await
            }
            WarmSend::Refused => false,
        },
        Route::Held(_) | Route::Undeliverable => false,
    }
}

/// The chosen transport for a message — a **pure** decision so both planes are
/// unit-testable without touching the network.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    /// No sole addressee: gossip is the transport, structurally.
    Broadcast,
    /// Directed to a known endpoint: unicast only. The underlying iroh
    /// connection uses a direct path when one exists, else the registered
    /// multihop transport — the send decision doesn't distinguish.
    Unicast(EndpointId),
    /// Directed to a known endpoint whose only path is the relay, on a mesh
    /// where the relay carries no payload: parked until a direct path is
    /// proven, never sent relayed.
    Held(EndpointId),
    /// Directed with no known endpoint: an error, never gossip.
    Undeliverable,
}

fn route(msg: &Message, state: &EventLoopState) -> Route {
    let Some(nick) = sole_addressee(&msg.kind) else {
        return Route::Broadcast;
    };
    match directed_endpoint(nick, state) {
        Some(eid) if held(eid, state) => Route::Held(eid),
        Some(eid) => Route::Unicast(eid),
        None => Route::Undeliverable,
    }
}

/// Where an answer to the digest signed by `signer` (its hex `pubkey`) can go
/// point-to-point: the endpoint that key proved in its `PeerInfo`, when it is
/// a linked gossip neighbor with a usable path. Proven, because a nickname is
/// a label any signer can claim, and one answer is up to a whole resend budget
/// of frames aimed at whoever holds that endpoint. Linked, because every
/// holder that hears a digest answers it: the asker's link count bounds how
/// many answers reach its unicast inbox. `None` means answer on gossip.
pub(crate) fn unicast_answer_target(signer: &str, state: &EventLoopState) -> Option<EndpointId> {
    let signer = crate::transport::endpoint_proof::signer_bytes(signer)?;
    let eid = state
        .proven_endpoints
        .get(&signer)
        .filter(|eid| state.rendezvous_id != Some(*eid))?;
    (state.linked_endpoints.contains(&eid) && !held(eid, state)).then_some(eid)
}

/// The error [`deliver`] returns for a [`Route::Held`] frame. Typed, so a
/// caller that would rather park the frame than fail it (`send_app`) can tell
/// it from a real send failure with a downcast.
#[derive(Debug)]
pub(crate) struct HeldForDirect {
    eid: EndpointId,
}

impl std::fmt::Display for HeldForDirect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "directed message held: {}'s only path is the relay, which is lookup only on this mesh",
            self.eid
        )
    }
}

impl std::error::Error for HeldForDirect {}

/// A frame held for a lane peer is the reason to open its session: the peer has no IP path, and
/// a send could not dial it without one. So is a frame held for a pair that lost its direct path
/// and reads as the relay. Call this when a send failed with [`HeldForDirect`]; any other error,
/// and a peer that has an IP path and no relay reading, change nothing.
pub(crate) fn note_held(state: &mut EventLoopState, error: &anyhow::Error) {
    let Some(held) = error.downcast_ref::<HeldForDirect>() else {
        return;
    };
    let needs_lane = state
        .peer_endpoints
        .values()
        .find(|addr| addr.id == held.eid)
        .is_some_and(|addr| super::webrtc::pair_needs_lane(addr, state.local_udp_transport));
    // A pair that lost its direct path reads as the relay: if its offer failed, nobody would
    // offer again, so the parked frame asks.
    let reads_as_relay = state.pair_path_kind(held.eid) == Some(super::probe::PathKind::Relay);
    if needs_lane || reads_as_relay {
        state.want_lane_session(held.eid, crate::util::clock::Instant::now());
    }
}

/// Whether a directed frame to `eid` is parked right now: the relay is lookup
/// only and no direct path to the peer is proven yet. An unprobed peer is
/// held too — the alive tick probes every known peer, so the hold is short.
fn held(eid: EndpointId, state: &EventLoopState) -> bool {
    !state.relay_transport
        && state.direct.get(&eid) != Some(&crate::daemon::state::DirectState::Direct)
}

/// The lane a directed frame to `nick` would take right now — [`Route`]
/// stripped of its endpoint payload so the roster can serialize it. Sharing
/// [`directed_endpoint`] keeps the surfaced column from ever drifting from the
/// real send decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Lane {
    Unicast,
    Multihop,
    /// The peer's only path is the relay. Only reported on a mesh whose relay
    /// is lookup only, where that path carries no payload; elsewhere it reads
    /// `unicast`.
    #[serde(rename = "relay-only")]
    RelayOnly,
    Unreachable,
}

/// The roster's `transport` column. A directed frame to a known peer takes a
/// unicast connect; we label it `unicast` when a *direct* path is expected (the
/// peer is in our gossip mesh) and `multihop` otherwise — a best-effort hint,
/// since the actual path is chosen by iroh at connect time.
pub(crate) fn lane_for(nick: &Nickname, state: &EventLoopState) -> Lane {
    let Some(eid) = directed_endpoint(nick, state) else {
        return Lane::Unreachable;
    };
    if held(eid, state) {
        return Lane::RelayOnly;
    }
    if directly_meshed(nick, state) {
        Lane::Unicast
    } else {
        Lane::Multihop
    }
}

/// The endpoint a directed message to `nick` can be sent to, or `None` for an
/// addressee we hold no endpoint for or the rendezvous pseudo-node (never a
/// directed target). Reachability is left to iroh's connect (direct or multihop).
fn directed_endpoint(nick: &Nickname, state: &EventLoopState) -> Option<EndpointId> {
    let eid = state.peer_endpoints.get(nick)?.id;
    if state.rendezvous_id == Some(eid) {
        return None;
    }
    Some(eid)
}

/// Whether `nick` is a known peer in our live gossip mesh — the signal that a
/// *direct* unicast path is expected rather than a multihop one.
fn directly_meshed(nick: &Nickname, state: &EventLoopState) -> bool {
    state.meshed && directed_endpoint(nick, state).is_some()
}

/// Warm pooled connection first (steady state, no dial — an optimistic
/// fire-and-forget handoff; a write that fails on a dead connection redials
/// and resends once in the background); a cold peer is dialed inline, and the
/// dial error is the send's outcome — there is no fallback.
async fn send_unicast(eid: EndpointId, bytes: Bytes, state: &EventLoopState) -> Result<()> {
    let pool = state.unicast_pool.clone();
    match pool.send_if_warm(eid, bytes.clone()).await {
        WarmSend::Sent => Ok(()),
        WarmSend::Refused => Err(anyhow::anyhow!("{}", super::RELAY_REFUSED)),
        WarmSend::Cold => pool
            .dial_and_send(eid, bytes)
            .await
            .with_context(|| format!("unicast dial to {eid} failed")),
    }
}

/// Send a courtesy reply from the receive path, where a stall is not this
/// message's problem but every other arm's: the daemon runs one `select!`, so
/// whatever the receive path waits on, nothing else is being served meanwhile.
///
/// Returns whether it went out, or was handed to a background dial. A reply
/// nobody gets is the right outcome here — the peer's next round simply misses
/// us.
pub(crate) async fn send_best_effort(
    eid: EndpointId,
    bytes: Bytes,
    state: &EventLoopState,
) -> bool {
    // Never dial inline: that would let anyone who can be pinged back choose
    // how long this daemon stops answering, once per identity. A linked
    // neighbor still gets a dial, off the loop — its address is proven by the
    // link, and a link can come up with neither side holding a unicast
    // connection, which left a peer linked only by gossip unanswerable.
    match state.unicast_pool.send_if_warm(eid, bytes.clone()).await {
        WarmSend::Sent => true,
        WarmSend::Cold if state.linked_endpoints.contains(&eid) => {
            state
                .unicast_pool
                .dial_and_send_in_background(eid, bytes)
                .await
        }
        WarmSend::Cold | WarmSend::Refused => false,
    }
}

async fn broadcast(sender: &MeshSender, bytes: Bytes) -> Result<()> {
    sender
        .broadcast(bytes)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))
}

#[cfg(test)]
mod tests {
    use crate::testing::{endpoint_id, fresh_state, nick};

    use bytes::Bytes;

    use iroh::EndpointId;

    use super::{Lane, Route, lane_for, note_held, resolve, route};
    use crate::daemon::state::EventLoopState;
    use crate::protocol::message::AppFrameParams;
    use crate::protocol::{AppTag, CorrId, MeshId, Message, MessageBody, MessageId};

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
        state
            .direct
            .insert(bob, crate::daemon::state::DirectState::Direct);
        (state, bob)
    }

    /// A directed frame addressed to `bob` — a `Pong` is the simplest one.
    fn directed_msg() -> Message {
        Message::new_pong(&mesh(), &nick("alice"), nick("bob"), &MessageId::random())
    }

    fn open_broadcast() -> Message {
        Message::new_app(
            &mesh(),
            &nick("alice"),
            AppFrameParams {
                tag: AppTag::from("app_msg"),
                to: None,
                corr: None,
                body: body(),
            },
        )
    }

    // ── lane peers ────────────────────────────────────────────────────

    /// A lane peer: no IP address, only a relay. On a mesh whose relay is lookup only, a frame to
    /// it is held, and holding it is what asks for its session.
    fn state_knowing_a_lane_bob() -> (EventLoopState, EndpointId) {
        let mut state = fresh_state();
        state.meshed = true;
        state.local_udp_transport = true;
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
        let now = crate::util::clock::Instant::now();
        assert!(!state.lane_session_wanted(bob, now), "nothing is held yet");

        let error = resolve(&directed_msg(), Bytes::from_static(b"hi"), &state)
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
        state.local_udp_transport = true;

        let error = resolve(&directed_msg(), Bytes::from_static(b"hi"), &state)
            .expect_err("a lookup-only relay holds the frame");
        note_held(&mut state, &error);

        assert!(!state.lane_session_wanted(bob, crate::util::clock::Instant::now()));
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
        state.local_udp_transport = true;
        state.direct.insert(bob, DirectState::RelayOnly);
        state.path_kinds.insert(bob, PathKind::Relay);

        let error = resolve(&directed_msg(), Bytes::from_static(b"hi"), &state)
            .expect_err("a lookup-only relay holds the frame");
        note_held(&mut state, &error);

        assert!(state.lane_session_wanted(bob, crate::util::clock::Instant::now()));
    }

    /// On a mesh whose relay carries payload, the cold send to a lane peer is not held: it goes
    /// over the relay, and the climb opens the session later.
    #[test]
    fn on_a_payload_relay_the_cold_send_to_a_lane_peer_is_not_held() {
        let (mut state, bob) = state_knowing_a_lane_bob();
        state.relay_transport = true;

        assert_eq!(route(&directed_msg(), &state), Route::Unicast(bob));
    }

    // ── the p2p path ──────────────────────────────────────────────────

    /// **The receive path must not dial.**
    ///
    /// The daemon is one `select!`, so an inline dial from a receive arm stalls
    /// every other arm with it — timers, IPC, and every other peer's traffic.
    /// The auto-pong replies to whoever pinged us, so a peer that advertises an
    /// address nothing answers on buys a full dial timeout of daemon silence,
    /// once per identity it cares to mint.
    #[tokio::test]
    async fn a_courtesy_reply_to_a_cold_peer_does_not_dial() {
        let (state, bob) = state_knowing_bob();
        let sent = super::send_best_effort(bob, Bytes::from_static(b"pong"), &state).await;

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
    #[tokio::test]
    async fn a_courtesy_reply_to_a_cold_linked_neighbor_dials_off_the_loop() {
        let (mut state, bob) = state_knowing_bob();
        state.linked_endpoints.insert(bob);
        let sent = super::send_best_effort(bob, Bytes::from_static(b"pong"), &state).await;

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
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
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
        state
            .direct
            .insert(bob_addr.id, crate::daemon::state::DirectState::Direct);
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
    #[tokio::test]
    async fn a_background_send_to_a_cold_peer_returns_at_once() {
        let (state, _endpoint, sender, _silent) = state_with_silent_bob().await;
        let msg = directed_msg();
        let bytes = Bytes::from(msg.serialize().expect("serialize"));

        let started = std::time::Instant::now();
        let sent = super::deliver_in_background(&msg, bytes, &state, &sender).await;
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
    }

    /// A peer on the dial-failure cooldown gets no dial, so nothing was
    /// started and the caller must not count the send.
    #[tokio::test]
    async fn a_background_send_to_a_peer_on_dial_cooldown_is_not_sent() {
        let (state, bob) = state_knowing_bob();
        state.unicast_pool.note_dial_failure(bob).await;
        let (_endpoint, sender) = loopback_node().await;
        let msg = directed_msg();
        let bytes = Bytes::from(msg.serialize().expect("serialize"));

        let sent = super::deliver_in_background(&msg, bytes, &state, &sender).await;

        assert!(
            !sent,
            "the cooldown refuses the dial, so nothing was started"
        );
        tokio::task::yield_now().await;
        assert_eq!(state.unicast_pool.dial_attempts(), 0);
    }

    /// Two cold sends to one peer share one dial: each dial is a handshake
    /// and a connection, and the pool keeps only the last one. The second
    /// send comes after a yield, while the first dial is really in flight.
    #[tokio::test]
    async fn two_background_sends_to_one_cold_peer_share_one_dial() {
        let (state, _endpoint, sender, _silent) = state_with_silent_bob().await;
        let msg = directed_msg();
        let bytes = Bytes::from(msg.serialize().expect("serialize"));

        let first = super::deliver_in_background(&msg, bytes.clone(), &state, &sender).await;
        tokio::task::yield_now().await;
        let second = super::deliver_in_background(&msg, bytes, &state, &sender).await;
        tokio::task::yield_now().await;

        assert!(first, "the first send starts the dial");
        assert!(!second, "the second send finds the dial in flight");
        assert_eq!(state.unicast_pool.dial_attempts(), 1);
    }

    /// A courtesy reply and a background send to one cold linked neighbour
    /// share one dial, the same as two background sends do.
    #[tokio::test]
    async fn a_courtesy_reply_shares_a_background_dial_in_flight() {
        let (mut state, bob) = state_knowing_bob();
        state.linked_endpoints.insert(bob);
        let (_endpoint, sender) = loopback_node().await;
        let msg = directed_msg();
        let bytes = Bytes::from(msg.serialize().expect("serialize"));

        let sent = super::deliver_in_background(&msg, bytes.clone(), &state, &sender).await;
        let replied = super::send_best_effort(bob, bytes, &state).await;
        tokio::task::yield_now().await;

        assert!(sent, "the background send starts the dial");
        assert!(!replied, "the reply finds the dial in flight");
        assert_eq!(state.unicast_pool.dial_attempts(), 1);
    }

    /// No known endpoint: nothing to dial, and the caller learns that
    /// nothing went out.
    #[tokio::test]
    async fn a_background_send_to_an_unknown_peer_is_not_sent() {
        let state = fresh_state();
        let (_endpoint, sender) = loopback_node().await;
        let msg = directed_msg();
        let bytes = Bytes::from(msg.serialize().expect("serialize"));

        let sent = super::deliver_in_background(&msg, bytes, &state, &sender).await;

        assert!(!sent, "bob has no known endpoint");
        tokio::task::yield_now().await;
        assert_eq!(state.unicast_pool.dial_attempts(), 0);
    }

    /// A warm peer gets the frame, whole.
    #[tokio::test]
    async fn a_background_send_to_a_warm_peer_delivers() {
        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (endpoint, sender) = loopback_node().await;
        let state = state_with_pool(&endpoint, bob_endpoint.addr());
        let received = tokio::spawn(async move {
            let conn = bob_endpoint
                .accept()
                .await
                .expect("an incoming connection")
                .await
                .expect("accept the connection");
            let mut stream = conn.accept_uni().await.expect("a uni stream");
            let bytes = stream.read_to_end(64 * 1024).await.expect("read the frame");
            (bytes, bob_endpoint, conn)
        });
        let conn = state
            .unicast_pool
            .warm_or_dial(endpoint_of_bob(&state))
            .await
            .expect("warm the pool");
        assert!(
            crate::transport::path::wait_direct(&conn, std::time::Duration::from_secs(5)).await,
            "loopback selects a direct path"
        );
        let msg = directed_msg();
        let bytes = Bytes::from(msg.serialize().expect("serialize"));

        let sent = super::deliver_in_background(&msg, bytes.clone(), &state, &sender).await;

        assert!(sent, "a warm peer is sent to");
        let (got, _bob_endpoint, _conn) =
            tokio::time::timeout(std::time::Duration::from_secs(5), received)
                .await
                .expect("bob reads the frame in time")
                .expect("reader task");
        assert_eq!(got, bytes.to_vec());
        assert_eq!(
            state.unicast_pool.dial_attempts(),
            0,
            "the warm send entered the dial path"
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
        let (state, bob) = state_knowing_bob();
        assert_eq!(route(&directed_msg(), &state), Route::Unicast(bob));
    }

    #[test]
    fn directed_rpc_and_pong_also_take_unicast() {
        let (state, bob) = state_knowing_bob();
        let req = Message::new_app(
            &mesh(),
            &nick("alice"),
            AppFrameParams {
                tag: AppTag::from("app_req"),
                to: Some(nick("bob")),
                corr: Some(CorrId::from("00000000-0000-0000-0000-0000000000aa")),
                body: body(),
            },
        );
        let pong = Message::new_pong(&mesh(), &nick("alice"), nick("bob"), &MessageId::random());
        assert_eq!(route(&req, &state), Route::Unicast(bob));
        assert_eq!(route(&pong, &state), Route::Unicast(bob));
    }

    /// A known peer we're not yet meshed with is still reached by a unicast
    /// connect — iroh's path selection uses the multihop transport when no direct
    /// path exists, so mesh membership doesn't gate the directed send.
    #[test]
    fn known_peer_while_unmeshed_still_takes_unicast() {
        let (mut state, bob) = state_knowing_bob();
        state.meshed = false;
        assert_eq!(route(&directed_msg(), &state), Route::Unicast(bob));
    }

    // ── the gossip plane (broadcasts only) ────────────────────────────

    #[test]
    fn broadcast_message_always_takes_gossip() {
        let (state, _) = state_knowing_bob();
        // Even with a known peer, a non-directed kind is a broadcast.
        assert_eq!(route(&open_broadcast(), &state), Route::Broadcast);
    }

    // ── undeliverable ─────────────────────────────────────────────────

    #[test]
    fn directed_message_with_unknown_endpoint_is_undeliverable() {
        let mut state = fresh_state();
        state.meshed = true; // meshed, but we hold no endpoint for bob
        assert_eq!(route(&directed_msg(), &state), Route::Undeliverable);
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
        assert_eq!(route(&directed_msg(), &state), Route::Undeliverable);
    }

    /// With the relay lookup only, a directed frame is parked until a direct
    /// path to the peer is proven — unprobed, pending and relay-only alike;
    /// once proven it takes unicast like any other.
    #[test]
    fn directed_frame_is_held_until_a_direct_path_is_proven_when_the_relay_is_lookup_only() {
        use crate::daemon::state::DirectState;
        let (mut state, bob) = state_knowing_bob();
        state.direct.insert(bob, DirectState::RelayOnly);
        state.relay_transport = true;
        assert_eq!(route(&directed_msg(), &state), Route::Unicast(bob));
        state.relay_transport = false;
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
        assert_eq!(route(&directed_msg(), &state), Route::Unicast(bob));
    }

    // ── the roster lane ───────────────────────────────────────────────

    #[test]
    fn lane_is_unicast_for_a_meshed_known_peer() {
        let (state, _) = state_knowing_bob();
        assert_eq!(lane_for(&nick("bob"), &state), Lane::Unicast);
    }

    #[test]
    fn lane_is_multihop_for_a_known_but_unmeshed_peer() {
        let (mut state, _) = state_knowing_bob();
        state.meshed = false;
        assert_eq!(lane_for(&nick("bob"), &state), Lane::Multihop);
    }

    /// When the relay is lookup only, a link whose only path is the relay
    /// carries no payload, and the roster says so. Elsewhere the same reading
    /// is just a relayed unicast.
    #[test]
    fn lane_is_relay_only_when_the_relay_is_lookup_only() {
        use crate::daemon::state::DirectState;
        let (mut state, bob) = state_knowing_bob();
        state.direct.insert(bob, DirectState::RelayOnly);
        state.relay_transport = true;
        assert_eq!(lane_for(&nick("bob"), &state), Lane::Unicast);
        state.relay_transport = false;
        assert_eq!(lane_for(&nick("bob"), &state), Lane::RelayOnly);
        state.direct.insert(bob, DirectState::Direct);
        assert_eq!(lane_for(&nick("bob"), &state), Lane::Unicast);
    }

    #[test]
    fn lane_is_unreachable_for_an_unknown_peer() {
        let (state, _) = state_knowing_bob();
        assert_eq!(lane_for(&nick("carol"), &state), Lane::Unreachable);
    }

    /// Linked with a usable path: the answer goes point-to-point. Every other
    /// case answers on gossip as before.
    #[test]
    fn a_digest_answer_goes_point_to_point_only_to_a_linked_neighbor() {
        use super::unicast_answer_target;
        let bob = endpoint_id(1);
        let bob_key = "bb".repeat(32);
        let carol_key = "cc".repeat(32);
        let linked = || {
            let mut state = fresh_state();
            prove(&mut state, &bob_key, bob);
            state
                .direct
                .insert(bob, crate::daemon::state::DirectState::Direct);
            state.linked_endpoints.insert(bob);
            state
        };

        assert_eq!(unicast_answer_target(&bob_key, &linked()), Some(bob));
        assert_eq!(
            unicast_answer_target(&carol_key, &linked()),
            None,
            "no known endpoint"
        );
        let mut rendezvous = linked();
        rendezvous.rendezvous_id = Some(bob);
        assert_eq!(
            unicast_answer_target(&bob_key, &rendezvous),
            None,
            "the rendezvous pseudo-node"
        );
        let mut held = linked();
        held.direct.remove(&bob);
        assert_eq!(
            unicast_answer_target(&bob_key, &held),
            None,
            "no proven direct path on a lookup-only relay"
        );
        let mut unlinked = linked();
        unlinked.linked_endpoints.remove(&bob);
        assert_eq!(
            unicast_answer_target(&bob_key, &unlinked),
            None,
            "known but not a gossip neighbor"
        );
    }

    /// Record, as a verified `PeerInfo` proof would, that the signing key
    /// `pubkey` (hex) owns `endpoint`.
    fn prove(state: &mut EventLoopState, pubkey: &str, endpoint: EndpointId) {
        let signer = crate::transport::endpoint_proof::signer_bytes(pubkey).expect("a 32-byte key");
        let linked = state.linked_endpoints.clone();
        state.proven_endpoints.insert(signer, endpoint, &linked);
    }

    /// [`prove`] for the key of `identity`.
    fn prove_identity(
        state: &mut EventLoopState,
        identity: &crate::protocol::identity::Identity,
        endpoint: EndpointId,
    ) {
        let pubkey = crate::protocol::identity::encode_pubkey(&identity.public());
        prove(state, &pubkey, endpoint);
    }

    /// What a `HandlerCtx` borrows, kept apart from the state so a test can
    /// hold a context and a `&mut EventLoopState` at once. The state digest
    /// answer tests live here, not in `antientropy`, for the loopback helpers.
    struct Net {
        endpoint: iroh::Endpoint,
        sender: crate::transport::MeshSender,
        mesh: MeshId,
        identity: crate::protocol::identity::Identity,
        our_pubkey: String,
        author: crate::protocol::Nickname,
        sink: crate::gossip::event::SilentSink,
    }

    impl Net {
        fn ctx(&self) -> crate::daemon::ctx::HandlerCtx<'_> {
            crate::daemon::ctx::HandlerCtx {
                sender: &self.sender,
                endpoint: &self.endpoint,
                mesh: &self.mesh,
                author: &self.author,
                identity: &self.identity,
                our_pubkey: &self.our_pubkey,
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
    ) -> (Net, EventLoopState, Vec<Bytes>) {
        use crate::protocol::Channel;
        use crate::protocol::identity::{Identity, encode_pubkey};

        let (endpoint, sender) = loopback_node().await;
        let mut state = state_with_pool(&endpoint, bob_addr);
        let mesh = MeshId::from("test");
        let seed = *state.identity.public().as_bytes();
        let mut write = |channel: Channel| -> Vec<Bytes> {
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
                        .signed(&state.identity);
                    let _ = state.doc_mut(channel).ingest(&frame);
                    Bytes::from(frame.serialize().expect("serialize"))
                })
                .collect()
        };
        let frames = write(Channel::State);
        write(Channel::Meta);
        let identity = Identity::generate();
        let our_pubkey = encode_pubkey(&identity.public());
        let net = Net {
            endpoint,
            sender,
            mesh,
            identity,
            our_pubkey,
            author: nick("alice"),
            sink: crate::gossip::event::SilentSink,
        };
        (net, state, frames)
    }

    /// `bob`'s digest on `channel`, advertising `heads`, signed by `asker`.
    fn digest(
        mesh: &MeshId,
        channel: crate::protocol::Channel,
        heads: &serde_json::Value,
        asker: &crate::protocol::identity::Identity,
    ) -> Message {
        let body = MessageBody::new(serde_json::json!({ "heads": heads }).to_string())
            .expect("a JSON body");
        Message::new_channel_digest(mesh, &nick("bob"), body, channel).signed(asker)
    }

    /// A state digest from a linked neighbor with a direct path is answered
    /// on the unicast plane, every frame, in order: on gossip every other
    /// member already holds these frames, so a hop drops them as seen.
    #[tokio::test]
    async fn a_linked_neighbors_state_digest_is_answered_point_to_point_in_order() {
        use crate::protocol::Channel;

        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (net, mut state, frames) = holder(bob_endpoint.addr(), 3).await;
        state.linked_endpoints.insert(bob_endpoint.id());
        let bob_id = bob_endpoint.id();
        let received = tokio::spawn(async move {
            let conn = bob_endpoint
                .accept()
                .await
                .expect("an incoming connection")
                .await
                .expect("accept the connection");
            let mut got = Vec::new();
            for _ in 0..3 {
                let mut stream = conn.accept_uni().await.expect("a uni stream");
                got.push(stream.read_to_end(64 * 1024).await.expect("read the frame"));
            }
            (got, bob_endpoint, conn)
        });
        let asker = crate::protocol::identity::Identity::generate();
        prove_identity(&mut state, &asker, bob_id);
        let digest = digest(&net.mesh, Channel::State, &serde_json::json!([]), &asker);

        let answered = crate::gossip::antientropy::handle_state_digest(
            Channel::State,
            &digest,
            &mut state,
            &net.ctx(),
        )
        .await;

        assert_eq!(answered.broadcast, 0, "nothing went on gossip");
        assert_eq!(answered.unicast, 3);
        let (got, _bob_endpoint, _conn) =
            tokio::time::timeout(std::time::Duration::from_secs(5), received)
                .await
                .expect("bob reads the answer in time")
                .expect("reader task");
        let expected: Vec<Vec<u8>> = frames.iter().map(|bytes| bytes.to_vec()).collect();
        assert_eq!(got, expected, "every frame, in order");
    }

    /// The heads that close a point-to-point answer tell the receiver how far
    /// the holder is; they are not a request. Answering them sent the holder
    /// frames it had, and that answer closed with heads of its own: a loop
    /// that cost a serve at each turn. The receiver only asks back.
    #[tokio::test]
    async fn the_heads_that_close_an_answer_draw_no_answer() {
        use crate::gossip::antientropy::handle_state_digest;
        use crate::protocol::Channel;

        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
        state.linked_endpoints.insert(bob_endpoint.id());
        let bob = crate::protocol::identity::Identity::generate();
        prove_identity(&mut state, &bob, bob_endpoint.id());
        let body = MessageBody::new(
            serde_json::json!({ "heads": ["heads-we-do-not-hold"], "closing": true }).to_string(),
        )
        .expect("a JSON body");
        let closing =
            Message::new_channel_digest(&net.mesh, &nick("bob"), body, Channel::State).signed(&bob);

        let answered = handle_state_digest(Channel::State, &closing, &mut state, &net.ctx()).await;
        assert_eq!(
            answered.unicast + answered.broadcast,
            0,
            "no frames for closing heads"
        );
        assert!(
            state.fast_rounds.asked_heads(Channel::State).is_some(),
            "bob is ahead, so we ask him back"
        );
    }

    /// A peer holds every change it signed, since a change's actor is its
    /// signer's key and a session key lives no longer than its document. So
    /// its own changes are never missing from it, even when it advertises
    /// heads we do not hold, where we cannot tell what it has.
    #[tokio::test]
    async fn a_peer_is_not_sent_its_own_changes() {
        use crate::gossip::antientropy::handle_state_digest;
        use crate::protocol::Channel;

        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
        state.linked_endpoints.insert(bob_endpoint.id());
        let author = state.identity.clone();
        prove_identity(&mut state, &author, bob_endpoint.id());
        let unknown = serde_json::json!(["heads-we-do-not-hold"]);
        let from_the_author = digest(&net.mesh, Channel::State, &unknown, &author);

        let answered =
            handle_state_digest(Channel::State, &from_the_author, &mut state, &net.ctx()).await;
        assert_eq!(
            answered.unicast + answered.broadcast,
            0,
            "all 3 changes are its own"
        );
    }

    /// Unknown heads from anyone else still draw every change: we cannot tell
    /// what that peer lacks, so we over-serve rather than under-serve.
    #[tokio::test]
    async fn a_third_peer_with_unknown_heads_gets_every_change() {
        use crate::gossip::antientropy::handle_state_digest;
        use crate::protocol::Channel;

        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
        state.linked_endpoints.insert(bob_endpoint.id());
        let third = crate::protocol::identity::Identity::generate();
        prove_identity(&mut state, &third, bob_endpoint.id());
        let unknown = serde_json::json!(["heads-we-do-not-hold"]);
        let request = digest(&net.mesh, Channel::State, &unknown, &third);

        // The plane does not matter here: our ask back to the peer is still
        // dialing, so the answer may take gossip.
        let answered = handle_state_digest(Channel::State, &request, &mut state, &net.ctx()).await;
        assert_eq!(answered.unicast + answered.broadcast, 3);
    }

    /// A nickname is a label any signer can put on a digest, so it must not
    /// pick the point-to-point target: a digest signed by a key that proved no
    /// endpoint is answered on gossip, even when a linked peer has that
    /// nickname. Otherwise any member could aim answers at a victim.
    #[tokio::test]
    async fn a_digest_from_a_key_with_no_proven_endpoint_is_answered_on_gossip() {
        use crate::gossip::antientropy::{Answered, handle_state_digest};
        use crate::protocol::Channel;

        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
        state.linked_endpoints.insert(bob_endpoint.id());
        let stranger = crate::protocol::identity::Identity::generate();
        let posing_as_bob = digest(&net.mesh, Channel::State, &serde_json::json!([]), &stranger);

        let answered =
            handle_state_digest(Channel::State, &posing_as_bob, &mut state, &net.ctx()).await;
        assert_eq!(
            answered,
            Answered {
                unicast: 0,
                broadcast: 3
            }
        );
    }

    /// One serve per asker, channel and plane per window: a new node sends a
    /// digest pair for every peer it sees, all with the same heads, and every
    /// holder hears each one. The re-ask at the asker's first real-peer link
    /// switches it to the unicast plane, so it is still answered.
    #[tokio::test]
    async fn a_state_digest_is_served_once_per_asker_channel_and_plane_per_window() {
        use crate::gossip::antientropy::{Answered, handle_state_digest};
        use crate::protocol::Channel;

        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
        let ctx = net.ctx();
        let asker = crate::protocol::identity::Identity::generate();
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
            handle_state_digest(Channel::State, &state_digest, &mut state, &ctx).await,
            gossip,
            "an unlinked asker is answered on gossip"
        );
        assert_eq!(
            handle_state_digest(Channel::State, &state_digest, &mut state, &ctx).await,
            refused,
            "a second gossip answer inside the window"
        );
        assert_eq!(
            handle_state_digest(Channel::Meta, &meta_digest, &mut state, &ctx).await,
            gossip,
            "the meta digest right after is its own serve"
        );

        state.linked_endpoints.insert(bob_endpoint.id());
        assert_eq!(
            handle_state_digest(Channel::State, &state_digest, &mut state, &ctx).await,
            Answered {
                unicast: 3,
                broadcast: 0
            },
            "the re-ask once linked goes on the other plane"
        );
        assert_eq!(
            handle_state_digest(Channel::State, &state_digest, &mut state, &ctx).await,
            refused,
            "a second unicast answer inside the window"
        );
    }

    /// Two answers in flight at once each end with the holder's heads, and our
    /// heads move with every frame of either. Asking again on each of them
    /// ran two chains of asks, and each round cost the holder two of its
    /// serves, so a long backfill ran out of them. The holder is asked again
    /// at once only after a full answer landed since the last ask.
    #[tokio::test]
    async fn a_partial_answer_does_not_ask_the_round_peer_again_at_once() {
        use crate::gossip::antientropy::handle_state_digest;
        use crate::protocol::Channel;

        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let bob_addr = bob_endpoint.addr();
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();
        let _bob = tokio::spawn(async move {
            let conn = bob_endpoint
                .accept()
                .await
                .expect("an incoming connection")
                .await
                .expect("accept the connection");
            let _ = connected_tx.send(());
            while let Ok(mut stream) = conn.accept_uni().await {
                let _ = stream.read_to_end(1 << 20).await;
            }
            bob_endpoint
        });
        let (net, mut state, _frames) = holder(bob_addr.clone(), 3).await;
        state.linked_endpoints.insert(bob_addr.id);
        let ctx = net.ctx();
        let bob = crate::protocol::identity::Identity::generate();
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
                .await
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), connected_rx)
            .await
            .expect("the dial to bob completes")
            .expect("bob's task reports the connection");

        handle_state_digest(Channel::State, &ahead, &mut state, &ctx).await;
        let first = state.fast_rounds.asked_heads(Channel::State);
        assert!(first.is_some(), "bob is ahead, so we ask him");

        apply_one(&mut state, &net.mesh, 100);
        handle_state_digest(Channel::State, &ahead, &mut state, &ctx).await;
        assert_eq!(
            state.fast_rounds.asked_heads(Channel::State),
            first,
            "one change landed since the ask: not a full answer, so no new ask"
        );

        for step in 101..101 + crate::util::tuning::antientropy_max_resend() {
            apply_one(&mut state, &net.mesh, step);
        }
        handle_state_digest(Channel::State, &ahead, &mut state, &ctx).await;
        assert_ne!(
            state.fast_rounds.asked_heads(Channel::State),
            first,
            "a full answer landed since the ask, so we ask again at once"
        );
    }

    /// A serve is counted when the batch is handed to the pool, not when it is
    /// delivered, so a failed batch still costs one, but it does not strand
    /// the asker: the same digest after the repeat interval is answered
    /// again. Here the pool refuses the second send, because the dial failed
    /// (a cooldown) or is still in flight, so the second answer goes on
    /// gossip; the same-plane repeat is
    /// `budget_tests::the_serve_budget_takes_new_heads_up_to_its_count`.
    #[tokio::test]
    async fn after_a_failed_batch_the_asker_is_answered_again_on_gossip() {
        use crate::gossip::antientropy::handle_state_digest;
        use crate::protocol::Channel;

        // Linked and known by nickname, but with no address to dial: the
        // batch's dial fails at once.
        let unreachable = iroh::EndpointAddr::new(iroh::SecretKey::generate().public());
        let (net, mut state, _frames) = holder(unreachable.clone(), 3).await;
        state.linked_endpoints.insert(unreachable.id);
        let ctx = net.ctx();
        let asker = crate::protocol::identity::Identity::generate();
        prove_identity(&mut state, &asker, unreachable.id);
        let behind = digest(&net.mesh, Channel::State, &serde_json::json!([]), &asker);

        let first = handle_state_digest(Channel::State, &behind, &mut state, &ctx).await;
        assert_eq!(
            first.unicast, 3,
            "handed to the pool as a point-to-point batch"
        );

        tokio::time::sleep(std::time::Duration::from_millis(
            crate::util::tuning::FAST_ROUND_MIN_INTERVAL_MS + 50,
        ))
        .await;
        let again = handle_state_digest(Channel::State, &behind, &mut state, &ctx).await;
        assert_eq!(
            again,
            crate::gossip::antientropy::Answered {
                unicast: 0,
                broadcast: 3
            },
            "answered again, on gossip: the pool refuses the send, the dial failed or is in flight"
        );
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
            .signed(&state.identity);
        let _ = state.doc_mut(Channel::State).ingest(&frame);
    }

    /// A digest with nothing to answer must not use up the window: the
    /// asker's next digest, with a real gap, is still served. (The gate is
    /// checked before the missing-frames query, which this test cannot see.)
    #[tokio::test]
    async fn a_digest_with_nothing_missing_does_not_use_the_serve() {
        use crate::gossip::antientropy::handle_state_digest;
        use crate::protocol::Channel;

        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (net, mut state, _frames) = holder(bob_endpoint.addr(), 3).await;
        let ctx = net.ctx();
        let asker = crate::protocol::identity::Identity::generate();
        let current = serde_json::to_value(state.doc(Channel::State).heads()).expect("heads");
        let up_to_date = digest(&net.mesh, Channel::State, &current, &asker);
        let behind = digest(&net.mesh, Channel::State, &serde_json::json!([]), &asker);

        let nothing = handle_state_digest(Channel::State, &up_to_date, &mut state, &ctx).await;
        assert_eq!(nothing.broadcast + nothing.unicast, 0, "nothing is missing");
        let gap = handle_state_digest(Channel::State, &behind, &mut state, &ctx).await;
        assert_eq!(gap.broadcast, 3, "the gap is served inside the window");
    }

    /// A node sends its state and meta digests back to back, so a holder
    /// answers the same warm peer twice at once. The in-flight guard exists
    /// for a cold peer's dial; a warm connection must take both batches.
    #[tokio::test]
    async fn two_batches_to_a_warm_peer_both_go_out() {
        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (endpoint, _sender) = loopback_node().await;
        let state = state_with_pool(&endpoint, bob_endpoint.addr());
        let received = tokio::spawn(async move {
            let conn = bob_endpoint
                .accept()
                .await
                .expect("an incoming connection")
                .await
                .expect("accept the connection");
            let mut got = Vec::new();
            for _ in 0..4 {
                let mut stream = conn.accept_uni().await.expect("a uni stream");
                got.push(stream.read_to_end(64 * 1024).await.expect("read the frame"));
            }
            (got, bob_endpoint, conn)
        });
        let bob = endpoint_of_bob(&state);
        let conn = state
            .unicast_pool
            .warm_or_dial(bob)
            .await
            .expect("warm the pool");
        assert!(
            crate::transport::path::wait_direct(&conn, std::time::Duration::from_secs(5)).await,
            "loopback selects a direct path"
        );
        let batch = |tag: &str| {
            (0..2)
                .map(|step| Bytes::from(format!("{tag}{step}")))
                .collect::<Vec<_>>()
        };

        let first = state
            .unicast_pool
            .send_batch_in_background(bob, batch("state"))
            .await;
        let second = state
            .unicast_pool
            .send_batch_in_background(bob, batch("meta"))
            .await;

        assert!(first, "the first batch starts");
        assert!(second, "the second batch to the same warm peer starts too");
        let (mut got, _bob_endpoint, _conn) =
            tokio::time::timeout(std::time::Duration::from_secs(5), received)
                .await
                .expect("bob reads both batches in time")
                .expect("reader task");
        got.sort();
        assert_eq!(
            got,
            vec![
                b"meta0".to_vec(),
                b"meta1".to_vec(),
                b"state0".to_vec(),
                b"state1".to_vec()
            ]
        );
    }

    /// Bob's side of a loopback link: the next `count` frames he reads.
    fn read_frames(
        bob_endpoint: iroh::Endpoint,
        count: usize,
    ) -> tokio::task::JoinHandle<(Vec<Vec<u8>>, iroh::Endpoint)> {
        tokio::spawn(async move {
            let conn = bob_endpoint
                .accept()
                .await
                .expect("an incoming connection")
                .await
                .expect("accept the connection");
            let mut got = Vec::new();
            for _ in 0..count {
                let mut stream = conn.accept_uni().await.expect("a uni stream");
                got.push(stream.read_to_end(64 * 1024).await.expect("read the frame"));
            }
            (got, bob_endpoint)
        })
    }

    /// A point-to-point answer ends with the holder's own heads, so the asker
    /// can tell whether it is still behind and ask again.
    #[tokio::test]
    async fn a_point_to_point_answer_ends_with_the_holders_heads() {
        use crate::protocol::{Channel, MessageKind};

        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (net, mut state, frames) = holder(bob_endpoint.addr(), 3).await;
        state.linked_endpoints.insert(bob_endpoint.id());
        let bob_id = bob_endpoint.id();
        let received = read_frames(bob_endpoint, 4);
        let asker = crate::protocol::identity::Identity::generate();
        prove_identity(&mut state, &asker, bob_id);
        let digest = digest(&net.mesh, Channel::State, &serde_json::json!([]), &asker);

        crate::gossip::antientropy::handle_state_digest(
            Channel::State,
            &digest,
            &mut state,
            &net.ctx(),
        )
        .await;

        let (got, _bob) = tokio::time::timeout(std::time::Duration::from_secs(5), received)
            .await
            .expect("bob reads the answer in time")
            .expect("reader task");
        let expected: Vec<Vec<u8>> = frames.iter().map(|bytes| bytes.to_vec()).collect();
        assert_eq!(got[..3], expected[..], "the three frames first, in order");
        let last = Message::parse(&got[3]).expect("the last frame parses");
        assert_eq!(last.kind, MessageKind::StateDigest, "then a state digest");
        assert_eq!(
            last.body.as_str(),
            format!(
                r#"{{"heads":{},"closing":true}}"#,
                serde_json::json!(state.doc(Channel::State).heads())
            ),
            "carrying the holder's heads"
        );
    }

    /// A linked neighbor's digest with heads we do not hold makes us ask that
    /// neighbor directly; heads we hold, or a sender that is not linked, do
    /// not.
    #[tokio::test]
    async fn a_digest_from_a_neighbor_that_is_ahead_is_asked_back_directly() {
        use crate::protocol::{Channel, MessageKind};

        let (other_endpoint, _other_sender) = loopback_node().await;
        let (_other_net, ahead, _frames) = holder(other_endpoint.addr(), 3).await;
        let ahead_heads = serde_json::json!(ahead.doc(Channel::State).heads());
        let (bob_endpoint, _bob_sender) = loopback_node().await;
        let (net, mut state, _none) = holder(bob_endpoint.addr(), 0).await;
        let bob = crate::protocol::identity::Identity::generate();
        prove_identity(&mut state, &bob, bob_endpoint.id());
        let now = crate::util::clock::Instant::now();

        let own = serde_json::json!(state.doc(Channel::State).heads());
        let up_to_date = digest(&net.mesh, Channel::State, &own, &bob);
        crate::gossip::antientropy::handle_state_digest(
            Channel::State,
            &up_to_date,
            &mut state,
            &net.ctx(),
        )
        .await;
        assert!(
            !state.fast_rounds.active(Channel::State, now),
            "heads we hold"
        );

        let from_ahead = digest(&net.mesh, Channel::State, &ahead_heads, &bob);
        crate::gossip::antientropy::handle_state_digest(
            Channel::State,
            &from_ahead,
            &mut state,
            &net.ctx(),
        )
        .await;
        assert!(
            !state.fast_rounds.active(Channel::State, now),
            "bob is not linked"
        );

        state.linked_endpoints.insert(bob_endpoint.id());
        let received = read_frames(bob_endpoint, 1);
        crate::gossip::antientropy::handle_state_digest(
            Channel::State,
            &from_ahead,
            &mut state,
            &net.ctx(),
        )
        .await;
        assert!(state.fast_rounds.active(Channel::State, now), "asked bob");
        let (got, _bob) = tokio::time::timeout(std::time::Duration::from_secs(5), received)
            .await
            .expect("bob reads the ask in time")
            .expect("reader task");
        let ask = Message::parse(&got[0]).expect("the ask parses");
        assert_eq!(ask.kind, MessageKind::StateDigest);
        assert_eq!(
            ask.body.as_str(),
            serde_json::json!({ "heads": own }).to_string()
        );
    }
}
