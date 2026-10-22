//! Gossip **outbound/send plane** (engine primitives): fire-and-forget
//! broadcast, the shared-state merge write, and presence / `PeerInfo`
//! announcements. The application payload send path (broadcast chat, task
//! legs, directed RPC) lives app-side in the application's send plane; this layer only
//! carries the generic transport primitives the app rides. Inbound dispatch
//! lives in [`super::recv`].

use crate::transport::MeshSender;

use crate::daemon::ctx::HandlerCtx;
use crate::daemon::state::{EventLoopState, PingRound};
use crate::gossip::app::AppClass;
use crate::gossip::event::{NodeEvent, NodeSink};
use crate::protocol::message::AppFrameParams;
use crate::protocol::message::{Verified, WireFrame};
use crate::protocol::{Channel, MeshId, Message, MessageBody, Nickname};
use crate::util::consts::MAX_MESSAGE_SIZE;

/// Build → sign → deliver one outbound `App` frame — the payload-generic
/// counterpart to the application's own (chain-stamping, sharding, sealing) chat /
/// task builders. A consumer with its own data model emits its `App`-tagged payloads through
/// this one primitive: it stamps the frame with `tag`/`to`/`corr`, signs it with
/// the loop identity, and routes it with the same single-send decision the application
/// path uses ([`crate::transport::deliver`]) — unicast to a sole addressee,
/// gossip for a broadcast (`to == None`).
///
/// Reliability matches the engine's own plumbing: while unmeshed the frame is
/// buffered into `pending_outbound` and flushed through the send decision on
/// the meshed edge; a directed frame whose addressee is still unknown at that
/// flush is re-buffered and retried as `PeerInfo`s arrive (dropped only when
/// the bounded buffer overflows).
///
/// This is a **single-frame** send: unlike the application's chat path it does not split a
/// large body across shards (that logic is entangled with the application's per-author hash
/// chain), so `body` must fit one wire frame. A body whose signed frame would
/// exceed [`MAX_MESSAGE_SIZE`] is refused rather than silently dropped by the
/// gossip actor; a bytes-carrying consumer chunks its stream below that bound.
/// It also does **not** seal a directed frame — the recipient's encryption key
/// is discovered through an app-level convention (the application publishes cards to the
/// meta channel) the engine does not own; a directed `App` frame sent here rides
/// in plaintext (authenticated by the Ed25519 frame signature).
///
/// Nor does it seal a **broadcast** body: on a passworded mesh (a
/// `broadcast_key` is set), receivers require every broadcast body to be
/// mesh-key-sealed and drop a plaintext one on decrypt (see
/// `gossip::recv::decrypt_broadcast`). A generic consumer that needs passworded
/// broadcast must therefore seal its body under the mesh key before calling
/// this; the shipped application does so on its broadcast chat path.
///
/// `frame` comes from [`app_frame`], and `class` is what the app says of it
/// (`app.classify(&frame)`). A **broadcast** frame that the class marks as loggable is kept in
/// the message log of the sender, as at the ingest of the same frame on a peer. Without it a peer that holds the frame
/// would resend it to its author on every digest round, and the author could not serve it to a
/// peer that missed it. A frame the app does not log is not kept. The log holds a frame
/// once, so a consumer that also pushes the same frame into it costs a lookup, not a duplicate.
///
/// A directed frame to a cold peer comes back as [`crate::transport::Delivered::Pending`]: the dial runs on a task,
/// and the caller awaits the handle off its event loop.
///
/// # Errors
/// Refuses a body too large for one frame, propagates a serialize/deliver
/// failure, and errors if the unmeshed buffer is full.
pub async fn send_app(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    frame: Verified,
    class: AppClass,
) -> anyhow::Result<crate::transport::Delivered> {
    if frame.wire_len() > MAX_MESSAGE_SIZE {
        anyhow::bail!(
            "app frame too large: {} bytes exceeds the {MAX_MESSAGE_SIZE}-byte single-frame limit",
            frame.wire_len()
        );
    }
    let bytes = frame.serialize()?;
    crate::logging::messages::log_out(&frame);
    if state.meshed {
        // Directed vs. broadcast is decided inside `deliver` from the frame's
        // `to` — the same routing the application's send path rides. A frame
        // held off a relay-only peer is parked, not failed: the proven direct
        // path flushes it (see `gossip::recv::flush_pending`).
        match crate::transport::deliver(&frame, bytes.clone(), state, ctx.sender).await {
            Err(error) if error.is::<crate::transport::HeldForDirect>() => {
                park_and_offer(state, ctx, &frame, &bytes);
            }
            outcome => {
                if outcome.is_ok() {
                    super::recv::retain_own_app_broadcast(state, &frame, &class);
                }
                return outcome;
            }
        }
    } else {
        park_and_offer(state, ctx, &frame, &bytes);
    }
    if state.pending_outbound.push((frame.clone(), bytes)) {
        // Buffered until the meshed edge flushes it through the same send
        // decision (see `gossip::recv::flush_pending`). A parked frame is still ours.
        super::recv::retain_own_app_broadcast(state, &frame, &class);
        Ok(crate::transport::Delivered::Done)
    } else {
        anyhow::bail!("pending outbound buffer full; app frame dropped")
    }
}

/// Build and sign the frame that [`send_app`] sends. A plain function, so that a caller can
/// classify the frame (`app.classify(&frame)`) before the send and hold no reference to the app
/// across the `await` of [`send_app`]: the app is not `Sync`, and a future that holds it is not
/// `Send`.
#[must_use]
pub fn app_frame(ctx: &HandlerCtx<'_>, params: AppFrameParams) -> Verified {
    Message::new_app(ctx.mesh, ctx.author, params).sign(ctx.identity)
}

/// Fire-and-forget gossip broadcast. Serialize errors are swallowed:
/// this helper is for presence / `PeerInfo` announcements where a
/// failed serialize must not block the daemon. A failed *broadcast* is
/// logged — it means the gossip actor refused the send (the wedge the
/// roster-collapse soak hit silently), not a routine empty gossip.
pub async fn broadcast_msg(sender: &MeshSender, msg: &Verified) {
    crate::logging::messages::log_out(msg);
    if let Ok(bytes) = msg.serialize()
        && let Err(error) = sender.broadcast(bytes).await
    {
        tracing::warn!(
            target: "habilis_network::gossip",
            %error,
            "presence/plumbing broadcast failed"
        );
    }
}

/// Start an RTT round: arm it and broadcast the first probe. The event loop sends the second probe
/// at the middle of the window (`send_second_probe`); the round ends at its deadline and reports
/// the first pong of each peer. This is the one place that starts a round.
pub async fn start_ping_round(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    resp: Option<tokio::sync::oneshot::Sender<Vec<(Nickname, u64)>>>,
) {
    let now = n0_future::time::Instant::now();
    let window = crate::util::tuning::ping_window();
    let probe = Message::new_ping(ctx.mesh, ctx.author).sign(ctx.identity);
    state.arm_ping_round(PingRound::new(&probe, now, now + window, resp));
    broadcast_msg(ctx.sender, &probe).await;
}

/// Send the second probe of the round in flight, a fresh ping: a repeat of the first one would be
/// dropped as a duplicate by gossip and by `ingest`, and would never reach a peer's `auto_pong`.
pub(crate) async fn send_second_probe(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    let Some(round) = state.ping_round.as_mut() else {
        return;
    };
    let probe = Message::new_ping(ctx.mesh, ctx.author).sign(ctx.identity);
    round
        .probes
        .insert(probe.id.clone(), n0_future::time::Instant::now());
    broadcast_msg(ctx.sender, &probe).await;
}

/// Parameters for [`broadcast_state_merge`]. A dedicated struct rather than
/// reusing `HandlerCtx`: several root-crate callers only hold loose
/// `mesh`/`author`/`sender`/`sink` locals, not a full `HandlerCtx`.
#[expect(
    missing_debug_implementations,
    reason = "sink is a &'a dyn NodeSink trait object with no Debug impl"
)]
pub struct StateMergeParams<'mesh> {
    pub mesh: &'mesh MeshId,
    pub author: &'mesh Nickname,
    pub merge: serde_json::Value,
    pub sender: &'mesh MeshSender,
    pub sink: &'mesh dyn NodeSink,
    pub channel: Channel,
    pub surface: bool,
}

/// The single shared-state write helper, shared by the IPC `state_merge` command
/// and the in-process `StateMerge` request. Translates the RFC 7386 merge into one
/// automerge change, gossips it inside a signed frame, and retains it locally so
/// anti-entropy can serve it (gossip never echoes to self).
///
/// The change is built on a fork and the frame size-gated **before** the change
/// touches the live doc, so an oversize merge never lands in a doc it could not
/// be gossiped for. Applying then runs through [`MeshDoc::ingest`](crate::doc::MeshDoc::ingest)'s gate, so a
/// local write that would forge another peer's card is refused, not silently
/// diverged.
///
/// `surface` controls whether the local write is reported to the operator/agent
/// as a `state`/`meta` event (`you changed …`). Agent-driven merges pass
/// `true`; the daemon's own automatic card publish passes `false` — that write is
/// internal plumbing, not something the agent did, so it must not appear as a
/// "you changed shared state" event (nor race into a `fetch_messages` long-poll).
///
/// Returns the signed wire bytes that were gossiped (`None` for a no-op
/// merge), so a shutdown-path caller can mirror them over the unicast plane
/// ([`unicast_farewell`]).
///
/// # Errors
/// Unrepresentable merge, oversize frame, a rejected foreign-card write, or a
/// broadcast refusal.
pub async fn broadcast_state_merge(
    state: &mut EventLoopState,
    params: StateMergeParams<'_>,
) -> anyhow::Result<Option<WireFrame>> {
    use crate::doc::Ingested;

    let StateMergeParams {
        mesh,
        author,
        merge,
        sender,
        sink,
        channel,
        surface,
    } = params;

    // 1. Build the change on a fork (no live mutation yet); a no-op merge is a
    //    silent success.
    // The actor seed is the session's signing key, not the nickname: a
    // rejoined session under a nickname-derived actor would collide seq
    // numbers with its predecessor's history (see `doc::actor_for`).
    let actor_seed = *state.identity.public().as_bytes();
    let built = state.doc(channel).build_change(&merge, &actor_seed)?;
    let Some(change_bytes) = built else {
        return Ok(None);
    };

    // 2. Compose + sign + size-gate before the change touches the live doc.
    //    Carry the input merge as the surfaced delta only for agent-visible
    //    writes; the internal card publish stays lean (no delta on the wire).
    //    On a passworded mesh the wire body is sealed under the channel key;
    //    `plain_body` keeps the plaintext for our own surfacing below.
    let (wire_body, plain_body) = state
        .doc(channel)
        .compose_wire_body(&change_bytes, surface.then_some(&merge))?;
    let signed = Message::new_channel_event(mesh, author, wire_body, channel).sign(&state.identity);
    let bytes = signed.serialize()?;
    crate::logging::messages::log_out(&signed);

    // 3. Apply the signed frame to the live doc through the authorization gate.
    //    Ingest retains the frame as the re-serve store (replacing `StateLog`),
    //    so anti-entropy can forward it with its original signature.
    let ingested = state.doc_mut(channel).ingest(&signed);
    let after = match ingested {
        Ingested::Applied { doc, .. } => doc,
        Ingested::Duplicate => return Ok(None),
        Ingested::Rejected => {
            anyhow::bail!("write rejected: a member may only write its own /peers/<nick>/card")
        }
        Ingested::Buffered => unreachable!("a locally-built change's deps are always present"),
        Ingested::Ignored => unreachable!("a locally-built change body always decodes"),
    };

    // 4. Surface our own change, and gossip it (or buffer while no gossip path
    //    exists — the change is safe in the local doc for heads-based
    //    anti-entropy).
    if surface {
        // Surface our own change from a plaintext-bodied view so the `m` delta
        // renders even when the wire body we signed is sealed.
        sink.emit(NodeEvent::StateChanged {
            channel,
            event: Box::new(signed.with_body(plain_body)),
            document: after,
            is_self: true,
        });
    }
    if state.overlay_reachable() {
        sender
            .broadcast(bytes.clone())
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    } else {
        // No gossip path yet: buffer until we mesh. (The change is already in
        // the local doc, so heads anti-entropy still reconciles it if the
        // buffer is full.)
        state.pending_outbound.push((signed, bytes.clone()));
    }
    Ok(Some(bytes))
}

/// Mirror a farewell frame over the unicast plane to every rostered peer —
/// fire-and-forget dials racing the shutdown propagation sleep. The gossip
/// overlay can be silently linkless (a post-join flap heals in seconds, but a
/// leaver exits first), and a farewell that dies with the leaver can never be
/// healed by anti-entropy — no live replica holds it. Receiver-side dedup
/// makes the double delivery a no-op; the unicast acceptor feeds the same
/// `ingest` path as gossip. Spawned dials that outlive the shutdown window
/// die with the endpoint — still best-effort, just no longer single-path.
///
/// For channel-event farewells (the meta retraction) ONLY — never presence:
/// a mirrored `Left` from a beacon host can land while a survivor's gossip
/// still holds the dying beacon's link, and the presence-driven fast-reclaim
/// then re-stands the beacon into a stale connection and stalls
/// (iroh-gossip#10).
pub fn unicast_farewell(state: &EventLoopState, bytes: &WireFrame) {
    for (nick, endpoint_id) in &state.peer_endpoints {
        // The rendezvous pseudo-node is never a directed target, and a
        // quiet/ghost peer's stale hint isn't worth a dial at shutdown.
        if state.rendezvous_id == Some(endpoint_id.id) || !state.peers.contains(nick) {
            continue;
        }
        let pool = state.unicast_pool.clone();
        let endpoint_id = endpoint_id.id;
        let bytes = bytes.clone();
        n0_future::task::spawn(async move {
            if let Err(error) = pool.dial_and_send(endpoint_id, bytes.into_bytes()).await {
                tracing::debug!(target: "habilis_network::gossip", %error, "unicast farewell mirror failed");
            }
        });
    }
}

/// The body of our `PeerInfo`: our address, the proof that we own it, and, while we hold the
/// rendezvous, a flag that lets another holder in the same overlay order itself against us.
pub(crate) fn peer_info_json(
    addr: &iroh::EndpointAddr,
    proof: String,
    holds_beacon: bool,
) -> serde_json::Value {
    let mut json = crate::protocol::peer_addr::endpoint_addr_to_json(addr);
    json["proof"] = serde_json::Value::String(proof);
    if holds_beacon {
        json["beacon"] = serde_json::Value::Bool(true);
    }
    json
}

/// Broadcast a `PeerInfo` carrying our endpoint address so peers can
/// dial us directly. Unlike `joined`, `PeerInfo` never enters the
/// message log (`handle_peer_info` returns before the log push), so
/// re-sending it is invisible to `poll`/`fetch_messages` consumers —
/// safe to repeat on every new neighbor. Stamps `peerinfo_flooded_at`, the
/// window the `joined` re-flood gate reads.
pub(crate) async fn broadcast_peer_info(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    state.peerinfo_flooded_at = Some(crate::util::clock::Instant::now());
    state.peerinfo_deferred = false;
    let our_addr = ctx.endpoint.addr();
    state.last_flooded_addr = Some(our_addr.clone());
    tracing::debug!(
        target: "habilis_network::gossip",
        local = %ctx.endpoint.id().fmt_short(),
        relay = ?our_addr.relay_urls().next(),
        addrs = our_addr.ip_addrs().count(),
        ip_addrs = ?our_addr.ip_addrs().collect::<Vec<_>>(),
        "peerinfo flooded"
    );
    let proof = state
        .peer_info_proof
        .get_or_insert_with(|| {
            crate::transport::endpoint_proof::sign(
                ctx.endpoint.secret_key(),
                ctx.mesh,
                &state.identity.author_key(),
            )
        })
        .clone();
    let addr_json = peer_info_json(&our_addr, proof, state.hosts_rendezvous);
    let addr_data = serde_json::to_string(&addr_json)
        .expect("endpoint_addr_to_json produces a Value that always serializes");
    let addr_body =
        MessageBody::new(addr_data).expect("endpoint address JSON has no control characters");
    broadcast_msg(
        ctx.sender,
        &Message::new_peer_info(ctx.mesh, ctx.author, addr_body).sign(ctx.identity),
    )
    .await;
}

/// Announce our arrival: `joined` presence followed by `PeerInfo`.
/// Called once at the top of the event loop; the caller bumps
/// `last_sent_at` afterwards.
///
/// Takes `state` only to retain the `joined` locally — see
/// [`retain_own_broadcast`](super::recv::retain_own_broadcast) for why a node
/// that does not hold its own presence makes anti-entropy unconvergeable.
pub(super) async fn announce_arrival(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    let joined = Message::new_joined(ctx.mesh, ctx.author).sign(ctx.identity);
    broadcast_msg(ctx.sender, &joined).await;
    super::recv::retain_own_broadcast(state, &joined);
    broadcast_peer_info(state, ctx).await;
}

/// A directed frame that is parked because the node is not meshed yet still asks for the session
/// of a peer that needs one: a node becomes meshed by its first link to a member, and on a lane pair
/// that link needs the session, so a frame that waited for the link could never ask for it. The rule
/// is the one of a frame held on a meshed node ([`crate::transport::note_held`]).
fn mark_parked(state: &mut EventLoopState, frame: &Verified, bytes: &WireFrame) {
    if let Err(error) = crate::transport::resolve(frame, bytes.clone(), state) {
        crate::transport::note_held(state, &error);
    }
}

/// A directed frame is parked, by `send_app` or by a flush that held it again: ask for the session
/// of its peer, and offer it now. One helper for both, so that the two cannot drift.
pub(crate) fn park_and_offer(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    frame: &Verified,
    bytes: &WireFrame,
) {
    mark_parked(state, frame, bytes);
    offer_for_parked(state, ctx, frame);
}

/// Offer the session of the peer now, if the parked frame asked for it. Without this the offer waits
/// for the next tick of the retry pass, up to 30 s, and a user waits with it. The peer is a lane peer,
/// or a pair with an IP path that reads as the relay (`note_held` marks both).
fn offer_for_parked(state: &mut EventLoopState, ctx: &HandlerCtx<'_>, frame: &Verified) {
    let Some(nick) = crate::protocol::message::sole_addressee(&frame.kind) else {
        return;
    };
    let Some(addr) = state.peer_endpoints.get(nick).cloned() else {
        return;
    };
    if state.lane_session_wanted(addr.id, crate::util::clock::Instant::now()) {
        crate::transport::webrtc::negotiate_session(state, ctx, addr.id, addr);
    }
}

#[cfg(test)]
mod tests {
    use crate::transport::UdpTransport;
    use habilis_network_test_tracing::test;

    use super::{mark_parked, peer_info_json};
    use crate::protocol::{MeshId, Message};
    use crate::testing::{endpoint_id, fresh_state, nick};

    #[test]
    fn our_peer_info_says_so_while_we_hold_the_rendezvous() {
        let addr = iroh::EndpointAddr::new(iroh::SecretKey::generate().public());

        let holding = peer_info_json(&addr, "proof".to_owned(), true);
        let idle = peer_info_json(&addr, "proof".to_owned(), false);

        assert_eq!(holding["beacon"], serde_json::Value::Bool(true));
        assert_eq!(holding["proof"], "proof");
        assert!(
            idle.get("beacon").is_none(),
            "no key while we do not hold it"
        );
    }

    /// Members built before the flag read the body by key. The new key must not stop them from
    /// reading the address.
    #[test]
    fn a_reader_that_predates_the_flag_still_reads_the_address() {
        let id = iroh::SecretKey::generate().public();
        let json = peer_info_json(&iroh::EndpointAddr::new(id), "proof".to_owned(), true);

        let (read, _) =
            crate::protocol::peer_addr::endpoint_addr_from_json(&json).expect("the address reads");

        assert_eq!(read, id);
    }

    /// A node that is not meshed parks a directed frame to a lane peer, and the park asks for the
    /// peer's session.
    #[test]
    fn an_unmeshed_directed_frame_to_a_lane_peer_marks_the_peer_wanted() {
        let mut state = fresh_state();
        state.meshed = false;
        state.local_udp_transport = UdpTransport::Present;
        let bob = endpoint_id(1);
        state.peer_endpoints.insert(
            nick("bob"),
            iroh::EndpointAddr::new(bob)
                .with_relay_url("https://relay.invalid".parse().expect("relay url")),
        );
        let frame = Message::new_pong(
            &MeshId::from("test"),
            &nick("alice"),
            nick("bob"),
            &crate::protocol::MessageId::random(),
        )
        .sign(&crate::protocol::Identity::generate());
        let bytes = frame.serialize().expect("serialize");
        let now = crate::util::clock::Instant::now();
        assert!(
            !state.lane_session_wanted(bob, now),
            "nothing is parked yet"
        );

        mark_parked(&mut state, &frame, &bytes);

        assert!(state.lane_session_wanted(bob, now), "the parked frame asks");
    }

    /// A broadcast has no addressee, so parking it asks for nothing.
    #[test]
    fn an_unmeshed_broadcast_asks_for_no_session() {
        let mut state = fresh_state();
        state.meshed = false;
        let bob = endpoint_id(1);
        state
            .peer_endpoints
            .insert(nick("bob"), iroh::EndpointAddr::new(bob));
        let frame = Message::new_app(
            &MeshId::from("test"),
            &nick("alice"),
            crate::protocol::message::AppFrameParams {
                tag: crate::protocol::AppTag::new("app_msg").expect("a valid app tag"),
                to: None,
                corr: None,
                body: crate::protocol::MessageBody::from("hi"),
            },
        )
        .sign(&crate::protocol::Identity::generate());
        mark_parked(&mut state, &frame, &frame.serialize().expect("serialize"));
        assert!(!state.lane_session_wanted(bob, crate::util::clock::Instant::now()));
    }

    /// The offer goes out at once for a peer that is wanted, and a second call does not start a
    /// second one: the admission table keeps one round per peer.
    #[cfg(feature = "host")]
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn offering_for_a_parked_frame_starts_one_round_and_no_more() {
        let node = crate::testing::LaneNode::start().await;
        let ctx = node.ctx();
        let mut state = node.state();
        let frame = node.frame_to_bob();
        assert_eq!(state.webrtc_admission.in_flight(), 0);

        state.want_lane_session(node.bob, crate::util::clock::Instant::now());
        super::offer_for_parked(&mut state, &ctx, &frame);
        assert_eq!(state.webrtc_admission.in_flight(), 1, "the offer is out");
        super::offer_for_parked(&mut state, &ctx, &frame);
        assert_eq!(state.webrtc_admission.in_flight(), 1, "not a second round");

        state.webrtc_admission.close();
        node.endpoint.close().await;
    }

    /// A peer that nobody asked for is not offered a session.
    #[cfg(feature = "host")]
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn nothing_is_offered_for_a_peer_that_is_not_wanted() {
        let node = crate::testing::LaneNode::start().await;
        let ctx = node.ctx();
        let mut state = node.state();
        super::offer_for_parked(&mut state, &ctx, &node.frame_to_bob());
        assert_eq!(state.webrtc_admission.in_flight(), 0);
        node.endpoint.close().await;
    }
}
