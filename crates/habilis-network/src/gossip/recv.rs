//! Gossip **inbound plane**: the gossip-event pump (`Received` /
//! `NeighborUp` / `NeighborDown` / `Lagged` / stream end), neighbor
//! up/down bookkeeping, the per-message router (parse → self-echo drop →
//! rate-check → lifecycle observe → dispatch by kind → message-log), and
//! `PeerInfo` linking. Outbound/send lives in `super::broadcast`; this
//! layer never touches the peer roster directly — it calls into
//! `lifecycle::observe` and dispatches by kind.

use crate::daemon::state::{Arrival, FrameShape, RendezvousFlag, Standing};
use std::ops::ControlFlow;

use bytes::Bytes;
use iroh_gossip::api::{ApiError, Event};

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::seed_job;
use crate::daemon::state::{DirectState, EventLoopState, RivalFlag};
use crate::gossip::event::NodeEvent;
use crate::lifecycle::membership_update::{self, MembershipUpdate};
use crate::protocol::messages::{
    Authored, MessageBody, MessageError, Proof, Verified, WireFrame, shard_fits_log,
};
use crate::protocol::{AuthorKey, Channel, ContentHash, Message, MessageKind, PresenceSubtype};
use crate::util::clock::Instant;
use crate::{lifecycle, lookup};
// The timer-driver clock the ping round's deadlines are kept in — distinct from
// `clock::Instant` off wasm32. See `daemon::state`.
use n0_future::time::Instant as TokioInstant;

use super::antientropy::{self, Plane};
use super::app::{AppClass, InboundApp, NodeApp};
use super::merge_ctx::{announce_arrival, broadcast_peer_info};
use crate::net;

#[cfg(feature = "multihop")]
use crate::daemon::event_loop;
use crate::doc::wire;
use crate::logging::messages;
use crate::protocol::{peer_addr_error, seal_error};
#[cfg(feature = "multihop")]
use crate::transport::underlay_webrtc;
use crate::transport::{probe, proven_endpoints, webrtc};
use tokio::sync::mpsc;

use crate::transport::Delivered;
use crate::{doc, transport};
use iroh_gossip::api;
use n0_future::task as n0future_task;
use std::ops;
/// The first link to a real peer: user content can be delivered now, so flush what was
/// buffered while unmeshed, in order, and ask again for state and chat.
async fn mesh_on_first_link(
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    state.standing.insert(Standing::Meshed);
    state.standing.remove(&Standing::Degraded);
    flush_pending(state, context, "first real-peer link up").await;
    // Our first digests may have gone out over the rendezvous
    // alone, and their answers re-send frames every hop there
    // already saw: iroh-gossip drops a message id it has seen,
    // so none of it reaches us. Ask again over a link that can
    // carry the answer. The chat log asks too: a broadcast sent
    // before this link could not reach us, and the tick that
    // would ask for it can be an interval away.
    tracing::debug!(target: "habilis_network::gossip", "asked for state and chat again on the first real-peer link");
    antientropy::broadcast_state_digests(
        state,
        context.sender,
        context.mesh,
        context.author,
        antientropy::DigestTrigger::Event,
    )
    .await;
    antientropy::broadcast_digest(state, context.sender, context.mesh, context.author).await;
    // Re-publish anything whose value depends on being meshed
    // (the app's card dial hint); see `NodeApp::on_meshed`.
    app.on_meshed(state, context).await;
}

/// Dispatch a single item from the gossip receiver stream:
/// `Received` → `ingest`; `NeighborUp` →
/// announce / `PeerInfo` re-send; `NeighborDown` → prune the link and
/// arm reclaim; `Lagged` / errors logged; terminal `None` flips
/// `state.standing.contains(&Standing::GossipOpen)` to `false`.
pub(crate) async fn handle_gossip_event(
    event: Option<Result<Event, ApiError>>,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    match event {
        Some(Ok(Event::Received(received))) => {
            ingest(received.content, state, app, context).await;
        }
        Some(Ok(Event::NeighborUp(node_id))) => {
            let (connection, relay) = net::conn_path(context.endpoint, node_id).await;
            let local = context.endpoint.id().fmt_short();
            let relay_label = relay.as_ref().map_or("-", |url| url.as_str());
            tracing::info!(target: "habilis_network::gossip",
                local = %local,
                endpoint_id = %node_id,
                is_rendezvous = node_id == context.rendezvous_id,
                connection = connection.label(),
                relay = relay_label,
                "gossip neighbor up"
            );
            // Announce on the first link, not at startup: a joiner's
            // first link is the rendezvous relay, and `joined` is a
            // one-shot — sending it before any link exists loses it.
            // Later neighbors only get a `PeerInfo` re-send, and only once
            // per window since any flood: a flapping link must not
            // re-flood our address to the whole mesh on every up-transition
            // (the residual amplifier behind the soak's `neighbor up` storm).
            let now = Instant::now();
            if state.standing.contains(&Standing::Announced) {
                if state.neighbor_up_refloods_peerinfo(now) {
                    broadcast_peer_info(state, context).await;
                    state.last_sent_at = now;
                } else {
                    state.defer_peerinfo();
                    tracing::debug!(target: "habilis_network::gossip", endpoint_id = %node_id, "held back the PeerInfo re-flood (window)");
                }
            } else {
                announce_arrival(state, context).await;
                state.standing.insert(Standing::Announced);
                state.last_sent_at = now;
                tracing::info!(target: "habilis_network::gossip", "announced arrival on first gossip link");
            }
            // The co-hosted rendezvous is overlay plumbing, not a
            // peer — never cache its pseudo-node in the
            // bootstrap set. Transport links are not surfaced at all:
            // arrival is surfaced once, via membership presence
            // (`joined`), keyed by nickname and join-horizon gated.
            if node_id == context.rendezvous_id {
                // Re-arms the healer's probe gate: while this is true the
                // heal tick must not connect-probe the rendezvous (the
                // probe would supersede this very link on the beacon).
                // The link is up: a return that was owed is paid (and the visit
                // lasts its dwell time), and the next `NeighborDown` is a loss
                // again until we release it anew.
                state.note_rendezvous_link_up(Instant::now());
                state.rendezvous_flags.remove(&RendezvousFlag::SessionStale);
                state
                    .rendezvous_flags
                    .remove(&RendezvousFlag::OfferFallback);
                // This link settles the arbitration: someone holds the port
                // a pending free verdict read as free.
                state.forget_rendezvous_verdict();
            } else {
                // `NeighborUp`/`NeighborDown` are the only writers of
                // `linked_endpoints`: it must mirror the *live* overlay
                // links, because the silent-partition WARN and the
                // re-bridge gate read it as link truth. (A `PeerInfo`
                // used to insert here optimistically — before any link
                // formed — leaving permanent ghosts that suppressed
                // both; see the 2026-06-12 roster-collapse review.)
                state.link(node_id);
                // A linked neighbour is a path for a proof request (the send dials it in the background):
                // the asks that waited for one to this endpoint go now, and not at the next sweep tick.
                // The late link of the simultaneous-open tie-break comes up a few milliseconds after the
                // ask was skipped.
                lifecycle::retry_deferred_asks(state, context, Some(node_id)).await;
                // A new neighbor: the underlay may owe it a session, and may take
                // its signal.
                #[cfg(feature = "multihop")]
                underlay_webrtc::tick_now(state);
                if state.relay_transport.relay_allowed() {
                    state.observe_path(node_id, connection);
                } else {
                    // The accept gate and the graft probe both admit a link
                    // only on a selected non-relay path, so a link up is the
                    // proof; `conn_path` cannot see which path is selected.
                    state.direct.insert(node_id, DirectState::Direct);
                }
                // A frame parked across a gap in the links waits for the next link:
                // `meshed` stays set through the gap, so the first-link edge below
                // does not come again, and a `PeerInfo` may not either.
                if state.standing.contains(&Standing::Meshed) && !state.pending_outbound.is_empty()
                {
                    flush_pending(state, context, "link up").await;
                }
                // First link to a *real* peer: now (and only now) can
                // user content actually be delivered. Flush anything
                // buffered while we were unmeshed, in order.
                if !state.standing.contains(&Standing::Meshed) {
                    mesh_on_first_link(state, app, context).await;
                }
                // The vector names the address of our underlay, and a neighbor that holds it
                // can offer a session at once: it does not wait for the 15 s tick, which would
                // leave the first session for the moment that the relay watcher closes the
                // links that stayed on the relay.
                #[cfg(feature = "multihop")]
                event_loop::linkstate_now(state, context).await;
                super::heal::release_rendezvous_if_due(state, context).await;
            }
        }
        Some(Ok(Event::NeighborDown(node_id))) => {
            let is_rendezvous = node_id == context.rendezvous_id;
            tracing::info!(target: "habilis_network::gossip", local = %context.endpoint.id().fmt_short(), endpoint_id = %node_id, is_rendezvous, "gossip neighbor down");
            if is_rendezvous {
                rendezvous_neighbor_down(state, context, node_id);
            } else {
                state.unlink(node_id);
                let spread = rand::Rng::random_range(&mut rand::rng(), -1.0..=1.0);
                state.plan_regraft_on_link_loss(node_id, Instant::now(), spread);
                if let Some(address) = state.relay_race_on_link_loss(node_id, Instant::now()) {
                    webrtc::negotiate_session::negotiate_session(state, context, node_id, address);
                }
            }
            if arms_reclaim(
                is_rendezvous && !state.rendezvous_flags.contains(&RendezvousFlag::Released),
                state.linked_endpoints.len(),
                !state.rendezvous_flags.contains(&RendezvousFlag::Linked)
                    && state.rendezvous_wanted(),
            ) {
                state.arm_reclaim(Instant::now());
                tracing::info!(target: "habilis_network::gossip",
                    reason = if is_rendezvous {
                        "rendezvous-loss"
                    } else if state.linked_endpoints.is_empty() {
                        "last-peer"
                    } else {
                        "beaconless"
                    },
                    "armed fast reclaim window"
                );
            }
        }
        Some(Ok(Event::Lagged)) => {
            // Upstream reports the lag and keeps the subscription open (it
            // does not close it, whatever its docs say): the split counts it
            // on the transport handle, and this arm only tells the user. A
            // terminal `None` is another event, handled below.
            context.sink.emit(NodeEvent::Info(
                "Event stream lagged, some messages may have been missed".to_owned(),
            ));
            tracing::warn!(target: "habilis_network::gossip", "gossip event stream lagged; some messages missed");
        }
        Some(Err(error)) => {
            context
                .sink
                .emit(NodeEvent::Error(format!("Gossip error: {error}")));
            tracing::warn!(target: "habilis_network::gossip", %error, "gossip error");
        }
        None => {
            // Terminal: the actor closed this subscription (lag
            // eviction) or died. The heal arm re-subscribes; meanwhile
            // IPC msg/poll keep serving the local buffer.
            //
            // `warn`, not `error`: this is recovered automatically, and the
            // case where recovery is genuinely exhausted has an `error` of
            // its own (`Resubscribe::Fatal`, which then shuts the daemon
            // down). Logging both at the same level buried the one that
            // means the node is finished under the one that means it is
            // reconnecting.
            state.standing.remove(&Standing::GossipOpen);
            context.sink.emit(NodeEvent::Error(
                "gossip stream ended; resubscribing".to_owned(),
            ));
            tracing::warn!(target: "habilis_network::gossip", "gossip stream ended; heal arm will resubscribe");
        }
    }
}

/// The rendezvous neighbour went down. A link we let go of on purpose is no
/// loss: there is nothing to detach, to offer again, or to re-graft, and the
/// rule that released it also says when to come back.
///
/// A `NeighborDown` that the beacon's own `HyParView` caused (it drops a random
/// member when its view is full) reads as a loss here and arms a reclaim on a
/// node with links enough. That costs one probe, and is left as it is.
fn rendezvous_neighbor_down(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    node_id: iroh::EndpointId,
) {
    state.rendezvous_flags.remove(&RendezvousFlag::Linked);
    // The holder is gone, so the identity is up for arbitration
    // again and any earlier reading of it is spent.
    state.forget_rendezvous_verdict();
    if state.rendezvous_flags.contains(&RendezvousFlag::Released) {
        return;
    }
    // The holder is gone, so a round that is still dialling it is moot, and its slot would refuse
    // the re-offer below for the rest of the round deadline.
    state.cancel_rendezvous_round();
    // A shed beacon takes its session table with it (the rival
    // re-check releases and re-claims the rendezvous on a fresh
    // endpoint), so a held session is stale the moment the link
    // drops — and admission would refuse every re-offer with
    // `HaveSession`. Drop it so the next heal tick offers anew.
    if let Some(handle) = state.webrtc.as_ref()
        && handle.detach(&node_id)
    {
        tracing::debug!(target: "habilis_network::gossip", "detached the stale rendezvous webrtc session");
    }
    // Re-offer now rather than on the next heal tick: every
    // saved interval halves the relink cycle a beacon shed costs
    // a webrtc-shaped peer.
    webrtc::rendezvous::offer_rendezvous_off_tick(state, context);
}

/// Whether a `NeighborDown` should arm the fast reclaim burst — the
/// event-driven half of beacon failover, as opposed to waiting out a heal
/// tick.
///
/// Three signals, all meaning "there may be no beacon and we could be the one
/// to stand it up":
///
/// - `rendezvous_lost` — the link we lost *was* the beacon, and we did not let
///   it go on purpose.
/// - `links_left == 0` — that was our last tracked peer; we are isolated.
/// - `!rendezvous_linked` — we hold no live beacon link at all, and want one
///   (`rendezvous_wanted`: a node with enough links to others has let go of it
///   on purpose). This is the case the first two miss and the one the
///   kill-the-producer drill lives in:
///   two tabs plus an origin, the origin dies, and each tab is still linked to
///   the other. Not isolated, and the tab that meshed via the origin's *peer*
///   endpoint never had a rendezvous link to lose — so nothing armed, and
///   failover waited out the 15s heal cadence.
///
/// The narrow gate this replaces existed to keep a plain `HyParView` shuffle (a
/// peer flapping while others remain) from making initial multi-node
/// convergence pay a needless ~6s bind storm on every non-beacon node. That
/// storm needed a *claim*, and a claim needs a probe that says the rendezvous
/// is free — which during convergence it is not. The probe could only say so
/// because it was dialing an id it had no way to resolve; see
/// `beacon::spawn_rival_probe`. **This widening is only safe with that fix**:
/// a convergence-time probe now finds the origin's beacon and nobody binds.
///
/// Losing the rendezvous arms it even when this node has links enough to be
/// done with the beacon: it may be dead, and failover needs someone to notice.
/// Losing a link we released on purpose is no loss, and arms nothing.
fn arms_reclaim(
    rendezvous_lost: bool,
    links_left: usize,
    beacon_wanted_but_unlinked: bool,
) -> bool {
    rendezvous_lost || links_left == 0 || beacon_wanted_but_unlinked
}

/// Drain the message payloads a dead subscription buffered before its
/// stream ended, so they reach the app instead of vanishing. The gossip
/// actor already counts them as delivered — its overlay dedup will
/// *not* re-push them, and anti-entropy resends of them are likewise
/// dropped below the app — so the buffer is the only copy this node
/// will ever see. Only `Received` payloads are processed: neighbor
/// up/down from a dead subscription is stale link state the fresh
/// subscription re-derives immediately.
pub(crate) async fn drain_dead_receiver(
    receiver: &mut api::GossipReceiver,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    use futures_util::{FutureExt as _, StreamExt as _};
    let mut recovered = 0usize;
    loop {
        match receiver.next().now_or_never() {
            Some(Some(item @ Ok(Event::Received(_)))) => {
                // A buffered frame goes to the transport, as in the split: it is not a message.
                if super::split::route_and_deliver(&item, state.gossip_handle.as_ref())
                    != super::split::Route::Data
                {
                    continue;
                }
                if let Ok(Event::Received(incoming)) = item {
                    ingest(incoming.content, state, app, context).await;
                    recovered += 1;
                }
            }
            // Skip stale membership events / errors; stop on a terminal
            // `None` (the stream's actual end) or an empty buffer.
            Some(Some(_)) => {}
            Some(None) | None => break,
        }
    }
    tracing::info!(target: "habilis_network::gossip",
        recovered,
        "drained buffered messages from the dead gossip subscription"
    );
}

/// Hand to the app the mesh messages that the old subscription already queued for it, before
/// the resubscribe drops that queue. The loop does not read the queue while the topic is marked
/// closed, yet the old splitter keeps filling it until its receiver is dropped, and the gossip
/// layer has counted each message as delivered: the queue holds the only copy. A message that
/// arrives after this drain and before the drop is the residue; the resend repairs it (see
/// `transport::outbox` and the nonce of the resend).
pub(crate) async fn drain_queued<S>(
    receiver: &mut super::split::MeshReceiver<S>,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    use futures_util::FutureExt as _;
    let mut recovered = 0usize;
    while let Some(Some(item)) = receiver.next().now_or_never() {
        if let Ok(Event::Received(incoming)) = item {
            ingest(incoming.content, state, app, context).await;
            recovered += 1;
        }
    }
    tracing::info!(target: "habilis_network::gossip",
        recovered,
        "drained the messages that the old subscription had queued"
    );
}

/// Drain `pending_outbound` onto the wire, in order. Runs on the meshed
/// edges — the first real-peer `NeighborUp`, and a degraded node's first
/// inbound message after a fault (starvation recovery / resume) — and again
/// on every later `NeighborUp` and `PeerInfo` arrival while frames remain buffered: a frame that
/// fails to deliver (typically a directed frame whose addressee's endpoint
/// isn't known yet at the first flush) is re-buffered for that retry, not
/// dropped.
pub(crate) async fn flush_pending(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    edge: &'static str,
) {
    let mut delivered = 0usize;
    let mut requeued = 0usize;
    for (message, bytes) in state.pending_outbound.take() {
        // Re-route each frame through the send decision rather than blanket-
        // broadcasting: a directed frame buffered while unmeshed must still
        // take unicast, never the gossip flood.
        match transport::deliver(&message, bytes.clone(), state, context.sender).await {
            Ok(Delivered::Done) => delivered += 1,
            Ok(Delivered::Pending(handle)) => {
                delivered += 1;
                watch_flush(handle, message, bytes, state.flush_failed.clone());
            }
            Err(error) => {
                if requeue(state, context, message, bytes) {
                    requeued += 1;
                    tracing::debug!(target: "habilis_network::gossip", %error, "buffered outbound message not deliverable yet; requeued");
                } else {
                    tracing::warn!(target: "habilis_network::gossip", %error, "buffered outbound message undeliverable and the buffer is full; dropped");
                }
            }
        }
    }
    tracing::info!(target: "habilis_network::gossip",
        delivered,
        requeued,
        edge,
        "meshed: flushed buffered messages"
    );
}

/// A flushed frame whose unicast leg runs on a task. If the dial or the write fails, the frame goes
/// back to the loop through `failed`, which buffers it again as a flush does for a frame that cannot
/// be delivered yet: a failed dial never loses a buffered frame.
fn watch_flush(
    handle: transport::PendingSend,
    message: Verified,
    bytes: WireFrame,
    failed: mpsc::UnboundedSender<(Verified, WireFrame)>,
) {
    n0future_task::spawn(async move {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::debug!(target: "habilis_network::gossip", %error, "buffered outbound message not delivered; requeued");
                let _ = failed.send((message, bytes));
            }
            Err(_) => {
                let _ = failed.send((message, bytes));
            }
        }
    });
}

/// A frame of a flush whose dial failed, back on the loop: put it in `pending_outbound` again.
pub(crate) fn requeue_failed(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    message: Verified,
    bytes: WireFrame,
) {
    if !requeue(state, context, message, bytes) {
        tracing::warn!(target: "habilis_network::gossip", "buffered outbound message undeliverable and the buffer is full; dropped");
    }
}

/// Put a frame that failed to deliver back in `pending_outbound`. A frame that is held for a lane
/// peer asks for its session, at every flush: a frame that was parked before the peer was known has
/// no other chance to ask, and without the session the lane pair never links. Returns whether the
/// frame was kept.
fn requeue(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    message: Verified,
    bytes: WireFrame,
) -> bool {
    super::merge_ctx::park_and_offer(state, context, &message, &bytes);
    state.pending_outbound.push((message, bytes))
}

/// Tests only: whether the hook that names a frame asked the node to drop this one before the app
/// reads it, as a full queue between the gossip layer and the loop does.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
fn dropped_by_test_hook(state: &mut EventLoopState, message: &Verified) -> bool {
    use crate::daemon::state::TestDrop;
    let drops = match &state.test_drop {
        Some(TestDrop::AppBody(body)) => {
            matches!(message.kind, MessageKind::App { .. }) && message.body.as_str() == body
        }
        Some(TestDrop::StateChange) => matches!(message.kind, MessageKind::State),
        None => false,
    };
    if drops {
        state.test_drop = None;
        state.test_drops_fired += 1;
        tracing::debug!(target: "habilis_network::gossip", "test hook: dropped an inbound frame");
    }
    drops
}

#[cfg(not(all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
fn dropped_by_test_hook(_state: &mut EventLoopState, _message: &Verified) -> bool {
    false
}

/// The first [`VERSION_TEXT_MAX`] characters of a version that a sender chose, each one that is not
/// printable ASCII replaced by `?`. The frame is not verified, so the text is hostile: this bounds
/// the error line and the set of named versions, whatever the sender wrote.
fn printable_prefix(version: &str) -> String {
    version
        .chars()
        .take(VERSION_TEXT_MAX)
        .map(|ch| if ch.is_ascii_graphic() { ch } else { '?' })
        .collect()
}

/// The longest version text that an error line names.
const VERSION_TEXT_MAX: usize = 16;

/// Say that an inbound frame did not parse. A frame of another protocol version names it, once for
/// each version: the key of the sender is not proven before the frame parses, so a sender could
/// make up keys, and the set of named versions is bounded.
fn report_unparsed(error: &MessageError, state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    if let MessageError::UnsupportedVersion(wire_version) = error {
        let version = printable_prefix(wire_version);
        // The frame is not verified, so the log obeys the same cap as the error lines.
        if let Some(line) = state.receive_memory.refused_version_line(&version) {
            context.sink.emit(NodeEvent::Error(line));
            tracing::warn!(target: "habilis_network::gossip", %version, "dropping a frame of an unsupported protocol version");
        }
        return;
    }
    context
        .sink
        .emit(NodeEvent::Error("Failed to parse message".to_owned()));
    tracing::warn!(target: "habilis_network::gossip", "failed to parse inbound gossip message");
}

/// Validate + dispatch one inbound wire message, regardless of transport. Both
/// the gossip event pump (`handle_gossip_event`) and the unicast inbound arm
/// (`daemon::event_loop`) funnel here, so signature-verify, the mesh gate, and
/// `mark_seen` dedup are identical on both planes — a message delivered over
/// both surfaces exactly once. The frame is a [`Verified`] from the first check on: a directed frame
/// sealed to us is decrypted on a plain copy before surfacing (see `gate_and_decrypt`), and the log
/// keeps the verified ciphertext.
///
/// This is the wrapper for the gossip plane: the census counts the frame as arrived by gossip. A
/// caller on another plane must call [`ingest_from`] with its plane.
pub(crate) async fn ingest(
    frame: Bytes,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    ingest_from(Plane::Gossip, frame, state, app, context).await;
}

/// [`ingest`] for a frame that came on `plane`: the census counts a repeat by it.
pub(crate) async fn ingest_from(
    plane: Plane,
    frame: Bytes,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    let shape = FrameShape::of(&frame);
    state.idle.wire_in.note_received(&shape);
    let (message, resend_nonce) = match Message::parse_wire(&frame) {
        Ok(parsed) => parsed,
        Err(error) => {
            report_unparsed(&error, state, context);
            return;
        }
    };
    // Authenticity gate, **before** the self-echo drop, dedup, and every other step: every inbound
    // message must carry a valid signature over its canonical bytes. Verifying before `mark_seen`
    // stops a forged/unsigned message from poisoning the dedup window with a replayed id and
    // suppressing the genuine signed copy. Relayed and anti-entropy copies keep their original
    // author's signature, so they verify here too. Canonical bytes are computed once and reused for
    // the verify, the content hash at the log site, and the shard/retain steps below.
    let (verified, canonical) = match message.verify_canonical() {
        Ok(checked) => checked,
        Err(message) => {
            tracing::warn!(target: "habilis_network::gossip", author = %message.author, "dropping message with missing/invalid signature");
            return;
        }
    };
    // Self-echo drop: keyed on our **public key**, not the nickname. With
    // non-unique display names a peer may legitimately share our nickname —
    // only our own signing key identifies our own echoed broadcasts. The
    // key is taken once at loop setup (`ctx.our_pubkey`), so this is a 32-byte
    // compare, not a key derivation per message. It runs after verify: a forged
    // copy that claims our key is counted as invalid above, not dropped here.
    if verified.key() == context.our_pubkey {
        return;
    }
    if dropped_by_test_hook(state, &verified) {
        return;
    }
    tracing::trace!(target: "habilis_network::gossip", author = %verified.author, "gossip message received");
    // Mesh gate: the gossip topic already isolates honest meshes, but a peer
    // crafted onto our topic could stamp an arbitrary (signed) `mesh` string
    // that would otherwise flow unchecked into the `--output json` agent API.
    // Drop anything not stamped with our own mesh id.
    if verified.mesh != *context.mesh {
        tracing::warn!(target: "habilis_network::gossip", author = %verified.author, "dropping message stamped with a foreign mesh id");
        return;
    }
    // Starvation watchdog signal, *before* dedup: even a duplicate
    // delivery proves the mesh carries traffic. On the degraded→meshed
    // edge (recovery succeeded) the outbound buffer flushes here.
    if state.note_inbound(Instant::now()) {
        flush_pending(state, context, "inbound traffic resumed").await;
    }
    // Duplicate suppression: a true repeat delivery must not
    // re-heartbeat, re-run membership, re-push, re-log, or re-print.
    // Keyed on the author-bound dedup key (`SHA-256(pubkey ‖ id)`), so a peer
    // signing its own message under a **victim's** id gets a different key and
    // cannot suppress the victim's genuine message. Re-broadcasts of
    // `joined`/`Alive` mint fresh ids so they are never falsely suppressed
    // here. Only authenticated messages reach this gate.
    if state.mark_seen(&verified) {
        state.idle.duplicates += 1;
        state
            .idle
            .wire_in
            .note_dup(&shape, Arrival::of(plane, resend_nonce));
        restore_lost_proof(&verified, state, app, context).await;
        return;
    }
    state.idle.fresh += 1;
    state.idle.wire_in.note_fresh(&shape);
    // Identity is the signing key, not the nickname (p2panda-style): the
    // signature above authenticates the *key*; the `author` nickname is a
    // non-unique display label and is deliberately **not** pinned/claimed,
    // so a nickname is never "burned" by a restart on a long-lived mesh.
    // Identities are distinguished by their key fingerprint, not the name.
    // Fork (equivocation) detection and DAG folding happen at the log-push
    // site below, coupled to retention so their indexes stay bounded by the
    // log window.

    // Heartbeat + membership + surfacing + join horizon. The lifecycle
    // layer owns every roster/presentation side effect; the gossip
    // layer only routes by kind below.
    messages::log_in(&verified);
    let Some(observed) = roster_gate(&verified, state, app, context).await else {
        return;
    };
    let surfaceable = observed.surfaceable;
    if observed.update.joined_new {
        greet_new_peer(&verified, state, context).await;
    }

    // A shard of a split body never surfaces as a raw slice — see
    // `handle_shard` for the retain/reassemble/gate/surface sequence.
    if verified.shard.is_some() {
        handle_shard(
            InboundFrame {
                message: &verified,
                canonical: &canonical,
                surfaceable,
            },
            state,
            app,
            context,
        )
        .await;
        return;
    }

    // Directed frames are sealed to their addressee. A **relay** forwards the
    // opaque frame and never validates, surfaces or retains its content (it can't read it, and
    // `maybe_push_inbound` is gated to the addressee). The **addressee** decrypts the body in place, then the
    // recovered plaintext passes the app boundary gate exactly as a broadcast
    // does. A frame sealed to us that fails to open (tampered / wrong key) is
    // dropped. Retention gets the original `verified` frame, so the log keeps
    // the ciphertext the author signed.
    //
    // The gate hands back the view to surface, which holds the plaintext body. The
    // classification is computed once there, so the push and retain steps never
    // re-parse the payload. `None` for an infra frame (no app payload).
    let (app_class, view) = match gate_and_decrypt(&verified, state, context, &*app) {
        Gated::Pass { class, view } => (class, view),
        Gated::Drop => return,
    };

    maybe_push_inbound(context, &view, surfaceable, app_class.as_ref());

    // `true` means the kind is fully handled and never reaches retention.
    let stop = match &view.kind {
        // The app-payload seam: dispatch RPC legs / chat / task frames.
        // `false` means the frame is plumbing or addressed elsewhere —
        // stop before retention.
        MessageKind::App { .. } => {
            !app.on_app_frame(
                InboundApp {
                    message: &view,
                    surfaceable,
                },
                state,
                context,
            )
            .await
        }
        // Everything the engine owns itself. Spelled out rather than `_` so
        // a new kind has to be routed deliberately.
        MessageKind::Presence { .. }
        | MessageKind::PeerInfo
        | MessageKind::Digest
        | MessageKind::Ping
        | MessageKind::Pong { .. }
        | MessageKind::ProofRequest { .. }
        | MessageKind::State
        | MessageKind::StateDigest
        | MessageKind::Meta
        | MessageKind::MetaDigest
        | MessageKind::LinkState => dispatch_infra(
            &verified,
            surfaceable,
            &observed.update,
            state,
            app,
            context,
        )
        .await
        .is_break(),
        _ => false,
    };
    if stop {
        return;
    }

    if retained_after_lifecycle(&observed.update, &verified.kind) {
        retain_and_index(
            verified,
            RetainMeta {
                canonical: &canonical,
                class: app_class.as_ref(),
                wire_len: None,
            },
            state,
            context,
        );
    }
}

/// The engine's own message kinds: presence, peer info, digests, ping/pong,
/// channel events, link state.
///
/// [`ControlFlow::Break`] means the kind is fully handled here and must not
/// reach retention — which is every arm but `Presence`, whose frame is still
/// logged like any other. Split out of [`ingest`] because ten arms of routing
/// sat between that function's gate and its retention step, and only one of
/// them was the app seam the gate exists for.
async fn dispatch_infra(
    message: &Verified,
    surfaceable: bool,
    update: &MembershipUpdate,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) -> ControlFlow<()> {
    match &message.kind {
        MessageKind::PeerInfo => {
            // A stale frame proves no presence: it registers no endpoint and starts no dial.
            if !update.stale {
                handle_peer_info(message, state, context).await;
            }
            return ControlFlow::Break(());
        }
        MessageKind::Digest => {
            antientropy::handle_digest(message, state, &context.our_pubkey);
            return ControlFlow::Break(());
        }
        MessageKind::Ping => {
            auto_pong(message, state, context).await;
            return ControlFlow::Break(());
        }
        MessageKind::Pong { to, probe } => {
            // Record the RTT for the active round only if addressed to us, from a
            // known peer, and naming a probe of this round — the roster gate
            // bounds the map and keeps `responded`/`known` honest against a peer
            // that forges pongs from fabricated authors, and the probe id drops a
            // pong that answers a round that is over.
            if *to == context.our_pubkey
                && state.peers.contains(&message.key())
                && let Some(round) = state.ping_round.as_mut()
            {
                let known = round.record_pong(
                    message.key(),
                    message.author.clone(),
                    probe,
                    TokioInstant::now(),
                );
                if !known {
                    tracing::debug!(target: "habilis_network::gossip", pong_from = %message.author, "pong names no probe of this round");
                }
            }
            return ControlFlow::Break(());
        }
        MessageKind::State => {
            dispatch_channel(
                ChannelEvent {
                    channel: Channel::State,
                    message,
                    surfaceable,
                },
                state,
                app,
                context,
            );
            return ControlFlow::Break(());
        }
        MessageKind::StateDigest => {
            antientropy::handle_state_digest(Channel::State, message, state, context).await;
            return ControlFlow::Break(());
        }
        MessageKind::Meta => {
            dispatch_channel(
                ChannelEvent {
                    channel: Channel::Meta,
                    message,
                    surfaceable,
                },
                state,
                app,
                context,
            );
            return ControlFlow::Break(());
        }
        MessageKind::MetaDigest => {
            antientropy::handle_state_digest(Channel::Meta, message, state, context).await;
            return ControlFlow::Break(());
        }
        MessageKind::LinkState => {
            if handle_link_state(message, state) {
                probe::nudge_climbing_pairs(state, context, true);
            }
            return ControlFlow::Break(());
        }
        MessageKind::Presence { subtype } => {
            lifecycle::handle_presence(
                lifecycle::PresenceEvent {
                    message,
                    subtype: *subtype,
                    update,
                    surfaceable,
                },
                state,
                app,
                context,
            )
            .await;
        }
        MessageKind::App { .. } => unreachable!("the app seam is handled by `ingest`"),
        MessageKind::ProofRequest { to } => {
            answer_proof_request(to, message, state, context).await;
            return ControlFlow::Break(());
        }
        _ => {}
    }
    ControlFlow::Continue(())
}

/// The roster gate of a received frame. The proof in a `joined` frame comes first, so a session that
/// proves its nickname is admitted by the frame that carries the proof. `None` means: drop the
/// frame, a membership frame of a session that claims a nickname that another member holds. A
/// refused `alive` still asks the session for its proof, and the answer comes as a `joined` frame
/// that this gate admits. A refused frame of another kind goes on as a data frame, and changes no
/// roster entry ([`lifecycle::Observed::refused`]). An admitted frame is observed.
async fn roster_gate(
    verified: &Verified,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) -> Option<lifecycle::Observed> {
    let joined = matches!(
        verified.kind,
        MessageKind::Presence {
            subtype: PresenceSubtype::Joined
        }
    );
    // Read before the proof is held: whether this frame leaves its sender in the roster. A proof that binds a
    // nickname ends the sessions of other members under it only for a sender that is there.
    let claimant_enters = joined && membership_update::leaves_sender_in_roster(verified, state);
    if joined && state.note_joined_proof(verified, context.mesh, context.author, claimant_enters) {
        let line = format!(
            "The nickname {} is held by another member with another key. The two nodes do not accept the frames of each other",
            context.author
        );
        tracing::warn!(target: "habilis_network::lifecycle", nickname = %context.author, "our nickname is held by another member");
        context.sink.emit(NodeEvent::Error(line));
    }
    end_displaced_sessions(verified, state, app, context).await;
    let admitted = state.admits_session(verified, context.author);
    if admitted {
        if let Some(run) = state.newer_run_of_our_member(verified, context.author) {
            let line = format!(
                "Another, newer run of this member is active (run {run}): this node is superseded: stop it"
            );
            tracing::warn!(target: "habilis_network::lifecycle", run, "a newer run of our member is active");
            context.sink.emit(NodeEvent::Error(line));
        }
        // A proof that was held while its sender was out of the roster ends the sessions of other members under
        // the nickname when the sender enters it, and before its arrival is shown.
        if state.proofs.is_waiting_to_evict(&verified.key())
            && membership_update::leaves_sender_in_roster(verified, state)
        {
            state.evict_for_waiting_claimant(verified);
            end_displaced_sessions(verified, state, app, context).await;
        }
        return Some(lifecycle::observe(verified, state, context));
    }
    // A goodbye is signed by the key that leaves, whatever nickname the frame names: the gate refuses the
    // nickname, not the departure of a key of the roster, so the session of that key ends.
    let goodbye = matches!(
        verified.kind,
        MessageKind::Presence {
            subtype: PresenceSubtype::Left
        }
    );
    let key = verified.key();
    if goodbye && (state.peers.contains(&key) || state.quiet.contains(&key)) {
        let signed = lifecycle::Goodbye::Signed(verified);
        lifecycle::end_session(key, signed, state, app, context).await;
        return None;
    }
    if !is_membership_kind(&verified.kind) {
        if matches!(verified.kind, MessageKind::PeerInfo) {
            retain_refused_peer_info_address(verified, state);
        }
        return Some(lifecycle::Observed::refused());
    }
    let alive = matches!(
        verified.kind,
        MessageKind::Presence {
            subtype: PresenceSubtype::Alive
        }
    );
    if alive {
        lifecycle::ask_for_proof(verified, state, context).await;
    }
    None
}

/// A copy of a `joined` frame gives back the proof that the book lost for its session, and nothing else. A
/// member signs its answer to a proof request once for each run, so an asker that dropped the proof of that
/// session (the session left the roster and came back) gets the same frame again, and the frame is a
/// duplicate there. Only a session that is in the roster gets its proof back: a copy for any other session
/// keeps nothing, so a flood of old copies cannot fill the book. The copy is no arrival and no heartbeat.
async fn restore_lost_proof(
    verified: &Verified,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    let joined = matches!(
        verified.kind,
        MessageKind::Presence {
            subtype: PresenceSubtype::Joined
        }
    );
    let key = verified.key();
    let in_roster = state.peers.contains(&key) || state.quiet.contains(&key);
    if !joined || !in_roster || verified.joined_proof().is_none() {
        return;
    }
    if state.proofs.proof_of(&key).is_some() {
        return;
    }
    state.note_joined_proof(verified, context.mesh, context.author, true);
    end_displaced_sessions(verified, state, app, context).await;
}

/// End the sessions that a proof displaced: the sessions of other members under a nickname that the proof bound
/// (with no `left` line for a session that was never shown), and the older sessions of a member whose newer run
/// came: a restart leaves no ghost until the timeout.
async fn end_displaced_sessions(
    verified: &Verified,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    for intruder in state.proofs.take_evicted() {
        let goodbye = lifecycle::Goodbye::Refused(&verified.author);
        lifecycle::end_session(intruder, goodbye, state, app, context).await;
    }
    for older in state.proofs.take_replaced() {
        let goodbye = lifecycle::Goodbye::Replaced(&verified.author);
        lifecycle::end_session(older, goodbye, state, app, context).await;
    }
}

/// Whether a frame of this kind changes the roster or the routes of a peer. The gate refuses these
/// from a session that claims a nickname that another member holds. A `PeerInfo` is not one of
/// them: it only gives an address, and a session that asks for a proof needs one. The frames that
/// carry data (app, state, meta, digests) are never refused here; they are stored and relayed, and
/// they change no roster entry.
fn is_membership_kind(kind: &MessageKind) -> bool {
    matches!(
        kind,
        MessageKind::Presence { .. }
            | MessageKind::Ping
            | MessageKind::Pong { .. }
            | MessageKind::LinkState
    )
}

/// Fold a received multihop link-state advertisement into the routing table. The
/// author's own measured links + underlay address (`body` = a serialized
/// `LinkVector`) supersede the last vector we held for that origin. Dropped
/// silently when the multihop transport is off or the body is malformed —
/// plumbing like the digests, never logged or surfaced. Returns whether the topology changed.
fn handle_link_state(message: &Verified, state: &mut EventLoopState) -> bool {
    #[cfg(not(feature = "multihop"))]
    {
        // No multihop transport off-host: nothing consumes a routing table.
        let _ = (message, state);
        false
    }
    #[cfg(feature = "multihop")]
    {
        let Some(handle) = state.multihop.as_ref() else {
            return false; // multihop off: nothing consumes the routing table
        };
        let decoded: serde_json::Result<habilis_network_iroh_multihop_transport::LinkVector> =
            serde_json::from_str(message.body.as_str());
        match decoded {
            Ok(vector) => {
                // A signature proves who made the vector, not that the origin is
                // a member: anyone holding the mesh id can mint keys. So the
                // origin must be the endpoint that the signer proved, the same
                // proof that a point-to-point answer follows. A nickname is a
                // label, so the dial hint under it is no proof. A signer that has
                // proved none yet is waited for: its next vector, one interval
                // on, finds the proof.
                let signer = message.key();
                let bound = state.proven_endpoints.trusted(&signer);
                // The `PeerInfo` of the signer can be a few milliseconds behind its first
                // vector: the vector waits for the proof, and is fed when it is recorded.
                if bound.is_none() {
                    let kept = state.parked_link_states.park(signer, vector);
                    tracing::debug!(target: "habilis_network::gossip",
                        author = %message.author,
                        kept,
                        "parked multihop link-state: its signer has proved no endpoint yet"
                    );
                    return false;
                }
                if bound != Some(vector.origin().get()) {
                    tracing::debug!(target: "habilis_network::gossip",
                        author = %message.author,
                        "dropping multihop link-state: its origin is not the endpoint its signer proved"
                    );
                    return false;
                }
                let updated = handle.feed_topology(vector);
                // A vector that waited for this author is older than the one just fed.
                state.parked_link_states.take(&signer);
                tracing::debug!(target: "habilis_network::gossip",
                    author = %message.author,
                    updated,
                    "multihop link-state received"
                );
                // The vector holds the underlay address of its origin, which a
                // neighbor needs before the underlay can offer it a session.
                #[cfg(feature = "multihop")]
                if updated {
                    underlay_webrtc::tick_now(state);
                }
                updated
            }
            Err(error) => {
                tracing::debug!(target: "habilis_network::gossip",
                    author = %message.author,
                    %error,
                    "dropping malformed multihop link-state"
                );
                false
            }
        }
    }
}

/// Auto-respond to a probe with a pong addressed to the pinger. The daemon
/// owns this — no agent involvement.
///
/// Over a warm connection, or a background dial to a linked neighbor — never
/// an inline dial. Anyone who reaches this mesh can ping, and a pinger
/// advertising an address nothing answers on used to buy a full dial timeout
/// here — on the sole event loop, so every timer, IPC call and other peer's
/// traffic waited with it, once per identity the pinger cared to mint. A pong
/// nobody receives is the right outcome: the pinger's round misses us and
/// tries again.
async fn auto_pong(message: &Verified, state: &EventLoopState, context: &HandlerCtx<'_>) {
    let (answer, target) = pong_for(message, state, context);
    messages::log_out(&answer);
    match (target, answer.serialize()) {
        (Some(eid), Ok(bytes)) => {
            if !transport::send_best_effort(eid, bytes, state).await {
                tracing::debug!(target: "habilis_network::gossip", pinger = %message.author, "auto-pong skipped: no warm path");
            }
        }
        _ => {
            tracing::debug!(target: "habilis_network::gossip", pinger = %message.author, "auto-pong skipped: no known endpoint");
        }
    }
}

/// Answer a proof request that names this node with a `joined` frame that carries the proof of
/// this session, sent to the asker alone over a warm path. The path is checked before the answer
/// takes a slot of the per-minute cap, so an answer that cannot go out costs no slot. No warm path
/// means no answer, and the asker asks again by the retry rule of the proof exchange. A send that
/// fails after the slot was taken keeps the slot and the 60 s window of the asker, so the first retry
/// that can work is the one at 90 s: the one at 30 s is refused.
async fn answer_proof_request(
    to: &AuthorKey,
    message: &Verified,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) {
    let Some(eid) = return_path(state, &message.key()) else {
        tracing::debug!(target: "habilis_network::gossip", asker = %message.author, "proof answer skipped: no warm path");
        return;
    };
    let Some(answer) = state.proof_answer(
        to,
        &message.key(),
        context.author,
        context.mesh,
        Instant::now(),
    ) else {
        return;
    };
    messages::log_out(&answer);
    let sent = match answer.serialize() {
        Ok(bytes) => transport::send_best_effort(eid, bytes, state).await,
        Err(_) => false,
    };
    if !sent {
        tracing::debug!(target: "habilis_network::gossip", asker = %message.author, "proof answer skipped: the send failed");
        return;
    }
    keep_the_answer(state);
}

/// The endpoint that the answer to a proof request from `asker` goes to.
fn return_path(state: &EventLoopState, asker: &AuthorKey) -> Option<iroh::EndpointId> {
    // The address in the roster may be the old one of an asker that moved: it counts only when a unicast can
    // start on it, as for the arrival.
    let known = state
        .address_of(asker)
        .map(|address| address.id)
        .filter(|eid| transport::can_unicast(*eid, state));
    // A request can come before the `PeerInfo` of its sender: then the connection that it arrived on is
    // the return path, if a unicast can start on it.
    let arrival = state
        .state_digest_serves
        .unicast
        .arrived_from
        .filter(|eid| transport::can_unicast(*eid, state));
    known
        .or(arrival)
        .filter(|eid| Some(*eid) != state.rendezvous_id)
}

/// Keep the proof answer of this run in the log of its author, once. The answer is a signed `joined` frame
/// that every asker holds from now on, and the same frame for every asker: a peer that holds a frame of its
/// author that the author never kept resends it to her at every digest round, forever, and a fresh frame
/// for each asker would spread through the mesh by anti-entropy, one for each asker.
fn keep_the_answer(state: &mut EventLoopState) {
    if let Some(answer) = state.take_answer_to_keep() {
        retain_own_broadcast(state, answer);
    }
}

/// The pong that answers `ping`, and where it goes: the endpoint that the signer of the ping proved
/// in its `PeerInfo`, unless it is the rendezvous. The roster's trust of the key comes first, because
/// it has no cap, and the proof table is a FIFO that a roster key can fall out of. The nickname on
/// the ping is a label that any signer can take, so the dial hint under that nickname can name the
/// endpoint of another key. A signer that has proved no endpoint gets no target, and so no pong. A
/// warm connection does not change that: it proves which endpoint it reaches, and nothing ties the
/// key of a gossip ping to it.
fn pong_for(
    request: &Verified,
    state: &EventLoopState,
    context: &HandlerCtx<'_>,
) -> (Verified, Option<iroh::EndpointId>) {
    let signer = request.key();
    let answer =
        Message::new_pong(context.mesh, context.author, signer, &request.id).sign(context.identity);
    let proofs = &state.proven_endpoints;
    let target: Option<iroh::EndpointId> = proofs
        .trusted(&signer)
        .or_else(|| proofs.get(&signer))
        .filter(|eid| Some(*eid) != state.rendezvous_id);
    (answer, target)
}

struct InboundFrame<'message> {
    message: &'message Verified,
    canonical: &'message [u8],
    surfaceable: bool,
}

/// One shard of a split body: retain it for anti-entropy (so a missing shard
/// heals like any message) and, when its group completes, gate the
/// reassembled logical message through the application boundary and surface it once —
/// pushed and dispatched exactly like an ordinary inbound message.
async fn handle_shard(
    frame: InboundFrame<'_>,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    let InboundFrame {
        message,
        canonical,
        surfaceable,
    } = frame;
    // A directed shard (task leg / RPC) not addressed to us is relayed at the
    // gossip layer but never retained or reassembled here — a third party must
    // not persist or reconstruct a task exchange it is not part of. The
    // single-frame path hands such a frame to the app, which decides.
    if !addressed_to_us(message, &context.our_pubkey) {
        return;
    }
    // The raw shard's own per-tag policy (loggability/chain) — computed from its
    // fragment body, matching the pre-thread behavior of the internal classify.
    let kind_tag = message.kind.app_tag();
    let shard_class = kind_tag.map(|_| app.classify(&message.authored()));
    // Only a small group's shards enter the message log (anti-entropy heals
    // them like any message — point-to-point when the shard is directed, so
    // the addressee still recovers); a big group would evict the mesh's whole
    // anti-entropy history, so its shards stay out of the log — on the send
    // side too (`shard_fits_log`) — and the group heals via shard repair.
    // (RPC shards are plumbing — `retain_and_index` skips them by kind
    // either way.)
    if shard_fits_log(message) {
        retain_and_index(
            message.clone(),
            RetainMeta {
                canonical,
                class: shard_class.as_ref(),
                wire_len: None,
            },
            state,
            context,
        );
    }
    if let Some(logical) = state.reassemble(message) {
        // The same gate the single-frame path runs, now on the reassembled body:
        // unseal a directed frame sealed to us or a mesh-key-sealed broadcast,
        // then validate the payload. Shared rather than restated, so a change to
        // the gate cannot reach one path and silently miss the other. The
        // ciphertext it hands back is for `ingest`'s retention step — the shards
        // here were already retained above, as ciphertext.
        let Gated::Pass { class, view } = gate_and_decrypt(&logical, state, context, app) else {
            return;
        };
        maybe_push_inbound(context, &view, surfaceable, class.as_ref());
        // Dispatch the reassembled logical frame exactly like a single-frame one:
        // a directed RPC request/response (both shard now) reaches its handler,
        // and content surfaces. The shards were already retained above, so the
        // retain decision `on_app_frame` returns is ignored here.
        let _ = app
            .on_app_frame(
                InboundApp {
                    message: &view,
                    surfaceable,
                },
                state,
                context,
            )
            .await;
    }
}

/// Fork detection, cross-author DAG folding, and chat-log retention for a
/// surviving inbound message. Coupled to logging on purpose: only a message we
/// actually **retain** is folded into the indexes, so `by_hash`/`dag_heads`/
/// `author_seqs` stay bounded by the log window (pruned on eviction). A
/// rate-dropped chat frame, one addressed to another peer, or a `State` event
/// returned earlier and never reaches here. Only a **broadcast chat** `app_msg`
/// carries `seq`/parents; task-related `app_msg` frames (offer/context/change)
/// are presence-like — `broadcast_task` stamps them without a chain, so they
/// must stay out of the fork/DAG indexes (see the `task` glossary invariant).
/// Presence is loggable but not indexed.
#[derive(Clone, Copy)]
struct RetainMeta<'meta> {
    canonical: &'meta [u8],
    class: Option<&'meta AppClass>,
    // the wire length of the frame, when the caller holds the bytes it came in
    wire_len: Option<usize>,
}

/// Whether a frame that membership read goes into the log. A stale presence frame does not: it is
/// a copy of a departed key's `joined` or `alive`, which `drop_departed_presence` took out of the
/// log on the goodbye, and `seen` may have forgotten it since. Retained again, it would be a
/// resend subject again. A stale chat frame stays retainable: the departed key's chat is kept.
fn retained_after_lifecycle(update: &MembershipUpdate, kind: &MessageKind) -> bool {
    !(update.stale
        && matches!(
            kind,
            MessageKind::Presence {
                subtype: PresenceSubtype::Joined | PresenceSubtype::Alive
            }
        ))
}

fn retain_and_index(
    message: Verified,
    meta: RetainMeta<'_>,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) {
    let RetainMeta {
        canonical,
        class,
        wire_len,
    } = meta;
    // App frames carry the app's per-tag policy (`classify`, computed once by the
    // caller and threaded in here); infra kinds (`class == None`) use the engine's
    // own rule. A beat is plumbing — never retained/indexed.
    let loggable = class.map_or_else(|| is_loggable(&message.kind), |cls| cls.loggable());
    let beat = class.is_some_and(|cls| cls.beat());
    if !loggable || beat {
        return;
    }
    if class.is_some_and(|cls| cls.chained()) {
        let hash = ContentHash::of(canonical);
        // A second, *different* content hash at an already-seen `(author, seq)`
        // is cryptographic proof of equivocation — surface a `fork` once per
        // offending key (order-independent; we keep both).
        if let Some(seq) = message.seq
            && state.note_msg_seq(&message.key(), seq, hash)
        {
            context.sink.emit(NodeEvent::Fork {
                nickname: message.author.clone(),
                pubkey: message.key().to_string(),
                seq,
            });
            tracing::warn!(target: "habilis_network::gossip", author = %message.author, seq, "fork detected: conflicting messages at same seq");
        }
        // Fold into the DAG tip set; flag a backdated timestamp.
        if state.note_dag(hash, &message.parents, message.timestamp) {
            tracing::warn!(target: "habilis_network::gossip", author = %message.author, "message timestamp precedes a referenced parent; possible backdating");
        }
    }
    push_to_log(state, message, wire_len);
}

/// Push a retained message into the anti-entropy log, keeping the DAG + fork
/// indexes bounded with the log window as the push evicts.
pub(super) fn push_to_log(state: &mut EventLoopState, message: Verified, wire_len: Option<usize>) {
    let evicted = match wire_len {
        Some(len) => state.message_log.push_sized(message, len),
        None => state.message_log.push(message),
    };
    if let Some(evicted) = evicted {
        let evicted_hash = evicted.content_hash();
        state.forget_hash(&evicted_hash);
        if let Some(seq) = evicted.seq {
            state.forget_msg_seq(&evicted.key(), seq, &evicted_hash);
        }
    }
}

/// Retain a message **this node just broadcast** in its own anti-entropy log.
///
/// Gossip never echoes a node's own publications back to it, so a message we
/// author reaches every peer's [`ingest`] but never our own. Without this our
/// `message_log` — and so the digest we advertise — omits everything we wrote,
/// with two consequences:
///
/// * We cannot serve our own `joined` to a peer that missed it, which is the
///   one repair anti-entropy exists to make.
/// * Worse, every peer that *does* hold it reads the omission as a gap and
///   re-sends it to us on **every** digest round, forever: we can never
///   acknowledge it, because we can never receive it. Each such message is a
///   permanent per-round broadcast to the whole mesh, and since a re-announced
///   `joined` mints a fresh id, the unconvergeable set ratchets upward — the
///   mesh-wide CPU/traffic runaway this guards against.
///
/// The state/meta channel already retains its own writes for exactly this
/// reason; see [`super::broadcast_state_merge`].
pub(crate) fn retain_own_broadcast(state: &mut EventLoopState, message: Verified) {
    if !is_loggable(&message.kind) {
        return;
    }
    // Ours by construction, so it can never arrive again — but mark it seen so
    // a peer still running the old resend behaviour is deduped at the gate
    // rather than double-pushed here.
    state.mark_seen(&message);
    push_to_log(state, message, None);
}

/// Keep an app broadcast that this node sent, when the app's class says it is loggable. The same
/// reason as for [`retain_own_broadcast`]: a peer that holds the frame resends it to its author
/// on every digest round, forever, if the author's digest never lists it, and the author cannot
/// serve it to a peer that missed it. The class comes from the app, as at the ingest of a frame
/// (`retain_and_index`), so an app that does not log its frames keeps none. A directed frame is
/// not kept: its body is sealed on the way out and only its addressee may be served.
pub(crate) fn retain_own_app_broadcast(
    state: &mut EventLoopState,
    message: &Verified,
    class: AppClass,
) {
    if !class.loggable()
        || class.beat()
        || !matches!(message.kind, MessageKind::App { to: None, .. })
    {
        return;
    }
    state.mark_seen(message);
    push_to_log(state, message.clone(), None);
}

/// Route a received `State`/`Meta` event to its channel doc, then — for `meta` —
/// adopt the author's endpoint hint into the dial book. Selects the disjoint doc
/// field so the borrow released by [`ingest_channel_event`] frees `state` for the
/// address adoption.
#[derive(Clone, Copy)]
struct ChannelEvent<'message> {
    channel: Channel,
    message: &'message Verified,
    surfaceable: bool,
}

/// A node that holds no frame of another author adopts at once the epoch that a frame started: it
/// has nothing to lose. The sweep writes its entry again. A node that holds the frames of others
/// waits for [`crate::util::consts::DOC_EPOCH_ADOPT_WAIT_TICKS`] ticks of the minute timer.
fn adopt_new_epoch(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    let adopted = state
        .doc_mut(Channel::Meta)
        .adopt_if_alone(&context.our_pubkey);
    if let Some(switch) = adopted {
        state.note_epoch_switch(switch);
    }
}

fn dispatch_channel(
    event: ChannelEvent<'_>,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    let ChannelEvent {
        channel, message, ..
    } = event;
    let count_before = state.doc(channel).change_count();
    let far_ok = seed_job::far_jump_allowed(state, channel);
    match ingest_channel_event(event, state.doc_mut(channel), context, far_ok) {
        ChannelOutcome::Refused => state.idle.state_rejected += 1,
        ChannelOutcome::Repeat => state.idle.wire_in.note_content_dup(),
        ChannelOutcome::Taken => {}
    }
    if channel == Channel::Meta {
        adopt_new_epoch(state, context);
    } else {
        seed_job::adopt_far(state);
    }
    let changed = state.doc(channel).change_count() > count_before;
    if changed {
        state.fast_rounds.note_change(channel, Instant::now());
    }
    for key in state.doc_mut(channel).take_dropped() {
        state.seen.remove(&key);
    }
    if channel == Channel::Meta {
        // Post-apply hook: let the app adopt the author's endpoint hint from the
        // freshly-synced meta doc (the borrow above released `state`).
        app.on_meta_applied(&message.key(), state, context);
    }
}

/// A plaintext-bodied view of `message` for surfacing: when `plain` differs from
/// the wire body (a decrypted `enc` body), a clone with the body replaced; else
/// the original borrowed unchanged. The output helpers read `event.body` for the
/// `m` delta, so they must see plaintext.
fn surface_view(frame: &Verified, plain: Option<String>) -> Authored {
    let changed = plain.filter(|text| text != frame.body.as_str());
    let body = changed.and_then(|text| MessageBody::try_new(&text).ok());
    match body {
        Some(body) => frame.copy_with_body(body),
        None => frame.authored(),
    }
}

/// Ingest a durable channel event (`State`/`Meta`) into its `log`: dedup-insert,
/// then surface a `StateChanged` for `channel` only when the derived doc changed
/// and we're past the join horizon (a backfilling joiner updates its doc silently
/// instead of reacting to replayed intermediate states). A received event is
/// never our own (`is_self = false`). Both channels share this path verbatim.
///
/// Returns what the document made of the change.
fn ingest_channel_event(
    event: ChannelEvent<'_>,
    doc: &mut doc::MeshDoc,
    context: &HandlerCtx<'_>,
    // Whether the frame may make a far jump of epoch: the answer of the first request.
    far_ok: bool,
) -> ChannelOutcome {
    use crate::doc::Ingested;

    let ChannelEvent {
        channel,
        message,
        surfaceable,
    } = event;
    // The doc dedups by change hash, buffers out-of-order changes until their
    // deps land, retains the signed frame for re-serve, and gates card forgery
    // (the card carries the peer's cryptographic identity) — every recipient
    // applies the same gate, so a forgery converges nowhere.
    let ingested = if far_ok {
        doc.ingest_far_ok(message)
    } else {
        doc.ingest(message)
    };
    match ingested {
        Ingested::Applied {
            changed: true,
            doc: after,
        } if surfaceable => {
            // On a passworded mesh the received body is ciphertext; surface a
            // plaintext-bodied view so the human/JSON `m` delta still renders.
            // The frame retained for re-serve (inside `ingest`) stays ciphertext.
            let surfaced = surface_view(message, doc.surface_body(message));
            context.sink.emit(NodeEvent::StateChanged {
                channel,
                event: Box::new(surfaced),
                document: after,
                is_self: false,
            });
        }
        Ingested::Rejected => {
            tracing::warn!(target: "habilis_network::gossip",
                author = %message.author,
                "dropping a {} change that forges another peer's agent card",
                channel.label()
            );
            return ChannelOutcome::Refused;
        }
        Ingested::Ignored => return ChannelOutcome::Refused,
        Ingested::Duplicate => return ChannelOutcome::Repeat,
        // A root of a higher epoch is kept as the candidate: `adopt_new_epoch` reads it next.
        Ingested::Buffered | Ingested::NewEpoch { .. } | _ => {}
    }
    ChannelOutcome::Taken
}

/// What the document made of a channel event.
enum ChannelOutcome {
    /// The document refused or ignored the change.
    Refused,
    /// The document had applied this change already.
    Repeat,
    Taken,
}

/// A directed leg (a directed `app_msg` or a `Task`) is surfaced **only by
/// its addressee** — a third party relays it without ever seeing it
/// (glossary: "a third party never sees it"). Broadcast (`to: None`) and
/// non-directed kinds are for everyone. Our own echoes never reach the
/// receive path (the pubkey self-echo gate drops them earlier), so on receive
/// "addressee" is the whole rule. This is the same gate the print/log path
/// applies in `lifecycle::{handle_msg, handle_task}`.
/// A structurally **directed** app frame — one with an addressee (`to:
/// Some(_)`). Whether its body is *sealed* (encrypted to that addressee) is a
/// separate, app-driven decision ([`super::app::AppClass::sealed`]): an app's
/// directed tags arrive sealed, a plaintext-directed consumer's do not. `Pong`
/// is directed for routing but a distinct infra kind, so it is not covered here.
fn is_directed_content(kind: &MessageKind) -> bool {
    matches!(kind, MessageKind::App { to: Some(_), .. })
}

/// Outcome of the inbound gate. `Pass` carries the frame's [`AppClass`] (`class`:
/// `Some` for an App frame, classified once on the opened body; `None` for an infra
/// frame with no app payload) and the [`Authored`] view to surface, which holds the
/// plaintext body the gate opened. The frame the caller retains is untouched.
enum Gated {
    Drop,
    Pass {
        class: Option<AppClass>,
        view: Authored,
    },
}

/// Classify an App frame and enforce the app boundary gate in one parse:
/// returns the [`AppClass`] on a valid payload, `None` (logging the drop) when
/// the payload fails its frame's contract. Callers reuse the returned class
/// rather than re-classifying.
fn gate_app_payload(view: &Authored, app: &dyn NodeApp) -> Option<AppClass> {
    let class = app.classify(view);
    if class.valid() {
        Some(class)
    } else {
        tracing::warn!(target: "habilis_network::gossip",
            author = %view.author,
            "dropping app frame with an invalid payload"
        );
        None
    }
}

/// Validate + (for the addressee) decrypt an inbound **non-sharded** logical
/// frame before surfacing. The decrypted body lives only in the returned view, so
/// retention keeps the frame the author signed.
fn gate_and_decrypt<F: Proof>(
    frame: &F,
    state: &EventLoopState,
    context: &HandlerCtx<'_>,
    app: &dyn NodeApp,
) -> Gated {
    if is_directed_content(&frame.kind) {
        if !addressed_to_us(frame, &context.our_pubkey) {
            // Relay: an opaque directed frame — forwarded, never validated, surfaced or
            // retained. The engine cannot open it, so it has no classification, and an
            // `App` kind without one is not loggable (see `is_loggable`).
            return Gated::Pass {
                class: None,
                view: frame.authored(),
            };
        }
        return gate_directed_to_us(frame, state, app);
    }
    // A broadcast app frame on a passworded mesh must arrive sealed with the
    // mesh key: decrypt it so validation + surfacing see plaintext, rejecting an
    // unsealed or unopenable body (cleartext can't slip past the guarantee). Only
    // broadcast MSG is ever mesh-key sealed — a structural `App{to:None}` gate is
    // behavior-identical to the former `is_app(MSG)` one.
    if matches!(&frame.kind, MessageKind::App { to: None, .. }) && state.broadcast_key.is_some() {
        let Some(body) = decrypt_broadcast(frame, state) else {
            return Gated::Drop;
        };
        let view = frame.copy_with_body(body);
        let Some(class) = gate_app_payload(&view, app) else {
            return Gated::Drop;
        };
        return Gated::Pass {
            class: Some(class),
            view,
        };
    }
    // Broadcast app / infra logical frames validate as they are. An infra kind has
    // no app payload — it passes with `class: None`.
    let view = frame.authored();
    match frame.kind.app_tag() {
        Some(_) => match gate_app_payload(&view, app) {
            Some(class) => Gated::Pass {
                class: Some(class),
                view,
            },
            None => Gated::Drop,
        },
        None => Gated::Pass { class: None, view },
    }
}

/// Validate + decrypt a directed frame that's addressed to us (as opposed to
/// one we're only relaying).
fn gate_directed_to_us<F: Proof>(frame: &F, state: &EventLoopState, app: &dyn NodeApp) -> Gated {
    // Whether the directed body is sealed is the app's call, not a
    // structural given: an app's directed tags may arrive encrypted, but a
    // consumer with its own data model may send plaintext directed bytes. The frame is
    // signature-authenticated either way; `sealed=false` only means "not
    // additionally encrypted".
    let wire = frame.authored();
    if !app.classify(&wire).sealed() {
        // Plaintext directed body: the wire body is already the final body.
        let Some(class) = gate_app_payload(&wire, app) else {
            return Gated::Drop;
        };
        return Gated::Pass {
            class: Some(class),
            view: wire,
        };
    }
    let Some(body) = decrypt_directed(frame, state) else {
        return Gated::Drop;
    };
    let view = frame.copy_with_body(body);
    let Some(class) = gate_app_payload(&view, app) else {
        return Gated::Drop;
    };
    Gated::Pass {
        class: Some(class),
        view,
    }
}

/// Decrypt a broadcast chat body sealed under the mesh key. Returns the plaintext
/// body, or `None` when there is no key or the body is not a decryptable `enc`
/// envelope (on a passworded mesh that means an unsealed/tampered body — the caller
/// drops it).
fn decrypt_broadcast<F: ops::Deref<Target = Message>>(
    message: &F,
    state: &EventLoopState,
) -> Option<MessageBody> {
    let key = state.broadcast_key.as_ref()?;
    // A key exists (passworded mesh), so a body that will not open is either
    // cleartext or tampered — drop it, but say so (mirroring the directed-drop
    // warn) rather than vanishing silently. A generic `send_app` broadcast that
    // did not mesh-key-seal its body lands here; see `send_app`'s doc.
    let Some(plain) = wire::decrypt_body(message.body.as_str(), Some(key)) else {
        tracing::warn!(target: "habilis_network::gossip",
            author = %message.author,
            "dropping a broadcast body that failed mesh-key decryption (cleartext on a passworded mesh?)"
        );
        return None;
    };
    MessageBody::try_new(&plain).ok()
}

/// Unseal a directed body sealed to us. Returns the plaintext body, or `None` when
/// the frame fails to open (tampered / wrong key), so the caller drops it. The
/// caller only calls this on the addressee's path.
fn decrypt_directed<F: ops::Deref<Target = Message>>(
    message: &F,
    state: &EventLoopState,
) -> Option<MessageBody> {
    match seal_error::unseal_from_body(&state.identity.seal_secret(), &message.body) {
        Ok(plaintext) => MessageBody::try_new(&plaintext).ok(),
        Err(error) => {
            tracing::warn!(target: "habilis_network::gossip", %error, author = %message.author, "dropping a directed frame sealed to us that failed to open");
            None
        }
    }
}

fn addressed_to_us(message: &Message, us: &AuthorKey) -> bool {
    match &message.kind {
        MessageKind::App { to: Some(to), .. } => to == us,
        // Broadcast app frames (chat) and infra kinds are delivered to everyone.
        MessageKind::App { to: None, .. }
        | MessageKind::Presence { .. }
        | MessageKind::PeerInfo
        | MessageKind::Digest
        | MessageKind::Ping
        | MessageKind::Pong { .. }
        | MessageKind::State
        | MessageKind::StateDigest
        | MessageKind::Meta
        | MessageKind::MetaDigest
        | MessageKind::ProofRequest { .. }
        | MessageKind::LinkState
        | _ => true,
    }
}

/// Hand a surviving inbound message to the in-process driver before kind
/// routing, so the consumer sees `msg` / `presence` / `peer_info` /
/// `task` alike. Non-blocking by construction (bounded broadcast); a send error
/// or full ring is intentionally dropped so a slow consumer never stalls
/// the gossip loop. The `receiver_count` gate skips the per-message clone while
/// nobody has subscribed yet; a consumer that never wants the fan-out passes no
/// sender at all, so the field is `None` and even that gate is skipped.
/// `surfaceable` keeps pre-join backlog off the inbound push channel too; plumbing
/// kinds (digest/ping/pong) are excluded. `class` is the caller's once-computed
/// classification (`None` for an infra frame).
/// The kinds that infrastructure dispatch consumes and no application subscriber is told about.
fn is_plumbing(kind: &MessageKind) -> bool {
    matches!(
        kind,
        MessageKind::Digest
            | MessageKind::StateDigest
            | MessageKind::MetaDigest
            | MessageKind::State
            | MessageKind::Meta
            | MessageKind::Ping
            | MessageKind::Pong { .. }
            | MessageKind::ProofRequest { .. }
    )
}

fn maybe_push_inbound(
    context: &HandlerCtx<'_>,
    message: &Authored,
    surfaceable: bool,
    class: Option<&AppClass>,
) {
    // Short-circuit the cheap structural guards first: no live inbound subscriber
    // (always so for CLI/MCP, where the field is `None`), a pre-join or
    // third-party frame, or an infra kind.
    let Some(tx) = context.external_msg_tx else {
        return;
    };
    if tx.receiver_count() == 0
        || !surfaceable
        || !addressed_to_us(message, &context.our_pubkey)
        || is_plumbing(&message.kind)
    {
        return;
    }
    // An App frame reaches an in-process consumer only when it is loggable (not RPC
    // plumbing) and not a liveness beat — the app's per-tag policy, threaded in
    // from the caller's single classification. An infra frame (`class == None`,
    // `app_tag` also `None`) is always pushable past the structural guards above.
    let kind_tag = message.kind.app_tag();
    let app_pushable = match kind_tag {
        Some(_) => class.is_some_and(|cls| cls.loggable() && !cls.beat()),
        None => true,
    };
    if app_pushable {
        let _ = tx.send(message.clone());
    }
}

/// Our heads and our address go out on the first frame from any new peer, not
/// only on its `joined`: a digest is how a newcomer gets backfilled, a
/// newcomer behind the rendezvous learns our address only from this flood,
/// and which frame a peer sends first depends on its version and its links.
/// If the newcomer has the lower endpoint id we wait for it to dial. A first
/// frame that is its `joined` floods our address in `handle_presence` instead.
async fn greet_new_peer(message: &Verified, state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    antientropy::broadcast_state_digests(
        state,
        context.sender,
        context.mesh,
        context.author,
        antientropy::DigestTrigger::Event,
    )
    .await;
    if !matches!(
        message.kind,
        MessageKind::Presence {
            subtype: PresenceSubtype::Joined
        }
    ) {
        tracing::debug!(target: "habilis_network::gossip", author = %message.author, "flooded our address on a new peer's first frame");
        broadcast_peer_info(state, context).await;
        state.last_sent_at = Instant::now();
    }
}

/// The number of links below which a graft that a `PeerInfo` triggers may go
/// ahead. `members` counts every member of the mesh, this node included.
///
/// A mesh that fits in the active view (at most G + 1 members) has room at every
/// peer and may take the view up to G. In a bigger mesh the rule leaves the last
/// slot to the paced fill tick (`probe::fill_active_view`).
///
/// The rule was made for a graft that was a `Join`: a full peer accepts a `Join` by
/// evicting a random neighbor, so a graft moved two links. A graft is a low priority
/// request now, and a full peer refuses it, so that reason is gone. The rule stays
/// because the measurements of the churn (0.8 link-ups per member per minute at
/// N = 24 and G = 8) were made with it. Whether to drop it is open: it would let
/// a `PeerInfo` fill the last slot too, and it needs a new run to show the effect.
fn peer_info_graft_below(max_peers: usize, members: usize) -> usize {
    if members <= max_peers.saturating_add(1) {
        max_peers
    } else {
        max_peers.saturating_sub(1).max(1)
    }
}

/// The address of a `PeerInfo` of a session that the roster gate refused. The frame binds no hint and
/// adds no roster entry (the gate treats it as stale), but the session is asked for its proof over a
/// warm path, and with no address for it that request is skipped: the address is retained for the key,
/// as for a second live key of a nickname, and it is no hint.
fn retain_refused_peer_info_address(message: &Verified, state: &mut EventLoopState) {
    let decoded: serde_json::Result<serde_json::Value> =
        serde_json::from_str(message.body.as_str());
    let Ok(parsed) = decoded else {
        return;
    };
    let Ok((_, peer_addr)) = peer_addr_error::endpoint_addr_from_json(&parsed) else {
        return;
    };
    if !state.key_said_goodbye(message.key()) {
        state.retain_refused_endpoint(message.key(), peer_addr);
    }
}

async fn handle_peer_info(
    message: &Verified,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) {
    let decoded: serde_json::Result<serde_json::Value> =
        serde_json::from_str(message.body.as_str());
    let Ok(parsed) = decoded else {
        return;
    };
    let Ok((peer_id, peer_addr)) = peer_addr_error::endpoint_addr_from_json(&parsed) else {
        return;
    };
    if peer_id == context.endpoint.id() {
        return;
    }
    // This `PeerInfo` is signed by `message.author` and carries that author's
    // own endpoint — the one binding from a nickname to a node id. Record it
    // for the roster's `direct`/`gossip` tag; last-writer-wins, so a restart's
    // fresh endpoint replaces the old. The beacon gossips *as* the rendezvous,
    // so it advertises `rendezvous_id` here — record that too, so a joiner can
    // tell its rendezvous link belongs to the beacon's nickname.
    // The hint belongs to the key that made it. A key that said goodbye never speaks again, so
    // its `PeerInfo` is a replay and binds nothing. Another key under the same nickname binds
    // nothing while the key that made the hint is still in the roster: a directed send must not
    // reach a node that only borrowed the label.
    let hinter = message.key();
    // Whether the address differs from the one registered for this endpoint. A dial hint is no
    // registration: a hint of another nickname can name the address that nothing put in the book.
    // It does not depend on `may_bind`: a rival key binds no hint, but its address is still a
    // path to its node.
    let changed = !state.unicast_pool.remembers_address(&peer_addr);
    state.place_endpoint(hinter, &message.author, peer_addr.clone());
    // The rendezvous is overlay plumbing, not a dialable member peer:
    // the binding above is recorded, but skip the known-endpoints/re-bridge
    // dial path for it.
    if peer_id == context.rendezvous_id {
        return;
    }
    // The only binding a digest's answer may follow: this signer proved it
    // owns `peer_id`. A `PeerInfo` arrives many times, so a pair that the roster trusts is not
    // checked again. A proof that the table holds for a signer not yet in the roster is checked
    // again, so the trust follows the roster.
    let signer = message.key();
    if let Some(proof) = parsed["proof"].as_str()
        && state.proven_endpoints.trusted(&signer) != Some(peer_id)
        && proven_endpoints::verifies(peer_id, context.mesh, &signer, proof)
    {
        state.note_proven_endpoint(signer, peer_id, message.timestamp);
    }
    // A holder of the rendezvous says so in its `PeerInfo`; only a sender that proved its
    // endpoint is believed.
    let proven = state.proven_endpoints.get(&signer) == Some(peer_id)
        || state.proven_endpoints.trusted(&signer) == Some(peer_id);
    state.note_rival_beacon_flag(
        context.endpoint.id(),
        signer,
        peer_id,
        RivalFlag {
            proven,
            held: parsed["beacon"].as_bool() == Some(true),
        },
        Instant::now(),
    );
    // Remember every advertised peer for the rendezvous-independent
    // re-bridge, and register its address once. Unconditional on link
    // state — a `PeerInfo` normally arrives over an already-formed link,
    // and recovery (`heal::rebridge_known`, the starvation watchdog's
    // precondition) needs the memory precisely *after* that link dies.
    let first_sighting = state.known_endpoints.insert(peer_id);
    let peer_ips: Vec<_> = peer_addr.ip_addrs().collect();
    let local = context.endpoint.id().fmt_short();
    let peer = peer_id.fmt_short();
    let relay = peer_addr.relay_urls().next();
    tracing::debug!(
        target: "habilis_network::gossip",
        local = %local,
        author = %message.author,
        peer = %peer,
        first_sighting,
        relay = ?relay,
        ip_addrs = ?peer_ips,
        "peerinfo received"
    );
    // Every address that is new or differs from the last one of this author is handed to
    // the endpoint, whatever the link state: a home relay that came late, or an interface
    // that changed, is learned by a peer that is already linked. `add_endpoint_addr`
    // makes the address a path of the live connections, so it does not matter whether
    // it runs before or after the dial that follows; the lookup serves a dial by bare id.
    // The call goes through two actor inboxes of the endpoint, so the loop never awaits
    // it. An address with no entry is not given to it: with none known it would start an
    // Address Lookup and wait for it.
    if first_sighting || changed {
        lookup::add_peer_addr(&state.address_book, peer_addr.clone());
        state.unicast_pool.note_addr(&peer_addr);
        if !peer_addr.addrs.is_empty() {
            let endpoint = context.endpoint.clone();
            let address = peer_addr.clone();
            n0future_task::spawn(async move {
                if let Err(error) = endpoint.add_endpoint_addr(address).await {
                    tracing::debug!(target: "habilis_network::gossip", peer = %peer_id.fmt_short(), %error, "the endpoint did not take the peer address");
                }
            });
        }
    }
    // The address of a session that is in the roster with no proof is the warm path that its proof
    // request was waiting for: ask now, and not at its next alive frame, 30 s or more away. The ask comes
    // after the address is registered, because the dial that it can start uses the address of the pool.
    lifecycle::ask_for_proof(message, state, context).await;
    // A buffered directed frame addressed to this author may just have become
    // deliverable — its endpoint binding and dial address are now registered.
    // Only while meshed: the pre-mesh backlog waits for the meshed edge.
    if state.standing.contains(&Standing::Meshed) && !state.pending_outbound.is_empty() {
        flush_pending(state, context, "peer info arrival").await;
    }
    let now = Instant::now();
    // Simultaneous-open tie-break: on a peer's *first* sighting, only the
    // numerically lower endpoint id dials.
    //
    // A join floods its `PeerInfo` to everyone at once, so both sides of a new
    // pair reach this dial in the same millisecond and each opens a connection.
    // iroh-gossip does dedup the pair — but each side independently closes the
    // connection *it* dialed, and those are the two different halves, so both
    // die and the pair is left unlinked. Observed directly: `neighbor up` for
    // both, then `remaining 1 other connections`, then `closed by peer: close
    // from disconnect` ~23ms later, leaving each node in `silent partition
    // (meshed but zero peer links)` — which is how a graceful `Left` came to be
    // broadcast into the void, since by then the leaver had no neighbors.
    //
    // Comparing ids gives both sides the same answer without a round trip.
    // Deliberately scoped to the first sighting, so it defers a dial rather
    // than vetoing one: if the lower id never dials (it may not hold our
    // `PeerInfo` yet), the next re-receipt past the relink cooldown dials from
    // this side after all. The rendezvous is exempt — it returned above — so
    // the bootstrap link is never subject to this.
    let defer_first_dial = first_sighting && context.endpoint.id() > peer_id;
    if defer_first_dial {
        // The deferral starts the relink cooldown, as a dial would: a copy of
        // this `PeerInfo` right after it is not a first sighting, and without
        // the cooldown it would dial after all.
        state.note_relink(peer_id, now);
        tracing::debug!(target: "habilis_network::gossip",
            endpoint_id = %peer_id,
            "deferring first dial to the lower endpoint id (simultaneous-open tie-break)"
        );
    }
    // A `PeerInfo` is a dial hint, never a link: `linked_endpoints` is
    // owned by `NeighborUp`/`NeighborDown` (link truth), so an unlinked
    // peer's `PeerInfo` only re-registers its (possibly fresh) address
    // and *asks* the gossip actor to graft it. Until the link
    // materializes, each post-cooldown re-receipt retries the dial —
    // the healer's per-peer backstop.
    // Negotiate a direct WebRTC session alongside the graft, never in front of
    // it. Blocking the graft on the session deadlocks mesh formation — see the
    // note on `negotiate_session`.
    webrtc::negotiate_session::negotiate_session(state, context, peer_id, peer_addr.clone());
    // No `rendezvous_wanted` gate on this graft: `peer_id` is never the
    // rendezvous here, which returned above.
    let below = state.linked_endpoints.len()
        < peer_info_graft_below(context.max_peers, state.member_addresses().len() + 1);
    if !defer_first_dial
        && below
        && !state.linked_endpoints.contains(&peer_id)
        && !state.relink_on_cooldown(peer_id, now)
        && !state.graft_blocked(peer_id, now)
    {
        state.note_relink(peer_id, now);
        lookup::add_peer_addr(&state.address_book, peer_addr.clone());
        state.unicast_pool.note_addr(&peer_addr);
        // With the relay lookup only, the graft waits for a proven direct
        // path (`transport::probe`); the loop grafts on the probe's verdict.
        if probe::ensure_direct(state, context, peer_id, &peer_addr) {
            if let Err(error) = probe::request_graft(state, context, peer_id, false).await {
                tracing::warn!(target: "habilis_network::gossip", endpoint_id = %peer_id, %error, "PeerInfo graft request failed");
            }
        } else {
            tracing::debug!(target: "habilis_network::gossip", endpoint_id = %peer_id, "graft held until a direct path is proven");
        }
        if let Ok(frame) = message.serialize() {
            let _ = context.sender.broadcast(frame).await;
        }
        state.last_sent_at = Instant::now();
        tracing::debug!(target: "habilis_network::gossip",
            endpoint_id = %peer_id,
            linked = state.linked_endpoints.len(),
            "dialing peer from PeerInfo"
        );
    }
}

/// `Alive` keepalives, `PeerInfo` endpoint plumbing, anti-entropy `Digest`s,
/// and ping/pong probes are infrastructure; everything else (real chat frames
/// and `joined`/`left` presence) goes in the log (and so to `poll`/`fetch`).
/// App-frame loggability is the app's own per-tag policy ([`NodeApp::classify`]);
/// this predicate covers only the engine's infra kinds.
///
/// `PeerInfo` is classified as non-loggable here so the rule is encoded in one
/// place rather than relying on its match arm's early `return`: a future code
/// path that reaches the log gate must not start persisting endpoint-address
/// plumbing into the poll/fetch buffer.
fn is_loggable(kind: &MessageKind) -> bool {
    !matches!(
        kind,
        MessageKind::Presence {
            subtype: PresenceSubtype::Alive
        } | MessageKind::PeerInfo
            | MessageKind::Digest | MessageKind::StateDigest | MessageKind::MetaDigest
            // A newer vector replaces this one, and a peer never logs it (its
            // handler ends before retention), so a copy kept here is one no peer
            // holds and every digest asks this node for again.
            | MessageKind::LinkState
            | MessageKind::Ping
            | MessageKind::Pong { .. }
            // Durable state lives in its own un-pruned log, never the chat
            // message-log / poll-fetch buffer (it also returns before reaching
            // here; this keeps the predicate honest if that changes).
            | MessageKind::State
            | MessageKind::Meta
            // App-frame loggability is decided by the app's `classify`, never
            // this infra predicate. An App kind that reaches here has no class: it is the
            // opaque directed frame of a relay, which is not kept.
            | MessageKind::App { .. }
    )
}

#[cfg(test)]
mod arms_reclaim_tests {

    #[test]
    fn the_beacon_link_dropping_arms_it() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            super::arms_reclaim(true, 3, false),
            "the beacon link dropping arms the reclaim"
        );
    }

    #[test]
    fn losing_the_last_peer_arms_it() {
        // Isolated: nobody left to mesh through, so a beacon may be ours to
        // stand up even if we never held a link to the old one.
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            super::arms_reclaim(false, 0, false),
            "losing the last peer arms the reclaim"
        );
    }

    #[test]
    fn any_loss_while_beaconless_arms_it() {
        // The kill-the-producer drill: two tabs and an origin, the origin
        // dies, each tab still linked to the other. Not the rendezvous, not
        // isolation — and before this the tab armed nothing and waited out the
        // heal cadence.
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            super::arms_reclaim(false, 1, true),
            "any loss while beaconless arms the reclaim"
        );
    }

    #[test]
    fn a_shuffle_under_a_healthy_beacon_does_not() {
        // A peer flapping while the beacon link is live is HyParView doing its
        // job. Arming here is what would make initial convergence pay a bind
        // storm on every non-beacon node.
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            !super::arms_reclaim(false, 1, false),
            "a shuffle under a healthy beacon arms nothing"
        );
        assert!(
            !super::arms_reclaim(false, 64, false),
            "a large shuffle under a healthy beacon arms nothing"
        );
    }

    #[test]
    fn a_rendezvous_released_on_purpose_arms_nothing() {
        // Enough links to others, the beacon let go of by choice: the
        // `NeighborDown` it causes is not a loss, and nothing may come back.
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            !super::arms_reclaim(false, 3, false),
            "a rendezvous released on purpose arms nothing"
        );
    }

    #[test]
    fn a_lost_rendezvous_arms_even_when_the_node_wants_none() {
        // It may be dead, and failover needs someone to notice.
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            super::arms_reclaim(true, 5, false),
            "a lost rendezvous arms the reclaim even when the node wants none"
        );
    }

    #[test]
    fn a_node_with_enough_links_does_not_arm_for_a_beacon_it_does_not_hold() {
        // Released earlier, and a plain neighbour drops: still no reason to
        // go back to the rendezvous.
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            !super::arms_reclaim(false, 3, false),
            "a node with enough links does not arm for a beacon it does not hold"
        );
    }

    #[test]
    fn a_node_below_the_release_count_wants_the_beacon_back() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            super::arms_reclaim(false, 2, true),
            "a node below the release count arms the reclaim for the beacon"
        );
    }
}

#[cfg(test)]
mod is_loggable_tests {
    use super::{is_loggable, retained_after_lifecycle};
    use crate::lifecycle::membership_update::MembershipUpdate;
    use crate::protocol::{MessageKind, PresenceSubtype};

    /// A stale `joined` or `alive` is a copy of a departed key's presence: it stays out of the
    /// log. A stale chat frame and a fresh presence frame go in.
    #[test]
    fn a_stale_presence_frame_is_not_retained() {
        let _guard = ::habilis_network_test_tracing::init();
        let stale = MembershipUpdate {
            returned: false,
            joined_new: false,
            stale: true,
        };
        let fresh = MembershipUpdate {
            returned: false,
            joined_new: true,
            stale: false,
        };
        let joined = MessageKind::Presence {
            subtype: PresenceSubtype::Joined,
        };
        let alive = MessageKind::Presence {
            subtype: PresenceSubtype::Alive,
        };
        assert!(
            !retained_after_lifecycle(&stale, &joined),
            "a stale presence frame is not retained beside a joined frame"
        );
        assert!(
            !retained_after_lifecycle(&stale, &alive),
            "a stale presence frame is not retained beside an alive frame"
        );
        assert!(
            retained_after_lifecycle(&stale, &MessageKind::app_broadcast("app_msg")),
            "a stale presence frame is still retained beside an app broadcast"
        );
        assert!(
            retained_after_lifecycle(&fresh, &joined),
            "a fresh presence frame is retained beside a joined frame"
        );
    }

    #[test]
    fn alive_presence_is_not_loggable() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            !is_loggable(&MessageKind::Presence {
                subtype: PresenceSubtype::Alive
            }),
            "alive presence is not loggable"
        );
    }

    #[test]
    fn joined_and_left_presence_are_loggable() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            is_loggable(&MessageKind::Presence {
                subtype: PresenceSubtype::Joined
            }),
            "joined presence is loggable"
        );
        assert!(
            is_loggable(&MessageKind::Presence {
                subtype: PresenceSubtype::Left
            }),
            "left presence is loggable"
        );
    }

    #[test]
    fn peerinfo_is_not_loggable() {
        // PeerInfo is endpoint plumbing — never logged/surfaced, and the
        // classifier (not just its early-return) says so.
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            !is_loggable(&MessageKind::PeerInfo),
            "peer info is not loggable"
        );
    }
}

/// Replicates the second mesh-wide CPU runaway at its mechanism: a node that
/// does not retain its **own** broadcasts advertises a digest that omits them,
/// and since gossip never echoes a node's publications back to it, it can never
/// acknowledge them — so every peer re-sends them on every anti-entropy round,
/// forever. Measured at 6 peers: 180 resend events/minute steady-state and
/// ~108% total CPU, against 12 (join-window only, then silent) and ~54% once
/// the author retains its own presence.
#[cfg(test)]
mod retain_own_broadcast_tests {
    use crate::testing;
    use std::collections::HashSet;

    use crate::daemon::message_log::{MissingQuery, WindowRange};
    use crate::daemon::state::EventLoopState;
    use crate::protocol::messages::Verified;
    use crate::protocol::{DedupKey, MeshId, Message, Nickname};

    use crate::gossip::app;
    use crate::protocol;
    use crate::protocol::messages::AppFrameParams;
    fn joined(state: &EventLoopState, author: &str) -> Verified {
        Message::new_joined(&MeshId::from("💬test"), &Nickname::from(author)).sign(&state.identity)
    }

    /// The invariant: our own `joined` is in our log, so the digest we
    /// advertise names it.
    #[test]
    fn own_presence_lands_in_the_local_log() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = testing::fresh_state();
        let mine = joined(&state, "me");
        assert_eq!(state.message_log.len(), 0, "log starts empty");
        super::retain_own_broadcast(&mut state, mine);
        assert_eq!(
            state.message_log.len(),
            1,
            "a node must hold the presence it just broadcast — it is the only source for it"
        );
    }

    /// Plumbing we broadcast but never log stays out, so retaining our own
    /// sends does not quietly widen what anti-entropy replays.
    #[test]
    fn own_unloggable_plumbing_is_not_retained() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = testing::fresh_state();
        let body = protocol::MessageBody::try_new("{}").expect("valid body");
        let peer_info =
            Message::new_peer_info(&MeshId::from("💬test"), &Nickname::from("me"), body)
                .sign(&state.identity);
        super::retain_own_broadcast(&mut state, peer_info);
        assert_eq!(
            state.message_log.len(),
            0,
            "PeerInfo is never logged inbound, so it must not be logged outbound either"
        );
    }

    fn app_frame(state: &EventLoopState, to: Option<&str>) -> Verified {
        Message::new_app(
            &MeshId::from("💬test"),
            &Nickname::from("me"),
            AppFrameParams::new(
                protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                to.map(testing::test_key),
                None,
                protocol::MessageBody::from("hello"),
            ),
        )
        .sign(&state.identity)
    }

    fn class(loggable: bool) -> app::AppClass {
        app::AppClass::NONE
            .plus_if(app::AppClass::LOGGABLE, loggable)
            .union(app::AppClass::VALID)
    }

    /// An app broadcast that the app logs is held by its author, as at the ingest of a peer: the
    /// author can serve it to a peer that missed it, and the peers that hold it do not resend it
    /// to her on every round.
    #[test]
    fn an_own_app_broadcast_that_the_app_logs_is_retained() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = testing::fresh_state();
        let frame = app_frame(&state, None);
        super::retain_own_app_broadcast(&mut state, &frame, class(true));
        assert_eq!(
            state.message_log.len(),
            1,
            "an own app broadcast that the app logs is retained"
        );
    }

    /// The class is the app's, not the kind's: an app that does not log its frames keeps none, and a
    /// directed frame is never kept (its body is sealed on the way out, and only its addressee may
    /// be served).
    #[test]
    fn an_own_app_frame_that_the_app_does_not_log_or_that_is_directed_is_not_retained() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = testing::fresh_state();
        let broadcast = app_frame(&state, None);
        super::retain_own_app_broadcast(&mut state, &broadcast, class(false));
        let directed = app_frame(&state, Some("you"));
        super::retain_own_app_broadcast(&mut state, &directed, class(true));
        assert_eq!(
            state.message_log.len(),
            0,
            "an own frame that is directed or unlogged is not retained"
        );
    }

    /// The end-to-end property, as the two peers actually exchange it: a holder
    /// computing gaps against our digest must find **nothing** to re-send.
    /// Before the fix this returned our own `joined` on every round, forever.
    #[test]
    fn a_peer_offers_nothing_back_against_our_digest() {
        // Us: we broadcast our own `joined`, and receive the peer's.
        let _guard = ::habilis_network_test_tracing::init();
        let mut us = testing::fresh_state();
        let ours = joined(&us, "us");
        super::retain_own_broadcast(&mut us, ours.clone());
        let mut them = testing::fresh_state();
        let theirs = joined(&them, "them");
        super::retain_own_broadcast(&mut them, theirs.clone());
        // Each side ingests the other's presence, as gossip delivers it.
        super::push_to_log(&mut us, theirs, None);
        super::push_to_log(&mut them, ours, None);

        // We advertise what we hold; they compute what we are missing.
        let window = us.message_log.recent_window(64).expect("non-empty log");
        let have: HashSet<DedupKey> = window.ids.into_iter().collect();
        let offered = them.message_log.missing_in_window(MissingQuery {
            range: WindowRange {
                lo: window.lo,
                hi: window.hi,
            },
            have: &have,
            max: 64,
            // "us" is the peer whose digest advertised the window; presence is
            // undirected, so the addressee gate passes it either way.
            requester: &testing::test_key("us"),
        });
        assert!(
            offered.is_empty(),
            "two converged peers must have nothing to re-send; got {} message(s) — \
             the anti-entropy loop is back",
            offered.len()
        );
    }
}

/// A change the channel doc evicts from its orphan buffer is recovered when
/// anti-entropy re-serves it. The re-served frame is the original signed one,
/// so it carries the dedup key the receive path recorded on first arrival.
#[cfg(test)]
mod evicted_orphan_tests {
    use iroh::endpoint::presets;
    use iroh_gossip::net::Gossip;
    use serde_json::json;

    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::state::EventLoopState;
    use crate::doc::Ingested;
    use crate::gossip::app::{AppClass, InboundApp, NodeApp};
    use crate::gossip::event::SilentSink;
    use crate::protocol::identity::Identity;
    use crate::protocol::messages::{Authored, Verified};
    use crate::protocol::{Channel, MeshId, Message, Nickname};
    use crate::testing::{endpoint_id, fresh_state, nick};
    use crate::transport::MeshSender;
    use habilis_network_util::consts::DOC_PENDING_AUTHOR_MAX;

    use iroh_gossip::proto;
    /// State frames never reach the app, so it only has to exist.
    struct Inert;

    #[async_trait::async_trait]
    impl NodeApp for Inert {
        fn classify(&self, _message: &Authored) -> AppClass {
            AppClass::BEAT.union(AppClass::VALID)
        }

        async fn on_app_frame(
            &mut self,
            _frame: InboundApp<'_>,
            _state: &mut EventLoopState,
            _ctx: &HandlerCtx<'_>,
        ) -> bool {
            false
        }
    }

    /// `count` state changes by one author, each depending on the one before.
    fn chain(
        writer: &mut EventLoopState,
        mesh: &MeshId,
        author: &Nickname,
        count: usize,
    ) -> Vec<Verified> {
        let seed = *writer.identity.public().as_bytes();
        (0..count)
            .map(|step| {
                let state_doc = writer.doc(Channel::State);
                let change = state_doc
                    .build_change(&json!({ format!("k{step}"): step }), &seed)
                    .expect("a JSON object merges")
                    .expect("a non-empty merge yields a change");
                let (wire, _plain) = writer
                    .doc(Channel::State)
                    .compose_wire_body(&change, None)
                    .expect("compose the wire body");
                let frame = Message::new_channel_event(mesh, author, wire, Channel::State)
                    .sign(&writer.identity);
                assert!(
                    matches!(
                        writer.doc_mut(Channel::State).ingest(&frame),
                        Ingested::Applied { .. }
                    ),
                    "the state document applies the frame"
                );
                frame
            })
            .collect()
    }

    fn holds(state: &EventLoopState, step: usize) -> bool {
        state
            .doc(Channel::State)
            .to_json()
            .get(format!("k{step}"))
            .is_some()
    }

    #[test]
    fn an_evicted_orphan_is_recovered_when_its_frame_is_re_served() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network::gossip",
                "channel orphan buffer full for this author",
            );
            let mesh = MeshId::from("test");
            let mut writer = fresh_state();
            let frames = chain(
                &mut writer,
                &mesh,
                &nick("writer"),
                DOC_PENDING_AUTHOR_MAX + 32,
            );

            let endpoint = iroh::Endpoint::builder(presets::Minimal)
                .bind()
                .await
                .expect("bind a local endpoint");
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let topic = gossip
                .subscribe(proto::TopicId::from_bytes([3u8; 32]), vec![])
                .await
                .expect("subscribe to a peerless topic");
            let (gossip_sender, _receiver) = topic.split();
            let sender = MeshSender::new(gossip_sender);
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let reader_nick = nick("reader");
            let sink = SilentSink;
            let context = HandlerCtx {
                sender: &sender,
                endpoint: &endpoint,
                mesh: &mesh,
                author: &reader_nick,
                identity: &identity,
                our_pubkey,
                max_peers: 16,
                rendezvous_id: endpoint_id(9),
                external_msg_tx: None,
                sink: &sink,
            };
            let mut reader = fresh_state();
            let mut app = Inert;
            let wire = |frame: &Verified| frame.serialize().expect("serialize").into_bytes();

            // Newest first: every frame but the root arrives as an orphan, so the
            // per-author ceiling evicts the stalest of them before the root lands.
            let newest_first: Vec<&Verified> = frames.iter().rev().collect();
            for frame in newest_first {
                super::ingest(wire(frame), &mut reader, &mut app, &context).await;
            }
            let missing: Vec<&Verified> = (0..frames.len())
                .filter(|&step| !holds(&reader, step))
                .map(|step| &frames[step])
                .collect();
            assert!(
                !missing.is_empty(),
                "nothing was evicted, so this test proves nothing"
            );
            let missing_refs = missing.iter();
            let fresh = missing_refs.filter(|frame| reader.seen.contains(&frame.dedup_key()));
            let already_seen: usize = fresh.count();
            assert_eq!(
                already_seen,
                0,
                "{already_seen} of the {} dropped frames are still in the seen set, so \
                 their re-send will be discarded as a repeat",
                missing.len()
            );

            // What anti-entropy does for a peer whose heads show the gap: re-serve
            // the author's original signed frames.
            for frame in &missing {
                super::ingest(wire(frame), &mut reader, &mut app, &context).await;
            }

            let held = (0..frames.len())
                .filter(|&step| holds(&reader, step))
                .count();
            assert_eq!(
                held,
                frames.len(),
                "the reader holds {held} of {} changes after the {} evicted ones were \
                 re-served; {already_seen} of those were already in the seen set, so \
                 the receive path dropped them as duplicates",
                frames.len(),
                missing.len()
            );
            endpoint.close().await;
        });
    }
}

#[cfg(test)]
mod first_contact_tests {
    use crate::daemon::state::{RendezvousFlag, Standing};
    use crate::protocol::UnixSecs;
    use crate::transport::UdpTransport;
    use iroh::endpoint::presets;
    use iroh_gossip::api::Event;
    use iroh_gossip::net::Gossip;

    use super::{
        ChannelEvent, dispatch_channel, dispatch_infra, handle_gossip_event, ingest, pong_for,
    };
    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::message_log::{self, MissingQuery};
    use crate::daemon::state::{EventLoopState, PingRound};
    use crate::gossip::app::{AppClass, InboundApp, NodeApp};
    use crate::gossip::event::{NodeEvent, NodeSink, SilentSink};
    use crate::lifecycle::membership_update::MembershipUpdate;
    use crate::ops;
    use crate::protocol::identity::Identity;
    use crate::protocol::messages::{Authored, MessageBody, Verified};
    use crate::protocol::{AuthorKey, Channel, MeshId, Message, MessageKind, Nickname};
    use crate::testing::{endpoint_id, fresh_state, nick, test_key};
    use crate::transport::MeshSender;
    use bytes::Bytes;

    use crate::daemon::state::DirectState;
    #[cfg(feature = "multihop")]
    use crate::gossip;
    use crate::gossip::split;
    use crate::lifecycle::heartbeat;
    use crate::protocol::messages::{AppFrameParams, sole_addressee};
    use crate::transport::outbox::Resend;
    use crate::transport::proven_endpoints::ProvenEndpoints;
    use crate::transport::{PayloadPath, webrtc};
    use crate::util::{clock, tuning};
    use crate::{lifecycle, lookup, protocol, transport};
    use iroh_gossip::proto;
    use n0_future::task;
    use n0_future::time::Instant as TokioInstant;
    use std::collections::HashSet;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex, atomic};
    use std::time::{Duration as std_Duration, Instant as std_Instant};
    use std::{future, net};
    use tokio::sync::mpsc;
    use tokio::{task as tokio_task, time as tokio_time};
    struct Inert;

    #[async_trait::async_trait]
    impl NodeApp for Inert {
        fn classify(&self, _message: &Authored) -> AppClass {
            AppClass::BEAT.union(AppClass::VALID)
        }

        async fn on_app_frame(
            &mut self,
            _frame: InboundApp<'_>,
            _state: &mut EventLoopState,
            _ctx: &HandlerCtx<'_>,
        ) -> bool {
            false
        }
    }

    /// One node on a peerless topic, with everything a `HandlerCtx` borrows.
    struct Node {
        endpoint: iroh::Endpoint,
        _gossip: Gossip,
        sender: MeshSender,
        mesh: MeshId,
        identity: Identity,
        our_pubkey: AuthorKey,
        author: Nickname,
        sink: SilentSink,
    }

    impl Node {
        async fn spawn() -> Self {
            let endpoint = iroh::Endpoint::builder(presets::Minimal)
                .bind()
                .await
                .expect("bind a local endpoint");
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let topic = gossip
                .subscribe(proto::TopicId::from_bytes([4u8; 32]), vec![])
                .await
                .expect("subscribe to a peerless topic");
            let (gossip_sender, _receiver) = topic.split();
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            Self {
                endpoint,
                _gossip: gossip,
                sender: MeshSender::new(gossip_sender),
                mesh: MeshId::from("test"),
                identity,
                our_pubkey,
                author: nick("holder"),
                sink: SilentSink,
            }
        }

        fn context(&self) -> HandlerCtx<'_> {
            HandlerCtx {
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

    /// A directed frame in the buffer, to a peer that nobody serves: the flush returns at once, the
    /// dial fails on its task, and the frame comes back to the loop and is buffered again. It is
    /// not lost, and the loop did not wait for the dial.
    #[test]
    fn a_pending_frame_whose_dial_fails_is_parked_again() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let node = Node::spawn().await;
                let context = node.context();
                let silent = net::UdpSocket::bind("127.0.0.1:0").expect("bind a silent socket");
                let bob = iroh::SecretKey::generate().public();
                let bob_addr = iroh::EndpointAddr::from_parts(
                    bob,
                    [iroh::TransportAddr::Ip(
                        silent.local_addr().expect("silent addr"),
                    )],
                );
                lookup::add_peer_addr(&lookup::address_book(&node.endpoint), bob_addr.clone());
                let mut state = fresh_state();
                state.standing.insert(Standing::Meshed);
                state.unicast_pool = transport::UnicastPool::new(node.endpoint.clone(), false);
                state.direct.insert(bob, DirectState::Direct);
                state.names.insert(test_key("bob"), nick("bob"));
                state.bind_peer_endpoint(test_key("bob"), nick("bob"), bob_addr);
                let (failed_tx, mut failed_rx) = mpsc::unbounded_channel();
                state.flush_failed = failed_tx;
                let frame = Message::new_pong(
                    &node.mesh,
                    &node.author,
                    test_key("bob"),
                    &protocol::MessageId::random(),
                )
                .sign(&Identity::generate());
                let bytes = frame.serialize().expect("serialize");
                assert!(
                    state.pending_outbound.push((frame.clone(), bytes)),
                    "a pending frame is parked again after a failed dial"
                );

                let started = std_Instant::now();
                super::flush_pending(&mut state, &context, "test").await;
                assert!(
                    started.elapsed() < std_Duration::from_millis(500),
                    "the flush waited for the dial"
                );
                assert!(
                    state.pending_outbound.take().is_empty(),
                    "the frame was handed to its task, so the buffer is empty until the dial fails"
                );

                let (failed, returned) =
                    tokio_time::timeout(std_Duration::from_secs(10), failed_rx.recv())
                        .await
                        .expect("the failed dial reports back to the loop")
                        .expect("the loop keeps its channel");
                super::requeue_failed(&mut state, &context, failed.clone(), returned);

                let parked = state.pending_outbound.take();
                assert_eq!(parked.len(), 1, "the frame is in the buffer again");
                assert_eq!(parked[0].0.id, frame.id, "and it is the same frame");
                node.endpoint.close().await;
            },
        );
    }

    /// A directed frame names a key, so a nickname that two live peers use does not make it
    /// undeliverable: the frame to the second key of the nickname waits only for an endpoint of
    /// that key. The flush keeps it until the key retains one, and then the send decision routes
    /// it to that endpoint, not to the dial hint that the first key owns.
    #[test]
    fn a_buffered_frame_to_the_second_key_of_a_nickname_waits_for_its_own_endpoint() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.standing.insert(Standing::Meshed);
            let twin = nick("twin");
            let (first, second) = (test_key("twin#first"), test_key("twin#second"));
            for key in [first, second] {
                state.names.insert(key, twin.clone());
                state.peers.insert(key);
            }
            state.names.insert(first, twin.clone());
            state.bind_peer_endpoint(first, twin, iroh::EndpointAddr::new(endpoint_id(5)));
            let frame = Message::new_pong(
                &node.mesh,
                &node.author,
                second,
                &protocol::MessageId::random(),
            )
            .sign(&Identity::generate());
            let bytes = frame.serialize().expect("serialize");
            assert!(
                state.pending_outbound.push((frame.clone(), bytes.clone())),
                "the frame is parked before the flush"
            );

            super::flush_pending(&mut state, &context, "test").await;

            assert!(
                !state.pending_outbound.is_empty(),
                "the flush dropped a frame that a later flush can deliver"
            );

            state.retain_refused_endpoint(second, iroh::EndpointAddr::new(endpoint_id(6)));
            state.direct.insert(endpoint_id(6), DirectState::Direct);

            assert!(
                matches!(
                    transport::resolve(&frame, bytes, &state),
                    Ok(Resend::Unicast(eid, _)) if eid == endpoint_id(6)
                ),
                "the frame to the second key did not route to the endpoint of that key"
            );
            node.endpoint.close().await;
        });
    }

    /// A directed frame to either of two live keys that use a nickname is accepted. An unmeshed
    /// node buffers each frame with its own key as the recipient, in the order of the sends, and
    /// tells the caller `Ok`.
    #[test]
    fn an_unmeshed_send_to_either_key_of_a_nickname_is_buffered() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.standing.remove(&Standing::Meshed);
            let twin = nick("twin");
            let (first, second) = (test_key("twin#first"), test_key("twin#second"));
            for key in [first, second] {
                state.names.insert(key, twin.clone());
                state.peers.insert(key);
            }

            for to in [second, first] {
                let frame =
                    Message::new_pong(&node.mesh, &node.author, to, &protocol::MessageId::random())
                        .sign(&Identity::generate());
                let sent = ops::send_app(&mut state, &context, frame, AppClass::NONE).await;
                assert!(
                    sent.is_ok(),
                    "the send to a key of the nickname was refused"
                );
            }

            let buffered = state.pending_outbound.take();
            let recipients: Vec<AuthorKey> = buffered
                .iter()
                .filter_map(|(frame, _)| sole_addressee(&frame.kind).copied())
                .collect();
            assert_eq!(
                recipients,
                [second, first],
                "the buffer lost a frame or the key of a recipient"
            );
            node.endpoint.close().await;
        });
    }

    /// An unmeshed node buffers a directed frame until the meshed edge. A key that no roster, quiet
    /// set or address book holds is a key that nobody can deliver to, and the caller was told `Ok`
    /// before. It is refused at once and the buffer stays empty. A quiet key, and a key that only
    /// has a retained endpoint, can still return or be dialed, so their frames wait.
    #[test]
    fn an_unmeshed_send_to_a_key_outside_the_roster_is_refused() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.standing.remove(&Standing::Meshed);
            let (quiet, hinted, stranger) =
                (test_key("quiet"), test_key("hinted"), test_key("stranger"));
            state.names.insert(quiet, nick("quiet"));
            state.quiet.insert(quiet);
            state.retain_refused_endpoint(hinted, iroh::EndpointAddr::new(endpoint_id(8)));
            let frame_to = |to: AuthorKey| {
                Message::new_pong(&node.mesh, &node.author, to, &protocol::MessageId::random())
                    .sign(&Identity::generate())
            };

            let refused =
                ops::send_app(&mut state, &context, frame_to(stranger), AppClass::NONE).await;
            assert!(
                matches!(refused, Err(transport::SendError::Undeliverable(_))),
                "the unmeshed send to a stranger was not refused: {refused:?}"
            );
            assert!(
                state.pending_outbound.is_empty(),
                "the refused frame was buffered"
            );

            for key in [quiet, hinted] {
                let sent = ops::send_app(&mut state, &context, frame_to(key), AppClass::NONE).await;
                assert!(sent.is_ok(), "the unmeshed send to {key} was refused");
            }
            assert_eq!(
                state.pending_outbound.take().len(),
                2,
                "the frames of the quiet key and of the key with an endpoint wait"
            );
            node.endpoint.close().await;
        });
    }

    /// Two live keys use one nickname. A directed frame names one key, so the other key is not its
    /// addressee, though it shares the nickname and a relay can hand it the frame. A broadcast is
    /// for both.
    #[test]
    fn a_frame_to_one_key_of_a_nickname_is_not_addressed_to_the_other_key() {
        let _guard = ::habilis_network_test_tracing::init();
        let (first, second) = (test_key("twin#first"), test_key("twin#second"));
        let tag = protocol::AppTag::try_new("app_msg").expect("a valid app tag");
        let frame = |to: Option<AuthorKey>| {
            Message::new_app(
                &MeshId::from("test"),
                &nick("sender"),
                AppFrameParams::new(tag.clone(), to, None, MessageBody::from("hi")),
            )
        };

        let to_first = frame(Some(first));
        assert!(
            super::addressed_to_us(&to_first, &first),
            "the addressee did not take its frame"
        );
        assert!(
            !super::addressed_to_us(&to_first, &second),
            "the other key of the nickname took a frame meant for the first"
        );
        assert!(
            super::addressed_to_us(&frame(None), &second),
            "a broadcast is for every key"
        );
    }

    /// Feed one gossip event to the handler, as the loop does.
    async fn feed(event: Event, state: &mut EventLoopState, context: &HandlerCtx<'_>) {
        handle_gossip_event(Some(Ok(event)), state, &mut Inert, context).await;
    }

    /// A frame parked while the links were down is sent at the next `NeighborUp`. The
    /// node stays meshed through the gap, so the first-link edge does not come again,
    /// and no `PeerInfo` arrives to flush it.
    #[test]
    fn a_frame_parked_across_a_gap_in_the_links_is_sent_at_the_next_neighbor_up() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            feed(Event::NeighborUp(endpoint_id(1)), &mut state, &context).await;
            feed(Event::NeighborDown(endpoint_id(1)), &mut state, &context).await;
            assert!(
                state.standing.contains(&Standing::Meshed),
                "the gap does not clear meshed"
            );
            let frame = Message::new_joined(&node.mesh, &node.author).sign(&Identity::generate());
            let bytes = frame.serialize().expect("serialize");
            assert!(
                state.pending_outbound.push((frame, bytes)),
                "a frame parked across a gap is queued for the next neighbor up"
            );

            feed(Event::NeighborUp(endpoint_id(2)), &mut state, &context).await;

            assert!(
                state.pending_outbound.is_empty(),
                "the parked frame waits for a PeerInfo that may not come"
            );
            node.endpoint.close().await;
        });
    }

    /// A proof ask that waited for a path goes when the gossip link to its endpoint comes up: the link
    /// is a path (the send dials the neighbour in the background), and it is the first sign of one, long
    /// before the next sweep tick. The late links of the simultaneous-open tie-break come up a few
    /// milliseconds after the ask was skipped.
    #[test]
    fn an_ask_that_waited_for_a_path_goes_when_the_gossip_link_to_its_endpoint_comes_up() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let session = Identity::generate();
            let endpoint = endpoint_id(7);
            state.peers.insert(session.author_key());
            state.names.insert(session.author_key(), nick("alice"));
            state.place_endpoint(
                session.author_key(),
                &nick("alice"),
                iroh::EndpointAddr::new(endpoint),
            );
            state
                .proofs
                .defer_ask(session.author_key(), &nick("alice"), clock::Instant::now());

            feed(Event::NeighborUp(endpoint), &mut state, &context).await;

            assert_eq!(
                (
                    state.proofs.deferred_len(),
                    state.proof_requests_signed.load(Ordering::Relaxed)
                ),
                (0, 1),
                "the ask goes once the link is up, and nothing waits"
            );
            node.endpoint.close().await;
        });
    }

    /// The sweep tick is the fallback of the deferred asks: it sends the ask of a session that has a path
    /// by now though no event said so, and it drops the ask that waited longer than its time, so that
    /// session is asked again at its next alive frame.
    #[test]
    fn the_sweep_sends_the_deferred_ask_that_has_a_path_and_drops_the_one_that_waited_too_long() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let (with_path, expired) = (Identity::generate(), Identity::generate());
            for (session, name, endpoint) in [
                (&with_path, "alice", endpoint_id(7)),
                (&expired, "bob", endpoint_id(8)),
            ] {
                state.peers.insert(session.author_key());
                state.names.insert(session.author_key(), nick(name));
                state.place_endpoint(
                    session.author_key(),
                    &nick(name),
                    iroh::EndpointAddr::new(endpoint),
                );
            }
            let now = clock::Instant::now();
            let long_ago = now
                .checked_sub(std_Duration::from_secs(31))
                .expect("a clock that runs for more than 31 s");
            state
                .proofs
                .defer_ask(with_path.author_key(), &nick("alice"), now);
            state
                .proofs
                .defer_ask(expired.author_key(), &nick("bob"), long_ago);
            // the path to alice is up, and no event said so
            state.linked_endpoints.insert(endpoint_id(7));

            lifecycle::retry_deferred_asks(&mut state, &context, None).await;

            assert_eq!(
                state.proof_requests_signed.load(Ordering::Relaxed),
                1,
                "the ask of the session with a path went, and the one that waited too long did not"
            );
            assert_eq!(
                state.proofs.deferred_len(),
                0,
                "nothing waits: the one asked is out, and the old one expired"
            );
            node.endpoint.close().await;
        });
    }

    /// The roster keys a peer by author key, so two live keys that share a nickname are two
    /// peers, and each one that answers the ping is a responder.
    #[test]
    fn two_live_keys_of_one_nickname_both_answer_a_ping_round() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let twin = nick("twin");
            let runs = [Identity::generate(), Identity::generate()];
            for run in &runs {
                state.names.insert(run.author_key(), twin.clone());
                state.peers.insert(run.author_key());
            }
            let probe = Message::new_ping(&node.mesh, &node.author);
            let started = TokioInstant::now();
            let window = started + std_Duration::from_secs(10);
            state.arm_ping_round(PingRound::new(&probe, started, window, None));
            let update = MembershipUpdate {
                returned: false,
                joined_new: false,
                stale: false,
            };

            for run in &runs {
                let pong =
                    Message::new_pong(&node.mesh, &twin, node.our_pubkey, &probe.id).sign(run);
                let flow =
                    dispatch_infra(&pong, true, &update, &mut state, &mut Inert, &context).await;
                assert!(flow.is_break(), "a pong is handled by the engine");
            }

            let answered = state.ping_round.as_ref().map(|round| round.pongs.len());
            assert_eq!(
                answered,
                Some(2),
                "the second key of the nickname was dropped from the responders"
            );
            node.endpoint.close().await;
        });
    }

    /// Two live keys share a nickname, and each proved its own endpoint. The dial hint under the
    /// nickname names the endpoint of one of them. The pong to a ping goes to the endpoint of the
    /// key that signed the ping.
    #[test]
    fn a_pong_goes_to_the_endpoint_that_the_ping_signer_proved() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let mut state = fresh_state();
            let twin = nick("twin");
            let (first, second) = (Identity::generate(), Identity::generate());
            let (first_endpoint, second_endpoint) = (endpoint_id(21), endpoint_id(22));
            state
                .peer_endpoints
                .insert(twin.clone(), iroh::EndpointAddr::new(first_endpoint));
            state.proven_endpoints.insert(
                first.author_key(),
                first_endpoint,
                UnixSecs::from(1),
                &HashSet::new(),
                |_| true,
            );
            state.proven_endpoints.insert(
                second.author_key(),
                second_endpoint,
                UnixSecs::from(1),
                &HashSet::new(),
                |_| true,
            );

            let request = Message::new_ping(&node.mesh, &twin).sign(&second);

            let (answer, target) = pong_for(&request, &state, &node.context());

            assert_eq!(
                target,
                Some(second_endpoint),
                "the pong went to the endpoint under the nickname, not to the signer's"
            );
            assert!(
                matches!(&answer.kind, MessageKind::Pong { to, probe } if *to == second.author_key() && *probe == request.id),
                "the pong does not answer the probe of the pinger: {:?}",
                answer.kind
            );
            node.endpoint.close().await;
        });
    }

    /// The proof table is a FIFO with a cap, and a roster key can fall out of it. The roster keeps
    /// its own trust of each key it holds, with no cap, so a ping from a roster key still finds the
    /// endpoint that the key proved.
    #[test]
    fn a_ping_from_a_roster_key_whose_proof_left_the_fifo_still_gets_its_pong() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let mut state = fresh_state();
            state.proven_endpoints = ProvenEndpoints::new(2);
            let pinger = Identity::generate();
            let pinger_endpoint = endpoint_id(31);
            state.peers.insert(pinger.author_key());
            state.note_proven_endpoint(pinger.author_key(), pinger_endpoint, UnixSecs::from(1));
            for byte in 0..2u8 {
                let stranger = Identity::generate().author_key();
                state.note_proven_endpoint(stranger, endpoint_id(40 + byte), UnixSecs::from(1));
            }
            assert_eq!(
                state.proven_endpoints.get(&pinger.author_key()),
                None,
                "precondition: strangers pushed the proof of the roster key out of the FIFO"
            );

            let request = Message::new_ping(&node.mesh, &nick("pinger")).sign(&pinger);
            let (_answer, target) = pong_for(&request, &state, &node.context());

            assert_eq!(
                target,
                Some(pinger_endpoint),
                "a ping from a roster key got no pong after its proof left the FIFO"
            );
            node.endpoint.close().await;
        });
    }

    /// A signer that has proved no endpoint gets no pong, whatever dial hint its nickname has: a
    /// hint is a claim. The ping round of that signer misses us and tries again.
    #[test]
    fn a_ping_from_a_signer_with_no_proof_gets_no_pong() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let mut state = fresh_state();
            let pinger = nick("pinger");
            state
                .peer_endpoints
                .insert(pinger.clone(), iroh::EndpointAddr::new(endpoint_id(21)));
            let request = Message::new_ping(&node.mesh, &pinger).sign(&Identity::generate());

            let (_answer, target) = pong_for(&request, &state, &node.context());

            assert_eq!(
                target, None,
                "a hint under the nickname was taken for a proof"
            );
            node.endpoint.close().await;
        });
    }

    /// An app frame counts the times that it reaches the app.
    // the app and the test share the counter
    struct Counting(Arc<atomic::AtomicUsize>);

    #[async_trait::async_trait]
    impl NodeApp for Counting {
        fn classify(&self, _message: &Authored) -> AppClass {
            AppClass::BEAT.union(AppClass::VALID)
        }

        async fn on_app_frame(
            &mut self,
            _frame: InboundApp<'_>,
            _state: &mut EventLoopState,
            _ctx: &HandlerCtx<'_>,
        ) -> bool {
            self.0.fetch_add(1, Ordering::Relaxed);
            true
        }
    }

    /// A sink that keeps the text of each error line.
    #[derive(Default)]
    struct ErrorLines(Mutex<Vec<String>>);

    impl NodeSink for ErrorLines {
        fn emit(&self, event: NodeEvent) {
            if let NodeEvent::Error(text) = event {
                self.0
                    .lock()
                    .expect("the lines lock is not poisoned")
                    .push(text);
            }
        }
    }

    /// A frame of another protocol version does not parse. The error line names the version that
    /// the frame carries, so an operator can tell a peer that runs an older build from a corrupt
    /// frame, and a second frame of the same version adds no line.
    #[test]
    fn a_frame_of_another_wire_version_is_reported_by_its_version_once() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network::gossip",
                "dropping a frame of an unsupported protocol version",
            );
            let node = Node::spawn().await;
            let lines = ErrorLines::default();
            let context = HandlerCtx {
                sink: &lines,
                ..node.context()
            };
            let mut state = fresh_state();
            let mut app = Inert;
            let frame = Message::new_app(
                &node.mesh,
                &nick("alice"),
                AppFrameParams::new(
                    protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                    None,
                    None,
                    MessageBody::from("old"),
                ),
            )
            .sign(&Identity::generate());
            let text = frame.serialize().expect("serialize").into_bytes();
            let old = String::from_utf8(text.to_vec())
                .expect("a frame is text")
                .replacen(r#""v":"14.0""#, r#""v":"12.0""#, 1);
            assert!(old.contains("12.0"), "the test frame names version 12.0");

            ingest(Bytes::from(old.clone()), &mut state, &mut app, &context).await;
            ingest(Bytes::from(old), &mut state, &mut app, &context).await;

            let seen = lines
                .0
                .lock()
                .expect("the lines lock is not poisoned")
                .clone();
            let naming: Vec<&String> = seen.iter().filter(|line| line.contains("12.0")).collect();
            assert_eq!(
                naming.len(),
                1,
                "the version of the frame is named once: {seen:?}"
            );
            node.endpoint.close().await;
        });
    }

    /// A newer run of our own member is admitted, and the newest run wins at the other nodes: this node is
    /// superseded and says so, once for each run number.
    #[test]
    fn a_newer_run_of_our_own_member_is_reported_once_for_each_run() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network::lifecycle",
                "a newer run of our member is active",
            );
            let node = Node::spawn().await;
            let lines = ErrorLines::default();
            let context = HandlerCtx {
                sink: &lines,
                ..node.context()
            };
            let mut state = fresh_state();
            let member = state
                .member_identity
                .clone()
                .expect("a test state has a member key");
            let mut app = Inert;

            // Our run is 1. The runs 5, 5 (another session) and 6 of our member arrive, then the run 0.
            for run in [5u64, 5, 6, 0] {
                let session = Identity::generate();
                let key = session.author_key();
                let proof = member.prove(&key, node.author.as_ref(), node.mesh.as_ref(), run);
                let joined =
                    Message::new_joined_with_proof(&node.mesh, &node.author, &proof).sign(&session);
                let bytes = joined.serialize().expect("serialize").into_bytes();
                ingest(bytes, &mut state, &mut app, &context).await;
            }

            let seen = lines
                .0
                .lock()
                .expect("the lines lock is not poisoned")
                .clone();
            let superseded: Vec<&String> = seen
                .iter()
                .filter(|line| line.contains("newer run of this member"))
                .collect();
            assert_eq!(
                superseded.len(),
                2,
                "one line for the run 5 and one for the run 6, none for the second run 5 or the older run: {seen:?}"
            );
            node.endpoint.close().await;
        });
    }

    /// The version of a frame that does not parse is chosen by its sender, and the frame is not
    /// verified. A version of 500 characters with control bytes gives a short line of printable
    /// characters, and the set of named versions holds the cut text.
    #[test]
    fn the_version_in_the_error_line_is_cut_and_printable() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network::gossip",
                "dropping a frame of an unsupported protocol version",
            );
            let node = Node::spawn().await;
            let lines = ErrorLines::default();
            let context = HandlerCtx {
                sink: &lines,
                ..node.context()
            };
            let mut state = fresh_state();
            let mut app = Inert;
            let frame = Message::new_app(
                &node.mesh,
                &nick("alice"),
                AppFrameParams::new(
                    protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                    None,
                    None,
                    MessageBody::from("hostile"),
                ),
            )
            .sign(&Identity::generate());
            let wire: Bytes = frame.serialize().expect("serialize").into_bytes();
            let text = String::from_utf8(wire.to_vec()).expect("a frame is text");
            let version = format!(r"\u0007\u001b[31m{}", "x".repeat(500));
            let hostile = text.replacen(r#""v":"14.0""#, &format!(r#""v":"{version}""#), 1);

            ingest(Bytes::from(hostile), &mut state, &mut app, &context).await;

            let seen: Vec<String> = {
                let held = lines.0.lock().expect("the lines lock is not poisoned");
                held.clone()
            };
            assert_eq!(seen.len(), 1, "one line for the frame: {seen:?}");
            let line = &seen[0];
            let printable: bool = line
                .chars()
                .all(|ch| ch.is_ascii() && !ch.is_ascii_control());
            assert!(
                line.len() < 120 && printable,
                "the line is long or holds a control byte: {line:?}"
            );
            node.endpoint.close().await;
        });
    }

    /// A sender that makes up versions gets a bounded number of error lines. The frame is not
    /// verified, so a version set that evicts its oldest entry lets a cycle of `cap + 1` versions
    /// name each frame again. After the cap, the set takes no new version and one line says that
    /// many versions are unknown.
    #[test]
    fn a_sender_that_cycles_versions_gets_at_most_cap_plus_one_lines() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network::gossip",
                "dropping a frame of an unsupported protocol version",
            );
            let node = Node::spawn().await;
            let lines = ErrorLines::default();
            let context = HandlerCtx {
                sink: &lines,
                ..node.context()
            };
            let mut state = fresh_state();
            let mut app = Inert;
            let frame = Message::new_app(
                &node.mesh,
                &nick("alice"),
                AppFrameParams::new(
                    protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                    None,
                    None,
                    MessageBody::from("cycle"),
                ),
            )
            .sign(&Identity::generate());
            let wire: Bytes = frame.serialize().expect("serialize").into_bytes();
            let text = String::from_utf8(wire.to_vec()).expect("a frame is text");
            let cap = tuning::UNSUPPORTED_VERSION_CAP;

            // Two passes over `cap + 1` versions: an evicting set names every frame of both.
            for version in (0..=cap).chain(0..=cap) {
                let other = text.replacen(r#""v":"14.0""#, &format!(r#""v":"v{version}""#), 1);
                ingest(Bytes::from(other), &mut state, &mut app, &context).await;
            }

            let seen: Vec<String> = {
                let held = lines.0.lock().expect("the lines lock is not poisoned");
                held.clone()
            };
            assert_eq!(
                seen.len(),
                cap + 1,
                "one line for each of the first {cap} versions and one for the rest: {seen:?}"
            );
            let warned = ::habilis_network_test_tracing::warn_count(
                "habilis_network::gossip",
                "dropping a frame of an unsupported protocol version",
            );
            assert_eq!(
                warned,
                cap + 1,
                "the stderr log of an unauthenticated flood obeys the cap of the error lines"
            );
            let last = seen.last().expect("the lines are not empty");
            assert!(
                last.contains("many unknown versions"),
                "the last line says that many versions are unknown: {last:?}"
            );
            node.endpoint.close().await;
        });
    }

    /// A relay forwards a directed frame of another key and keeps no copy, whatever the app
    /// returns. The engine cannot open the body, and no app of the workspace asks to keep such a
    /// frame, so a copy would be one that only the log cap bounds. The engine gives no repair for a
    /// directed frame: the author keeps none, and a relay keeps none. A key that was away gets the
    /// frame only if the app protocol sends it again.
    #[test]
    fn a_relayed_directed_frame_is_not_kept_whatever_the_app_returns() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            // the app and the test share the counter
            let reads = Arc::new(atomic::AtomicUsize::new(0));
            // `Counting` returns `true` for every frame, the answer that asked for a copy.
            let mut app = Counting(Arc::clone(&reads));
            let addressee = test_key("twin#addressee");
            let params = AppFrameParams::new(
                protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                Some(addressee),
                None,
                MessageBody::from("for one key"),
            );
            let frame =
                Message::new_app(&node.mesh, &nick("alice"), params).sign(&Identity::generate());
            let wire = frame.serialize().expect("serialize");

            ingest(wire.into_bytes(), &mut state, &mut app, &context).await;

            assert_eq!(
                reads.load(Ordering::Relaxed),
                1,
                "the app sees the frame of another key once"
            );
            let have = HashSet::new();
            let query = MissingQuery {
                range: message_log::seconds(UnixSecs::ZERO, UnixSecs::MAX),
                have: &have,
                max: 16,
                requester: &addressee,
            };
            assert_eq!(
                state.message_log.missing_in_window(query).len(),
                0,
                "a relay kept a directed frame of another key"
            );
            node.endpoint.close().await;
        });
    }

    /// A resend of a message that the app already read has a new gossip payload, and the ingest
    /// of the app still drops it by the id of the message inside: the app sees the frame once.
    #[test]
    fn a_resend_of_a_known_message_reaches_the_app_once() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            // the app and the test share the counter
            let reads = Arc::new(atomic::AtomicUsize::new(0));
            let mut app = Counting(Arc::clone(&reads));
            let frame = Message::new_app(
                &node.mesh,
                &nick("alice"),
                AppFrameParams::new(
                    protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                    None,
                    None,
                    MessageBody::from("hello"),
                ),
            )
            .sign(&Identity::generate());
            let original = frame.serialize().expect("serialize");
            let resend = original.copy_with_resend_nonce(42);

            ingest(original.into_bytes(), &mut state, &mut app, &context).await;
            ingest(resend.into_bytes(), &mut state, &mut app, &context).await;

            assert_eq!(
                reads.load(Ordering::Relaxed),
                1,
                "the first delivery reaches the app and the resend does not"
            );
            node.endpoint.close().await;
        });
    }

    /// An app that records who the meta hook names.
    // the app and the test share the record
    struct MetaRecorder(Arc<Mutex<Vec<AuthorKey>>>);

    #[async_trait::async_trait]
    impl NodeApp for MetaRecorder {
        fn classify(&self, _message: &Authored) -> AppClass {
            AppClass::NONE
        }

        async fn on_app_frame(
            &mut self,
            _frame: InboundApp<'_>,
            _state: &mut EventLoopState,
            _ctx: &HandlerCtx<'_>,
        ) -> bool {
            false
        }

        fn on_meta_applied(
            &mut self,
            author: &AuthorKey,
            _state: &mut EventLoopState,
            _context: &HandlerCtx<'_>,
        ) {
            if let Ok(mut record) = self.0.lock() {
                record.push(*author);
            }
        }
    }

    /// Two keys can use one nickname, and the meta slot of each is its own. The hook that tells
    /// the app which slot changed names the key of the author, so the app reads the slot of that
    /// key and not the slot of the other key.
    #[test]
    fn the_meta_hook_tells_two_keys_of_one_nickname_apart() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            // the app and the test share the record
            let record = Arc::new(Mutex::new(Vec::new()));
            let mut app = MetaRecorder(Arc::clone(&record));
            let twin = nick("twin");
            let identities = [Identity::generate(), Identity::generate()];
            for identity in &identities {
                let frame = Message::new_channel_event(
                    &node.mesh,
                    &twin,
                    MessageBody::from("{}"),
                    Channel::Meta,
                )
                .sign(identity);
                dispatch_channel(
                    ChannelEvent {
                        channel: Channel::Meta,
                        message: &frame,
                        surfaceable: true,
                    },
                    &mut state,
                    &mut app,
                    &context,
                );
            }

            let heard = record.lock().expect("the record lock").clone();
            let keys: Vec<AuthorKey> = identities.iter().map(Identity::author_key).collect();
            assert_eq!(
                heard, keys,
                "the hook did not name the key of each author, in order"
            );
            node.endpoint.close().await;
        });
    }

    /// The messages that the old subscription queued reach the app when the topic is swapped.
    /// The loop does not read the queue while the topic is marked closed, and the gossip layer
    /// counted each message as delivered, so the queue holds the only copy.
    #[test]
    fn the_messages_the_old_subscription_queued_reach_the_app_at_the_swap() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use futures_util::stream::{self, StreamExt as _};
            use iroh_gossip::api::Message as GossipMessage;
            use iroh_gossip::proto::DeliveryScope;

            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let author = Identity::generate();
            let frames: Vec<Verified> = ["ann", "bob", "cat"]
                .into_iter()
                .map(|name| Message::new_joined(&node.mesh, &nick(name)).sign(&author))
                .collect();
            let (feed_topic, topic_rx) = mpsc::unbounded_channel();
            let events = stream::unfold(topic_rx, |mut rx| async move {
                rx.recv().await.map(|item| (item, rx))
            })
            .boxed();
            let mut receiver = split::spawn_split(events, None);
            for message in &frames {
                let wire = message.serialize().expect("serialize").into_bytes();
                let delivered = GossipMessage {
                    content: wire,
                    scope: DeliveryScope::Neighbors,
                    delivered_from: endpoint_id(9),
                };
                feed_topic
                    .send(Ok(Event::Received(delivered)))
                    .expect("the splitter reads the topic");
            }
            while receiver.high_water() < frames.len() {
                tokio_task::yield_now().await;
            }

            super::drain_queued(&mut receiver, &mut state, &mut Inert, &context).await;

            for message in &frames {
                assert!(
                    state.mark_seen(message),
                    "{} was queued by the old subscription and never reached the app",
                    message.author
                );
            }
            node.endpoint.close().await;
        });
    }

    /// The frame of the field red: a directed frame parked across a gap in the links reaches
    /// its addressee at the next `NeighborUp`, with no `PeerInfo`.
    #[test]
    fn a_directed_frame_parked_across_a_gap_in_the_links_is_delivered_at_the_next_neighbor_up() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use iroh::protocol::Router;

                use crate::protocol::MessageId;
                use crate::transport::{UNICAST_ALPN, UnicastAcceptor, UnicastPool};

                let node = Node::spawn().await;
                let context = node.context();
                let bob = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind bob");
                let (inbox, mut frames) = mpsc::channel(8);
                let router = Router::builder(bob.clone())
                    .accept(
                        UNICAST_ALPN,
                        UnicastAcceptor::with_idle(
                            inbox,
                            PayloadPath::DirectOnly,
                            std_Duration::from_mins(1),
                        ),
                    )
                    .spawn();
                lookup::add_peer_addr(&lookup::address_book(&node.endpoint), bob.addr());
                let mut state = fresh_state();
                state.unicast_pool = UnicastPool::new(node.endpoint.clone(), false);
                state.names.insert(test_key("bob"), nick("bob"));
                state.bind_peer_endpoint(test_key("bob"), nick("bob"), bob.addr());
                feed(Event::NeighborUp(bob.id()), &mut state, &context).await;
                feed(Event::NeighborDown(bob.id()), &mut state, &context).await;
                assert!(
                    state.standing.contains(&Standing::Meshed),
                    "the gap does not clear meshed"
                );
                let frame = Message::new_pong(
                    &node.mesh,
                    &node.author,
                    test_key("bob"),
                    &MessageId::random(),
                )
                .sign(&Identity::generate());
                let bytes = frame.serialize().expect("serialize");
                assert!(
                    state.pending_outbound.push((frame, bytes.clone())),
                    "a directed frame parked across a gap is queued"
                );

                feed(Event::NeighborUp(bob.id()), &mut state, &context).await;

                let delivered =
                    tokio_time::timeout(std_Duration::from_secs(5), frames.recv()).await;
                assert_eq!(
                    delivered.ok().flatten().map(|inbound| inbound.bytes),
                    Some(bytes.into_bytes()),
                    "bob never got the parked frame"
                );
                assert!(
                    state.pending_outbound.is_empty(),
                    "the directed frame stays parked across a second gap"
                );
                router.shutdown().await.expect("shutdown");
                node.endpoint.close().await;
            },
        );
    }

    /// A node that reaches the release count tells gossip to leave the
    /// rendezvous and marks the release at once. The leave ends the link by
    /// itself, whatever the endpoint is, so the mark does not wait for a
    /// connection to be closed from here: a node that left but was not marked
    /// would read the `NeighborDown` that follows as a loss and arm a reclaim.
    /// The link is still up when the mark is made; gossip ends it afterwards.
    #[test]
    fn reaching_the_release_count_leaves_the_rendezvous_and_marks_it() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.rendezvous_release_links = 3;

            feed(
                Event::NeighborUp(context.rendezvous_id),
                &mut state,
                &context,
            )
            .await;
            assert!(
                state.rendezvous_flags.contains(&RendezvousFlag::Linked),
                "the rendezvous is marked linked after the release"
            );
            assert!(
                !state.rendezvous_flags.contains(&RendezvousFlag::Released),
                "below the count: still a visitor"
            );
            for seed in 1..=3 {
                feed(Event::NeighborUp(endpoint_id(seed)), &mut state, &context).await;
            }

            assert!(
                state.rendezvous_flags.contains(&RendezvousFlag::Released),
                "gossip was told to leave, so the release is marked"
            );
            assert!(
                state.rendezvous_flags.contains(&RendezvousFlag::Linked),
                "gossip ends the link, and the NeighborDown clears this"
            );
            node.endpoint.close().await;
        });
    }

    /// The `NeighborDown` that a release causes is a choice, not a loss: no
    /// reclaim window opens, and nothing wants the rendezvous back.
    #[test]
    fn the_neighbor_down_after_a_release_arms_nothing() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.rendezvous_release_links = 2;
            feed(
                Event::NeighborUp(context.rendezvous_id),
                &mut state,
                &context,
            )
            .await;
            for seed in 1..=2 {
                feed(Event::NeighborUp(endpoint_id(seed)), &mut state, &context).await;
            }
            // Released, as `mark_rendezvous_released` marks it when gossip is told
            // to leave the rendezvous.
            state.rendezvous_flags.insert(RendezvousFlag::Released);

            feed(
                Event::NeighborDown(context.rendezvous_id),
                &mut state,
                &context,
            )
            .await;

            assert!(
                !state.rendezvous_flags.contains(&RendezvousFlag::Linked),
                "the neighbor down after a release leaves the rendezvous unlinked"
            );
            assert!(state.reclaim_until.is_none(), "no loss, no reclaim");
            assert!(!state.rendezvous_wanted(), "no graft, no offer");
            node.endpoint.close().await;
        });
    }

    /// The holder of the rendezvous is gone: a round that is still dialling it holds the slot, and
    /// the re-offer that follows the `NeighborDown` would be refused `InFlight` for the rest of the
    /// round deadline.
    #[test]
    fn losing_the_rendezvous_ends_a_round_that_is_still_dialling_it() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.rendezvous_id = Some(context.rendezvous_id);
            let hub = lookup::build_webrtc_handle(node.endpoint.id());
            let held_round = state
                .webrtc_admission
                .try_admit(context.rendezvous_id, &hub)
                .expect("a free slot");
            let epoch = held_round.epoch();
            let task = task::spawn(async move {
                let _held_round = held_round;
                let forever: future::Pending<()> = future::pending();
                forever.await;
            });
            state
                .webrtc_admission
                .track(context.rendezvous_id, epoch, task.abort_handle());
            feed(
                Event::NeighborUp(context.rendezvous_id),
                &mut state,
                &context,
            )
            .await;
            assert_eq!(
                state.webrtc_admission.in_flight(),
                1,
                "one slot is in flight while the round is dialling"
            );

            feed(
                Event::NeighborDown(context.rendezvous_id),
                &mut state,
                &context,
            )
            .await;

            let round_running = state.webrtc_admission.in_flight() != 0;
            node.endpoint.close().await;
            assert!(
                !round_running,
                "the round to the lost holder still holds the slot of the rendezvous"
            );
        });
    }

    /// Losing a rendezvous we did not release still arms the reclaim: it may
    /// be dead, and someone has to stand up the next one.
    #[test]
    fn losing_a_rendezvous_that_was_not_released_still_arms_the_reclaim() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.rendezvous_release_links = 3;
            feed(
                Event::NeighborUp(context.rendezvous_id),
                &mut state,
                &context,
            )
            .await;
            feed(Event::NeighborUp(endpoint_id(1)), &mut state, &context).await;

            feed(
                Event::NeighborDown(context.rendezvous_id),
                &mut state,
                &context,
            )
            .await;

            assert!(
                state.reclaim_until.is_some(),
                "losing a rendezvous that was not released arms the reclaim"
            );
            assert!(state.rendezvous_wanted(), "below the count: come back");
            node.endpoint.close().await;
        });
    }

    /// A node below the count after a release wants the rendezvous again, and
    /// the link coming back ends the release and the debt.
    #[test]
    fn the_link_coming_back_clears_the_release_and_the_owed_return() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.rendezvous_release_links = 1;
            state.rendezvous_flags.insert(RendezvousFlag::Released);
            state.owe_rendezvous_return(clock::Instant::now());

            feed(
                Event::NeighborUp(context.rendezvous_id),
                &mut state,
                &context,
            )
            .await;

            assert!(
                state.rendezvous_flags.contains(&RendezvousFlag::Linked),
                "the link coming back restores the rendezvous link"
            );
            assert!(
                !state.rendezvous_flags.contains(&RendezvousFlag::Released),
                "the link coming back clears the released mark"
            );
            assert!(
                state.rendezvous_comeback_until.is_none(),
                "the debt is paid"
            );
            assert!(
                state.rendezvous_dwell_until.is_some(),
                "and the visit lasts its dwell time"
            );
            node.endpoint.close().await;
        });
    }

    /// Two islands, each wide enough to have let go of the rendezvous, are
    /// split by a block. Neither sees the other, so each sweeps its silent
    /// neighbours, and that sweep is what sends the island back to the place
    /// where the islands meet.
    #[test]
    fn an_island_whose_peers_went_silent_comes_back_to_the_rendezvous() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use std::time::Duration;

            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.rendezvous_release_links = 3;
            feed(
                Event::NeighborUp(context.rendezvous_id),
                &mut state,
                &context,
            )
            .await;
            for seed in 1..=3 {
                feed(Event::NeighborUp(endpoint_id(seed)), &mut state, &context).await;
            }
            feed(
                Event::NeighborDown(context.rendezvous_id),
                &mut state,
                &context,
            )
            .await;
            assert!(!state.rendezvous_wanted(), "an island of its own, content");
            assert!(
                !webrtc::rendezvous::rendezvous_graftable(&state),
                "an island whose peers went silent is not graftable to the rendezvous"
            );

            let silent = clock::Instant::now()
                .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
                .expect("a past instant");
            state.last_seen.insert(test_key("far-side"), silent);
            state.peer_for_test("far-side");
            state.surfaced_for_test("far-side");
            heartbeat::tick_sweep(&mut state, &SilentSink);

            assert!(state.rendezvous_wanted(), "the sweep owes one return");
            assert!(
                webrtc::rendezvous::rendezvous_graftable(&state),
                "so the heal tick may graft it"
            );
            node.endpoint.close().await;
        });
    }

    /// A `PeerInfo` binds its signer to its endpoint only with that endpoint's
    /// proof over that signer. Bob's proof is public on gossip, so a frame that
    /// carries it but is signed by another key must bind nothing.
    #[test]
    fn a_peer_info_binds_its_signer_only_with_the_endpoints_proof() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::messages::MessageBody;
            use crate::protocol::{AuthorKey, identity, peer_addr_error};
            use crate::transport::proven_endpoints;

            let node = Node::spawn().await;
            let context = node.context();
            let bob_endpoint_key = iroh::SecretKey::generate();
            let bob_endpoint = bob_endpoint_key.public();
            let bob = Identity::generate();
            let stranger = Identity::generate();
            let bob_signer = AuthorKey::decode_hex(&identity::encode_pubkey(&bob.public()))
                .expect("a 32-byte key");
            let peer_info = |proof: Option<&str>, signed_by: &Identity| {
                let mut json =
                    peer_addr_error::endpoint_addr_to_json(&iroh::EndpointAddr::new(bob_endpoint));
                if let Some(proof) = proof {
                    json["proof"] = serde_json::Value::String(proof.to_owned());
                }
                let body = MessageBody::try_new(&json.to_string()).expect("an address body");
                Message::new_peer_info(&node.mesh, &nick("bob"), body).sign(signed_by)
            };
            let bobs_proof = proven_endpoints::sign(&bob_endpoint_key, &node.mesh, &bob_signer);

            let mut state = fresh_state();
            super::handle_peer_info(
                &peer_info(Some(&bobs_proof), &stranger),
                &mut state,
                &context,
            )
            .await;
            let stranger_signer =
                AuthorKey::decode_hex(&identity::encode_pubkey(&stranger.public()))
                    .expect("a 32-byte key");
            assert_eq!(
                state.proven_endpoints.get(&stranger_signer),
                None,
                "bob's proof, another signer"
            );

            super::handle_peer_info(&peer_info(None, &bob), &mut state, &context).await;
            assert_eq!(state.proven_endpoints.get(&bob_signer), None, "no proof");

            super::handle_peer_info(&peer_info(Some(&bobs_proof), &bob), &mut state, &context)
                .await;
            assert_eq!(
                state.proven_endpoints.get(&bob_signer),
                Some(bob_endpoint),
                "bob's proof, bob's frame"
            );
            node.endpoint.close().await;
        });
    }

    /// A proof request can come before the `PeerInfo` of its sender, so the sender has no address here. The
    /// connection that the request arrived on is a return path of its own: the answer goes there, and so
    /// takes its slot of the per-minute cap.
    #[test]
    fn a_proof_request_without_a_known_sender_address_is_answered_on_its_arrival_connection() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let asker = Identity::generate();
            let to = state.identity.author_key();
            let request = Message::new_proof_request(&node.mesh, &nick("asker"), to).sign(&asker);
            state.direct.insert(endpoint_id(80), DirectState::Direct);
            state.state_digest_serves.unicast.arrived_from = Some(endpoint_id(80));

            super::answer_proof_request(&to, &request, &mut state, &context).await;

            let again = state.proof_answer(
                &to,
                &asker.author_key(),
                context.author,
                context.mesh,
                clock::Instant::now(),
            );
            assert!(
                again.is_none(),
                "the request was dropped for want of an address, so its slot of the cap is still free"
            );
            node.endpoint.close().await;
        });
    }

    /// The answer to a proof request goes where a send can go. An asker that moved to another endpoint can
    /// leave its old address in the roster: that address has no usable path, and the connection that the
    /// request came on has. The answer must not be sent to the old address, where it is lost after it took a
    /// slot of the cap. An address that does have a usable path stays the first choice.
    #[test]
    fn a_proof_answer_goes_to_the_arrival_when_the_cached_address_has_no_usable_path() {
        let mut state = fresh_state();
        let asker = Identity::generate().author_key();
        let (old, new) = (endpoint_id(81), endpoint_id(82));
        state.peers.insert(asker);
        state.names.insert(asker, nick("asker"));
        state.place_endpoint(asker, &nick("asker"), iroh::EndpointAddr::new(old));
        state.direct.insert(new, DirectState::Direct);
        state.state_digest_serves.unicast.arrived_from = Some(new);

        assert_eq!(
            super::return_path(&state, &asker),
            Some(new),
            "the answer was aimed at the old address, which has no usable path"
        );

        state.direct.insert(old, DirectState::Direct);
        assert_eq!(
            super::return_path(&state, &asker),
            Some(old),
            "an address with a usable path is no longer the first choice"
        );
    }

    /// Two live keys use one nickname, and the second binds no dial hint. When the first leaves,
    /// the second is the only key of the nickname, and its endpoint becomes the hint at once: a
    /// directed send does not wait for its next `PeerInfo`.
    #[test]
    fn the_endpoint_a_rival_key_was_refused_becomes_the_hint_when_the_first_key_leaves() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::messages::MessageBody;
            use crate::protocol::peer_addr_error;

            let node = Node::spawn().await;
            let context = node.context();
            let twin = nick("twin");
            let (first_endpoint, second_endpoint) = (endpoint_id(51), endpoint_id(52));
            let (first, second) = (Identity::generate(), Identity::generate());
            let mut state = fresh_state();
            for (run, endpoint) in [(&first, first_endpoint), (&second, second_endpoint)] {
                state.names.insert(run.author_key(), twin.clone());
                state.peers.insert(run.author_key());
                let json =
                    peer_addr_error::endpoint_addr_to_json(&iroh::EndpointAddr::new(endpoint));
                let body = MessageBody::try_new(&json.to_string()).expect("an address body");
                let peer_info = Message::new_peer_info(&node.mesh, &twin, body).sign(run);
                super::handle_peer_info(&peer_info, &mut state, &context).await;
            }
            assert_eq!(
                state.peer_endpoints.get(&twin).map(|address| address.id),
                Some(first_endpoint),
                "the first key holds the hint"
            );

            state.forget_key(first.author_key());

            assert_eq!(
                state.peer_endpoints.get(&twin).map(|address| address.id),
                Some(second_endpoint),
                "the survivor's endpoint was not bound when the first key left"
            );
            assert!(
                !state.refused_endpoints.contains_key(&second.author_key()),
                "the retained endpoint stayed after the rebind"
            );
            node.endpoint.close().await;
        });
    }

    /// A refused key binds a hint at last, when the key that held the nickname is gone from the
    /// roster. The endpoint that it had retained is not a hint, and its address leaves the book.
    #[test]
    fn a_refused_key_that_binds_releases_the_endpoint_it_had_retained() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::messages::MessageBody;
            use crate::protocol::peer_addr_error;

            let node = Node::spawn().await;
            let context = node.context();
            let twin = nick("twin");
            let (held, bound) = (endpoint_id(54), endpoint_id(55));
            let (first, second) = (Identity::generate(), Identity::generate());
            let mut state = fresh_state();
            for run in [&first, &second] {
                state.names.insert(run.author_key(), twin.clone());
                state.peers.insert(run.author_key());
            }
            let advertise = |run: &Identity, endpoint| {
                let json =
                    peer_addr_error::endpoint_addr_to_json(&iroh::EndpointAddr::new(endpoint));
                let body = MessageBody::try_new(&json.to_string()).expect("an address body");
                Message::new_peer_info(&node.mesh, &twin, body).sign(run)
            };
            super::handle_peer_info(&advertise(&first, endpoint_id(53)), &mut state, &context)
                .await;
            super::handle_peer_info(&advertise(&second, held), &mut state, &context).await;
            assert!(
                state.refused_endpoints.contains_key(&second.author_key()),
                "the second key was not refused"
            );
            state.peers.remove(&first.author_key());

            super::handle_peer_info(&advertise(&second, bound), &mut state, &context).await;

            assert!(
                !state
                    .unicast_pool
                    .remembers_address(&iroh::EndpointAddr::new(held)),
                "the endpoint that the key had retained stayed in the book after it bound"
            );
            node.endpoint.close().await;
        });
    }

    /// The roster trusts a key whose proof the capped table has dropped. Its beacon flag is
    /// believed: the trust is what a pong and a link vector follow too.
    #[test]
    fn the_beacon_flag_of_a_trusted_key_whose_proof_left_the_table_is_believed() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::messages::MessageBody;
            use crate::protocol::{AuthorKey, identity, peer_addr_error};

            let node = Node::spawn().await;
            let context = node.context();
            let bob_endpoint = iroh::SecretKey::generate().public();
            let bob = Identity::generate();
            let bob_signer = AuthorKey::decode_hex(&identity::encode_pubkey(&bob.public()))
                .expect("a 32-byte key");
            let mut json =
                peer_addr_error::endpoint_addr_to_json(&iroh::EndpointAddr::new(bob_endpoint));
            json["beacon"] = serde_json::Value::Bool(true);
            let body = MessageBody::try_new(&json.to_string()).expect("an address body");
            let peer_info = Message::new_peer_info(&node.mesh, &nick("bob"), body).sign(&bob);

            let mut state = fresh_state();
            state.peers.insert(bob_signer);
            state.proven_endpoints.trust(bob_signer, bob_endpoint);
            assert_eq!(
                state.proven_endpoints.get(&bob_signer),
                None,
                "the table holds no proof of bob"
            );

            super::handle_peer_info(&peer_info, &mut state, &context).await;

            assert_eq!(
                state.rival_holders.get(&bob_signer),
                Some(&bob_endpoint),
                "the flag of a key that the roster trusts was dropped"
            );
            node.endpoint.close().await;
        });
    }

    /// A `PeerInfo` can come before its signer is in the roster. The table then holds the proof
    /// and the trust map does not, so the next `PeerInfo` with the same proof must still make the
    /// trust once the signer is a peer.
    #[test]
    fn a_proof_recorded_before_the_signer_joined_the_roster_is_trusted_by_the_next_peer_info() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::messages::MessageBody;
            use crate::protocol::{AuthorKey, identity, peer_addr_error};
            use crate::transport::proven_endpoints;

            let node = Node::spawn().await;
            let context = node.context();
            let bob_endpoint_key = iroh::SecretKey::generate();
            let bob_endpoint = bob_endpoint_key.public();
            let bob = Identity::generate();
            let bob_signer = AuthorKey::decode_hex(&identity::encode_pubkey(&bob.public()))
                .expect("a 32-byte key");
            let proof = proven_endpoints::sign(&bob_endpoint_key, &node.mesh, &bob_signer);
            let mut json =
                peer_addr_error::endpoint_addr_to_json(&iroh::EndpointAddr::new(bob_endpoint));
            json["proof"] = serde_json::Value::String(proof);
            let body = MessageBody::try_new(&json.to_string()).expect("an address body");
            let peer_info = Message::new_peer_info(&node.mesh, &nick("bob"), body).sign(&bob);

            let mut state = fresh_state();
            super::handle_peer_info(&peer_info, &mut state, &context).await;
            assert_eq!(
                state.proven_endpoints.get(&bob_signer),
                Some(bob_endpoint),
                "the proof is recorded"
            );
            assert_eq!(
                state.proven_endpoints.trusted(&bob_signer),
                None,
                "bob is not a peer yet, so nothing is trusted"
            );

            state.peers.insert(bob_signer);
            super::handle_peer_info(&peer_info, &mut state, &context).await;
            assert_eq!(
                state.proven_endpoints.trusted(&bob_signer),
                Some(bob_endpoint),
                "bob is a peer now, and the same proof makes the trust"
            );
            node.endpoint.close().await;
        });
    }

    /// The first vector of a member goes out when its link comes up, and its `PeerInfo` can be a
    /// few milliseconds behind it. The vector waits for the binding, and the `PeerInfo` that
    /// writes the binding feeds it: not the tick, 15 s on, after the relay policy closed the links.
    #[cfg(feature = "multihop")]
    #[test]
    fn a_link_vector_that_came_before_the_peer_info_of_its_author_is_fed_by_that_peer_info() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use habilis_network_iroh_multihop_transport::{MultihopHandle, underlay_secret};
            use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};

            use crate::protocol::peer_addr_error;
            use crate::transport::proven_endpoints;

            async fn handle_for(secret: &SecretKey) -> MultihopHandle {
                let underlay_builder = Endpoint::builder(presets::Minimal)
                    .secret_key(underlay_secret(secret))
                    .relay_mode(RelayMode::Disabled);
                let underlay = underlay_builder.bind().await.expect("bind an underlay");
                MultihopHandle::new(
                    secret,
                    underlay,
                    lookup::multihop_handle_config(PayloadPath::DirectOnly),
                )
                .expect("underlay on the derived key")
            }

            let node = Node::spawn().await;
            let context = node.context();
            let author_key = SecretKey::generate();
            let other_key = SecretKey::generate();
            let ours = handle_for(&SecretKey::generate()).await;
            let theirs = handle_for(&author_key).await;
            let mut state = fresh_state();
            state.multihop = Some(ours.clone());

            let vector_body = gossip::json_body(&theirs.link_vector(vec![(
                habilis_network_iroh_multihop_transport::AppId::new(other_key.public()),
                10,
            )]))
            .expect("a vector serializes");
            let signer = Identity::generate();
            state.peers.insert(signer.author_key());
            let vector =
                Message::new_link_state(&node.mesh, &nick("alice-aa"), vector_body).sign(&signer);
            assert!(
                !super::handle_link_state(&vector, &mut state),
                "no proof yet: nothing is fed"
            );
            assert!(
                ours.topology_view().edges.is_empty(),
                "a node with no peers has no topology edges"
            );

            let mut address =
                peer_addr_error::endpoint_addr_to_json(&EndpointAddr::new(author_key.public()));
            address["proof"] = serde_json::Value::String(proven_endpoints::sign(
                &author_key,
                &node.mesh,
                &signer.author_key(),
            ));
            let address_body = MessageBody::try_new(&address.to_string()).expect("an address body");
            let peer_info =
                Message::new_peer_info(&node.mesh, &nick("alice-aa"), address_body).sign(&signer);
            super::handle_peer_info(&peer_info, &mut state, &context).await;
            assert_eq!(
                ours.topology_view().edges.len(),
                1,
                "the PeerInfo that proves the endpoint feeds the vector that waited for it"
            );
            node.endpoint.close().await;
            ours.close().await;
            theirs.close().await;
            node.endpoint.close().await;
        });
    }

    /// The address in the first `PeerInfo` of a peer must reach the endpoint, not only
    /// a lookup: the endpoint reads a lookup at a dial, and a connection that is live
    /// gets a path only from the call that hands the address over.
    #[test]
    fn the_address_of_a_first_peer_info_reaches_the_endpoint() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let peer = iroh::SecretKey::generate().public();
            let first = iroh::EndpointAddr::new(peer).with_ip_addr(test_ip());

            super::handle_peer_info(&peer_info(&node, &first), &mut state, &context).await;

            assert!(
                eventually(|| async { node.endpoint.remote_info(peer).await.is_some() }).await,
                "the first address reaches the endpoint"
            );
            node.endpoint.close().await;
        });
    }

    /// A peer that is linked is not asked for its address again, so a change of it
    /// (a home relay that came late, an interface that changed) reaches us only
    /// through its `PeerInfo`. The endpoint already knows the peer here, so only the
    /// change is under test: a relay that the peer gained must be handed over too.
    #[test]
    fn a_linked_peers_changed_address_is_applied() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let peer = iroh::SecretKey::generate().public();
            state.link(peer);
            let relay: iroh::RelayUrl = "https://relay.example".parse().expect("a relay url");
            let knows_relay = || async {
                let info = node.endpoint.remote_info(peer).await;
                info.is_some_and(|info| {
                    info.addrs().any(|known| matches!(known.addr(), iroh::TransportAddr::Relay(url) if *url == relay))
                })
            };
            let first = iroh::EndpointAddr::new(peer).with_ip_addr(test_ip());
            node.endpoint
                .add_endpoint_addr(first.clone())
                .await
                .expect("the endpoint takes the first address");
            let holder = Identity::generate();
            super::handle_peer_info(
                &peer_info_signed_by(&node, &first, &holder),
                &mut state,
                &context,
            )
            .await;
            state.names.insert(holder.author_key(), nick("bob"));
            state.peers.insert(holder.author_key());
            assert!(!knows_relay().await, "no relay yet");

            let later = first.with_relay_url(relay.clone());
            super::handle_peer_info(
                &peer_info_signed_by(&node, &later, &holder),
                &mut state,
                &context,
            )
            .await;

            assert!(
                eventually(knows_relay).await,
                "the relay that a linked peer gained reaches the endpoint"
            );
            node.endpoint.close().await;
        });
    }

    /// Polls `check` until it holds or five seconds pass. The endpoint takes an address
    /// from a task, so the test waits for the effect and not for a time.
    async fn eventually<F, Fut>(mut check: F) -> bool
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let deadline = std_Instant::now() + std_Duration::from_secs(5);
        while std_Instant::now() < deadline {
            if check().await {
                return true;
            }
            tokio_time::sleep(std_Duration::from_millis(10)).await;
        }
        check().await
    }

    /// An address from a documentation range (RFC 5737): no interface carries it.
    fn test_ip() -> net::SocketAddr {
        "192.0.2.10:4000".parse().expect("an address")
    }

    /// A `PeerInfo` of the author `bob` that carries `addr`, signed by a key that is new.
    fn peer_info(node: &Node, address: &iroh::EndpointAddr) -> Verified {
        peer_info_signed_by(node, address, &Identity::generate())
    }

    /// A `PeerInfo` of the author `bob` that carries `addr`, signed by `by`.
    fn peer_info_signed_by(node: &Node, address: &iroh::EndpointAddr, by: &Identity) -> Verified {
        use crate::protocol::messages::MessageBody;
        use crate::protocol::peer_addr_error;

        let body =
            MessageBody::try_new(&peer_addr_error::endpoint_addr_to_json(address).to_string())
                .expect("an address body");
        Message::new_peer_info(&node.mesh, &nick("bob"), body).sign(by)
    }

    /// A `PeerInfo` that carries the proof of `signer` for `endpoint_key`, stamped `at`.
    fn proving_peer_info(
        node: &Node,
        endpoint_key: &iroh::SecretKey,
        signer: &Identity,
        at: UnixSecs,
    ) -> Verified {
        use crate::protocol::messages::MessageBody;
        use crate::protocol::peer_addr_error;
        use crate::transport::proven_endpoints;

        let mut address =
            peer_addr_error::endpoint_addr_to_json(&iroh::EndpointAddr::new(endpoint_key.public()));
        address["proof"] = serde_json::Value::String(proven_endpoints::sign(
            endpoint_key,
            &node.mesh,
            &signer.author_key(),
        ));
        let body = MessageBody::try_new(&address.to_string()).expect("an address body");
        let mut message = Message::new_peer_info(&node.mesh, &nick("bob"), body);
        message.timestamp = at;
        message.sign(signer)
    }

    /// A crash restart keeps the key of the endpoint and makes a new signing key. A `PeerInfo` of
    /// the old key, replayed after the new key proved the endpoint, must not take the proof back:
    /// the digests of the peer would be answered on gossip until its next `PeerInfo`.
    #[test]
    fn a_replayed_old_peer_info_does_not_take_the_proof_of_the_new_signer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let endpoint_key = iroh::SecretKey::generate();
            let (old, new) = (Identity::generate(), Identity::generate());
            state.peers.insert(old.author_key());
            state.peers.insert(new.author_key());
            let now = UnixSecs::now();
            let earlier = now - std_Duration::from_secs(60);

            let first = proving_peer_info(&node, &endpoint_key, &old, earlier);
            super::handle_peer_info(&first, &mut state, &context).await;
            let restarted = proving_peer_info(&node, &endpoint_key, &new, now);
            super::handle_peer_info(&restarted, &mut state, &context).await;
            super::handle_peer_info(&first, &mut state, &context).await;

            assert_eq!(
                state.proven_endpoints.get(&new.author_key()),
                Some(endpoint_key.public()),
                "the replay of the old signer took the proof of the new signer"
            );
            assert_eq!(
                state.proven_endpoints.get(&old.author_key()),
                None,
                "an endpoint keeps its newest signer"
            );
            node.endpoint.close().await;
        });
    }

    /// The dial hint of a nickname belongs to the key that holds it. A `PeerInfo` of another key
    /// under the same nickname (a frame of one second that lost the nickname) must not move the
    /// hint, or a directed send reaches a node that does not hold the nickname. The holder may
    /// rebind (a restart), and a nickname with no holder takes the first hint.
    #[test]
    fn a_peer_info_of_a_key_that_does_not_hold_the_nickname_binds_no_endpoint() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let holder = Identity::generate();
            let rival = Identity::generate();
            let held = iroh::EndpointAddr::new(iroh::SecretKey::generate().public())
                .with_ip_addr(test_ip());
            let taken = iroh::EndpointAddr::new(iroh::SecretKey::generate().public())
                .with_ip_addr(test_ip());
            let restarted = iroh::EndpointAddr::new(iroh::SecretKey::generate().public())
                .with_ip_addr(test_ip());

            super::handle_peer_info(
                &peer_info_signed_by(&node, &held, &holder),
                &mut state,
                &context,
            )
            .await;
            assert_eq!(
                state.peer_endpoints.get("bob"),
                Some(&held),
                "a nickname with no holder takes the first hint"
            );
            state.names.insert(holder.author_key(), nick("bob"));
            state.peers.insert(holder.author_key());

            super::handle_peer_info(
                &peer_info_signed_by(&node, &taken, &rival),
                &mut state,
                &context,
            )
            .await;
            assert_eq!(
                state.peer_endpoints.get("bob"),
                Some(&held),
                "a key that does not hold the nickname moved the dial hint"
            );

            super::handle_peer_info(
                &peer_info_signed_by(&node, &restarted, &holder),
                &mut state,
                &context,
            )
            .await;
            assert_eq!(
                state.peer_endpoints.get("bob"),
                Some(&restarted),
                "the holder could not rebind its hint"
            );
            node.endpoint.close().await;
        });
    }

    /// A key that is not in the roster (it lapsed, or it was pruned) can still send a late
    /// `PeerInfo`. It must not bind a nickname that a live peer holds: a directed send would
    /// reach the old node until the live peer sends its own `PeerInfo`.
    #[test]
    fn a_late_peer_info_of_a_key_outside_the_roster_does_not_take_a_nickname_a_live_peer_holds() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let (live, late) = (Identity::generate(), Identity::generate());
            state.names.insert(live.author_key(), nick("bob"));
            state.peers.insert(live.author_key());
            let (old_id, current_id) = (
                iroh::SecretKey::generate().public(),
                iroh::SecretKey::generate().public(),
            );
            let old = iroh::EndpointAddr::new(old_id).with_ip_addr(test_ip());
            let current = iroh::EndpointAddr::new(current_id).with_ip_addr(test_ip());

            super::handle_peer_info(
                &peer_info_signed_by(&node, &old, &late),
                &mut state,
                &context,
            )
            .await;
            assert!(
                !state.peer_endpoints.contains_key("bob"),
                "a key outside the roster took a nickname that a live peer holds"
            );

            super::handle_peer_info(
                &peer_info_signed_by(&node, &current, &live),
                &mut state,
                &context,
            )
            .await;
            assert_eq!(
                state.peer_endpoints.get("bob"),
                Some(&current),
                "the live peer could not bind its own hint"
            );
            node.endpoint.close().await;
        });
    }

    /// A rival key does not bind the hint, but its address is still handed to the endpoint: the
    /// binding is the roster's, the address is a path to a node. Until then a dial goes to the
    /// stale address.
    #[test]
    fn a_rival_keys_changed_address_reaches_the_address_book() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let (owner, rival) = (Identity::generate(), Identity::generate());
            for key in [owner.author_key(), rival.author_key()] {
                state.names.insert(key, nick("bob"));
                state.peers.insert(key);
            }
            let held = iroh::EndpointAddr::new(iroh::SecretKey::generate().public())
                .with_ip_addr(test_ip());
            state.bind_peer_endpoint(owner.author_key(), nick("bob"), held);
            let rival_id = iroh::SecretKey::generate().public();
            let first: net::SocketAddr = "127.0.0.1:4101".parse().expect("an address");
            let second: net::SocketAddr = "127.0.0.1:4102".parse().expect("an address");

            for address in [first, second] {
                let moved = iroh::EndpointAddr::new(rival_id).with_ip_addr(address);
                super::handle_peer_info(
                    &peer_info_signed_by(&node, &moved, &rival),
                    &mut state,
                    &context,
                )
                .await;
            }

            let known = state
                .address_book
                .get_endpoint_info(rival_id)
                .expect("the book holds the rival endpoint")
                .into_endpoint_addr();
            let ports: Vec<net::SocketAddr> = known.ip_addrs().copied().collect();
            assert!(
                ports.contains(&second),
                "the changed address of a rival key never reached the address book: {ports:?}"
            );
            node.endpoint.close().await;
        });
    }

    /// A dial hint that another nickname holds for the same endpoint is a claim, not a registered
    /// address. When it names the advertised address, the address still has to reach the address
    /// book and the unicast pool, because nothing else put it there.
    #[test]
    fn an_address_held_as_a_hint_of_another_nickname_still_reaches_the_address_book() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let (carol, bob) = (Identity::generate(), Identity::generate());
            let endpoint_id = iroh::SecretKey::generate().public();
            let advertised = iroh::EndpointAddr::new(endpoint_id).with_ip_addr(test_ip());
            state.bind_peer_endpoint(carol.author_key(), nick("carol"), advertised.clone());
            // Not the first sighting, and already linked, so no graft registers the address:
            // only `changed` can.
            state.known_endpoints.insert(endpoint_id);
            state.linked_endpoints.insert(endpoint_id);

            super::handle_peer_info(
                &peer_info_signed_by(&node, &advertised, &bob),
                &mut state,
                &context,
            )
            .await;

            assert!(
                state.address_book.get_endpoint_info(endpoint_id).is_some(),
                "the address was held as a hint of another nickname and never reached the book"
            );
            assert!(
                state.unicast_pool.has_addr(endpoint_id),
                "the address was held as a hint of another nickname and never reached the pool"
            );
            node.endpoint.close().await;
        });
    }

    /// A `PeerInfo` of a key that said goodbye is a replay: the goodbye removed the nickname and
    /// its dial hint, and the replay must not bring the hint back.
    #[test]
    fn a_replayed_peer_info_of_a_key_that_said_goodbye_binds_no_endpoint() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let departed = Identity::generate();
            let address = iroh::EndpointAddr::new(iroh::SecretKey::generate().public())
                .with_ip_addr(test_ip());
            state.note_left(departed.author_key());

            super::handle_peer_info(
                &peer_info_signed_by(&node, &address, &departed),
                &mut state,
                &context,
            )
            .await;

            assert!(
                !state.peer_endpoints.contains_key("bob"),
                "a replayed PeerInfo of a departed key restored the dial hint"
            );
            node.endpoint.close().await;
        });
    }

    /// A stale `PeerInfo` proves no presence, so it registers no endpoint and starts no dial. The
    /// frame comes through `ingest`, which is where the lifecycle verdict is known.
    #[test]
    fn a_stale_peer_info_registers_no_endpoint() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            // the app and the test share the counter
            let mut app = Counting(Arc::new(atomic::AtomicUsize::new(0)));
            let departed = Identity::generate();
            let endpoint = iroh::SecretKey::generate().public();
            let address = iroh::EndpointAddr::new(endpoint).with_ip_addr(test_ip());
            state.note_left(departed.author_key());
            let frame = peer_info_signed_by(&node, &address, &departed)
                .serialize()
                .expect("serialize");

            ingest(frame.into_bytes(), &mut state, &mut app, &context).await;

            assert!(
                !state.known_endpoints.contains(&endpoint),
                "a stale PeerInfo registered its endpoint for a dial"
            );
            node.endpoint.close().await;
        });
    }

    /// A relayed `PeerInfo` is re-serialized from its verified form, so the bytes that go out are the
    /// bytes that came in: a `PeerInfo` carries no resend trailer, and the signed form round-trips.
    #[test]
    fn a_relayed_peer_info_is_the_inbound_bytes() {
        let _guard = ::habilis_network_test_tracing::init();
        let inbound = Message::new_peer_info(
            &MeshId::from("test"),
            &nick("alice"),
            MessageBody::from("{}"),
        )
        .sign(&Identity::generate())
        .serialize()
        .expect("serialize");
        let (parsed, nonce) = Message::parse_wire(inbound.as_bytes()).expect("parses");
        assert!(nonce.is_none(), "a relayed peer info carries no nonce");
        let verified_frame = parsed.verify().expect("verifies");
        let relayed = verified_frame.serialize().expect("serialize");
        assert_eq!(
            relayed.as_bytes(),
            inbound.as_bytes(),
            "a relayed peer info keeps the inbound bytes"
        );
    }

    /// The tie-break defers the first dial to the lower endpoint id. A second
    /// copy of the same `PeerInfo` milliseconds later (every member floods its
    /// address on a newcomer's first frame) must not dial either: both sides
    /// would dial each other, iroh-gossip closes both connections, and the pair
    /// is left with no link.
    #[test]
    fn a_second_peer_info_right_after_a_deferred_dial_does_not_dial() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::messages::MessageBody;
            use crate::protocol::peer_addr_error;

            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let lower = loop {
                let id = iroh::SecretKey::generate().public();
                if id < node.endpoint.id() {
                    break id;
                }
            };
            let body = MessageBody::try_new(
                &peer_addr_error::endpoint_addr_to_json(&iroh::EndpointAddr::new(lower))
                    .to_string(),
            )
            .expect("an address body");
            let peer_info = Message::new_peer_info(&node.mesh, &nick("lower"), body)
                .sign(&Identity::generate());

            super::handle_peer_info(&peer_info, &mut state, &context).await;
            assert!(
                !state.direct.contains_key(&lower),
                "the first sighting defers"
            );
            super::handle_peer_info(&peer_info, &mut state, &context).await;
            assert!(
                !state.direct.contains_key(&lower),
                "the copy right after must not dial"
            );
            state.relink.clear();
            super::handle_peer_info(&peer_info, &mut state, &context).await;
            assert!(
                state.direct.contains_key(&lower),
                "once the cooldown ends, this side dials after all"
            );
            node.endpoint.close().await;
        });
    }

    /// In a mesh of more than G + 1 members a graft meets a peer that may be full,
    /// and a full peer accepts it by evicting a random neighbor, so the links
    /// move and none is gained. A `PeerInfo` is the unpaced trigger, and it
    /// is re-flooded on every link-up, so it feeds a loop of grafts and
    /// evictions. It therefore leaves one slot free in such a mesh; the paced
    /// fill tick takes the last one. A mesh that fits in the view has room
    /// everywhere, so there it still grafts up to G.
    #[test]
    fn a_peer_info_leaves_one_slot_free_in_a_mesh_larger_than_g_plus_one() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::messages::MessageBody;
            use crate::protocol::peer_addr_error;

            let node = Node::spawn().await;
            let context = node.context();
            let max_peers = context.max_peers;
            // Higher than ours, so the first-sighting tie-break does not defer it.
            let newcomer = loop {
                let id = iroh::SecretKey::generate().public();
                if id > node.endpoint.id() {
                    break id;
                }
            };
            let body = MessageBody::try_new(
                &peer_addr_error::endpoint_addr_to_json(&iroh::EndpointAddr::new(newcomer))
                    .to_string(),
            )
            .expect("an address body");
            let peer_info = Message::new_peer_info(&node.mesh, &nick("newcomer"), body)
                .sign(&Identity::generate());
            let crowd = |state: &mut EventLoopState, members: usize| {
                for index in 0..members {
                    let id = iroh::SecretKey::generate().public();
                    state
                        .peer_endpoints
                        .insert(nick(&format!("member{index}")), iroh::EndpointAddr::new(id));
                }
            };
            let fill_view = |state: &mut EventLoopState, links: usize| {
                for _ in 0..links {
                    state
                        .linked_endpoints
                        .insert(iroh::SecretKey::generate().public());
                }
            };

            // More than G + 1 members, one link short of G: the last slot waits.
            let mut crowded = fresh_state();
            crowd(&mut crowded, max_peers + 2);
            fill_view(&mut crowded, max_peers - 1);
            super::handle_peer_info(&peer_info, &mut crowded, &context).await;
            assert!(
                !crowded.direct.contains_key(&newcomer),
                "a mesh larger than G + 1 leaves the last slot to the fill tick"
            );

            // A mesh that fits in the view has room everywhere: it grafts up to G.
            let mut small = fresh_state();
            crowd(&mut small, 3);
            fill_view(&mut small, 2);
            super::handle_peer_info(&peer_info, &mut small, &context).await;
            assert!(
                small.direct.contains_key(&newcomer),
                "a mesh that fits in the view grafts"
            );
            node.endpoint.close().await;
        });
    }

    /// A node whose first digests went out over the rendezvous alone can have
    /// every answer dropped on the way: each hop already saw those frames, and
    /// iroh-gossip drops a message id it has seen. So it asks again on its
    /// first real-peer link, and on no other link; the chat log asks there too.
    /// `idle.broadcasts` counts digest broadcasts and nothing else a link-up
    /// sends; the test sender cannot record frames, so the count stands in for
    /// the three digests.
    #[test]
    fn only_the_first_real_peer_link_asks_for_state_again() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;

            let mut digests_on_link_up = async |peer| {
                let before = state.idle.broadcasts;
                handle_gossip_event(
                    Some(Ok(Event::NeighborUp(peer))),
                    &mut state,
                    &mut app,
                    &context,
                )
                .await;
                state.idle.broadcasts - before
            };

            assert_eq!(
                digests_on_link_up(context.rendezvous_id).await,
                0,
                "the rendezvous link"
            );
            assert_eq!(
                digests_on_link_up(endpoint_id(1)).await,
                3,
                "the first real-peer link: one state, one meta and one chat digest"
            );
            assert_eq!(
                digests_on_link_up(endpoint_id(2)).await,
                0,
                "a second real-peer link"
            );
            node.endpoint.close().await;
        });
    }

    /// A newcomer behind the rendezvous learns our address only from our
    /// `PeerInfo` flood, and the lower endpoint id is the one that dials. Its
    /// first frame to reach us is not always its `joined`: under load its
    /// digest can overtake it. So the flood follows the first frame from a
    /// new peer, whatever its kind. A `State` frame does not mark a peer
    /// present, so it floods nothing. A `joined` first frame floods in
    /// `handle_presence`, which this test does not cover.
    #[test]
    fn a_new_peers_first_frame_floods_our_address_when_it_is_not_its_joined() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut app = Inert;
            let newcomer = Identity::generate();
            let wire = |frame: &Verified| frame.serialize().expect("serialize").into_bytes();
            let heads = || MessageBody::try_new(r#"{"heads":[]}"#).expect("a JSON body");

            let mut digest_first = fresh_state();
            let digest =
                Message::new_channel_digest(&node.mesh, &nick("late"), heads(), Channel::State)
                    .sign(&newcomer);
            ingest(wire(&digest), &mut digest_first, &mut app, &context).await;
            assert!(
                digest_first.peerinfo_flood.is_some(),
                "a newcomer's digest arrived first, and we never told it our address"
            );

            let mut change_first = fresh_state();
            let change =
                Message::new_channel_event(&node.mesh, &nick("late"), heads(), Channel::State)
                    .sign(&newcomer);
            ingest(wire(&change), &mut change_first, &mut app, &context).await;
            assert!(
                change_first.peerinfo_flood.is_none(),
                "a state frame does not mark its author present"
            );
            node.endpoint.close().await;
        });
    }

    /// A native node on a private mesh loses its rendezvous link when the
    /// beacon dies. Its own punch is the way back, so the loss must not arm
    /// the offer fallback: that fallback holds every timer graft, and a
    /// private rendezvous has no answerer to end it. Observed as a survivor
    /// that never linked its rendezvous again, so a new joiner's first
    /// message reached nobody.
    #[test]
    fn a_rendezvous_loss_keeps_a_native_node_grafting_on_its_timer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.webrtc = Some(lookup::build_webrtc_handle(node.endpoint.id()));
            state.relay_transport = PayloadPath::DirectOnly;
            state.local_udp_transport = UdpTransport::Present;
            state.rendezvous_flags.insert(RendezvousFlag::Linked);

            handle_gossip_event(
                Some(Ok(Event::NeighborDown(context.rendezvous_id))),
                &mut state,
                &mut Inert,
                &context,
            )
            .await;

            assert!(
                webrtc::rendezvous::rendezvous_graftable(&state),
                "the rendezvous loss held the timer graft"
            );
            node.endpoint.close().await;
        });
    }

    /// A native node on a private mesh still unlinked at a heal tick must not
    /// arm the offer fallback either: the fallback assumes an unreachable
    /// beacon is a tab, but a private rendezvous never answers JSEP, so the
    /// fallback would hold every timer graft with nothing to release it.
    #[test]
    fn a_heal_tick_never_arms_the_offer_fallback_on_a_private_mesh() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.webrtc = Some(lookup::build_webrtc_handle(node.endpoint.id()));
            state.relay_transport = PayloadPath::DirectOnly;
            state.local_udp_transport = UdpTransport::Present;
            state.rendezvous_flags.remove(&RendezvousFlag::AnswersJsep);

            webrtc::rendezvous::negotiate_rendezvous_session(&mut state, &context);

            assert!(
                webrtc::rendezvous::rendezvous_graftable(&state),
                "the heal tick held the timer graft on a private mesh"
            );
            node.endpoint.close().await;
        });
    }
}

#[cfg(all(test, feature = "host"))]
mod link_state_tests {
    use crate::protocol::UnixSecs;
    use habilis_network_iroh_multihop_transport::{MultihopHandle, underlay_secret};
    use iroh::endpoint::presets;
    use iroh::{Endpoint, RelayMode, SecretKey};

    use crate::protocol::identity::Identity;
    use crate::protocol::{MeshId, Message};
    use crate::testing::{fresh_state, nick};

    use crate::transport::PayloadPath;
    use crate::{gossip, lookup};
    /// A handle over a loopback underlay on the key derived from `secret`.
    async fn handle_for(secret: &SecretKey) -> MultihopHandle {
        let underlay_builder = Endpoint::builder(presets::Minimal)
            .secret_key(underlay_secret(secret))
            .relay_mode(RelayMode::Disabled);
        let underlay = underlay_builder.bind().await.expect("bind an underlay");
        MultihopHandle::new(
            secret,
            underlay,
            lookup::multihop_handle_config(PayloadPath::DirectOnly),
        )
        .expect("underlay on the derived key")
    }

    // A link-state vector is replaced by the next one and is never logged by the
    // peers that receive it. A node that kept its own would hold messages that no
    // peer holds, and every digest would ask it for them again: measured at
    // N = 33, 38% of the vectors a node received were repeats.
    #[test]
    fn a_link_vector_this_node_broadcast_is_not_retained_in_its_log() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let secret = SecretKey::from_bytes(&[53; 32]);
            let handle = handle_for(&secret).await;
            let mut state = fresh_state();
            let body = gossip::json_body(&handle.link_vector(Vec::new())).expect("serializes");
            let message = Message::new_link_state(&MeshId::from("test"), &nick("alice-aa"), body)
                .sign(&Identity::generate());
            super::retain_own_broadcast(&mut state, message);
            assert_eq!(state.message_log.len(), 0, "nothing retains a link-state");
            handle.close().await;
        });
    }

    // A signature proves who made a vector, not that the maker is a member, and
    // the endpoint that the signer proved is what ties an origin to a signer.
    #[test]
    fn a_link_vector_is_taken_in_only_from_the_signer_that_proved_its_origin() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (alice, bob) = (
                SecretKey::from_bytes(&[51; 32]),
                SecretKey::from_bytes(&[52; 32]),
            );
            let ours = handle_for(&SecretKey::from_bytes(&[50; 32])).await;
            let theirs = handle_for(&alice).await;
            let mut state = fresh_state();
            state.multihop = Some(ours.clone());

            let body = gossip::json_body(&theirs.link_vector(vec![(
                habilis_network_iroh_multihop_transport::AppId::new(bob.public()),
                10,
            )]))
            .expect("a vector serializes");
            let (alice_id, mallory_id) = (Identity::generate(), Identity::generate());
            state.peers.insert(alice_id.author_key());
            state.peers.insert(mallory_id.author_key());
            let message_from = |author: &str, signer: &Identity| {
                Message::new_link_state(&MeshId::from("test"), &nick(author), body.clone())
                    .sign(signer)
            };

            super::handle_link_state(&message_from("alice-aa", &alice_id), &mut state);
            assert!(
                ours.topology_view().edges.is_empty(),
                "no endpoint proved by the signer yet"
            );

            state.note_proven_endpoint(mallory_id.author_key(), bob.public(), UnixSecs::from(1));
            super::handle_link_state(&message_from("mallory-mm", &mallory_id), &mut state);
            assert!(
                ours.topology_view().edges.is_empty(),
                "a signer that proved another endpoint cannot speak for this origin"
            );

            state.note_proven_endpoint(alice_id.author_key(), alice.public(), UnixSecs::from(1));
            super::handle_link_state(&message_from("alice-aa", &alice_id), &mut state);
            assert_eq!(
                ours.topology_view().edges.len(),
                1,
                "the signer that proved the origin is heard"
            );
            ours.close().await;
            theirs.close().await;
        });
    }
}

/// A peer that says goodbye takes the links it advertised with it. Without
/// that, routes keep running through a peer that left until its vector ages out.
#[cfg(all(test, feature = "host"))]
mod left_tests {
    use crate::daemon::state::Standing;
    use iroh::EndpointAddr;
    use iroh_gossip::net::Gossip;

    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::state::EventLoopState;
    use crate::gossip::app::{AppClass, InboundApp, NodeApp};
    use crate::gossip::event::SilentSink;
    use crate::lifecycle::membership_update::MembershipUpdate;
    use crate::lifecycle::{PresenceEvent, handle_presence};
    use crate::lookup::{TransportOpts, build_peer_multihop};
    use crate::protocol::identity::Identity;
    use crate::protocol::meshes::LookupOpts;
    use crate::protocol::messages::Authored;
    use crate::protocol::{MeshId, Message, PresenceSubtype};
    use crate::testing::{endpoint_id, fresh_state, nick};
    use crate::transport::MeshSender;

    use crate::transport::PayloadPath;
    use iroh::endpoint::presets;
    use iroh_gossip::proto;
    use tokio::time;
    /// A `Left` never reaches the app's frame hook, so it only has to exist.
    struct Inert;

    #[async_trait::async_trait]
    impl NodeApp for Inert {
        fn classify(&self, _message: &Authored) -> AppClass {
            AppClass::BEAT.union(AppClass::VALID)
        }

        async fn on_app_frame(
            &mut self,
            _frame: InboundApp<'_>,
            _state: &mut EventLoopState,
            _ctx: &HandlerCtx<'_>,
        ) -> bool {
            false
        }
    }

    #[test]
    fn a_peer_that_left_takes_its_advertised_links_with_it() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let lookups = LookupOpts::loopback();
            let (endpoint, handle, _webrtc) = build_peer_multihop(
                &lookups,
                TransportOpts::default(),
                None,
                PayloadPath::DirectOnly,
            )
            .await
            .expect("a multihop peer binds");
            let (leaver_endpoint, leaver_handle, _leaver_webrtc) = build_peer_multihop(
                &lookups,
                TransportOpts::default(),
                None,
                PayloadPath::DirectOnly,
            )
            .await
            .expect("a second multihop peer binds");
            let leaver_id = leaver_handle.app_id().to_string();
            let advertises = |held_by: &habilis_network_iroh_multihop_transport::MultihopHandle| {
                held_by
                    .topology_view()
                    .edges
                    .iter()
                    .any(|edge| edge.from == leaver_id)
            };

            // We hear the leaver's links, and the roster binds it to its endpoint.
            let vector = leaver_handle.link_vector(vec![(handle.app_id(), 1)]);
            assert!(handle.feed_topology(vector), "the vector is new to us");
            assert!(advertises(&handle), "its links are in our routing table");
            let mut state = fresh_state();
            state.multihop = Some(handle.clone());
            let leaver = nick("leaver");
            // The leaver is a peer of the roster under the key of its run.
            let leaver_run = Identity::generate();
            state.names.insert(leaver_run.author_key(), leaver.clone());
            state.peers.insert(leaver_run.author_key());
            state.note_peer_endpoint(
                leaver.clone(),
                EndpointAddr::new(leaver_handle.app_id().get()),
            );

            let gossip = Gossip::builder().spawn(endpoint.clone());
            let topic = gossip
                .subscribe(proto::TopicId::from_bytes([5u8; 32]), vec![])
                .await
                .expect("subscribe to a peerless topic");
            let (gossip_sender, _receiver) = topic.split();
            let sender = MeshSender::new(gossip_sender);
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
                sender: &sender,
                endpoint: &endpoint,
                mesh: &mesh,
                author: &us,
                identity: &identity,
                our_pubkey,
                max_peers: 16,
                rendezvous_id: endpoint_id(9),
                external_msg_tx: None,
                sink: &sink,
            };
            let message = Message::new_left(&mesh, &leaver).sign(&leaver_run);
            let update = MembershipUpdate {
                returned: false,
                joined_new: false,
                stale: false,
            };
            let mut app = Inert;
            handle_presence(
                PresenceEvent {
                    message: &message,
                    subtype: PresenceSubtype::Left,
                    update: &update,
                    surfaceable: false,
                },
                &mut state,
                &mut app,
                &context,
            )
            .await;

            assert!(
                !advertises(&handle),
                "the leaver's links are still in our routing table after its goodbye"
            );
            endpoint.close().await;
            leaver_endpoint.close().await;
            handle.close().await;
            endpoint.close().await;
            leaver_handle.close().await;
            leaver_endpoint.close().await;
        });
    }

    /// A node that is not meshed yet still drops the links of a peer that stopped
    /// advertising: the tick expires first, then returns early.
    #[test]
    fn a_node_that_is_not_meshed_still_expires_stale_links() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use std::time::Duration;

            use habilis_network_iroh_multihop_transport::{
                HandleConfig, MultihopHandle, underlay_secret,
            };

            use crate::daemon::event_loop;

            let lookups = LookupOpts::loopback();
            let (endpoint, peer_handle, _webrtc) = build_peer_multihop(
                &lookups,
                TransportOpts::default(),
                None,
                PayloadPath::DirectOnly,
            )
            .await
            .expect("a multihop peer binds");
            // Our own handle, with a short max age so that a test can wait it out.
            let secret = iroh::SecretKey::generate();
            let underlay_builder = iroh::Endpoint::builder(presets::Minimal)
                .secret_key(underlay_secret(&secret))
                .relay_mode(iroh::RelayMode::Disabled);
            let underlay = underlay_builder.bind().await.expect("bind an underlay");
            let config = HandleConfig::default().vector_max_age(Duration::from_millis(400));
            let handle = MultihopHandle::new(&secret, underlay, config).expect("a handle");
            let (leaver_endpoint, leaver_handle, _leaver_webrtc) = build_peer_multihop(
                &lookups,
                TransportOpts::default(),
                None,
                PayloadPath::DirectOnly,
            )
            .await
            .expect("a second multihop peer binds");
            let leaver_id = leaver_handle.app_id().to_string();
            let advertises = |held_by: &MultihopHandle| {
                held_by
                    .topology_view()
                    .edges
                    .iter()
                    .any(|edge| edge.from == leaver_id)
            };
            let vector = leaver_handle.link_vector(vec![(handle.app_id(), 1)]);
            assert!(handle.feed_topology(vector), "the vector is new to us");
            assert!(advertises(&handle), "its links are in our routing table");

            let mut state = fresh_state();
            state.multihop = Some(handle.clone());
            assert!(
                !state.standing.contains(&Standing::Meshed),
                "the node is not meshed"
            );

            let gossip = Gossip::builder().spawn(endpoint.clone());
            let topic = gossip
                .subscribe(proto::TopicId::from_bytes([6u8; 32]), vec![])
                .await
                .expect("subscribe to a peerless topic");
            let (gossip_sender, _receiver) = topic.split();
            let sender = MeshSender::new(gossip_sender);
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
                sender: &sender,
                endpoint: &endpoint,
                mesh: &mesh,
                author: &us,
                identity: &identity,
                our_pubkey,
                max_peers: 16,
                rendezvous_id: endpoint_id(9),
                external_msg_tx: None,
                sink: &sink,
            };

            // The leaver says nothing more: wait out the max age, then tick.
            time::sleep(Duration::from_millis(900)).await;
            event_loop::linkstate_arm(&mut state, &context).await;
            assert!(
                !advertises(&handle),
                "the stale links are still in the routing table of a node that is not meshed"
            );
            handle.close().await;
            peer_handle.close().await;
            leaver_handle.close().await;
            endpoint.close().await;
            leaver_endpoint.close().await;
        });
    }
}

#[cfg(all(test, feature = "host"))]
mod requeue_tests {
    use crate::daemon::state::Standing;

    use crate::testing::{LaneNode, nick, test_key};

    use crate::transport;
    use crate::util::clock;
    /// A frame is parked before its addressee is known. The peer becomes known with a relay-only
    /// address, the flush delivers the frame again and it is held: the requeue asks for the session
    /// and offers it at once, so that the frame does not wait for the next tick of the retry pass.
    #[test]
    fn a_frame_parked_before_its_peer_is_known_asks_for_the_session_at_the_flush() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let node = LaneNode::start().await;
                let context = node.context();
                let mut state = node.state();
                state.standing.insert(Standing::Meshed);
                let address = state
                    .peer_endpoints
                    .remove(&nick("bob"))
                    .expect("the fixture knows bob");
                let frame = node.frame_to_bob();
                let bytes = frame.serialize().expect("serialize");
                let now = clock::Instant::now();
                drop(
                    transport::resolve(&frame, bytes.clone(), &state)
                        .expect_err("no endpoint is known for bob yet"),
                );
                assert!(
                    super::requeue(&mut state, &context, frame.clone(), bytes.clone()),
                    "a frame parked before its peer is known is requeued"
                );
                assert!(!state.lane_session_wanted(node.bob, now), "bob is unknown");
                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    0,
                    "one admission slot is in flight after the requeue"
                );

                state.bind_peer_endpoint(test_key("bob"), nick("bob"), address);
                drop(
                    transport::resolve(&frame, bytes.clone(), &state)
                        .expect_err("a lookup-only relay holds the frame"),
                );
                assert!(
                    super::requeue(&mut state, &context, frame, bytes),
                    "a second requeue is accepted"
                );

                assert!(
                    state.lane_session_wanted(node.bob, now),
                    "the requeued frame asks"
                );
                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    1,
                    "and the offer is in flight at once"
                );
                state.webrtc_admission.close();
                node.endpoint.close().await;
            },
        );
    }
}

#[cfg(all(test, feature = "host"))]
mod parked_link_state_tests {
    use std::thread;
    use std::time::Duration;

    use crate::protocol::UnixSecs;
    use crate::util::clock::Instant;
    use crate::util::tuning::PARKED_LINK_STATE_TTL;
    use habilis_network_iroh_multihop_transport::{MultihopHandle, underlay_secret};
    use iroh::endpoint::presets;
    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};

    use crate::daemon::state::{EventLoopState, ParkedLinkStates};
    use crate::protocol::identity::Identity;
    use crate::protocol::messages::Verified;
    use crate::protocol::{MeshId, Message};
    use crate::testing::{fresh_state, nick, test_key};

    use crate::transport::PayloadPath;
    use crate::{gossip, lookup};
    async fn handle_for(secret: &SecretKey) -> MultihopHandle {
        let underlay_builder = Endpoint::builder(presets::Minimal)
            .secret_key(underlay_secret(secret))
            .relay_mode(RelayMode::Disabled);
        let underlay = underlay_builder.bind().await.expect("bind an underlay");
        MultihopHandle::new(
            secret,
            underlay,
            lookup::multihop_handle_config(PayloadPath::DirectOnly),
        )
        .expect("underlay on the derived key")
    }

    fn vector_message(
        author: &str,
        handle: &MultihopHandle,
        links: Vec<(iroh::EndpointId, u32)>,
    ) -> Message {
        let links = links
            .into_iter()
            .map(|(id, cost)| {
                (
                    habilis_network_iroh_multihop_transport::AppId::new(id),
                    cost,
                )
            })
            .collect();
        let body = gossip::json_body(&handle.link_vector(links)).expect("a vector serializes");
        Message::new_link_state(&MeshId::from("test"), &nick(author), body)
    }

    /// A vector of `nickname`, signed by `signer`.
    fn signed_vector(
        nickname: &str,
        signer: &Identity,
        handle: &MultihopHandle,
        link: iroh::EndpointId,
    ) -> Verified {
        vector_message(nickname, handle, vec![(link, 10)]).sign(signer)
    }

    /// Two live keys of one nickname, each with its own origin: the keys, the secret keys of the
    /// origins, and the dial hint under the nickname, which names the origin of the first key.
    struct Twins {
        first: Identity,
        second: Identity,
        first_origin: SecretKey,
        second_origin: SecretKey,
    }

    impl Twins {
        fn new(seed: u8) -> Self {
            Self {
                first: Identity::generate(),
                second: Identity::generate(),
                first_origin: SecretKey::from_bytes(&[seed; 32]),
                second_origin: SecretKey::from_bytes(&[seed + 1; 32]),
            }
        }
    }

    // The nickname is a label that any signer can take. The dial hint under it names the endpoint
    // of one key, and the other key proved its own: a vector of the second key is taken in from
    // that proven endpoint.
    #[test]
    fn a_link_vector_is_taken_in_from_the_endpoint_its_signer_proved() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let twins = Twins::new(80);
            let carol = SecretKey::from_bytes(&[90; 32]);
            let ours = handle_for(&SecretKey::from_bytes(&[79; 32])).await;
            let second = handle_for(&twins.second_origin).await;
            let mut state = fresh_state();
            state.multihop = Some(ours.clone());
            state.peer_endpoints.insert(
                nick("twin-tt"),
                EndpointAddr::new(twins.first_origin.public()),
            );
            state.peers.insert(twins.first.author_key());
            state.peers.insert(twins.second.author_key());
            state.note_proven_endpoint(
                twins.first.author_key(),
                twins.first_origin.public(),
                UnixSecs::from(1),
            );
            state.note_proven_endpoint(
                twins.second.author_key(),
                twins.second_origin.public(),
                UnixSecs::from(1),
            );

            let vector = signed_vector("twin-tt", &twins.second, &second, carol.public());
            assert!(
                super::handle_link_state(&vector, &mut state),
                "the vector of the second key, from the endpoint it proved, changes the topology"
            );
            assert_eq!(
                ours.topology_view().edges.len(),
                1,
                "the one link of the vector is an edge"
            );
            ours.close().await;
            second.close().await;
        });
    }

    // One park slot per key: the vector of the second key of a nickname waits beside the vector of
    // the first, and neither the park of the first nor its proof takes it away.
    #[test]
    fn the_parked_vector_of_one_key_survives_another_key_of_its_nickname() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let twins = Twins::new(83);
            let carol = SecretKey::from_bytes(&[91; 32]);
            let ours = handle_for(&SecretKey::from_bytes(&[82; 32])).await;
            let (first, second) = (
                handle_for(&twins.first_origin).await,
                handle_for(&twins.second_origin).await,
            );
            let mut state = fresh_state();
            state.multihop = Some(ours.clone());

            state.peers.insert(twins.first.author_key());
            state.peers.insert(twins.second.author_key());
            super::handle_link_state(
                &signed_vector("twin-tt", &twins.second, &second, carol.public()),
                &mut state,
            );
            super::handle_link_state(
                &signed_vector("twin-tt", &twins.first, &first, carol.public()),
                &mut state,
            );
            state.note_proven_endpoint(
                twins.first.author_key(),
                twins.first_origin.public(),
                UnixSecs::from(1),
            );
            assert_eq!(
                ours.topology_view().edges.len(),
                1,
                "the vector of the first key is fed at its proof"
            );
            state.note_proven_endpoint(
                twins.second.author_key(),
                twins.second_origin.public(),
                UnixSecs::from(1),
            );
            assert_eq!(
                ours.topology_view().edges.len(),
                2,
                "the vector of the second key waited for its proof, and was fed there"
            );
            ours.close().await;
            first.close().await;
            second.close().await;
        });
    }

    /// The first peer of a roster proves its origin, then `others` more peers prove theirs: the
    /// state, the first peer's signer and its handle.
    async fn roster_of(
        others: usize,
        ours: &MultihopHandle,
    ) -> (EventLoopState, Identity, MultihopHandle) {
        let first_secret = SecretKey::from_bytes(&[100; 32]);
        let first = Identity::generate();
        let theirs = handle_for(&first_secret).await;
        let mut state = fresh_state();
        state.multihop = Some(ours.clone());
        state.peers.insert(first.author_key());
        state.note_proven_endpoint(first.author_key(), first_secret.public(), UnixSecs::from(1));
        for _ in 0..others {
            let peer = Identity::generate();
            state.peers.insert(peer.author_key());
            state.note_proven_endpoint(
                peer.author_key(),
                SecretKey::generate().public(),
                UnixSecs::from(1),
            );
        }
        (state, first, theirs)
    }

    // The trust of a proof is the roster's to keep, not a FIFO's: a mesh of more than the FIFO cap
    // (64) must hear the first peer that proved.
    #[test]
    fn a_roster_larger_than_the_proof_cap_keeps_the_trust_of_every_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let ours = handle_for(&SecretKey::from_bytes(&[99; 32])).await;
            let carol = SecretKey::from_bytes(&[98; 32]);
            let (mut state, first, theirs) = roster_of(69, &ours).await;

            let vector = signed_vector("first-ff", &first, &theirs, carol.public());
            assert!(
                super::handle_link_state(&vector, &mut state),
                "the first of 70 roster peers is still heard"
            );
            ours.close().await;
            theirs.close().await;
        });
    }

    // Keys that the roster does not hold are cheap to mint, and a proof of one must not push a
    // roster peer out of the trust.
    #[test]
    fn proofs_of_keys_outside_the_roster_do_not_take_the_trust_of_a_roster_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let ours = handle_for(&SecretKey::from_bytes(&[97; 32])).await;
            let carol = SecretKey::from_bytes(&[96; 32]);
            let (mut state, first, theirs) = roster_of(0, &ours).await;
            for _ in 0..70 {
                state.note_proven_endpoint(
                    Identity::generate().author_key(),
                    SecretKey::generate().public(),
                    UnixSecs::from(1),
                );
            }

            let vector = signed_vector("first-ff", &first, &theirs, carol.public());
            assert!(
                super::handle_link_state(&vector, &mut state),
                "70 minted proofs outside the roster do not evict the roster peer"
            );
            ours.close().await;
            theirs.close().await;
        });
    }

    // The trust rule is the one of a vector that arrives after its proof: the origin must be the
    // endpoint that the signer proved.
    #[test]
    fn a_parked_link_vector_whose_origin_is_not_the_proved_endpoint_is_dropped_at_the_proof() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (alice, bob) = (
                SecretKey::from_bytes(&[64; 32]),
                SecretKey::from_bytes(&[65; 32]),
            );
            let ours = handle_for(&SecretKey::from_bytes(&[63; 32])).await;
            let theirs = handle_for(&alice).await;
            let mut state = fresh_state();
            state.multihop = Some(ours.clone());

            let mallory = Identity::generate();
            let message =
                vector_message("mallory-mm", &theirs, vec![(bob.public(), 10)]).sign(&mallory);
            super::handle_link_state(&message, &mut state);
            state.note_proven_endpoint(mallory.author_key(), bob.public(), UnixSecs::from(1));
            assert!(
                ours.topology_view().edges.is_empty(),
                "a signer that proved another endpoint cannot speak for this origin"
            );
            ours.close().await;
            theirs.close().await;
        });
    }

    #[test]
    fn a_newer_parked_link_vector_replaces_the_older() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (alice, bob, carol) = (
                SecretKey::from_bytes(&[67; 32]),
                SecretKey::from_bytes(&[68; 32]),
                SecretKey::from_bytes(&[69; 32]),
            );
            let ours = handle_for(&SecretKey::from_bytes(&[66; 32])).await;
            let theirs = handle_for(&alice).await;
            let mut state = fresh_state();
            state.multihop = Some(ours.clone());

            let signer = Identity::generate();
            state.peers.insert(signer.author_key());
            let older = vector_message("alice-aa", &theirs, vec![(bob.public(), 10)]).sign(&signer);
            let newer = vector_message(
                "alice-aa",
                &theirs,
                vec![(bob.public(), 10), (carol.public(), 10)],
            )
            .sign(&signer);
            super::handle_link_state(&older, &mut state);
            super::handle_link_state(&newer, &mut state);
            state.note_proven_endpoint(signer.author_key(), alice.public(), UnixSecs::from(1));
            assert_eq!(
                ours.topology_view().edges.len(),
                2,
                "the newer vector, with two links, is the one that is fed"
            );
            ours.close().await;
            theirs.close().await;
        });
    }

    // A signer that never proves itself must not hold its slot for good: after the wait, the slot
    // is free for a signer that will.
    #[test]
    fn the_park_frees_the_slots_of_signers_that_never_prove() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let theirs = handle_for(&SecretKey::from_bytes(&[73; 32])).await;
            let vector = theirs.link_vector(Vec::new());
            let mut parked = ParkedLinkStates::new(2);
            parked.park(test_key("alice-aa"), vector.clone());
            parked.park(test_key("bobby-bb"), vector.clone());
            assert!(
                !parked.park(test_key("carol-cc"), vector.clone()),
                "the park is full of signers that wait"
            );

            parked.expire(Instant::now() + PARKED_LINK_STATE_TTL / 2);
            assert!(
                !parked.park(test_key("carol-cc"), vector.clone()),
                "a signer that waits inside the window keeps its slot"
            );

            parked.expire(Instant::now() + PARKED_LINK_STATE_TTL + Duration::from_secs(1));
            assert!(
                parked.park(test_key("carol-cc"), vector),
                "after the window the slot of a signer that never proved is free"
            );
            theirs.close().await;
        });
    }

    // The policy: the wait counts from the first vector of a signer. A signer that never proves
    // and keeps sending cannot renew its slot with each new vector.
    #[test]
    fn a_vector_that_replaces_a_parked_one_does_not_renew_the_wait() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let theirs = handle_for(&SecretKey::from_bytes(&[74; 32])).await;
            let vector = theirs.link_vector(Vec::new());
            let mut parked = ParkedLinkStates::new(1);
            parked.park(test_key("alice-aa"), vector.clone());
            thread::sleep(Duration::from_millis(20));
            parked.park(test_key("alice-aa"), vector.clone());

            let near_end = PARKED_LINK_STATE_TTL.saturating_sub(Duration::from_millis(5));
            parked.expire(Instant::now() + near_end);
            assert!(
                parked.park(test_key("bobby-bb"), vector),
                "alice waited longer than the window from her first vector, so her slot is free"
            );
            theirs.close().await;
        });
    }

    // A proof can come before its signer is in the roster. The signer is not trusted yet, so the
    // vector stays parked for the proof that comes with the roster.
    #[test]
    fn a_proof_of_a_key_outside_the_roster_leaves_its_vector_parked() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let secret = SecretKey::from_bytes(&[75; 32]);
            let theirs = handle_for(&secret).await;
            let signer = test_key("alice-aa");
            let mut state = fresh_state();
            state
                .parked_link_states
                .park(signer, theirs.link_vector(Vec::new()));

            state.note_proven_endpoint(signer, secret.public(), UnixSecs::from(1));
            let waiting = state.parked_link_states.take(&signer);
            assert!(
                waiting.is_some(),
                "a signer that is not trusted yet lost its parked vector"
            );
            if let Some(vector) = waiting {
                state.parked_link_states.park(signer, vector);
            }

            state.peers.insert(signer);
            state.note_proven_endpoint(signer, secret.public(), UnixSecs::from(1));
            assert!(
                state.parked_link_states.take(&signer).is_none(),
                "once the signer is trusted, the vector that waited is fed and gone"
            );
            theirs.close().await;
        });
    }

    #[test]
    fn the_park_holds_one_vector_per_author_up_to_its_cap() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let alice = SecretKey::from_bytes(&[71; 32]);
            let theirs = handle_for(&alice).await;
            let vector = theirs.link_vector(Vec::new());
            let mut parked = ParkedLinkStates::new(2);

            assert!(
                parked.park(test_key("alice-aa"), vector.clone()),
                "the first vector for alice is parked"
            );
            assert!(
                parked.park(test_key("bobby-bb"), vector.clone()),
                "the first vector for bobby is parked beside alice's"
            );
            assert!(
                !parked.park(test_key("carol-cc"), vector.clone()),
                "a third author is refused at the cap"
            );
            assert!(
                parked.park(test_key("alice-aa"), vector.clone()),
                "an author that waits is replaced at the cap"
            );
            assert!(
                parked.take(&test_key("alice-aa")).is_some(),
                "alice's vector is taken from the park"
            );
            assert!(parked.take(&test_key("alice-aa")).is_none(), "taken once");
            assert!(
                parked.park(test_key("carol-cc"), vector),
                "a taken vector frees its place"
            );
            theirs.close().await;
        });
    }
}

/// The census counts each frame that reaches the dedup as a first sighting or a repeat.
#[cfg(test)]
mod dedup_counter_tests {
    use iroh::endpoint::presets;
    use iroh_gossip::net::Gossip;
    use iroh_gossip::proto;
    use serde_json::json;

    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::state::{EventLoopState, by_arrival, by_class};
    use crate::gossip::antientropy::Plane;
    use crate::gossip::app::{AppClass, InboundApp, NodeApp};
    use crate::gossip::event::{NodeEvent, NodeSink, SilentSink};
    use crate::lifecycle;
    use crate::protocol::identity::Identity;
    use crate::protocol::messages::{Authored, MessageBody, Verified};
    use crate::protocol::{Channel, MeshId, Message};
    use crate::testing::{endpoint_id, fresh_state, nick};
    use crate::transport::MeshSender;
    use crate::util::clock::Instant;
    use bytes::Bytes;
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;

    struct Inert;

    #[async_trait::async_trait]
    impl NodeApp for Inert {
        fn classify(&self, _message: &Authored) -> AppClass {
            AppClass::BEAT.union(AppClass::VALID)
        }

        async fn on_app_frame(
            &mut self,
            _frame: InboundApp<'_>,
            _state: &mut EventLoopState,
            _context: &HandlerCtx<'_>,
        ) -> bool {
            false
        }
    }

    fn state_frame(writer: &EventLoopState, body: MessageBody) -> Verified {
        Message::new_channel_event(&MeshId::from("test"), &nick("writer"), body, Channel::State)
            .sign(&writer.identity)
    }

    /// A signed frame of the writer that carries `{"key": 1}` as one change.
    fn change_body(writer: &EventLoopState) -> MessageBody {
        let seed = *writer.identity.public().as_bytes();
        let doc = writer.doc(Channel::State);
        let change = doc
            .build_change(&json!({ "key": 1 }), &seed)
            .expect("a JSON object merges")
            .expect("a non-empty merge yields a change");
        let (body, _plain) = writer
            .doc(Channel::State)
            .compose_wire_body(&change, None)
            .expect("compose the wire body");
        body
    }

    fn reader_after(frames: &[&Verified]) -> EventLoopState {
        let arrivals: Vec<(Plane, Bytes)> = frames
            .iter()
            .map(|frame| {
                (
                    Plane::Gossip,
                    frame.serialize().expect("serialize").into_bytes(),
                )
            })
            .collect();
        reader_after_on(arrivals)
    }

    fn reader_after_on(arrivals: Vec<(Plane, Bytes)>) -> EventLoopState {
        reader_with(fresh_state(), arrivals)
    }

    /// [`reader_after_on`] for a reader that starts as `initial`.
    fn reader_with(initial: EventLoopState, arrivals: Vec<(Plane, Bytes)>) -> EventLoopState {
        reader_with_sink(initial, arrivals, &SilentSink)
    }

    /// [`reader_with`] with the sink that receives the events of the arrivals.
    fn reader_with_sink(
        initial: EventLoopState,
        arrivals: Vec<(Plane, Bytes)>,
        sink: &dyn NodeSink,
    ) -> EventLoopState {
        reader_full(initial, arrivals, sink, None)
    }

    /// [`reader_with_sink`], and then, with an endpoint: that endpoint becomes a linked neighbour, and a frame
    /// from it is taken to have arrived on a unicast connection, so the asks that waited for a path are tried.
    fn reader_full(
        initial: EventLoopState,
        arrivals: Vec<(Plane, Bytes)>,
        sink: &dyn NodeSink,
        path_up: Option<iroh::EndpointId>,
    ) -> EventLoopState {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mesh = MeshId::from("test");
            let endpoint = iroh::Endpoint::builder(presets::Minimal)
                .bind()
                .await
                .expect("bind a local endpoint");
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let topic = gossip
                .subscribe(proto::TopicId::from_bytes([5u8; 32]), vec![])
                .await
                .expect("subscribe to a peerless topic");
            let (gossip_sender, _receiver) = topic.split();
            let sender = MeshSender::new(gossip_sender);
            let identity = Identity::generate();
            let reader_nick = nick("reader");
            let context = HandlerCtx {
                sender: &sender,
                endpoint: &endpoint,
                mesh: &mesh,
                author: &reader_nick,
                identity: &identity,
                our_pubkey: identity.author_key(),
                max_peers: 16,
                rendezvous_id: endpoint_id(9),
                external_msg_tx: None,
                sink,
            };
            let mut reader = initial;
            let mut app = Inert;
            for (plane, bytes) in arrivals {
                super::ingest_from(plane, bytes, &mut reader, &mut app, &context).await;
            }
            if let Some(up) = path_up {
                reader.linked_endpoints.insert(up);
                lifecycle::retry_deferred_asks(&mut reader, &context, Some(up)).await;
            }
            endpoint.close().await;
            reader
        })
    }

    /// A sink that counts the synthetic presence events: the `left` lines that the node writes for a
    /// session that it ended itself, and not one that the session signed.
    #[derive(Default)]
    struct SyntheticPresence(Mutex<usize>);

    impl NodeSink for SyntheticPresence {
        fn emit(&self, event: NodeEvent) {
            if let NodeEvent::Presence {
                synthetic: true, ..
            } = event
            {
                *self.0.lock().expect("the count lock is not poisoned") += 1;
            }
        }
    }

    fn wire(frame: &Verified) -> u64 {
        frame.serialize().expect("serialize").len() as u64
    }

    /// The receive path counts the bytes of a frame in the log from the bytes it came in as, and does
    /// not serialize the message again. The count must be the length of the serialized frame, for a
    /// frame as it was sent and for a resend, which carries a trailer outside the frame.
    #[test]
    fn the_log_counts_a_received_frame_by_the_length_it_came_in_with() {
        let session = Identity::generate();
        let frame = Message::new_joined(&MeshId::from("test"), &nick("alice")).sign(&session);
        let wire = frame.serialize().expect("serialize");
        let resent = wire.copy_with_resend_nonce(7);
        let sent_len = wire.as_bytes().len();
        for (bytes, how) in [(wire.into_bytes(), "sent"), (resent.into_bytes(), "resent")] {
            let reader = reader_with(fresh_state(), vec![(Plane::Gossip, bytes)]);

            let (held, held_bytes) = reader.message_log.size();

            assert_eq!(held, 1, "a {how} frame is in the log");
            assert_eq!(
                held_bytes, sent_len,
                "a {how} frame counts its serialized length"
            );
        }
    }

    /// An alive frame of a session, as the bytes that arrive on the gossip plane.
    fn alive_of(session: &Identity, nickname: &str) -> (Plane, Bytes) {
        let frame = Message::new_alive(&MeshId::from("test"), &nick(nickname)).sign(session);
        (
            Plane::Gossip,
            frame.serialize().expect("serialize").into_bytes(),
        )
    }

    /// A state that holds the proof of the live session `bound`, which a member key made for
    /// the nickname `nickname`: the nickname is bound to that member key.
    fn state_with_bound_nickname(bound: &Identity, nickname: &str) -> EventLoopState {
        let mut state = fresh_state();
        let session = bound.author_key();
        let proof =
            Identity::generate().prove(&session, nickname, MeshId::from("test").as_ref(), 1);
        state.peers.insert(session);
        let held = state.proofs.accept(
            &session,
            &nick(nickname),
            &MeshId::from("test"),
            proof,
            |_| true,
        );
        assert!(held, "the proof of the bound session is held");
        state
    }

    /// The nickname of a member is bound to its member key. A session that claims it with no proof
    /// is no peer: its frames reach no roster.
    #[test]
    fn a_session_of_a_bound_nickname_with_no_proof_is_not_admitted() {
        let bound = Identity::generate();
        let intruder = Identity::generate();
        let initial = state_with_bound_nickname(&bound, "alice");

        let reader = reader_with(initial, vec![alive_of(&intruder, "alice")]);

        assert!(
            !reader.peers.contains(&intruder.author_key()),
            "a session with no proof, under the nickname of a bound member, is not in the roster"
        );
        assert!(
            reader.peers.contains(&bound.author_key()),
            "the bound session stays"
        );
    }

    /// The census counts the bytes of the frame that the log holds, which serialize gives, and not the bytes of
    /// the frame as it arrived: a signed frame with JSON white space holds the same message.
    #[test]
    fn the_log_gauge_counts_the_serialized_frame_not_the_white_space_of_the_arrival() {
        let sender = Identity::generate();
        let frame = Message::new_joined(&MeshId::from("test"), &nick("bob")).sign(&sender);
        let compact = frame.serialize().expect("serialize").into_bytes();
        let value: serde_json::Value = serde_json::from_slice(&compact).expect("a JSON frame");
        let pretty = serde_json::to_vec_pretty(&value).expect("pretty JSON");
        assert!(
            pretty.len() > compact.len(),
            "the arrival must carry white space for the test to mean anything"
        );

        let reader = reader_with(fresh_state(), vec![(Plane::Gossip, Bytes::from(pretty))]);

        let (held, bytes) = reader.message_log.size();
        assert_eq!(held, 1, "the frame is retained");
        assert_eq!(
            bytes,
            compact.len(),
            "the census counted white space that the log does not hold"
        );
    }

    /// A goodbye is signed by the key that leaves, so the key is authenticated whatever nickname the frame
    /// names. A roster key that says goodbye under a nickname that another member binds still ends its own
    /// session: the gate refuses the nickname, not the departure of the key.
    #[test]
    fn a_roster_key_that_says_goodbye_under_a_bound_nickname_still_leaves() {
        let bound = Identity::generate();
        let leaver = Identity::generate();
        let mut initial = state_with_bound_nickname(&bound, "alice");
        initial.peers.insert(leaver.author_key());
        initial.names.insert(leaver.author_key(), nick("carol"));
        let left = Message::new_left(&MeshId::from("test"), &nick("alice")).sign(&leaver);
        let frame = (
            Plane::Gossip,
            left.serialize().expect("serialize").into_bytes(),
        );

        let reader = reader_with(initial, vec![frame]);

        assert!(
            !reader.peers.contains(&leaver.author_key()),
            "the key said goodbye and stayed in the roster"
        );
        assert!(
            reader.peers.contains(&bound.author_key()),
            "the goodbye of one key ended the session of another"
        );
    }

    /// A proof request is consumed by the infrastructure dispatch: an application subscriber is never told
    /// about it, like the digests and the pings.
    #[test]
    fn a_proof_request_is_not_pushed_to_application_subscribers() {
        use crate::protocol::MessageKind;
        let to = Identity::generate().author_key();
        assert!(
            super::is_plumbing(&MessageKind::ProofRequest { to }),
            "an admitted peer's fresh proof request would reach the subscribers of the inbound push"
        );
    }

    /// The `PeerInfo` of a session that the roster gate refuses still gives its address: the session is
    /// asked for its proof over a warm path, and it has none without the address. The frame binds no
    /// hint and adds no roster entry.
    #[test]
    fn a_refused_session_peer_info_registers_the_address_for_the_proof_request() {
        use crate::protocol::messages::MessageBody;
        use crate::protocol::peer_addr_error;

        let bound = Identity::generate();
        let intruder = Identity::generate();
        let initial = state_with_bound_nickname(&bound, "alice");
        let json =
            peer_addr_error::endpoint_addr_to_json(&iroh::EndpointAddr::new(endpoint_id(61)));
        let body = MessageBody::try_new(&json.to_string()).expect("an address body");
        let peer_info =
            Message::new_peer_info(&MeshId::from("test"), &nick("alice"), body).sign(&intruder);
        let frame = (
            Plane::Gossip,
            peer_info.serialize().expect("serialize").into_bytes(),
        );

        let reader = reader_with(initial, vec![frame]);

        assert!(
            !reader.peers.contains(&intruder.author_key()),
            "the refused session entered the roster"
        );
        assert_eq!(
            reader
                .address_of(&intruder.author_key())
                .map(|address| address.id),
            Some(endpoint_id(61)),
            "the proof request to the session has no address to go to"
        );
    }

    /// The `PeerInfo` of a session of the roster that has no proof gives its address, and the proof request
    /// that it sets off goes to a linked peer by a dial in the background. That dial uses the address that
    /// the pool remembers, so the address must be registered before the request goes: a dial that starts
    /// with no address, or with the old one, can fail, and the request that was queued has started the retry
    /// clock of the session for nothing.
    #[test]
    fn the_address_of_a_peer_info_is_registered_in_the_pool_before_the_proof_request_goes() {
        use crate::protocol::messages::MessageBody;
        use crate::protocol::peer_addr_error;

        let session = Identity::generate();
        let address = iroh::EndpointAddr::new(endpoint_id(62));
        let mut initial = fresh_state();
        initial.linked_endpoints.insert(endpoint_id(62));
        let json = peer_addr_error::endpoint_addr_to_json(&address);
        let body = MessageBody::try_new(&json.to_string()).expect("an address body");
        let peer_info =
            Message::new_peer_info(&MeshId::from("test"), &nick("carol"), body).sign(&session);
        let info = (
            Plane::Gossip,
            peer_info.serialize().expect("serialize").into_bytes(),
        );

        let reader = reader_with(initial, vec![alive_of(&session, "carol"), info]);

        assert_eq!(
            reader.ask_dial_addrs,
            vec![Some(address)],
            "the proof request went before the pool remembered the address of its endpoint"
        );
    }

    /// A joined frame of a session, as the bytes that arrive on the gossip plane, with the proof of
    /// `member` for its `run`.
    fn joined_of(
        session: &Identity,
        member: &Identity,
        nickname: &str,
        run: u64,
    ) -> (Plane, Bytes) {
        let proof = member.prove(
            &session.author_key(),
            nickname,
            MeshId::from("test").as_ref(),
            run,
        );
        let frame = Message::new_joined_with_proof(&MeshId::from("test"), &nick(nickname), &proof)
            .sign(session);
        (
            Plane::Gossip,
            frame.serialize().expect("serialize").into_bytes(),
        )
    }

    /// A member restarts: the `joined` frame of its new session, with a higher run, replaces the old
    /// session in the roster. There is one peer for the member, the new one, and the old key does
    /// not stay a ghost until its timeout.
    #[test]
    fn a_restarted_member_replaces_its_old_session_in_the_roster() {
        let member = Identity::generate();
        let (old, new) = (Identity::generate(), Identity::generate());
        let mesh = MeshId::from("test");
        let mut initial = fresh_state();
        initial.peers.insert(old.author_key());
        initial.names.insert(old.author_key(), nick("alice"));
        let first = member.prove(&old.author_key(), "alice", mesh.as_ref(), 1);
        let held = initial
            .proofs
            .accept(&old.author_key(), &nick("alice"), &mesh, first, |_| true);
        assert!(held, "the proof of the old session is held");
        let (_, second) = joined_of(&new, &member, "alice", 2);
        let reader = reader_with(initial, vec![(Plane::Gossip, second)]);

        assert!(
            reader.peers.contains(&new.author_key()),
            "the new session is a peer"
        );
        assert!(
            !reader.peers.contains(&old.author_key()),
            "the old session of the same member is not a peer any more"
        );
        assert!(
            reader.proofs.proof_of(&old.author_key()).is_none(),
            "and its proof is gone"
        );
    }

    /// The nickname of this node is held by its member key. A session that claims it with no proof
    /// is no peer, and the session of the same member (its old run) is.
    #[test]
    fn our_own_nickname_admits_only_a_session_of_our_member() {
        let reader_state = fresh_state();
        let intruder = Identity::generate();
        let mut old_run = fresh_state();
        old_run.member_identity = reader_state.member_identity.clone();
        let mesh = MeshId::from("test");
        let proved: Verified = old_run.own_joined(&mesh, &nick("reader"));
        let joined = (
            Plane::Gossip,
            proved.serialize().expect("serialize").into_bytes(),
        );

        let reader = reader_with(reader_state, vec![alive_of(&intruder, "reader"), joined]);

        assert!(
            !reader.peers.contains(&intruder.author_key()),
            "a session with no proof under our nickname is no peer"
        );
        assert!(
            reader.peers.contains(&old_run.identity.author_key()),
            "a session that our member key proved is a peer"
        );
    }

    /// A session that our own member key proved under our nickname is a peer only when its run is not older
    /// than ours: a replay of an older run must not enter the roster beside the run that is live here.
    #[test]
    fn an_older_run_of_our_own_member_is_no_peer() {
        let session = Identity::generate();
        let state = fresh_state();
        let member = state
            .member_identity
            .clone()
            .expect("a test state has a member key");
        let proof_frame = joined_of(&session, &member, "reader", 0);

        let reader = reader_with(state, vec![proof_frame]);

        assert!(
            !reader.peers.contains(&session.author_key()),
            "a session of our member with run 0 against the local run 1 entered the roster"
        );
    }

    /// A `joined` frame with the proof of `member`, stamped `age_secs` seconds ago: a stored copy that a relay
    /// or an anti-entropy answer hands out long after its author spoke.
    fn old_joined_of(
        session: &Identity,
        member: &Identity,
        nickname: &str,
        age_secs: i64,
    ) -> (Plane, Bytes) {
        use crate::protocol::UnixSecs;
        let proof = member.prove(
            &session.author_key(),
            nickname,
            MeshId::from("test").as_ref(),
            1,
        );
        let mut message =
            Message::new_joined_with_proof(&MeshId::from("test"), &nick(nickname), &proof);
        message.timestamp = UnixSecs::from(UnixSecs::now().as_secs() - age_secs);
        let frame = message.sign(session);
        (
            Plane::Gossip,
            frame.serialize().expect("serialize").into_bytes(),
        )
    }

    /// An old signed `joined` frame of a member proves nothing about the member now: its sender does not enter
    /// the roster (the frame is too old to prove presence). It must not end the live session of another
    /// member under that nickname either: the live session would be gone, with the buffered frames for it, and
    /// nobody would hold the name. The proof is kept, and when its session shows it is alive, the name is bound
    /// to its member and the session of the other member ends.
    #[test]
    fn an_old_joined_frame_of_a_member_ends_no_session_while_its_sender_is_not_in_the_roster() {
        let member = Identity::generate();
        let (member_session, other_session) = (Identity::generate(), Identity::generate());

        let replayed = reader_with(
            fresh_state(),
            vec![
                alive_of(&other_session, "alice"),
                old_joined_of(&member_session, &member, "alice", 3 * 86_400),
            ],
        );

        assert!(
            replayed.peers.contains(&other_session.author_key()),
            "a replay of an old joined frame ended the live session of another member"
        );
        assert!(
            !replayed.peers.contains(&member_session.author_key()),
            "the sender of an old frame entered the roster"
        );

        let alive = reader_with(replayed, vec![alive_of(&member_session, "alice")]);

        assert!(
            alive.peers.contains(&member_session.author_key()),
            "the member whose proof is kept is a peer once it shows that it is alive"
        );
        assert!(
            !alive.peers.contains(&other_session.author_key()),
            "the session of the other member stays when the member that proved the name is alive"
        );
    }

    /// A member signs its answer to a proof request once for each run, so every asker gets the same frame. An
    /// asker that dropped the proof of that session (the session left the roster and came back) gets the frame
    /// again, and the frame is a duplicate there: dropped before anything reads its proof. The proof must come
    /// back for a session that is in the roster, with none of the other effects of the frame (it is no arrival
    /// and no heartbeat). A copy for a session that is not in the roster keeps no proof.
    #[test]
    fn a_duplicate_joined_frame_gives_back_the_proof_that_the_book_lost() {
        let (member, session) = (Identity::generate(), Identity::generate());
        let key = session.author_key();
        let frame = joined_of(&session, &member, "alice", 1);

        let mut first = reader_with(fresh_state(), vec![frame.clone()]);
        assert!(first.proofs.proof_of(&key).is_some(), "the proof is held");
        first.proofs.forget(&key);
        assert!(first.proofs.proof_of(&key).is_none(), "the proof was lost");

        let again = reader_with(first, vec![frame]);

        assert!(
            again.proofs.proof_of(&key).is_some(),
            "the copy of the joined frame did not give the proof back to a session that is in the roster"
        );
        assert_eq!(
            again.idle.duplicates, 1,
            "the copy is still counted as a duplicate"
        );

        let stranger = Identity::generate();
        let known = joined_of(&stranger, &member, "alice", 1);
        let mut other = reader_with(fresh_state(), vec![known.clone()]);
        other.peers.remove(&stranger.author_key());
        other.proofs.forget(&stranger.author_key());
        let after = reader_with(other, vec![known]);
        assert!(
            after.proofs.proof_of(&stranger.author_key()).is_none(),
            "a copy for a session that is not in the roster kept a proof"
        );
    }

    /// A free nickname is accepted with no proof: a member that has not proved yet, or a client
    /// that never will, is a peer, and its nickname stays unbound.
    #[test]
    fn a_session_of_a_free_nickname_with_no_proof_is_admitted_unbound() {
        let bound = Identity::generate();
        let newcomer = Identity::generate();
        let initial = state_with_bound_nickname(&bound, "alice");

        let reader = reader_with(initial, vec![alive_of(&newcomer, "carol")]);

        assert!(
            reader.peers.contains(&newcomer.author_key()),
            "a session under a free nickname is in the roster"
        );
        assert!(
            reader.proofs.proof_of(&newcomer.author_key()).is_none(),
            "it is unbound: no proof is held for it"
        );
    }

    /// Two members claim one nickname before either has proved it: both sessions are admitted, because
    /// no member key binds the name yet. When the proof of one of them arrives, the name is bound to
    /// that member, and the admitted session of the other member leaves the roster at once: a node
    /// that lists both lists an impostor under a bound nickname.
    #[test]
    fn a_proof_that_binds_a_nickname_ends_the_admitted_session_of_another_member() {
        let (alice, intruder) = (Identity::generate(), Identity::generate());
        let (alice_session, intruder_session) = (Identity::generate(), Identity::generate());

        let reader = reader_with(
            fresh_state(),
            vec![
                alive_of(&alice_session, "alice"),
                alive_of(&intruder_session, "alice"),
                joined_of(&alice_session, &alice, "alice", 1),
            ],
        );

        assert!(
            reader.peers.contains(&alice_session.author_key()),
            "the session of the member that proved the name stays"
        );
        assert!(
            !reader.peers.contains(&intruder_session.author_key()),
            "the session of the other member, admitted before the proof, is ended"
        );
        assert!(
            !reader.names.contains_key(&intruder_session.author_key()),
            "and the roster forgets its nickname"
        );
        let _ = intruder;
    }

    /// The first proof that a node processes binds the name, whoever the member is: the order of the
    /// proofs decides, at each node, and the order of the frames does not.
    #[test]
    fn the_member_whose_proof_comes_first_keeps_the_nickname_at_a_node() {
        let (alice, other) = (Identity::generate(), Identity::generate());
        let (alice_session, other_session) = (Identity::generate(), Identity::generate());

        let reader = reader_with(
            fresh_state(),
            vec![
                alive_of(&alice_session, "alice"),
                alive_of(&other_session, "alice"),
                joined_of(&other_session, &other, "alice", 1),
                joined_of(&alice_session, &alice, "alice", 1),
            ],
        );

        assert!(
            reader.peers.contains(&other_session.author_key()),
            "the member whose proof came first keeps the name"
        );
        assert!(
            !reader.peers.contains(&alice_session.author_key()),
            "the other member is not a peer, whatever frame came first"
        );
    }

    /// A session that went quiet holds its nickname too, so a proof of another member ends it as well.
    #[test]
    fn a_proof_that_binds_a_nickname_ends_a_quiet_session_of_another_member() {
        let (alice, quiet_session) = (Identity::generate(), Identity::generate());
        let alice_session = Identity::generate();
        let mut initial = fresh_state();
        initial.quiet.insert(quiet_session.author_key());
        initial
            .names
            .insert(quiet_session.author_key(), nick("alice"));

        let reader = reader_with(initial, vec![joined_of(&alice_session, &alice, "alice", 1)]);

        assert!(
            !reader.quiet.contains(&quiet_session.author_key()),
            "the quiet session of another member does not keep the name"
        );
        assert!(
            reader.peers.contains(&alice_session.author_key()),
            "the member that proved the name is a peer"
        );
    }

    /// The name stays held by the member that proved it, so the end of the other session is no `left`
    /// line for that name: the operator would read that the member went away.
    #[test]
    fn the_end_of_an_intruder_writes_no_left_line_for_the_name() {
        let (alice, intruder_session) = (Identity::generate(), Identity::generate());
        let alice_session = Identity::generate();
        let mut initial = fresh_state();
        initial.peers.insert(intruder_session.author_key());
        initial.surfaced.insert(intruder_session.author_key());
        initial
            .names
            .insert(intruder_session.author_key(), nick("alice"));
        let events = SyntheticPresence::default();

        let reader = reader_with_sink(
            initial,
            vec![joined_of(&alice_session, &alice, "alice", 1)],
            &events,
        );

        assert!(
            !reader.peers.contains(&intruder_session.author_key()),
            "the intruder is ended"
        );
        assert_eq!(
            *events.0.lock().expect("the count lock is not poisoned"),
            0,
            "no left line for a name that a member still holds"
        );
    }

    /// A `left` frame of a session, as the bytes that arrive on the gossip plane.
    fn left_of(session: &Identity, nickname: &str) -> (Plane, Bytes) {
        let frame = Message::new_left(&MeshId::from("test"), &nick(nickname)).sign(session);
        (
            Plane::Gossip,
            frame.serialize().expect("serialize").into_bytes(),
        )
    }

    /// The goodbye of a key that is not in the roster ends the endpoint that was retained for it, with the state
    /// of the pool: its pooled connection and its dial-failure cooldown go too, and the shared-endpoint check
    /// stays (an endpoint that another key still names is kept).
    #[test]
    fn the_goodbye_of_a_stranger_tears_down_the_pool_state_of_its_retained_endpoint() {
        let stranger = Identity::generate();
        let (retained, shared) = (endpoint_id(63), endpoint_id(64));
        let mut initial = fresh_state();
        initial.retain_refused_endpoint(stranger.author_key(), iroh::EndpointAddr::new(retained));
        let other = Identity::generate().author_key();
        initial.retain_refused_endpoint(other, iroh::EndpointAddr::new(shared));
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            initial.unicast_pool.note_dial_failure(retained).await;
            initial.unicast_pool.note_dial_failure(shared).await;
        });

        let reader = reader_with(initial, vec![left_of(&stranger, "carol")]);

        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            assert!(
                !reader.unicast_pool.is_cooling(retained).await,
                "the retained endpoint of a stranger that left kept its pool state"
            );
            assert!(
                reader.unicast_pool.is_cooling(shared).await,
                "the endpoint of another retained key lost its pool state"
            );
        });
    }

    /// The end of an intruder is no goodbye that it signed: the member that lost the name at a node can
    /// come back there. While the other member holds the name its frames are refused, and when that
    /// member leaves they are admitted again, with no restart of the first. Two honest members that
    /// share a nickname would otherwise split the mesh for the whole session.
    #[test]
    fn a_member_that_lost_the_nickname_is_admitted_again_when_the_holder_leaves() {
        let (alice, holder) = (Identity::generate(), Identity::generate());
        let (alice_session, holder_session) = (Identity::generate(), Identity::generate());

        let reader = reader_with(
            fresh_state(),
            vec![
                alive_of(&alice_session, "alice"),
                joined_of(&holder_session, &holder, "alice", 1),
                left_of(&holder_session, "alice"),
                alive_of(&alice_session, "alice"),
            ],
        );

        assert!(
            !reader.peers.contains(&holder_session.author_key()),
            "the holder left"
        );
        assert!(
            reader.peers.contains(&alice_session.author_key()),
            "the session that lost the name is a peer again once the holder is gone"
        );
        let _ = alice;
    }

    /// A `joined` frame of a session that carries no proof, as the bytes that arrive on the gossip plane.
    fn unproved_joined_of(session: &Identity, nickname: &str) -> (Plane, Bytes) {
        let frame = Message::new_joined(&MeshId::from("test"), &nick(nickname)).sign(session);
        (
            Plane::Gossip,
            frame.serialize().expect("serialize").into_bytes(),
        )
    }

    /// The end of an intruder is no goodbye, and no other node drops the frames of the session: this node
    /// keeps them too. A peer that holds them would resend them at every digest round, while the holder
    /// keeps the name, if this node dropped them.
    #[test]
    fn the_end_of_an_intruder_keeps_its_presence_frames_in_the_log() {
        let (alice, intruder_session) = (Identity::generate(), Identity::generate());
        let alice_session = Identity::generate();

        let reader = reader_with(
            fresh_state(),
            vec![
                unproved_joined_of(&intruder_session, "alice"),
                joined_of(&alice_session, &alice, "alice", 1),
            ],
        );

        assert!(
            !reader.peers.contains(&intruder_session.author_key()),
            "the intruder is ended"
        );
        assert_eq!(
            reader.message_log.size().0,
            2,
            "the log holds the joined frame of the intruder and the one of the member"
        );
    }

    /// An address with no warm path to it asks for nothing and signs nothing, however many frames of that
    /// session come: a frame of the session costs a lookup.
    #[test]
    fn fifty_frames_of_a_session_with_an_address_and_no_warm_path_sign_no_request() {
        let session = Identity::generate();
        let mut initial = fresh_state();
        initial.peers.insert(session.author_key());
        initial.names.insert(session.author_key(), nick("alice"));
        initial.place_endpoint(
            session.author_key(),
            &nick("alice"),
            iroh::EndpointAddr::new(endpoint_id(7)),
        );
        let frames: Vec<(Plane, Bytes)> = (0..50).map(|_| alive_of(&session, "alice")).collect();

        let reader = reader_with(initial, frames);

        assert_eq!(
            reader.proof_requests_signed.load(Ordering::Relaxed),
            0,
            "no request was signed for an address that no warm path reaches"
        );
    }

    /// Twenty sessions ask one member for its proof: they all get the same frame, and the log of that
    /// member keeps one entry, not twenty. A fresh frame for each asker is a frame that its author keeps
    /// and offers in her digest, so anti-entropy would spread each one to every peer.
    #[test]
    fn twenty_askers_get_the_same_answer_and_the_log_keeps_one_entry() {
        let mesh = MeshId::from("test");
        let me = nick("alice");
        let mut state = fresh_state();
        let own = state.identity.author_key();
        let mut ids = Vec::new();

        for _ in 0..20 {
            let asker = Identity::generate().author_key();
            let answer = state
                .proof_answer(&own, &asker, &me, &mesh, Instant::now())
                .expect("an answer within the cap");
            ids.push(answer.dedup_key());
            super::keep_the_answer(&mut state);
        }

        assert!(
            ids.iter().all(|id| *id == ids[0]),
            "every asker got the same frame"
        );
        assert_eq!(
            state.message_log.size().0,
            1,
            "the log of the author holds one entry for the run"
        );
    }

    /// A proof that a node refuses because another member holds the name must not mark its frame as seen
    /// for good: the answer of a member is one frame for the whole run, and when the holder leaves and the
    /// member is asked again, the same frame must be read again, not dropped as a duplicate. Otherwise the
    /// member stays unproven at that node for the rest of the run.
    #[test]
    fn the_refused_proof_of_a_member_is_accepted_when_the_holder_has_left_and_the_frame_comes_again()
     {
        let (holder, member) = (Identity::generate(), Identity::generate());
        let (holder_session, member_session) = (Identity::generate(), Identity::generate());
        let answer = joined_of(&member_session, &member, "alice", 1);

        let reader = reader_with(
            fresh_state(),
            vec![
                joined_of(&holder_session, &holder, "alice", 1),
                answer.clone(),
                left_of(&holder_session, "alice"),
                answer,
            ],
        );

        assert!(
            !reader.peers.contains(&holder_session.author_key()),
            "the holder left"
        );
        assert!(
            reader
                .proofs
                .proof_of(&member_session.author_key())
                .is_some_and(|proof| proof.identity == member.public()),
            "the proof of the member is held once the holder is gone"
        );
        assert!(
            reader.peers.contains(&member_session.author_key()),
            "and the member is a peer"
        );
    }

    /// A session with an address and no path is asked for its proof by nothing that frames bring, but its
    /// ask is not lost: it waits, and when a connection to its endpoint is up (a frame from it on a
    /// unicast connection, or the sweep tick) the request goes. The late path of the simultaneous-open
    /// tie-break of two processes is this case.
    #[test]
    fn an_ask_that_waited_for_a_path_goes_when_the_path_comes_up() {
        let session = Identity::generate();
        let endpoint = endpoint_id(7);
        let waiting = || {
            let mut initial = fresh_state();
            initial.peers.insert(session.author_key());
            initial.names.insert(session.author_key(), nick("alice"));
            initial.place_endpoint(
                session.author_key(),
                &nick("alice"),
                iroh::EndpointAddr::new(endpoint),
            );
            initial
        };

        let before = reader_full(
            waiting(),
            vec![alive_of(&session, "alice")],
            &SilentSink,
            None,
        );
        let after = reader_full(
            waiting(),
            vec![alive_of(&session, "alice")],
            &SilentSink,
            Some(endpoint),
        );

        assert_eq!(
            (
                before.proofs.deferred_len(),
                before.proof_requests_signed.load(Ordering::Relaxed)
            ),
            (1, 0),
            "with no path the ask waits, and nothing is signed"
        );
        assert_eq!(
            (
                after.proofs.deferred_len(),
                after.proof_requests_signed.load(Ordering::Relaxed)
            ),
            (0, 1),
            "when the path is up the ask goes once, and nothing waits"
        );
    }

    /// A session that the roster gate refuses (it claims a nickname that another member holds) is not in the
    /// roster, so the roster has no name for it. Its ask waits for a path as any ask does, and it keeps the
    /// nickname that the session claimed: when the path comes up the request goes, and does not die for want
    /// of a roster entry. The restart of a member whose alive frame came before its address is this case.
    #[test]
    fn an_ask_for_a_refused_session_that_waited_goes_when_the_path_comes_up() {
        use crate::protocol::messages::MessageBody;
        use crate::protocol::peer_addr_error;

        let bound = Identity::generate();
        let session = Identity::generate();
        let endpoint = endpoint_id(65);
        let json = peer_addr_error::endpoint_addr_to_json(&iroh::EndpointAddr::new(endpoint));
        let body = MessageBody::try_new(&json.to_string()).expect("an address body");
        let peer_info =
            Message::new_peer_info(&MeshId::from("test"), &nick("alice"), body).sign(&session);
        let info = (
            Plane::Gossip,
            peer_info.serialize().expect("serialize").into_bytes(),
        );
        let frames = || vec![info.clone(), alive_of(&session, "alice")];

        let before = reader_full(
            state_with_bound_nickname(&bound, "alice"),
            frames(),
            &SilentSink,
            None,
        );
        let after = reader_full(
            state_with_bound_nickname(&bound, "alice"),
            frames(),
            &SilentSink,
            Some(endpoint),
        );

        assert_eq!(
            (
                before.proofs.deferred_len(),
                before.proof_requests_signed.load(Ordering::Relaxed)
            ),
            (1, 0),
            "with no path the ask of the refused session waits, and nothing is signed"
        );
        assert_eq!(
            after.proof_requests_signed.load(Ordering::Relaxed),
            1,
            "when the path is up the ask of the refused session goes once"
        );
    }

    /// A `joined` frame whose proof is refused for a held nickname, as the verified frame and its bytes.
    fn proof_frame_of(
        session: &Identity,
        member: &Identity,
        forged: bool,
    ) -> (Verified, (Plane, Bytes)) {
        let mesh = MeshId::from("test");
        let mut proof = member.prove(&session.author_key(), "alice", mesh.as_ref(), 1);
        if forged {
            // a run that the member did not sign: the signature of the proof no longer verifies
            proof.run += 1;
        }
        let frame = Message::new_joined_with_proof(&mesh, &nick("alice"), &proof).sign(session);
        let bytes = (
            Plane::Gossip,
            frame.serialize().expect("serialize").into_bytes(),
        );
        (frame, bytes)
    }

    /// Only a proof whose signature verifies, and that is refused for the binding, takes its frame out of
    /// the seen set: the frame is read again when the holder has left. A forged proof keeps its key, so
    /// its copies are dropped as duplicates, and no copy costs more than a hash lookup.
    #[test]
    fn only_a_valid_refused_proof_takes_its_frame_out_of_the_seen_set() {
        let (holder, member) = (Identity::generate(), Identity::generate());
        let (holder_session, member_session) = (Identity::generate(), Identity::generate());
        let (valid, valid_bytes) = proof_frame_of(&member_session, &member, false);
        let (forged, forged_bytes) = proof_frame_of(&member_session, &member, true);

        let after_valid = reader_with(
            fresh_state(),
            vec![joined_of(&holder_session, &holder, "alice", 1), valid_bytes],
        );
        let after_forged = reader_with(
            fresh_state(),
            vec![
                joined_of(&holder_session, &holder, "alice", 1),
                forged_bytes,
            ],
        );

        assert!(
            !after_valid.seen.contains(&valid.dedup_key()),
            "a valid proof that is refused for the binding is read again later"
        );
        assert!(
            after_forged.seen.contains(&forged.dedup_key()),
            "a forged proof keeps its key: its copies are dropped as duplicates"
        );
    }

    /// A restart of the member that holds the name is no intrusion: its new session replaces the old
    /// one, as before, and a session of another member that claims the name leaves with it.
    #[test]
    fn a_newer_run_of_the_member_that_holds_the_name_replaces_its_old_session_and_not_more() {
        let (alice, intruder_session) = (Identity::generate(), Identity::generate());
        let (old, new) = (Identity::generate(), Identity::generate());
        let mesh = MeshId::from("test");
        let mut initial = fresh_state();
        initial.peers.insert(old.author_key());
        initial.surfaced.insert(old.author_key());
        initial.names.insert(old.author_key(), nick("alice"));
        let first = alice.prove(&old.author_key(), "alice", mesh.as_ref(), 1);
        assert!(
            initial
                .proofs
                .accept(&old.author_key(), &nick("alice"), &mesh, first, |_| true),
            "the proof of the old session is held"
        );
        let events = SyntheticPresence::default();

        let reader = reader_with_sink(
            initial,
            vec![
                alive_of(&intruder_session, "alice"),
                joined_of(&new, &alice, "alice", 2),
            ],
            &events,
        );

        assert!(
            reader.peers.contains(&new.author_key()),
            "the new session of the member is a peer"
        );
        assert!(
            !reader.peers.contains(&old.author_key()),
            "its old session is replaced, as before"
        );
        assert!(
            !reader.peers.contains(&intruder_session.author_key()),
            "a session of another member under the bound name is not a peer"
        );
        assert_eq!(
            *events.0.lock().expect("the count lock is not poisoned"),
            1,
            "the old session ended as replaced, which writes its left line (the eviction writes none)"
        );
    }

    /// A node that holds nothing from others adopts at once the epoch that a received frame
    /// starts, and keeps the switch for the sweep to write its entry again.
    #[test]
    fn a_node_that_holds_nothing_from_others_adopts_the_epoch_of_a_received_frame() {
        use crate::doc::{MeshDoc, SelfWriteGate};

        let gate = SelfWriteGate::new("peers".to_owned(), "card");
        let sender_identity = Identity::generate();
        let sender_nick = nick("sender");
        // A document that went through 1 reset: its first write is a root of epoch 1.
        let mut writer = MeshDoc::new_gated(gate.clone()).epoch_cap(0);
        assert!(
            writer.tick_epoch(&sender_identity.author_key()).is_some(),
            "the reset"
        );
        let seed = *sender_identity.public().as_bytes();
        let slot = sender_identity.author_key().to_string();
        let merge = json!({"peers": {(slot.clone()): {"card": "from epoch 1"}}});
        let change = writer
            .build_change(&merge, &seed)
            .expect("a JSON object merges")
            .expect("a non-empty merge yields a change");
        let (body, _plain) = writer
            .compose_wire_body(&change, None)
            .expect("compose the wire body");
        let root =
            Message::new_channel_event(&MeshId::from("test"), &sender_nick, body, Channel::Meta)
                .sign(&sender_identity);
        let bytes = root.serialize().expect("serialize").into_bytes();

        let mut initial = fresh_state();
        initial.meta_doc = MeshDoc::new_gated(gate);
        let reader = reader_with(initial, vec![(Plane::Gossip, bytes)]);

        let doc = reader.doc(Channel::Meta);
        assert_eq!(doc.epoch(), 1, "the reader adopted the epoch");
        assert_eq!(
            doc.to_json(),
            json!({"peers": {(slot): {"card": "from epoch 1"}}}),
            "the document holds the root frame of the new epoch"
        );
        assert!(
            reader.epoch_write.switch.is_some(),
            "the sweep writes the entry again"
        );
    }

    #[test]
    fn a_frame_delivered_3_times_counts_1_first_sighting_and_2_repeats() {
        let writer = fresh_state();
        let frame = state_frame(&writer, change_body(&writer));
        let reader = reader_after(&[&frame, &frame, &frame]);

        assert_eq!(
            reader.idle.fresh, 1,
            "the first delivery is a first sighting"
        );
        assert_eq!(reader.idle.duplicates, 2, "the 2 repeats are duplicates");
    }

    /// The census reads each received frame by kind: its wire bytes, and whether it was new or a
    /// repeat. The expected numbers are 1 frame of `wire` bytes new, and 2 of the same repeated.
    #[test]
    fn the_received_bytes_are_counted_by_kind_and_by_what_became_of_the_frame() {
        let writer = fresh_state();
        let body = change_body(&writer);
        // The body is a JSON string in the frame: its text, and 1 more byte for the backslash of
        // each of its quotes. Counted from the text, not with the reader that is under test.
        let quotes = body.as_str().matches('"').count();
        let body_on_the_wire = (body.as_str().len() + quotes) as u64;
        let frame = state_frame(&writer, body);
        let reader = reader_after(&[&frame, &frame, &frame]);
        let one = wire(&frame);

        let received = &reader.idle.wire_in;
        assert_eq!(received.frames, 3, "every frame that reached ingest");
        assert_eq!(received.wire, 3 * one, "the wire bytes are 3 frames");
        assert_eq!(
            by_class(&received.fresh),
            format!("state:{one}"),
            "the first sighting is counted once"
        );
        assert_eq!(
            by_class(&received.dup),
            format!("state:{}", 2 * one),
            "the 2 repeats are counted as repeats"
        );
        assert_eq!(
            received.body,
            3 * body_on_the_wire,
            "the body of each of the 3 frames, without the envelope"
        );
    }

    /// One first sighting of `frame`, then repeats that give each arrival its own count: 2 on
    /// gossip, 1 on gossip with a resend nonce, 1 on unicast, 2 on unicast with a resend nonce. A
    /// swap of two planes or of two names then moves bytes between cells of unequal value.
    fn arrivals_of(frame: &Verified) -> Vec<(Plane, Bytes)> {
        let plain = || frame.serialize().expect("serialize").into_bytes();
        let resent = |nonce: u64| {
            let wire = frame.serialize().expect("serialize");
            wire.copy_with_resend_nonce(nonce).into_bytes()
        };
        vec![
            (Plane::Gossip, plain()),
            (Plane::Gossip, plain()),
            (Plane::Gossip, plain()),
            (Plane::Gossip, resent(1)),
            (Plane::Unicast, plain()),
            (Plane::Unicast, resent(2)),
            (Plane::Unicast, resent(3)),
        ]
    }

    /// A repeat is counted by its kind and by how it arrived: on which plane, and with a resend
    /// nonce or without. Each of 2 kinds has one first sighting, then 2 repeats on gossip, 1 on
    /// gossip with a nonce, 1 on unicast, and 2 on unicast with a nonce, so no 2 cells are equal.
    #[test]
    fn a_repeat_is_counted_by_kind_and_by_the_plane_and_the_resend_it_came_on() {
        let writer = fresh_state();
        let body = change_body(&writer);
        let mesh = MeshId::from("test");
        let state = state_frame(&writer, body.clone());
        let meta = Message::new_channel_event(&mesh, &nick("writer"), body, Channel::Meta)
            .sign(&writer.identity);
        let mut arrivals: Vec<(Plane, Bytes)> = Vec::new();
        for frame in [&state, &meta] {
            arrivals.extend(arrivals_of(frame));
        }
        let reader = reader_after_on(arrivals);

        let (one_state, one_meta) = (wire(&state), wire(&meta));
        // The resend trailer is on the wire, so a resend counts its bytes.
        let resent = state
            .serialize()
            .expect("serialize")
            .copy_with_resend_nonce(1);
        let trailer: u64 = resent.len() as u64 - one_state;
        let expected = [
            format!("gossip.state:{}", 2 * one_state),
            format!("gossip.meta:{}", 2 * one_meta),
            format!("gossip_resend.state:{}", one_state + trailer),
            format!("gossip_resend.meta:{}", one_meta + trailer),
            format!("unicast.state:{one_state}"),
            format!("unicast.meta:{one_meta}"),
            format!("unicast_resend.state:{}", 2 * (one_state + trailer)),
            format!("unicast_resend.meta:{}", 2 * (one_meta + trailer)),
        ]
        .join(",");
        assert_eq!(
            by_arrival(&reader.idle.wire_in.dup_by_arrival),
            expected,
            "each repeat is in the cell of its arrival and kind"
        );
    }

    /// A frame can be new by id and carry a change that the document applied already: the same
    /// signed change in another frame. The census counts its bytes as content that came back.
    #[test]
    fn a_new_frame_with_a_change_the_document_holds_counts_as_content_that_came_back() {
        let writer = fresh_state();
        let body = change_body(&writer);
        let (first, again) = (
            state_frame(&writer, body.clone()),
            state_frame(&writer, body),
        );
        assert_ne!(first.dedup_key(), again.dedup_key(), "two frames, two ids");

        let reader = reader_after(&[&first, &again]);

        let received = &reader.idle.wire_in;
        assert_eq!(
            by_class(&received.fresh),
            format!("state:{}", wire(&first) + wire(&again)),
            "both frames are new by id"
        );
        assert_eq!(by_class(&received.dup), "-", "the dedup caught nothing");
        assert_eq!(
            by_class(&received.cdup),
            format!("state:{}", wire(&again)),
            "the second carries a change that was applied"
        );
    }

    /// A frame whose body is no change is ignored by the document, and the census counts it.
    #[test]
    fn a_state_frame_that_the_document_ignores_is_counted_as_rejected() {
        let writer = fresh_state();
        let junk = state_frame(&writer, "not a change".into());
        let real = state_frame(&writer, change_body(&writer));

        let reader = reader_after(&[&junk, &real]);

        assert_eq!(
            reader.idle.state_rejected, 1,
            "only the junk frame is refused"
        );
        assert_eq!(
            reader.doc(Channel::State).to_json(),
            json!({ "key": 1 }),
            "the real change is applied"
        );
    }
}
