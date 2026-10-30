//! Gossip **inbound plane**: the gossip-event pump (`Received` /
//! `NeighborUp` / `NeighborDown` / `Lagged` / stream end), neighbor
//! up/down bookkeeping, the per-message router (parse → self-echo drop →
//! rate-check → lifecycle observe → dispatch by kind → message-log), and
//! `PeerInfo` linking. Outbound/send lives in [`super::broadcast`]; this
//! layer never touches the peer roster directly — it calls into
//! `lifecycle::observe` and dispatches by kind.

use std::ops::ControlFlow;

use bytes::Bytes;
use iroh_gossip::api::{ApiError, Event};

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::{DirectState, EventLoopState, RivalFlag};
use crate::gossip::event::NodeEvent;
use crate::lifecycle::membership_update::MembershipUpdate;
use crate::protocol::message::{Authored, MessageBody, Proof, Verified, WireFrame};
use crate::protocol::{Channel, ContentHash, Message, MessageKind, Nickname, PresenceSubtype};
use crate::util::clock::Instant;
use crate::{lifecycle, lookup};
// The timer-driver clock the ping round's deadlines are kept in — distinct from
// `clock::Instant` off wasm32. See `daemon::state`.
use n0_future::time::Instant as TokioInstant;

use super::antientropy;
use super::app::{AppClass, InboundApp, NodeApp};
use super::merge_ctx::{announce_arrival, broadcast_peer_info};
use crate::net;

#[cfg(feature = "multihop")]
use crate::daemon::event_loop;
use crate::doc::wire;
use crate::logging::messages;
use crate::protocol::{message, peer_addr_error, seal_error};
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
    state.meshed = true;
    state.degraded = false;
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
/// `state.gossip_open` to `false`.
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
            if state.announced {
                if state.neighbor_up_refloods_peerinfo(now) {
                    broadcast_peer_info(state, context).await;
                    state.last_sent_at = now;
                } else {
                    state.defer_peerinfo();
                    tracing::debug!(target: "habilis_network::gossip", endpoint_id = %node_id, "held back the PeerInfo re-flood (window)");
                }
            } else {
                announce_arrival(state, context).await;
                state.announced = true;
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
                state.rendezvous_session_stale = false;
                state.rendezvous_offer_fallback = false;
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
                if state.meshed && !state.pending_outbound.is_empty() {
                    flush_pending(state, context, "link up").await;
                }
                // First link to a *real* peer: now (and only now) can
                // user content actually be delivered. Flush anything
                // buffered while we were unmeshed, in order.
                if !state.meshed {
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
                is_rendezvous && !state.rendezvous_released,
                state.linked_endpoints.len(),
                !state.rendezvous_linked && state.rendezvous_wanted(),
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
            state.gossip_open = false;
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
/// A `NeighborDown` that the beacon's own HyParView caused (it drops a random
/// member when its view is full) reads as a loss here and arms a reclaim on a
/// node with links enough. That costs one probe, and is left as it is.
fn rendezvous_neighbor_down(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    node_id: iroh::EndpointId,
) {
    state.rendezvous_linked = false;
    // The holder is gone, so the identity is up for arbitration
    // again and any earlier reading of it is spent.
    state.forget_rendezvous_verdict();
    if state.rendezvous_released {
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
/// The narrow gate this replaces existed to keep a plain HyParView shuffle (a
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

/// Validate + dispatch one inbound wire message, regardless of transport. Both
/// the gossip event pump (`handle_gossip_event`) and the unicast inbound arm
/// (`daemon::event_loop`) funnel here, so signature-verify, the mesh gate, and
/// `mark_seen` dedup are identical on both planes — a message delivered over
/// both surfaces exactly once. The frame is a [`Verified`] from the first check on: a directed frame
/// sealed to us is decrypted on a plain copy before surfacing (see `gate_and_decrypt`), and the log
/// keeps the verified ciphertext.
pub(crate) async fn ingest(
    frame: Bytes,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    let Ok((message, _resend_nonce)) = Message::parse_wire(&frame) else {
        context
            .sink
            .emit(NodeEvent::Error("Failed to parse message".to_owned()));
        tracing::warn!(target: "habilis_network::gossip", "failed to parse inbound gossip message");
        return;
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
        return;
    }
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
    let observed = lifecycle::observe(&verified, state, context);
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

    // Directed frames are sealed to their addressee. A **relay** forwards and
    // retains the opaque frame but never validates or surfaces its content (it
    // can't read it, and `maybe_push_inbound`/dispatch below are already gated to
    // the addressee). The **addressee** decrypts the body in place, then the
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
            handle_peer_info(message, state, context).await;
            return ControlFlow::Break(());
        }
        MessageKind::Digest => {
            antientropy::handle_digest(message, state, context.author);
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
            if to == context.author
                && state.peers.contains(message.author.as_str())
                && let Some(round) = state.ping_round.as_mut()
            {
                let known = round.record_pong(message.author.clone(), probe, TokioInstant::now());
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
        _ => {}
    }
    ControlFlow::Continue(())
}

/// Fold a received multihop link-state advertisement into the routing table. The
/// author's own measured links + underlay address (`body` = a serialized
/// `LinkVector`) supersede the last vector we held for that origin. Dropped
/// silently when the multihop transport is off or the body is malformed —
/// plumbing like the digests, never logged or surfaced. Returns whether the topology changed.
fn handle_link_state(message: &Message, state: &mut EventLoopState) -> bool {
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
        match serde_json::from_str::<habilis_network_iroh_multihop_transport::LinkVector>(
            message.body.as_str(),
        ) {
            Ok(vector) => {
                // A signature proves who made the vector, not that the origin is
                // a member: anyone holding the mesh id can mint keys. So the
                // origin must be the endpoint the roster binds to the message's
                // author, the same binding that routes a directed message. A
                // peer whose address we have not learned yet is waited for: its
                // next vector, one interval on, finds the binding.
                let bound = state
                    .peer_endpoints
                    .get(&message.author)
                    .map(|address| address.id);
                // The `PeerInfo` of the author can be a few milliseconds behind its first
                // vector: the vector waits for the binding, and is fed when it is written.
                if bound.is_none() {
                    let kept = state
                        .parked_link_states
                        .park(message.author.clone(), vector);
                    tracing::debug!(target: "habilis_network::gossip",
                        author = %message.author,
                        kept,
                        "parked multihop link-state: no endpoint is bound to its author yet"
                    );
                    return false;
                }
                if bound != Some(vector.origin().get()) {
                    tracing::debug!(target: "habilis_network::gossip",
                        author = %message.author,
                        "dropping multihop link-state: its origin is not the endpoint bound to its author"
                    );
                    return false;
                }
                let updated = handle.feed_topology(vector);
                // A vector that waited for this author is older than the one just fed.
                state.parked_link_states.take(&message.author);
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
async fn auto_pong(message: &Message, state: &EventLoopState, context: &HandlerCtx<'_>) {
    let pong = Message::new_pong(
        context.mesh,
        context.author,
        message.author.clone(),
        &message.id,
    )
    .sign(context.identity);
    messages::log_out(&pong);
    let author_endpoint = state.peer_endpoints.get(message.author.as_str());
    let warm_endpoint = author_endpoint
        .map(|address| address.id)
        .filter(|eid| Some(*eid) != state.rendezvous_id);
    match (warm_endpoint, pong.serialize()) {
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
    // single-frame path drops non-addressee directed frames the same way.
    if !addressed_to_us(message, context.author) {
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
    if message::shard_fits_log(message) {
        retain_and_index(
            message.clone(),
            RetainMeta {
                canonical,
                class: shard_class.as_ref(),
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
    let RetainMeta { canonical, class } = meta;
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
    push_to_log(state, message);
}

/// Push a retained message into the anti-entropy log, keeping the DAG + fork
/// indexes bounded with the log window as the push evicts.
pub(super) fn push_to_log(state: &mut EventLoopState, message: Verified) {
    if let Some(evicted) = state.message_log.push(message) {
        let evicted_hash = evicted.content_hash();
        state.forget_hash(&evicted_hash);
        if let Some(seq) = evicted.seq {
            state.forget_msg_seq(&evicted.key(), seq, &evicted_hash);
        }
    }
}

/// Retain a message **this node just broadcast** in its own anti-entropy log.
///
/// gossip never echoes a node's own publications back to it, so a message we
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
pub(crate) fn retain_own_broadcast(state: &mut EventLoopState, message: &Verified) {
    if !is_loggable(&message.kind) {
        return;
    }
    // Ours by construction, so it can never arrive again — but mark it seen so
    // a peer still running the old resend behaviour is deduped at the gate
    // rather than double-pushed here.
    state.mark_seen(message);
    push_to_log(state, message.clone());
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
    push_to_log(state, message.clone());
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

fn dispatch_channel(
    event: ChannelEvent<'_>,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    let ChannelEvent {
        channel, message, ..
    } = event;
    let changes = state.doc(channel).change_count();
    ingest_channel_event(event, state.doc_mut(channel), context);
    if state.doc(channel).change_count() > changes {
        state.fast_rounds.note_change(channel, Instant::now());
    }
    for key in state.doc_mut(channel).take_dropped() {
        state.seen.remove(&key);
    }
    if channel == Channel::Meta {
        // Post-apply hook: let the app adopt the author's endpoint hint from the
        // freshly-synced meta doc (the borrow above released `state`).
        app.on_meta_applied(&message.author, state, context);
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
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Ingested is a foreign non_exhaustive enum: the compiler needs its wildcard arm"
)]
fn ingest_channel_event(event: ChannelEvent<'_>, doc: &mut doc::MeshDoc, context: &HandlerCtx<'_>) {
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
    match doc.ingest(message) {
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
        }
        _ => {}
    }
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
        if !addressed_to_us(frame, context.author) {
            // Relay: an opaque directed frame — forwarded + retained, never
            // validated or surfaced (the dispatch below is gated to the
            // addressee), so it needs no classification here.
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

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "foreign non_exhaustive enum: the compiler needs a wildcard arm; the named variants are listed before it"
)]
fn addressed_to_us(message: &Message, us: &Nickname) -> bool {
    match &message.kind {
        MessageKind::App { to: Some(to), .. } => to == us,
        // Broadcast app frames (chat) and infra kinds are delivered to everyone.
        _ => true,
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
        || !addressed_to_us(message, context.author)
        || matches!(
            message.kind,
            MessageKind::Digest
                | MessageKind::StateDigest
                | MessageKind::MetaDigest
                | MessageKind::State
                | MessageKind::Meta
                | MessageKind::Ping
                | MessageKind::Pong { .. }
        )
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

async fn handle_peer_info(
    message: &Verified,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(message.body.as_str()) else {
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
    let changed = state.peer_endpoints.get(&message.author) != Some(&peer_addr);
    state.bind_peer_endpoint(message.author.clone(), peer_addr.clone());
    // The rendezvous is overlay plumbing, not a dialable member peer:
    // the binding above is recorded, but skip the known-endpoints/re-bridge
    // dial path for it.
    if peer_id == context.rendezvous_id {
        return;
    }
    // The only binding a digest's answer may follow: this signer proved it
    // owns `peer_id`. A `PeerInfo` arrives many times, so a known pair is not
    // checked again.
    let signer = message.key();
    if let Some(proof) = parsed["proof"].as_str()
        && state.proven_endpoints.get(&signer) != Some(peer_id)
        && proven_endpoints::verifies(peer_id, context.mesh, &signer, proof)
    {
        state
            .proven_endpoints
            .insert(signer, peer_id, &state.linked_endpoints);
    }
    // A holder of the rendezvous says so in its `PeerInfo`; only a sender that proved its
    // endpoint is believed.
    let proven = state.proven_endpoints.get(&signer) == Some(peer_id);
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
    // A buffered directed frame addressed to this author may just have become
    // deliverable — its endpoint binding and dial address are now registered.
    // Only while meshed: the pre-mesh backlog waits for the meshed edge.
    if state.meshed && !state.pending_outbound.is_empty() {
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
        < peer_info_graft_below(context.max_peers, state.peer_endpoints.len() + 1);
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
            // this infra predicate; an App kind never reaches here.
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
    use crate::protocol::message::Verified;
    use crate::protocol::{DedupKey, MeshId, Message, Nickname};

    use crate::gossip::app;
    use crate::protocol;
    use crate::protocol::message;
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
        super::retain_own_broadcast(&mut state, &mine);
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
        super::retain_own_broadcast(&mut state, &peer_info);
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
            message::AppFrameParams::new(
                protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                to.map(Nickname::from),
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
        super::retain_own_broadcast(&mut us, &ours);
        let mut them = testing::fresh_state();
        let theirs = joined(&them, "them");
        super::retain_own_broadcast(&mut them, &theirs);
        // Each side ingests the other's presence, as gossip delivers it.
        super::push_to_log(&mut us, theirs);
        super::push_to_log(&mut them, ours);

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
            requester: &Nickname::from("us"),
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
    use crate::protocol::message::{Authored, Verified};
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
            for frame in frames.iter().rev() {
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
    use crate::transport::UdpTransport;
    use iroh::endpoint::presets;
    use iroh_gossip::api::Event;
    use iroh_gossip::net::Gossip;

    use super::{handle_gossip_event, ingest};
    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::state::EventLoopState;
    use crate::gossip::app::{AppClass, InboundApp, NodeApp};
    use crate::gossip::event::SilentSink;
    use crate::protocol::identity::Identity;
    use crate::protocol::message::{Authored, MessageBody, Verified};
    use crate::protocol::{Channel, MeshId, Message, Nickname};
    use crate::testing::{endpoint_id, fresh_state, nick};
    use crate::transport::MeshSender;

    use crate::daemon::state::DirectState;
    #[cfg(feature = "multihop")]
    use crate::gossip;
    use crate::gossip::split;
    use crate::lifecycle::heartbeat;
    use crate::protocol::message;
    use crate::transport::{PayloadPath, webrtc};
    use crate::util::{clock, tuning};
    use crate::{lookup, protocol, transport};
    use iroh_gossip::proto;
    use n0_future::task;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, atomic};
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
        our_pubkey: protocol::AuthorKey,
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
                state.meshed = true;
                state.unicast_pool = transport::UnicastPool::new(node.endpoint.clone(), false);
                state.direct.insert(bob, DirectState::Direct);
                state.peer_endpoints.insert(nick("bob"), bob_addr);
                let (failed_tx, mut failed_rx) = mpsc::unbounded_channel();
                state.flush_failed = failed_tx;
                let frame = Message::new_pong(
                    &node.mesh,
                    &node.author,
                    nick("bob"),
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
            assert!(state.meshed, "the gap does not clear meshed");
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
                message::AppFrameParams::new(
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
                state.peer_endpoints.insert(nick("bob"), bob.addr());
                feed(Event::NeighborUp(bob.id()), &mut state, &context).await;
                feed(Event::NeighborDown(bob.id()), &mut state, &context).await;
                assert!(state.meshed, "the gap does not clear meshed");
                let frame =
                    Message::new_pong(&node.mesh, &node.author, nick("bob"), &MessageId::random())
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
                    delivered.ok().flatten(),
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
                state.rendezvous_linked,
                "the rendezvous is marked linked after the release"
            );
            assert!(
                !state.rendezvous_released,
                "below the count: still a visitor"
            );
            for seed in 1..=3 {
                feed(Event::NeighborUp(endpoint_id(seed)), &mut state, &context).await;
            }

            assert!(
                state.rendezvous_released,
                "gossip was told to leave, so the release is marked"
            );
            assert!(
                state.rendezvous_linked,
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
            state.rendezvous_released = true;

            feed(
                Event::NeighborDown(context.rendezvous_id),
                &mut state,
                &context,
            )
            .await;

            assert!(
                !state.rendezvous_linked,
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
                future::pending::<()>().await;
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
            state.rendezvous_released = true;
            state.owe_rendezvous_return(clock::Instant::now());

            feed(
                Event::NeighborUp(context.rendezvous_id),
                &mut state,
                &context,
            )
            .await;

            assert!(
                state.rendezvous_linked,
                "the link coming back restores the rendezvous link"
            );
            assert!(
                !state.rendezvous_released,
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
            state.last_seen.insert(nick("far-side"), silent);
            state.peers.insert(nick("far-side"));
            state.surfaced.insert(nick("far-side"));
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
            use crate::protocol::message::MessageBody;
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
            let vector = Message::new_link_state(&node.mesh, &nick("alice-aa"), vector_body)
                .sign(&Identity::generate());
            assert!(
                !super::handle_link_state(&vector, &mut state),
                "no binding yet: nothing is fed"
            );
            assert!(
                ours.topology_view().edges.is_empty(),
                "a node with no peers has no topology edges"
            );

            let address =
                peer_addr_error::endpoint_addr_to_json(&EndpointAddr::new(author_key.public()));
            let address_body = MessageBody::try_new(&address.to_string()).expect("an address body");
            let peer_info = Message::new_peer_info(&node.mesh, &nick("alice-aa"), address_body)
                .sign(&Identity::generate());
            super::handle_peer_info(&peer_info, &mut state, &context).await;
            assert_eq!(
                ours.topology_view().edges.len(),
                1,
                "the PeerInfo that writes the binding feeds the vector that waited for it"
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
            super::handle_peer_info(&peer_info(&node, &first), &mut state, &context).await;
            assert!(!knows_relay().await, "no relay yet");

            let later = first.with_relay_url(relay.clone());
            super::handle_peer_info(&peer_info(&node, &later), &mut state, &context).await;

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

    /// A `PeerInfo` of the author `bob` that carries `addr`.
    fn peer_info(node: &Node, address: &iroh::EndpointAddr) -> Verified {
        use crate::protocol::message::MessageBody;
        use crate::protocol::peer_addr_error;

        let body =
            MessageBody::try_new(&peer_addr_error::endpoint_addr_to_json(address).to_string())
                .expect("an address body");
        Message::new_peer_info(&node.mesh, &nick("bob"), body).sign(&Identity::generate())
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
            use crate::protocol::message::MessageBody;
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
            use crate::protocol::message::MessageBody;
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
                digest_first.peerinfo_flooded_at.is_some(),
                "a newcomer's digest arrived first, and we never told it our address"
            );

            let mut change_first = fresh_state();
            let change =
                Message::new_channel_event(&node.mesh, &nick("late"), heads(), Channel::State)
                    .sign(&newcomer);
            ingest(wire(&change), &mut change_first, &mut app, &context).await;
            assert!(
                change_first.peerinfo_flooded_at.is_none(),
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
            state.rendezvous_linked = true;

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
            state.rendezvous_answers_jsep = false;

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
    use habilis_network_iroh_multihop_transport::{MultihopHandle, underlay_secret};
    use iroh::endpoint::presets;
    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};

    use crate::protocol::{MeshId, Message};
    use crate::testing::{fresh_state, nick};

    use crate::transport::PayloadPath;
    use crate::{gossip, lookup, protocol};
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
                .sign(&protocol::Identity::generate());
            super::retain_own_broadcast(&mut state, &message);
            assert_eq!(state.message_log.len(), 0, "nothing retains a link-state");
            handle.close().await;
        });
    }

    // A signature proves who made a vector, not that the maker is a member, and
    // the roster binding is what ties an origin to an author.
    #[test]
    fn a_link_vector_is_taken_in_only_from_the_peer_the_roster_binds_to_its_origin() {
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
            let message_from = |author: &str| {
                Message::new_link_state(&MeshId::from("test"), &nick(author), body.clone())
            };

            super::handle_link_state(&message_from("alice-aa"), &mut state);
            assert!(
                ours.topology_view().edges.is_empty(),
                "no address learned for the author yet"
            );

            state
                .peer_endpoints
                .insert(nick("mallory-mm"), EndpointAddr::new(bob.public()));
            super::handle_link_state(&message_from("mallory-mm"), &mut state);
            assert!(
                ours.topology_view().edges.is_empty(),
                "an author bound to another endpoint cannot speak for this origin"
            );

            state
                .peer_endpoints
                .insert(nick("alice-aa"), EndpointAddr::new(alice.public()));
            super::handle_link_state(&message_from("alice-aa"), &mut state);
            assert_eq!(
                ours.topology_view().edges.len(),
                1,
                "the bound peer is heard"
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
    use crate::protocol::mesh::LookupOpts;
    use crate::protocol::message::Authored;
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
            let message = Message::new_left(&mesh, &leaver).sign(&Identity::generate());
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
            assert!(!state.meshed, "the node is not meshed");

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

    use crate::testing::{LaneNode, nick};

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
                state.meshed = true;
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

                state.note_peer_endpoint(nick("bob"), address);
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
    use habilis_network_iroh_multihop_transport::{MultihopHandle, underlay_secret};
    use iroh::endpoint::presets;
    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};

    use crate::daemon::state::ParkedLinkStates;
    use crate::protocol::{MeshId, Message};
    use crate::testing::{fresh_state, nick};

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

    // The trust rule is the one of a vector that arrives after its binding: the origin must be
    // the endpoint that the roster binds to the author.
    #[test]
    fn a_parked_link_vector_whose_origin_is_not_the_bound_endpoint_is_dropped_at_the_binding() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (alice, bob) = (
                SecretKey::from_bytes(&[64; 32]),
                SecretKey::from_bytes(&[65; 32]),
            );
            let ours = handle_for(&SecretKey::from_bytes(&[63; 32])).await;
            let theirs = handle_for(&alice).await;
            let mut state = fresh_state();
            state.multihop = Some(ours.clone());

            let message = vector_message("mallory-mm", &theirs, vec![(bob.public(), 10)]);
            super::handle_link_state(&message, &mut state);
            state.bind_peer_endpoint(nick("mallory-mm"), EndpointAddr::new(bob.public()));
            assert!(
                ours.topology_view().edges.is_empty(),
                "an author bound to another endpoint cannot speak for this origin"
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

            let older = vector_message("alice-aa", &theirs, vec![(bob.public(), 10)]);
            let newer = vector_message(
                "alice-aa",
                &theirs,
                vec![(bob.public(), 10), (carol.public(), 10)],
            );
            super::handle_link_state(&older, &mut state);
            super::handle_link_state(&newer, &mut state);
            state.bind_peer_endpoint(nick("alice-aa"), EndpointAddr::new(alice.public()));
            assert_eq!(
                ours.topology_view().edges.len(),
                2,
                "the newer vector, with two links, is the one that is fed"
            );
            ours.close().await;
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
                parked.park(nick("alice-aa"), vector.clone()),
                "the first vector for alice is parked"
            );
            assert!(
                parked.park(nick("bobby-bb"), vector.clone()),
                "the first vector for bobby is parked beside alice's"
            );
            assert!(
                !parked.park(nick("carol-cc"), vector.clone()),
                "a third author is refused at the cap"
            );
            assert!(
                parked.park(nick("alice-aa"), vector.clone()),
                "an author that waits is replaced at the cap"
            );
            assert!(
                parked.take(&nick("alice-aa")).is_some(),
                "alice's vector is taken from the park"
            );
            assert!(parked.take(&nick("alice-aa")).is_none(), "taken once");
            assert!(
                parked.park(nick("carol-cc"), vector),
                "a taken vector frees its place"
            );
            theirs.close().await;
        });
    }
}
