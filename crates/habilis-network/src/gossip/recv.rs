//! Gossip **inbound plane**: the gossip-event pump (`Received` /
//! `NeighborUp` / `NeighborDown` / `Lagged` / stream end), neighbor
//! up/down bookkeeping, the per-message router (parse → self-echo drop →
//! rate-check → lifecycle observe → dispatch by kind), and
//! `PeerInfo` linking. Outbound/send lives in `super::broadcast`; this
//! layer never touches the peer roster directly — it calls into
//! `lifecycle::observe` and dispatches by kind.

use crate::daemon::state::{FrameShape, RendezvousFlag, Standing};
use std::ops::ControlFlow;

use bytes::Bytes;
use iroh_gossip::api::{ApiError, Event};

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::{ChannelDocs, DirectState, EventLoopState, RivalFlag};
use crate::gossip::event::NodeEvent;
use crate::lifecycle::membership_update::{self, MembershipUpdate};
use crate::protocol::messages::{Authored, MessageBody, MessageError, Proof, Verified, WireFrame};
use crate::protocol::{
    AuthorKey, Channel, MeshId, Message, MessageKind, Nickname, PresenceSubtype,
};
use crate::util::clock::Instant;
use crate::{lifecycle, lookup};
use habilis_network_doc::SliceIngest;
// The timer-driver clock the ping round's deadlines are kept in — distinct from
// `clock::Instant` off wasm32. See `daemon::state`.
use n0_future::time::Instant as TokioInstant;

use super::app::{AppClass, InboundApp, NodeApp};
use super::merge_ctx::{announce_arrival, broadcast_peer_info, peer_info_seal_key};
use super::{backfill, digest_round};
use crate::net;
use habilis_network_protocol::digest::{DigestPage, DigestRoot};

#[cfg(feature = "multihop")]
use crate::daemon::event_loop;
use crate::doc::wire;
use crate::logging::messages;
use crate::protocol::{peer_addr_error, seal_error};
#[cfg(feature = "multihop")]
use crate::transport::underlay_webrtc;
use crate::transport::{probe, proven_endpoints, webrtc};

use crate::transport;
use crate::transport::Delivered;
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
                lifecycle::retry_deferred_asks(
                    state,
                    context,
                    Some(lifecycle::PathSign::LinkUp(node_id)),
                )
                .await;
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
                // A broadcast that failed to send across a gap in the links waits for the next
                // link: `meshed` stays set through the gap, so the first-link edge below does not
                // come again, and a `PeerInfo` may not either.
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
/// *not* re-push them, and repeats of them are likewise
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
/// arrives after this drain and before the drop is lost; no resend repairs it yet.
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

/// Drain `pending_outbound` onto the wire, in order. The buffer holds broadcast frames only. A
/// broadcast fails to send only when the gossip sender refuses it, and then the frame is
/// re-buffered for the next flush. These edges run a flush:
/// - the first real-peer `NeighborUp`;
/// - a `NeighborUp` on a meshed node (`link up`);
/// - the first inbound message after a fault (`inbound traffic resumed`);
/// - the silence sweep (`silence sweep`, in `daemon::event_loop`).
///
/// A `PeerInfo` arrival, a departure, and a direct path do not flush: none of them can change
/// whether the gossip sender accepts a broadcast.
pub(crate) async fn flush_pending(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    edge: &'static str,
) {
    let mut delivered = 0usize;
    let mut requeued = 0usize;
    for (message, bytes) in state.pending_outbound.take() {
        // Each buffered frame is a broadcast: it goes through the send decision, which sends it on
        // the gossip flood.
        match transport::deliver(&message, bytes.clone(), state, context.sender).await {
            Ok(Delivered::Done) => delivered += 1,
            // Only a directed frame dials, and a directed frame is never buffered.
            Ok(Delivered::Pending(_)) => {
                debug_assert!(false, "a buffered broadcast frame dialed");
                delivered += 1;
            }
            Err(error) => {
                if requeue(state, message, bytes) {
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

/// Put a frame that failed to deliver back in `pending_outbound`. Returns whether the frame was kept.
fn requeue(state: &mut EventLoopState, message: Verified, bytes: WireFrame) -> bool {
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
    ingest_from(frame, state, app, context).await;
}

/// Whether `verified` answers a slice pull of this node. It is a State or Meta frame that came by unicast
/// from the holder that the pull named, for the author that it named. The pull is spent by the answer.
fn take_pulled_answer(verified: &Verified, state: &mut EventLoopState, now: Instant) -> bool {
    let Some(holder) = state.unicast_arrival else {
        return false;
    };
    let channel = if matches!(&verified.kind, MessageKind::State) {
        Channel::State
    } else if matches!(&verified.kind, MessageKind::Meta) {
        Channel::Meta
    } else {
        return false;
    };
    state
        .outstanding_pulls
        .take(holder, channel, verified.key(), now)
}

/// [`ingest`] for a frame that came on a unicast connection: the census counts a repeat by it.
/// The test door of the loss tests: a State or Meta frame of the author of `drop_slices_from`, and a Left of the
/// author of `drop_left_from`, are dropped after the dedup gate.
#[cfg(feature = "iroh-test-utils")]
fn test_hook_drops(state: &EventLoopState, verified: &Verified) -> bool {
    let slice = state.drop_slices_from == Some(verified.key())
        && matches!(verified.kind, MessageKind::State | MessageKind::Meta);
    let left = state.drop_left_from == Some(verified.key())
        && matches!(
            verified.kind,
            MessageKind::Presence {
                subtype: PresenceSubtype::Left,
            }
        );
    if slice || left {
        tracing::debug!(target: "habilis_network::gossip", "test hook: dropped a frame after the dedup gate");
    }
    slice || left
}

pub(crate) async fn ingest_from(
    frame: Bytes,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    let shape = FrameShape::of(&frame);
    state.idle.wire_in.note_received(&shape);
    let message = match Message::parse(&frame) {
        Ok(parsed) => parsed,
        Err(error) => {
            report_unparsed(&error, state, context);
            return;
        }
    };
    // Authenticity gate, **before** the self-echo drop, dedup, and every other step: every inbound
    // message must carry a valid signature over its canonical bytes. Verifying before `mark_seen`
    // stops a forged/unsigned message from poisoning the dedup window with a replayed id and
    // suppressing the genuine signed copy. Relayed copies keep their original
    // author's signature, so they verify here too.
    let verified = match message.verify() {
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
    // here. Only authenticated messages reach this gate. A shard stays out of the set: the
    // reassembly store dedups its own slots, and a reaped group must complete when a shard is served again.
    // A slice that answers a pull skips this gate, because the store is idempotent and takes it once.
    let pulled = take_pulled_answer(&verified, state, Instant::now());
    if verified.shard.is_none() && !pulled && state.mark_seen(&verified) {
        state.idle.duplicates += 1;
        restore_lost_proof(&verified, state, app, context).await;
        return;
    }
    #[cfg(feature = "iroh-test-utils")]
    if test_hook_drops(state, &verified) {
        return;
    }
    // A shard of a group already surfaced is a repeat, and it is not a sighting of its author. A repeat
    // of a partial shard still counts as a sighting and reaches the lifecycle. That is accepted, because
    // a partial group lives at most one reassembly TTL.
    if verified.shard.as_ref().is_some_and(|shard| {
        state
            .receive_memory
            .reassembled_groups
            .contains(&(verified.key(), shard.group.clone()))
    }) {
        return;
    }
    state.idle.fresh += 1;
    state.idle.wire_in.note_fresh(&shape);
    // Identity is the signing key, not the nickname (p2panda-style): the
    // signature above authenticates the *key*; the `author` nickname is a
    // non-unique display label and is deliberately **not** pinned/claimed,
    // so a nickname is never "burned" by a restart on a long-lived mesh.
    // Identities are distinguished by their key fingerprint, not the name.

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

    match &view.kind {
        // The app-payload seam: dispatch RPC legs / chat / task frames.
        MessageKind::App { .. } => {
            app.on_app_frame(
                InboundApp {
                    message: &view,
                    surfaceable,
                },
                state,
                context,
            )
            .await;
        }
        // Everything the engine owns itself. Spelled out rather than `_` so
        // a new kind has to be routed deliberately.
        MessageKind::Presence { .. }
        | MessageKind::PeerInfo
        | MessageKind::Ping
        | MessageKind::Pong { .. }
        | MessageKind::ProofRequest { .. }
        | MessageKind::State
        | MessageKind::Meta
        | MessageKind::LinkState
        | MessageKind::SlicePull { .. }
        | MessageKind::SlicePageRequest { .. }
        | MessageKind::SliceRoot { .. }
        | MessageKind::SlicePage { .. } => {
            let _ = dispatch_infra(
                &verified,
                surfaceable,
                &observed.update,
                state,
                app,
                context,
                !pulled,
            )
            .await;
        }
        _ => {}
    }
}

/// The peer that asked for a slice: the endpoint of its connection, which the answer goes to, and the
/// author key, which the answer names. The budget counts the endpoint, because TLS proves it.
#[derive(Clone, Copy)]
struct Asker {
    endpoint: iroh::EndpointId,
    key: AuthorKey,
}

/// A holder's root is for this node when it names this node: the roots that differ are noted for the round.
fn note_digest_root(
    message: &Verified,
    to: &AuthorKey,
    root_state: &DigestRoot,
    root_meta: &DigestRoot,
    state: &mut EventLoopState,
) {
    let Some(endpoint) = state.unicast_arrival else {
        return;
    };
    if *to != state.identity.author_key() {
        return;
    }
    let roots = [(Channel::State, root_state), (Channel::Meta, root_meta)];
    digest_round::on_root(
        state,
        message.key(),
        endpoint,
        roots,
        Instant::now(),
        digest_round::settle_jitter(),
    );
}

/// A page of a holder's digest is for this node when it names this node: the round pulls and asks on.
async fn answer_digest_page(
    message: &Verified,
    to: AuthorKey,
    channel: Channel,
    page: &DigestPage,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) {
    let Some(endpoint) = state.unicast_arrival else {
        return;
    };
    if to != state.identity.author_key() {
        return;
    }
    digest_round::on_page(
        state,
        context,
        message.key(),
        endpoint,
        channel,
        page,
        Instant::now(),
    )
    .await;
}

/// The signed frames that answer a pull of `keys` on `channel` from `asker`: the held ones, at most a page.
/// A pull over the serve budget gets none.
fn slice_pull_answer(
    asker: Asker,
    channel: Channel,
    keys: &[AuthorKey],
    state: &mut EventLoopState,
    now: Instant,
) -> Vec<Verified> {
    if !state.serve_budget.admit(asker.endpoint, channel, now) {
        tracing::debug!(target: "habilis_network::gossip", "a slice pull over the serve budget gets no answer");
        return Vec::new();
    }
    state.docs.serve(channel, keys)
}

/// The signed page that answers a page request of `channel` from `asker`. A request over the serve budget,
/// or past the last page, gets none.
fn page_request_answer(
    asker: Asker,
    channel: Channel,
    index: usize,
    mesh: &MeshId,
    own: &Nickname,
    state: &mut EventLoopState,
    now: Instant,
) -> Option<Verified> {
    let page = state.docs.page(channel, index)?;
    if !state.serve_budget.admit(asker.endpoint, channel, now) {
        tracing::debug!(target: "habilis_network::gossip", "a page request over the serve budget gets no answer");
        return None;
    }
    let kind = MessageKind::SlicePage {
        to: asker.key,
        channel,
        page,
    };
    let Ok(body) = MessageBody::try_new("{}") else {
        return None;
    };
    Some(Message::new_frame(mesh, own, kind, body).sign(&state.identity))
}

/// Sends the slice frames that answer a pull, on the connection that the pull came on.
async fn answer_slice_pull(
    message: &Verified,
    channel: Channel,
    keys: &[AuthorKey],
    state: &mut EventLoopState,
) {
    let Some(eid) = state.unicast_arrival else {
        tracing::debug!(target: "habilis_network::gossip", "a slice pull that did not come by unicast gets no answer");
        return;
    };
    let asker = Asker {
        endpoint: eid,
        key: message.key(),
    };
    for frame in slice_pull_answer(asker, channel, keys, state, Instant::now()) {
        let Ok(bytes) = frame.serialize() else {
            tracing::debug!(target: "habilis_network::gossip", "a slice frame of a pull did not serialize, so it is not sent");
            continue;
        };
        transport::send_best_effort(eid, bytes, state).await;
    }
}

/// Sends the page that answers a page request, on the connection that the request came on.
async fn answer_page_request(
    message: &Verified,
    channel: Channel,
    index: usize,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) {
    let Some(eid) = state.unicast_arrival else {
        tracing::debug!(target: "habilis_network::gossip", "a page request that did not come by unicast gets no answer");
        return;
    };
    let asker = Asker {
        endpoint: eid,
        key: message.key(),
    };
    let answer = page_request_answer(
        asker,
        channel,
        index,
        context.mesh,
        context.author,
        state,
        Instant::now(),
    );
    let Some(answer) = answer else {
        return;
    };
    let Ok(bytes) = answer.serialize() else {
        tracing::debug!(target: "habilis_network::gossip", "a page answer did not serialize, so it is not sent");
        return;
    };
    transport::send_best_effort(eid, bytes, state).await;
}

/// The engine's own message kinds: presence, peer info, ping/pong,
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
    live: bool,
) -> ControlFlow<()> {
    match &message.kind {
        MessageKind::PeerInfo => {
            // A stale frame proves no presence: it registers no endpoint and starts no dial.
            if !update.stale {
                handle_peer_info(message, state, context).await;
            }
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
                    live,
                },
                state,
                app,
                context,
            );
            return ControlFlow::Break(());
        }
        MessageKind::Meta => {
            dispatch_channel(
                ChannelEvent {
                    channel: Channel::Meta,
                    message,
                    surfaceable,
                    live,
                },
                state,
                app,
                context,
            );
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
        MessageKind::SlicePull { to, channel, keys } => {
            if *to == state.identity.author_key() {
                answer_slice_pull(message, *channel, keys, state).await;
            }
            return ControlFlow::Break(());
        }
        MessageKind::SlicePageRequest { to, channel, index } => {
            if *to == state.identity.author_key() {
                answer_page_request(message, *channel, *index, state, context).await;
            }
            return ControlFlow::Break(());
        }
        MessageKind::SliceRoot {
            to,
            state: root_state,
            meta: root_meta,
        } => {
            note_digest_root(message, to, root_state, root_meta, state);
            return ControlFlow::Break(());
        }
        MessageKind::SlicePage { to, channel, page } => {
            answer_digest_page(message, *to, *channel, page, state, context).await;
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
        report_nickname_held(context);
    }
    end_displaced_sessions(verified, state, app, context).await;
    let admitted = state.admits_session(verified, context.author);
    if admitted {
        // A pending proof (valid, inactive: its sender was not live when it came) is activated when the sender
        // is admitted and live: it binds the nickname, replaces the older runs of its member, and ends the
        // sessions of other members, before the arrival of the sender is shown. Before the report of a newer run
        // of our member too: the report reads the active proof.
        if state.proofs.has_pending(&verified.key())
            && membership_update::leaves_sender_in_roster(verified, state)
        {
            state.activate_pending_proof(verified, context.mesh);
            end_displaced_sessions(verified, state, app, context).await;
        }
        if let Some(run) = state.newer_run_of_our_member(verified, context.author) {
            let line = format!(
                "Another, newer run of this member is active (run {run}): this node is superseded: stop it"
            );
            tracing::warn!(target: "habilis_network::lifecycle", run, "a newer run of our member is active");
            context.sink.emit(NodeEvent::Error(line));
        }
        let observed = lifecycle::observe(verified, state, context);
        if observed.update.returned || observed.update.joined_new {
            promote_pending(verified.key(), Instant::now(), state, app, context);
        }
        // The check before `observe` is pure. A quiet peer whose clock stepped back returns when `observe` completes
        // its run of rising frames, and that check read the last frame of the run as stale: the peer is in the
        // roster now with its proof still pending, so it is activated here (one frame late).
        if state.proofs.has_pending(&verified.key()) && state.peers.contains(&verified.key()) {
            state.activate_pending_proof(verified, context.mesh);
            end_displaced_sessions(verified, state, app, context).await;
        }
        return Some(observed);
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
        // A claimant of OUR nickname that is chatty sends no `Alive` (`tick_alive` stays silent after any broadcast), so
        // its other frames are asked for the proof too, after the address is retained: the same ask path, retry clock
        // and budgets as for its `Alive` frame.
        if verified.author == *context.author {
            lifecycle::ask_for_proof(verified, state, context).await;
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

/// Tell the operator that another member holds our nickname: the line that the app maps to its `nickname_held` event.
fn report_nickname_held(context: &HandlerCtx<'_>) {
    let line = format!(
        "The nickname {} is held by another member with another key. The two nodes do not accept the frames of each other",
        context.author
    );
    tracing::warn!(target: "habilis_network::lifecycle", nickname = %context.author, "our nickname is held by another member");
    context.sink.emit(NodeEvent::Error(line));
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
    let mut shown_left = false;
    for intruder in state.proofs.take_evicted() {
        let goodbye = lifecycle::Goodbye::Refused(&verified.author);
        shown_left |= lifecycle::end_session(intruder, goodbye, state, app, context).await;
    }
    // One proof can end several shown intruders: the member is shown again once, after their `left` lines.
    if shown_left {
        lifecycle::show_again(verified.key(), &verified.author, state, context);
    }
    for older in state.proofs.take_replaced() {
        let goodbye = lifecycle::Goodbye::Replaced(&verified.author);
        lifecycle::end_session(older, goodbye, state, app, context).await;
    }
}

/// Whether a frame of this kind changes the roster or the routes of a peer. The gate refuses these
/// from a session that claims a nickname that another member holds. A `PeerInfo` is not one of
/// them: it only gives an address, and a session that asks for a proof needs one. The frames that
/// carry data (app, state, meta) are never refused here; they are stored and relayed, and
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
/// plumbing like presence, never surfaced. Returns whether the topology changed.
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
/// this session, sent to the asker alone. The answer goes to the endpoint the asker is known by, or
/// back on the connection of the request when that is an unlinked arrival (a dial back, to that
/// authenticated arrival only). The path is checked before the answer takes a slot of the per-minute
/// cap, so an answer that cannot go out costs no slot. No path means no answer, and the asker asks
/// again by the retry rule of the proof exchange. A send that fails after the slot was taken keeps
/// the slot and the 60 s window of the asker, so the first retry that can work is the one at 90 s:
/// the one at 30 s is refused.
async fn answer_proof_request(
    to: &AuthorKey,
    message: &Verified,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) {
    let Some(eid) = return_path(state, &message.key()) else {
        tracing::debug!(target: "habilis_network::gossip", asker = %message.author, "proof answer skipped: no path");
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
    // The connection that the request came on is authenticated by the transport: when the answer goes to that
    // endpoint, a dial back in the background is allowed, as for the ask (an asker that only dialed us has no
    // gossip link and no connection of ours). One answer for each asker and window, and the cap, stay.
    let came_on_it = state.unicast_arrival == Some(eid);
    let sent = match answer.serialize() {
        Ok(bytes) if came_on_it => transport::send_dialing_back(eid, bytes, state).await,
        Ok(bytes) => transport::send_best_effort(eid, bytes, state).await,
        Err(_) => false,
    };
    if !sent {
        tracing::debug!(target: "habilis_network::gossip", asker = %message.author, "proof answer skipped: the send failed");
    }
    // The proof exchange opens the path to the asker, so the own slices go out now, not on the tick.
    let asker = message.key();
    backfill::owe(state, asker, Instant::now());
    if backfill::send_to(state, eid, came_on_it).await {
        state.owed_backfill.remove(&asker);
    }
}

/// The endpoint that the answer to a proof request from `asker` goes to.
fn return_path(state: &EventLoopState, asker: &AuthorKey) -> Option<iroh::EndpointId> {
    // The address in the roster may be the old one of an asker that moved: it counts only when a unicast can
    // start on it, as for the arrival.
    // The rendezvous is no path to the asker (a beacon gossips as the rendezvous), and it is left out of each
    // candidate before the choice: a cached address that is the rendezvous must not hide the arrival.
    let not_rendezvous = |eid: &iroh::EndpointId| Some(*eid) != state.rendezvous_id;
    let known: Option<iroh::EndpointId> = state
        .address_of(asker)
        .map(|address| address.id)
        .filter(not_rendezvous)
        .filter(|eid| transport::can_unicast(*eid, state));
    // A request can come before the `PeerInfo` of its sender: then the connection that it arrived on is
    // the return path, if a unicast can start on it.
    let arrival: Option<iroh::EndpointId> = state
        .unicast_arrival
        .filter(not_rendezvous)
        .filter(|eid| transport::can_unicast(*eid, state));
    known.or(arrival)
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
    surfaceable: bool,
}

/// One shard of a split body: retain it (so a missing shard
/// is kept like any message) and, when its group completes, gate the
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
        surfaceable,
        ..
    } = frame;
    // A directed shard (task leg / RPC) not addressed to us is relayed at the
    // gossip layer but never retained or reassembled here — a third party must
    // not persist or reconstruct a task exchange it is not part of. The
    // single-frame path hands such a frame to the app, which decides.
    if !addressed_to_us(message, &context.our_pubkey) {
        return;
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

/// Route a received `State`/`Meta` event to its channel doc, then — for `meta` —
/// adopt the author's endpoint hint into the dial book. Selects the disjoint doc
/// field so the borrow released by [`ingest_channel_event`] frees `state` for the
/// address adoption.
#[derive(Clone, Copy)]
struct ChannelEvent<'message> {
    channel: Channel,
    message: &'message Verified,
    surfaceable: bool,
    // False for a slice that answers a pull of this node: the store takes it with no token.
    live: bool,
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
    if state.key_said_goodbye(message.key()) {
        // A key that said goodbye does not rejoin, so its frame would wait in the pending set for nothing.
        tracing::debug!(target: "habilis_network::gossip", "a slice of a key that said goodbye is dropped");
        return;
    }
    if !state.keeps_slice(&message.key()) {
        // The slice waits until its author joins or returns, so a stranger cannot fill the store.
        if let Err(error) = state.docs.hold(channel, message, Instant::now()) {
            tracing::debug!(target: "habilis_network::gossip", %error, "a slice of an author outside the roster is refused");
        }
        return;
    }
    let applied = ingest_channel_event(event, &mut state.docs, Instant::now(), context);
    if applied && channel == Channel::Meta {
        // Post-apply hook: let the app adopt the author's endpoint hint from the
        // freshly-synced meta doc (the borrow above released `state`).
        app.on_meta_applied(&message.key(), state, context);
    }
}

/// Applies the held slices of `key` on both channels, once `key` joined or returned. Each one runs
/// through [`dispatch_channel`], so it takes its token now and reaches the app as an arrival.
fn promote_pending(
    key: AuthorKey,
    now: Instant,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    for channel in [Channel::State, Channel::Meta] {
        if let Some(frame) = state.docs.take_pending(channel, &key, now) {
            // The join horizon judges a held frame by its own timestamp, as it judges an arrival.
            let surfaceable = state.is_surfaceable(frame.timestamp);
            let event = ChannelEvent {
                channel,
                message: &frame,
                surfaceable,
                live: true,
            };
            dispatch_channel(event, state, app, context);
        }
    }
}

/// A plaintext-bodied view of `message` for surfacing: when `plain` differs from
/// the wire body (a decrypted `enc` body), a clone with the body replaced; else
/// the original borrowed unchanged. The output helpers read `event.body` for the
/// `m` delta, so they must see plaintext.
fn surface_view(frame: &Verified, plain: Option<MessageBody>) -> Authored {
    match plain {
        Some(body) => frame.copy_with_body(body),
        None => frame.authored(),
    }
}

/// Ingest a durable channel event (`State`/`Meta`) into its slice store, and say whether the store took
/// it. A `StateChanged` is surfaced for `channel` only when the store took the frame and we're past the
/// join horizon (a backfilling joiner updates its slice silently). A received event is never our own
/// (`is_self = false`). Both channels share this path verbatim.
fn ingest_channel_event(
    event: ChannelEvent<'_>,
    docs: &mut ChannelDocs,
    now: Instant,
    context: &HandlerCtx<'_>,
) -> bool {
    let ChannelEvent {
        channel,
        message,
        surfaceable,
        live,
    } = event;
    let applied = matches!(
        docs.ingest(channel, message, live, now),
        SliceIngest::Applied
    );
    if applied && surfaceable {
        let surfaced = surface_view(message, docs.plain_body(channel, &message.key()));
        context.sink.emit(NodeEvent::StateChanged {
            channel,
            event: Box::new(surfaced),
            document: docs.to_json(channel),
            is_self: false,
        });
    }
    applied
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
/// separate, app-driven decision ([`super::app::NodeApp::seals`]): an app's
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
            // `App` kind without one is not pushed to the consumer.
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
    // Whether the directed body is sealed is the app's call, by the tag, through the one rule that
    // `app_frame` seals by (`NodeApp::seals`): an app's directed tags may arrive encrypted, but a
    // consumer with its own data model may send plaintext directed bytes. The frame is
    // signature-authenticated either way; a tag that does not seal means "not additionally
    // encrypted". A directed frame of another kind has no tag and no seal.
    let wire = frame.authored();
    let seals = matches!(&frame.kind, MessageKind::App { tag, .. } if app.seals(tag));
    if !seals {
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
        MessageKind::App { to: Some(to), .. }
        | MessageKind::SliceRoot { to, .. }
        | MessageKind::SlicePull { to, .. }
        | MessageKind::SlicePageRequest { to, .. }
        | MessageKind::SlicePage { to, .. } => to == us,
        // Broadcast app frames (chat) and infra kinds are delivered to everyone.
        MessageKind::App { to: None, .. }
        | MessageKind::Presence { .. }
        | MessageKind::PeerInfo
        | MessageKind::Ping
        | MessageKind::Pong { .. }
        | MessageKind::State
        | MessageKind::Meta
        | MessageKind::ProofRequest { .. }
        | MessageKind::LinkState
        | _ => true,
    }
}

fn maybe_push_inbound(
    context: &HandlerCtx<'_>,
    message: &Authored,
    surfaceable: bool,
    class: Option<&AppClass>,
) {
    // Short-circuit the cheap structural guards first: no live inbound subscriber
    // (always so for CLI/MCP, where the field is `None`), a pre-join or
    // third-party frame, or a kind of the engine's own plumbing: the shared state and its
    // digest round, the proof exchange, the link state, the address cards, and the ping rounds.
    let Some(tx) = context.external_msg_tx else {
        return;
    };
    if tx.receiver_count() == 0
        || !surfaceable
        || !addressed_to_us(message, &context.our_pubkey)
        || matches!(
            message.kind,
            MessageKind::State
                | MessageKind::Meta
                | MessageKind::Ping
                | MessageKind::Pong { .. }
                | MessageKind::PeerInfo
                | MessageKind::ProofRequest { .. }
                | MessageKind::LinkState
                | MessageKind::SliceRoot { .. }
                | MessageKind::SlicePull { .. }
                | MessageKind::SlicePageRequest { .. }
                | MessageKind::SlicePage { .. }
        )
    {
        return;
    }
    // An App frame reaches an in-process consumer only when its class says PUSH (not RPC
    // plumbing) and it is not a liveness beat — the app's per-tag policy, threaded in
    // from the caller's single classification. An infra frame (`class == None`,
    // `app_tag` also `None`) is always pushable past the structural guards above.
    let kind_tag = message.kind.app_tag();
    let app_pushable = match kind_tag {
        Some(_) => class.is_some_and(|cls| cls.pushable() && !cls.beat()),
        None => true,
    };
    if app_pushable {
        let _ = tx.send(message.clone());
    }
}

/// Our address goes out on the first frame from any new peer, not only on its
/// `joined`: a newcomer behind the rendezvous learns our address only from this
/// flood, and which frame a peer sends first depends on its version and its links.
/// The backfill of the newcomer is owed here too (see [`super::backfill`]).
/// If the newcomer has the lower endpoint id we wait for it to dial. A first
/// frame that is its `joined` floods our address in `handle_presence` instead.
async fn greet_new_peer(message: &Verified, state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    let now = Instant::now();
    backfill::owe(state, message.key(), now);
    backfill::settle(state, now).await;
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

/// A copy of a `joined` frame gives back the proof that its session lost, and nothing else. A member signs its
/// answer to a proof request once for each run, so an asker that dropped the proof of that session (the session left
/// the roster and came back, or its pending proof was dropped at a cap) gets the same frame again, and the frame is a
/// duplicate there. A session that is live gets its proof back as an active proof. Any other session (a quiet one, or
/// one that the nickname gate refused and so is not in the roster) gets it back as a PENDING proof: valid and
/// inactive, it binds nothing and replaces nothing, so a flood of old copies cannot move a binding, and it is
/// activated when the session proves presence. A session that said goodbye gets nothing. The copy is no arrival and
/// no heartbeat.
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
    if !joined || verified.joined_proof().is_none() || state.key_said_goodbye(key) {
        return;
    }
    if state.proofs.proof_of(&key).is_some() || state.proofs.has_pending(&key) {
        return;
    }
    let live = state.peers.contains(&key);
    // The first proof that shows our own nickname bound to another member is the held error: the copy that reads it
    // first raises it, as the first arrival does, or the signal (`tell_once`) is spent with no line.
    if state.note_joined_proof(verified, context.mesh, context.author, live) {
        report_nickname_held(context);
    }
    if live {
        end_displaced_sessions(verified, state, app, context).await;
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
    // The seal key is part of the body: a `PeerInfo` that names none, or a text that is not a key,
    // is not a `PeerInfo` of this wire version, and it binds nothing.
    let Some(seal) = peer_info_seal_key(&parsed) else {
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
    // The same signature binds the seal key to the author: a directed body for this key is sealed
    // to it. The key of a signer that is not known yet waits for its join.
    state.note_seal_key(hinter, seal, Instant::now());
    // The rendezvous is overlay plumbing, not a dialable member peer:
    // the binding above is recorded, but skip the known-endpoints/re-bridge
    // dial path for it.
    if peer_id == context.rendezvous_id {
        return;
    }
    // The only binding a backfill answer may follow: this signer proved it
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
mod first_contact_tests {
    use crate::daemon::state::{RendezvousFlag, Standing};
    use crate::lifecycle;
    use crate::protocol::{Shard, ShardGroup, UnixSecs};
    use crate::transport::UdpTransport;
    use iroh::endpoint::presets;
    use iroh_gossip::api::Event;
    use iroh_gossip::net::Gossip;

    use super::{
        ChannelEvent, Gated, dispatch_channel, dispatch_infra, gate_and_decrypt,
        handle_gossip_event, ingest, maybe_push_inbound, pong_for, promote_pending,
    };
    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::state::{EventLoopState, PingRound};
    use crate::gossip::app::{AppClass, AppFrameError, InboundApp, NodeApp};
    use crate::gossip::event::{NodeEvent, NodeSink, SilentSink};
    use crate::lifecycle::membership_update::MembershipUpdate;
    use crate::ops;
    use crate::protocol::identity::Identity;
    use crate::protocol::messages::{Authored, MessageBody, Verified};
    use crate::protocol::{
        AuthorKey, Channel, ContentHash, MeshId, Message, MessageKind, Nickname,
    };
    use crate::testing::{address_json_with_seal, endpoint_id, fresh_state, nick, test_key};
    use crate::transport::MeshSender;
    use bytes::Bytes;
    use habilis_network_protocol::digest::{DigestEntry, DigestPage, DigestRoot};
    use habilis_network_util::tuning::{
        DIGEST_PULL_TTL, DIGEST_PULLS_OPEN, DIGEST_SERVES_PER_WINDOW, DIGEST_SETTLE,
        DIGEST_SETTLE_JITTER,
    };

    use crate::daemon::state::DirectState;
    #[cfg(feature = "multihop")]
    use crate::gossip;
    use crate::gossip::{ingest_from, split};
    use crate::lifecycle::heartbeat;
    use crate::protocol::messages::AppFrameParams;
    use crate::transport::outbox::Resend;
    use crate::transport::proven_endpoints::ProvenEndpoints;
    use crate::transport::{PayloadPath, webrtc};
    use crate::util::{clock, consts, tuning};
    use crate::{lookup, protocol, transport};
    use iroh_gossip::proto;
    use n0_future::task;
    use n0_future::time::Instant as TokioInstant;
    use std::collections::HashSet;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex, atomic};
    use std::time::{Duration, Instant as std_Instant};
    use std::{future, net};
    use tokio::sync::{broadcast, mpsc};
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

    /// An app whose tag `sealed_tag` seals its directed body, and whose tag `plain_tag` does not.
    struct Sealing;

    #[async_trait::async_trait]
    impl NodeApp for Sealing {
        fn classify(&self, _message: &Authored) -> AppClass {
            AppClass::PUSH.union(AppClass::VALID)
        }

        fn seals(&self, tag: &protocol::AppTag) -> bool {
            tag.as_str() == "sealed_tag"
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

    /// The frame of an app frame test: tag `tag`, to `to`, with the body `text`.
    fn frame_params(tag: &str, to: Option<AuthorKey>, text: &str) -> AppFrameParams {
        AppFrameParams::new(
            protocol::AppTag::try_new(tag).expect("a valid app tag"),
            to,
            None,
            MessageBody::try_new(text).expect("a body"),
        )
    }

    /// **A directed frame of a tag that seals is sealed on the wire, and its addressee opens it.**
    ///
    /// The sender knows the seal key of the addressee from a `PeerInfo`. The signed body is the
    /// envelope, which holds no byte of the text. The receiver gate reads the same rule of the app
    /// (`NodeApp::seals`) and hands the app the plain body. A tag that does not seal goes in plain,
    /// the control that keeps the rule to the tag.
    #[test]
    fn a_directed_frame_of_a_sealing_tag_is_sealed_on_the_wire_and_its_addressee_opens_it() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let receiver = fresh_state();
            let bob = receiver.identity.author_key();
            let mut sender = fresh_state();
            sender.peers.insert(bob);
            sender.note_seal_key(bob, receiver.identity.seal_public(), clock::Instant::now());
            let context = node.context();
            let app = Sealing;

            let sealed = ops::app_frame(
                &sender,
                &context,
                &app,
                frame_params("sealed_tag", Some(bob), "the secret"),
            )
            .expect("the frame is built");
            assert!(
                !sealed.body.as_str().contains("the secret"),
                "the signed body of a sealing tag holds the text: {}",
                sealed.body.as_str()
            );

            let at_bob = HandlerCtx {
                our_pubkey: bob,
                ..node.context()
            };
            let Gated::Pass { view: opened, .. } =
                gate_and_decrypt(&sealed, &receiver, &at_bob, &app)
            else {
                panic!("the addressee dropped the sealed frame");
            };
            assert_eq!(
                opened.body.as_str(),
                "the secret",
                "the addressee does not read the plain body"
            );

            let plain = ops::app_frame(
                &sender,
                &context,
                &app,
                frame_params("plain_tag", Some(bob), "the open text"),
            )
            .expect("the frame is built");
            assert_eq!(
                plain.body.as_str(),
                "the open text",
                "a tag that does not seal sent a sealed body"
            );
            let Gated::Pass {
                view: unchanged, ..
            } = gate_and_decrypt(&plain, &receiver, &at_bob, &app)
            else {
                panic!("the addressee dropped the plain frame");
            };
            assert_eq!(
                unchanged.body.as_str(),
                "the open text",
                "a plain body changed on its way through the gate"
            );
            node.endpoint.close().await;
        });
    }

    /// A tag that seals, to a key with no known seal key, is not built: the error names the key, and
    /// a later call can succeed once the `PeerInfo` has come. A tag that does not seal needs no key.
    #[test]
    fn a_sealing_tag_to_a_key_with_no_seal_key_is_not_built() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut sender = fresh_state();
            let bob = test_key("bob");
            sender.peers.insert(bob);
            let app = Sealing;

            let refused = ops::app_frame(
                &sender,
                &context,
                &app,
                frame_params("sealed_tag", Some(bob), "text"),
            );
            assert!(
                matches!(refused, Err(AppFrameError::NoSealKey { to }) if to == bob),
                "a sealing tag with no seal key was built"
            );
            let plain = ops::app_frame(
                &sender,
                &context,
                &app,
                frame_params("plain_tag", Some(bob), "text"),
            );
            assert!(plain.is_ok(), "a tag that does not seal needs no seal key");

            sender.note_seal_key(
                bob,
                x25519_dalek::PublicKey::from([4u8; 32]),
                clock::Instant::now(),
            );
            let later = ops::app_frame(
                &sender,
                &context,
                &app,
                frame_params("sealed_tag", Some(bob), "text"),
            );
            assert!(
                later.is_ok(),
                "the frame is not built once the key is known"
            );
            node.endpoint.close().await;
        });
    }

    /// **A broadcast body on a passworded mesh is sealed by the engine, and a peer reads it.**
    ///
    /// Receivers drop any other body on such a mesh, so no app can send a plain one. The tag does
    /// not matter: the app does not seal a broadcast. On a mesh with no password the body goes as it
    /// is.
    #[test]
    fn a_broadcast_on_a_passworded_mesh_is_sealed_by_the_engine_and_a_peer_reads_it() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let key = protocol::SymmetricKey::from([5u8; 32]);
            let mut sender = fresh_state();
            sender.broadcast_key = Some(key.clone());
            let mut peer = fresh_state();
            peer.broadcast_key = Some(key);
            let app = Sealing;

            let sealed = ops::app_frame(
                &sender,
                &context,
                &app,
                frame_params("plain_tag", None, "for everyone"),
            )
            .expect("the frame is built");
            assert!(
                !sealed.body.as_str().contains("for everyone"),
                "a broadcast body on a passworded mesh went in plain: {}",
                sealed.body.as_str()
            );
            let Gated::Pass { view, .. } = gate_and_decrypt(&sealed, &peer, &context, &app) else {
                panic!("a peer dropped the sealed broadcast");
            };
            assert_eq!(
                view.body.as_str(),
                "for everyone",
                "the peer does not read the plain body"
            );

            let open = ops::app_frame(
                &fresh_state(),
                &context,
                &app,
                frame_params("plain_tag", None, "for everyone"),
            )
            .expect("the frame is built");
            assert_eq!(
                open.body.as_str(),
                "for everyone",
                "a mesh with no password sealed a broadcast"
            );
            node.endpoint.close().await;
        });
    }

    /// **A sharded broadcast on a passworded mesh is sealed whole, then cut, and a peer opens it.**
    ///
    /// The receiver joins the shards and opens the joined body once, so a shard is a cut of one
    /// ciphertext and not an envelope of its own. The test seals the whole body with
    /// `seal_broadcast_body`, cuts the sealed text in two, signs the two shards, and a peer that
    /// holds the mesh key hands its app the plain text. The control seals each cut on its own, as an
    /// app would that sealed the shards: the joined text is no envelope, the peer drops it, and the
    /// app hears nothing.
    #[test]
    fn a_sharded_broadcast_on_a_passworded_mesh_is_sealed_whole_then_cut_and_a_peer_opens_it() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let key = protocol::SymmetricKey::from([5u8; 32]);
            let mut sender = fresh_state();
            sender.broadcast_key = Some(key.clone());
            let author = Identity::generate();
            let plain = MessageBody::from("a body that is cut into two shards");
            let shard = |group: &ShardGroup, index: u32, part: &str| {
                let mut message = Message::new_app(
                    &node.mesh,
                    &nick("bob"),
                    AppFrameParams::new(
                        protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                        None,
                        None,
                        MessageBody::try_new(part).expect("a body"),
                    ),
                );
                message.shard = Some(Shard::new(group.clone(), 2).index(index));
                message.sign(&author)
            };
            let wire = |frame: &Verified| frame.serialize().expect("serialize").into_bytes();
            let cut = |text: &str| {
                let (first, second) = text.split_at(text.len() / 2);
                (first.to_owned(), second.to_owned())
            };

            // The app and the test share the texts that it records.
            let delivered = Arc::new(Mutex::new(Vec::new()));
            let mut app = Recorded(Arc::clone(&delivered));
            let mut peer = fresh_state();
            peer.broadcast_key = Some(key.clone());

            let whole = ops::seal_broadcast_body(&sender, &plain).expect("the body is sealed");
            assert!(
                !whole.as_str().contains("cut into two"),
                "the sealed body holds the text"
            );
            let group = ShardGroup::parse_uuid("550e8400-e29b-41d4-a716-446655440001")
                .expect("a valid group");
            let (first, second) = cut(whole.as_str());
            ingest(
                wire(&shard(&group, 0, &first)),
                &mut peer,
                &mut app,
                &context,
            )
            .await;
            ingest(
                wire(&shard(&group, 1, &second)),
                &mut peer,
                &mut app,
                &context,
            )
            .await;
            assert_eq!(
                *delivered.lock().expect("no poison"),
                [plain.as_str().to_owned()],
                "the peer did not open the whole sealed body that was cut"
            );

            let each = |part: &str| {
                let part = MessageBody::try_new(part).expect("a body");
                ops::seal_broadcast_body(&sender, &part).expect("the part is sealed")
            };
            let (head, tail) = cut(plain.as_str());
            let other = ShardGroup::parse_uuid("550e8400-e29b-41d4-a716-446655440002")
                .expect("a valid group");
            let mut second_peer = fresh_state();
            second_peer.broadcast_key = Some(key);
            // The app and the test share the texts that it records.
            let overheard = Arc::new(Mutex::new(Vec::new()));
            let mut second_app = Recorded(Arc::clone(&overheard));
            let sealed_head = each(&head);
            let sealed_tail = each(&tail);
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network::gossip",
                "dropping a broadcast body that failed mesh-key decryption",
            );
            ingest(
                wire(&shard(&other, 0, sealed_head.as_str())),
                &mut second_peer,
                &mut second_app,
                &context,
            )
            .await;
            ingest(
                wire(&shard(&other, 1, sealed_tail.as_str())),
                &mut second_peer,
                &mut second_app,
                &context,
            )
            .await;
            assert!(
                overheard.lock().expect("no poison").is_empty(),
                "shards that were sealed one by one reached the app"
            );
            node.endpoint.close().await;
        });
    }

    /// A meshed send to a relay-only peer whose direct path is not probed is refused at once. The
    /// refusal asks for the lane session, so that the caller's retry can find it.
    #[test]
    fn a_meshed_directed_send_to_a_held_peer_is_refused_and_asks_for_the_lane_session() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.standing.insert(Standing::Meshed);
            state.relay_transport = PayloadPath::DirectOnly;
            let (bob, eid) = (test_key("bob"), endpoint_id(7));
            state.retain_refused_endpoint(bob, iroh::EndpointAddr::new(eid));
            state.direct.insert(eid, DirectState::RelayOnly);
            state
                .path_kinds
                .insert(eid, transport::probe::PathKind::Relay);
            let frame = Message::new_pong(
                &node.mesh,
                &node.author,
                bob,
                &protocol::MessageId::random(),
            )
            .sign(&Identity::generate());

            let refused = ops::send_app(&mut state, &context, frame).await;
            let Err(error) = &refused else {
                panic!("the send to a held peer was not refused: {refused:?}");
            };
            assert!(
                matches!(error, transport::SendError::Held { .. }),
                "the refusal is not Held: {error}"
            );
            assert!(
                error.to_string().contains("a probe found only the relay")
                    && error.to_string().contains("retry"),
                "the refusal does not tell the caller to retry: {error}"
            );
            assert!(
                state.lane_session_wanted(eid, clock::Instant::now()),
                "the refused send did not ask for the lane session"
            );
            assert!(
                state.pending_outbound.is_empty(),
                "a refused directed frame was buffered"
            );
            node.endpoint.close().await;
        });
    }

    /// **A directed send right after a join is not refused for want of a mesh or a probe.**
    ///
    /// The `PeerInfo` of a peer reaches the node a few milliseconds before its first real-peer link
    /// sets `Meshed` and the first reading of `direct`. In that window the node holds the endpoint
    /// of bob, is not meshed, and has read no path. The send must start: the dial waits for a direct
    /// path, and the live path of the connection decides. The peer is a lane peer, so the send
    /// asks for its session at once. Two controls keep the rule narrow: a pair
    /// that a probe proved relay-only is still held, and a broadcast is still buffered.
    #[test]
    fn an_unmeshed_directed_send_to_an_unprobed_peer_is_started_and_not_refused() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.standing.remove(&Standing::Meshed);
            state.relay_transport = PayloadPath::DirectOnly;
            state.local_udp_transport = UdpTransport::Present;
            let (bob, eid) = (test_key("bob"), endpoint_id(7));
            let lane_address = iroh::EndpointAddr::new(eid)
                .with_relay_url("https://relay.invalid".parse().expect("relay url"));
            state.names.insert(bob, nick("bob"));
            state.bind_peer_endpoint(bob, nick("bob"), lane_address);
            let frame = || {
                Message::new_pong(
                    &node.mesh,
                    &node.author,
                    bob,
                    &protocol::MessageId::random(),
                )
                .sign(&Identity::generate())
            };

            let sent = ops::send_app(&mut state, &context, frame()).await;
            assert!(
                matches!(sent, Ok(transport::Delivered::Pending(_))),
                "the send to an unprobed peer on an unmeshed node did not start: {sent:?}"
            );
            assert!(
                state.lane_session_wanted(eid, clock::Instant::now()),
                "the send to an unprobed lane peer did not ask for its session"
            );

            state.direct.insert(eid, DirectState::RelayOnly);
            let held = ops::send_app(&mut state, &context, frame()).await;
            assert!(
                matches!(held, Err(transport::SendError::Held { .. })),
                "a pair that a probe proved relay-only was not held: {held:?}"
            );

            let broadcast = Message::new_app(
                &node.mesh,
                &node.author,
                AppFrameParams::new(
                    protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                    None,
                    None,
                    MessageBody::from("hi"),
                ),
            )
            .sign(&Identity::generate());
            let buffered = ops::send_app(&mut state, &context, broadcast).await;
            assert!(
                matches!(buffered, Ok(transport::Delivered::Done)),
                "the unmeshed broadcast was not accepted: {buffered:?}"
            );
            assert_eq!(
                state.pending_outbound.len(),
                1,
                "the unmeshed broadcast was not buffered for the meshed edge"
            );
            node.endpoint.close().await;
        });
    }

    /// A meshed send to a peer with no path watcher, whose selected path is a multihop route, is not
    /// held: the send proves the peer by its route, and does not wait for the sweep tick. Only the
    /// lower id of a pair has a watcher, so the higher id had no other source of the proof.
    #[test]
    fn a_meshed_directed_send_to_an_unwatched_peer_on_a_multihop_route_is_not_held() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let node = Node::spawn().await;
                let context = node.context();
                let mut state = fresh_state();
                state.standing.insert(Standing::Meshed);
                state.relay_transport = PayloadPath::DirectOnly;
                let (bob, eid) = (test_key("bob"), endpoint_id(7));
                state.retain_refused_endpoint(bob, iroh::EndpointAddr::new(eid));
                state.direct.insert(eid, DirectState::RelayOnly);
                state
                    .path_kinds
                    .insert(eid, transport::probe::PathKind::Multihop);
                let frame = Message::new_pong(
                    &node.mesh,
                    &node.author,
                    bob,
                    &protocol::MessageId::random(),
                )
                .sign(&Identity::generate());

                let sent = ops::send_app(&mut state, &context, frame).await;

                assert!(
                    !matches!(sent, Err(transport::SendError::Held { .. })),
                    "the send to a pair on a multihop route was held: {sent:?}"
                );
                assert_eq!(
                    state.direct.get(&eid),
                    Some(&DirectState::Direct),
                    "the send did not prove the pair by its route"
                );
                assert!(
                    state.lane_session_wanted(eid, clock::Instant::now()),
                    "the proof at the send did not ask for the lane session"
                );
                node.endpoint.close().await;
            },
        );
    }

    /// A meshed send to a peer whose direct path is proven goes by unicast at once. The peer has no
    /// gossip link in this test, so nothing waits for one: the frame reaches a real acceptor on the
    /// peer's unicast endpoint.
    #[test]
    fn a_meshed_directed_send_to_a_proven_peer_arrives_by_unicast_at_once() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use iroh::protocol::Router;

                use std::time::Duration;

                use tokio::time;

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
                            Duration::from_mins(1),
                        ),
                    )
                    .spawn();
                lookup::add_peer_addr(&lookup::address_book(&node.endpoint), bob.addr());
                let mut state = fresh_state();
                state.standing.insert(Standing::Meshed);
                state.relay_transport = PayloadPath::DirectOnly;
                state.unicast_pool = UnicastPool::new(node.endpoint.clone(), false);
                state.names.insert(test_key("bob"), nick("bob"));
                state.bind_peer_endpoint(test_key("bob"), nick("bob"), bob.addr());
                state.direct.insert(bob.id(), DirectState::Direct);
                let frame = Message::new_pong(
                    &node.mesh,
                    &node.author,
                    test_key("bob"),
                    &protocol::MessageId::random(),
                )
                .sign(&Identity::generate());
                let bytes = frame.serialize().expect("serialize");

                let sent = ops::send_app(&mut state, &context, frame).await;
                assert!(
                    sent.is_ok(),
                    "the send across the gap was refused: {sent:?}"
                );
                assert!(
                    state.pending_outbound.is_empty(),
                    "a directed frame was buffered across the gap"
                );
                let delivered = time::timeout(Duration::from_secs(5), frames.recv()).await;
                assert_eq!(
                    delivered.ok().flatten().map(|arrived| arrived.bytes),
                    Some(bytes.into_bytes()),
                    "bob never got the frame by unicast"
                );
                router.shutdown().await.expect("shut bob down");
                node.endpoint.close().await;
            },
        );
    }

    /// A broadcast sent while unmeshed is still buffered for the meshed edge.
    #[test]
    fn a_broadcast_while_unmeshed_is_buffered() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            state.standing.remove(&Standing::Meshed);
            let frame = Message::new_joined(&node.mesh, &node.author).sign(&Identity::generate());

            let sent = ops::send_app(&mut state, &context, frame).await;
            assert!(
                sent.is_ok(),
                "the broadcast while unmeshed was refused: {sent:?}"
            );
            assert_eq!(
                state.pending_outbound.take().len(),
                1,
                "the broadcast was not buffered for the meshed edge"
            );
            node.endpoint.close().await;
        });
    }

    /// A directed frame names a key, so a nickname that two live peers use does not make it
    /// undeliverable. The second key of the nickname has no endpoint of its own yet, so a send to
    /// it is refused and nothing is buffered. Once the key retains an endpoint, the send decision
    /// routes the frame to that endpoint, not to the dial hint that the first key owns.
    #[test]
    fn a_directed_frame_to_the_second_key_of_a_nickname_routes_to_its_own_endpoint() {
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
            let refused = ops::send_app(&mut state, &context, frame.clone()).await;
            assert!(
                matches!(refused, Err(transport::SendError::Undeliverable(_))),
                "the send to the second key, with no endpoint of its own, was not refused: {refused:?}"
            );
            assert!(
                state.pending_outbound.is_empty(),
                "a refused directed frame was buffered"
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

    /// A directed frame to either of two live keys that use a nickname is refused while unmeshed.
    /// The refusal names the key, so the caller can tell the two keys apart, and nothing is
    /// buffered.
    #[test]
    fn an_unmeshed_send_to_either_key_of_a_nickname_is_refused() {
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
                let refused = ops::send_app(&mut state, &context, frame).await;
                assert!(
                    matches!(
                        &refused,
                        Err(transport::SendError::Undeliverable(error)) if error.contains(&to.to_string())
                    ),
                    "the send to {to} was not refused while unmeshed: {refused:?}"
                );
            }

            assert!(
                state.pending_outbound.is_empty(),
                "a refused directed frame was buffered"
            );
            node.endpoint.close().await;
        });
    }

    /// An unmeshed node routes a directed frame like a meshed one: it needs no gossip link. A key
    /// that no roster, quiet set or address book holds is undeliverable, and so is a quiet key with
    /// no endpoint, and the caller hears it at once. A key that has a retained endpoint is sent to
    /// by a task. The buffer holds broadcast frames only.
    #[test]
    fn an_unmeshed_send_is_refused_for_a_key_with_no_endpoint_and_started_for_one_with_an_endpoint()
    {
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

            let refused = ops::send_app(&mut state, &context, frame_to(stranger)).await;
            assert!(
                matches!(refused, Err(transport::SendError::Undeliverable(_))),
                "the unmeshed send to a stranger was not refused: {refused:?}"
            );
            assert!(
                state.pending_outbound.is_empty(),
                "the refused frame was buffered"
            );

            let quiet_outcome = ops::send_app(&mut state, &context, frame_to(quiet)).await;
            assert!(
                matches!(quiet_outcome, Err(transport::SendError::Undeliverable(_))),
                "the unmeshed send to a quiet key with no endpoint was not refused: {quiet_outcome:?}"
            );
            let hinted_outcome = ops::send_app(&mut state, &context, frame_to(hinted)).await;
            assert!(
                matches!(hinted_outcome, Ok(transport::Delivered::Pending(_))),
                "the unmeshed send to a key with an endpoint did not start: {hinted_outcome:?}"
            );
            assert!(
                state.pending_outbound.is_empty(),
                "a directed frame was buffered"
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

    /// A restart sends its alive frame before its address (a meta card gives the endpoint, with no ask of its
    /// own). The ask is not lost for want of an address: it waits as an ask that waits for a path does, and the
    /// sweep tick sends it once the address and a path are there, and not at the next alive frame, 30 s later.
    #[test]
    fn an_ask_for_a_session_with_no_address_yet_waits_for_it() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let session = Identity::generate();
            let key = session.author_key();
            state.peers.insert(key);
            state.names.insert(key, nick("alice"));
            let alive: Verified = Message::new_alive(&node.mesh, &nick("alice")).sign(&session);

            lifecycle::ask_for_proof(&alive, &mut state, &context).await;

            assert_eq!(
                (
                    state.proofs.deferred_len(),
                    state.proof_requests_signed.load(Ordering::Relaxed)
                ),
                (1, 0),
                "the ask for a session with no address was dropped, and nothing waits for the address"
            );

            let endpoint = endpoint_id(86);
            state.place_endpoint(key, &nick("alice"), iroh::EndpointAddr::new(endpoint));
            state.linked_endpoints.insert(endpoint);
            lifecycle::retry_deferred_asks(&mut state, &context, None).await;

            assert_eq!(
                state.proof_requests_signed.load(Ordering::Relaxed),
                1,
                "the sweep did not send the ask once the address and the path were there"
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
                .checked_sub(Duration::from_secs(31))
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
            let window = started + Duration::from_secs(10);
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
                    dispatch_infra(&pong, true, &update, &mut state, &mut Inert, &context, true)
                        .await;
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
                .replacen(r#""v":"18.0""#, r#""v":"12.0""#, 1);
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

    /// The claimant of OUR nickname (another member with its own key) is asked for its proof, as the claimant of a
    /// bound nickname is. Else the nickname-held event depends on one frame, the `joined` that the claimant sends at its
    /// start: a node that is not yet a neighbor of the claimant misses it, and nothing sends it again. Here the start
    /// `joined` never arrives, the `alive` frames of the claimant do, and the answer to the ask raises the event once.
    #[test]
    fn the_claimant_of_our_nickname_is_asked_for_its_proof_and_its_answer_raises_the_held_event() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network::lifecycle",
                "our nickname is held by another member",
            );
            let node = Node::spawn().await;
            let lines = ErrorLines::default();
            let context = HandlerCtx {
                sink: &lines,
                ..node.context()
            };
            let mut state = fresh_state();
            let mut app = Inert;
            let (claimant, other_member) = (Identity::generate(), Identity::generate());
            let key = claimant.author_key();
            let endpoint = endpoint_id(87);
            // the refused `PeerInfo` of the claimant gave its address, which the node retains for it
            state.retain_refused_endpoint(key, iroh::EndpointAddr::new(endpoint));
            state.linked_endpoints.insert(endpoint);

            // the start `joined` of the claimant never came: its `alive` frames do
            let alive: Verified = Message::new_alive(&node.mesh, &node.author).sign(&claimant);
            ingest(
                alive.serialize().expect("serialize").into_bytes(),
                &mut state,
                &mut app,
                &context,
            )
            .await;

            assert_eq!(
                state.proof_requests_signed.load(Ordering::Relaxed),
                1,
                "the claimant of our nickname was not asked for its proof: the held event waits for one frame"
            );
            let (name, mesh_text): (&str, &str) = (node.author.as_ref(), node.mesh.as_ref());
            let proof = other_member.prove(&key, name, mesh_text, 1);
            let answer: Verified =
                Message::new_joined_with_proof(&node.mesh, &node.author, &proof).sign(&claimant);
            ingest(
                answer.serialize().expect("serialize").into_bytes(),
                &mut state,
                &mut app,
                &context,
            )
            .await;
            let seen: Vec<String> = lines
                .0
                .lock()
                .expect("the lines lock is not poisoned")
                .clone();
            let held: usize = seen
                .iter()
                .filter(|line| line.contains("is held by another member"))
                .count();
            assert_eq!(
                held, 1,
                "the answer of the claimant did not raise the held event once"
            );
            node.endpoint.close().await;
        });
    }

    /// A claimant of OUR nickname that is chatty sends no `Alive` (a node that broadcast something recently sends none):
    /// its frames are a `PeerInfo` and app frames, which the gate refuses as no membership kind. The first of them is
    /// asked for its proof too, once for each wait of the retry clock, and the answer raises the held event.
    #[test]
    fn a_chatty_claimant_of_our_nickname_is_asked_for_its_proof_by_its_other_frames() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let claimant = Identity::generate();
            let endpoint = endpoint_id(89);
            state.linked_endpoints.insert(endpoint);
            let address = iroh::EndpointAddr::new(endpoint);
            let info: Verified = {
                use crate::protocol::messages::MessageBody;
                let body = MessageBody::try_new(&address_json_with_seal(&address).to_string())
                    .expect("an address body");
                Message::new_peer_info(&node.mesh, &node.author, body).sign(&claimant)
            };
            let chatter: Verified = Message::new_app(
                &node.mesh,
                &node.author,
                AppFrameParams::new(
                    protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                    None,
                    None,
                    MessageBody::from("hello"),
                ),
            )
            .sign(&claimant);

            for frame in [info, chatter] {
                ingest(
                    frame.serialize().expect("serialize").into_bytes(),
                    &mut state,
                    &mut app,
                    &context,
                )
                .await;
            }

            assert_eq!(
                state.proof_requests_signed.load(Ordering::Relaxed),
                1,
                "a claimant of our nickname that sends only a PeerInfo and an app frame was not asked, or was asked twice in one wait"
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
            let hostile = text.replacen(r#""v":"18.0""#, &format!(r#""v":"{version}""#), 1);

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
                let other = text.replacen(r#""v":"18.0""#, &format!(r#""v":"v{version}""#), 1);
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
                state.peers.insert(identity.author_key());
            }
            for identity in &identities {
                // A slice that the store takes: the hook runs only on an applied slice.
                let frame = Message::new_channel_event(
                    &node.mesh,
                    &twin,
                    MessageBody::from(r#"{"version":1,"value":{}}"#),
                    Channel::Meta,
                )
                .sign(identity);
                dispatch_channel(
                    ChannelEvent {
                        channel: Channel::Meta,
                        message: &frame,
                        surfaceable: true,
                        live: true,
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

    /// Two keys that use one nickname keep two slices: the meta view holds one slot for each key, and neither slice
    /// replaces the other.
    #[test]
    fn two_keys_of_one_nickname_keep_two_slices_in_the_view() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let twin = nick("twin");
            let identities = [Identity::generate(), Identity::generate()];
            for identity in &identities {
                state.peers.insert(identity.author_key());
            }
            let indexed: Vec<(usize, &Identity)> = identities.iter().enumerate().collect();
            for &(index, identity) in &indexed {
                let body = format!(r#"{{"version":1,"value":{{"a":{index}}}}}"#);
                let frame = Message::new_channel_event(
                    &node.mesh,
                    &twin,
                    MessageBody::from(body.as_str()),
                    Channel::Meta,
                )
                .sign(identity);
                dispatch_channel(
                    ChannelEvent {
                        channel: Channel::Meta,
                        message: &frame,
                        surfaceable: true,
                        live: true,
                    },
                    &mut state,
                    &mut app,
                    &context,
                );
            }
            let view = state.view(Channel::Meta);
            assert_eq!(
                view.as_object().map(serde_json::Map::len),
                Some(2),
                "two keys of one nickname keep one slot each in the view"
            );
            for &(index, identity) in &indexed {
                let hex = String::from_utf8_lossy(&identity.author_key().hex()).into_owned();
                assert_eq!(
                    view[&hex]["a"], index,
                    "the slot of each key holds the value that the key wrote"
                );
            }
            node.endpoint.close().await;
        });
    }

    /// A meta slice that the store refuses does not reach the hook: the hook adopts the endpoint hint of a
    /// slice the store took, so a stale version must not run it.
    #[test]
    fn a_refused_meta_slice_does_not_reach_the_meta_hook() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            // the app and the test share the record
            let record = Arc::new(Mutex::new(Vec::new()));
            let mut app = MetaRecorder(Arc::clone(&record));
            let twin = nick("twin");
            let identity = Identity::generate();
            state.peers.insert(identity.author_key());
            // Version 1 applies. A second frame with version 0 is stale, so the store refuses it.
            for version in [1, 0] {
                let frame = Message::new_channel_event(
                    &node.mesh,
                    &twin,
                    MessageBody::try_new(&format!(r#"{{"version":{version},"value":{{}}}}"#))
                        .expect("a slice body"),
                    Channel::Meta,
                )
                .sign(&identity);
                dispatch_channel(
                    ChannelEvent {
                        channel: Channel::Meta,
                        message: &frame,
                        surfaceable: true,
                        live: true,
                    },
                    &mut state,
                    &mut app,
                    &context,
                );
            }

            let heard = record.lock().expect("the record lock").clone();
            assert_eq!(
                heard,
                vec![identity.author_key()],
                "the hook ran for the applied slice only, not for the stale one"
            );
            node.endpoint.close().await;
        });
    }

    /// A signed meta slice of `identity` at `version`, for the tests of the roster gate.
    fn gate_slice(mesh: &MeshId, identity: &Identity, version: u64) -> Verified {
        Message::new_channel_event(
            mesh,
            &nick("slice"),
            MessageBody::try_new(&format!(r#"{{"version":{version},"value":{{}}}}"#))
                .expect("a slice body"),
            Channel::Meta,
        )
        .sign(identity)
    }

    /// A sink that counts the state changes it is told of.
    #[derive(Default)]
    struct StateChanges(atomic::AtomicUsize);

    impl StateChanges {
        fn count(&self) -> usize {
            self.0.load(Ordering::Relaxed)
        }
    }

    impl NodeSink for StateChanges {
        fn emit(&self, event: NodeEvent) {
            if matches!(event, NodeEvent::StateChanged { .. }) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// A meta app with an empty record, for the tests of the roster gate.
    fn meta_app() -> MetaRecorder {
        // The app and the test share the record, so the record is behind an Arc.
        MetaRecorder(Arc::new(Mutex::new(Vec::new())))
    }

    /// The meta slot of `key` in the view of `state`, or `None` when the view has no slot of it.
    fn meta_slot(state: &EventLoopState, key: &AuthorKey) -> Option<serde_json::Value> {
        let hex = String::from_utf8_lossy(&key.hex()).into_owned();
        state.docs.to_json(Channel::Meta).get(&hex).cloned()
    }

    #[test]
    fn fresh_keys_outside_the_roster_do_not_block_a_roster_author() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = meta_app();
            for _ in 0..256 {
                let stranger = Identity::generate();
                let frame = gate_slice(&node.mesh, &stranger, 1);
                let event = ChannelEvent {
                    channel: Channel::Meta,
                    message: &frame,
                    surfaceable: true,
                    live: true,
                };
                dispatch_channel(event, &mut state, &mut app, &context);
            }
            let member = Identity::generate();
            state.peers.insert(member.author_key());
            let frame = gate_slice(&node.mesh, &member, 1);
            let event = ChannelEvent {
                channel: Channel::Meta,
                message: &frame,
                surfaceable: true,
                live: true,
            };
            dispatch_channel(event, &mut state, &mut app, &context);
            assert!(
                meta_slot(&state, &member.author_key()).is_some(),
                "a roster author writes its slice while 256 strangers wait"
            );
            node.endpoint.close().await;
        });
    }

    /// A pull is spent by its answer, so the next frame of the same author from the same holder is live.
    #[test]
    fn a_spent_pull_does_not_open_the_gate_again() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let identity = Identity::generate();
            state.peers.insert(identity.author_key());
            for version in 1..=50 {
                let bytes = slice_bytes(&node, &identity, Channel::State, version);
                ingest(bytes, &mut state, &mut app, &context).await;
            }
            let holder = endpoint_id(81);
            state.outstanding_pulls.register(
                holder,
                Channel::State,
                identity.author_key(),
                clock::Instant::now(),
                usize::MAX,
            );
            state.unicast_arrival = Some(holder);
            let answer = slice_bytes(&node, &identity, Channel::State, 100);
            ingest_from(answer, &mut state, &mut app, &context).await;
            assert_eq!(
                held_n(&state.docs.to_json(Channel::State), &identity),
                Some(100),
                "the answer to the pull applies"
            );
            let next = slice_bytes(&node, &identity, Channel::State, 101);
            ingest_from(next, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            assert_eq!(
                held_n(&state.docs.to_json(Channel::State), &identity),
                Some(100),
                "a frame after the spent pull is live, and the empty bucket refuses it"
            );
            node.endpoint.close().await;
        });
    }

    /// An answer that comes after the pull TTL is live: it takes a token, and the empty bucket refuses it.
    #[test]
    fn an_answer_after_the_pull_ttl_is_charged() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let identity = Identity::generate();
            state.peers.insert(identity.author_key());
            for version in 1..=50 {
                let bytes = slice_bytes(&node, &identity, Channel::State, version);
                ingest(bytes, &mut state, &mut app, &context).await;
            }
            let holder = endpoint_id(81);
            let asked = clock::Instant::now()
                .checked_sub(DIGEST_PULL_TTL)
                .expect("an instant one pull TTL back");
            state.outstanding_pulls.register(
                holder,
                Channel::State,
                identity.author_key(),
                asked,
                usize::MAX,
            );
            state.unicast_arrival = Some(holder);
            let late = slice_bytes(&node, &identity, Channel::State, 100);
            ingest_from(late, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            assert_ne!(
                held_n(&state.docs.to_json(Channel::State), &identity),
                Some(100),
                "a late answer is charged, so the empty bucket refuses it"
            );
            node.endpoint.close().await;
        });
    }

    /// An addressed pull that arrives by unicast spends one answer of the serve budget, so the answer path
    /// runs from the receive path, not only through the pure function.
    #[test]
    fn a_pull_that_arrives_is_answered_through_the_receive_path() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let asker = Identity::generate();
            let pull: Bytes = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::SlicePull {
                    to: state.identity.author_key(),
                    channel: Channel::State,
                    keys: vec![],
                },
                MessageBody::from("{}"),
            )
            .sign(&asker)
            .serialize()
            .expect("a signed pull serializes")
            .into_bytes();
            state.unicast_arrival = Some(endpoint_id(81));
            ingest_from(pull, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            let now = clock::Instant::now();
            let answers: usize = (0..DIGEST_SERVES_PER_WINDOW)
                .filter(|_| {
                    state
                        .serve_budget
                        .admit(endpoint_id(81), Channel::State, now)
                })
                .count();
            assert_eq!(
                answers,
                DIGEST_SERVES_PER_WINDOW - 1,
                "the pull spent one slot, so 7 more answers fit in the window"
            );
            node.endpoint.close().await;
        });
    }

    /// A page request for a page that this node does not hold gets no answer, so it spends no answer of the budget.
    #[test]
    fn a_page_request_for_a_missing_page_spends_no_answer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let asker = Identity::generate();
            let request: Bytes = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::SlicePageRequest {
                    to: state.identity.author_key(),
                    channel: Channel::State,
                    index: 99,
                },
                MessageBody::from("{}"),
            )
            .sign(&asker)
            .serialize()
            .expect("a signed page request serializes")
            .into_bytes();
            state.unicast_arrival = Some(endpoint_id(81));
            ingest_from(request, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            let now = clock::Instant::now();
            let answers: usize = (0..DIGEST_SERVES_PER_WINDOW)
                .filter(|_| {
                    state
                        .serve_budget
                        .admit(endpoint_id(81), Channel::State, now)
                })
                .count();
            assert_eq!(
                answers, DIGEST_SERVES_PER_WINDOW,
                "a request for a missing page spends no answer of the budget"
            );
            node.endpoint.close().await;
        });
    }

    /// A pull addressed to another key is not this node's to answer, so it spends no answer of the budget.
    #[test]
    fn a_pull_to_another_key_leaves_the_budget_full() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let asker = Identity::generate();
            let pull: Bytes = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::SlicePull {
                    to: Identity::generate().author_key(),
                    channel: Channel::State,
                    keys: vec![],
                },
                MessageBody::from("{}"),
            )
            .sign(&asker)
            .serialize()
            .expect("a signed pull serializes")
            .into_bytes();
            state.unicast_arrival = Some(endpoint_id(81));
            ingest_from(pull, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            let now = clock::Instant::now();
            let answers: usize = (0..DIGEST_SERVES_PER_WINDOW)
                .filter(|_| {
                    state
                        .serve_budget
                        .admit(endpoint_id(81), Channel::State, now)
                })
                .count();
            assert_eq!(
                answers, DIGEST_SERVES_PER_WINDOW,
                "a pull addressed to another key spends no answer, so all 8 fit"
            );
            node.endpoint.close().await;
        });
    }

    /// An addressed page request that arrives by unicast spends one answer of the serve budget, as a pull does.
    #[test]
    fn a_page_request_that_arrives_is_answered_through_the_receive_path() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let asker = Identity::generate();
            let page_request: Bytes = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::SlicePageRequest {
                    to: state.identity.author_key(),
                    channel: Channel::State,
                    index: 0,
                },
                MessageBody::from("{}"),
            )
            .sign(&asker)
            .serialize()
            .expect("a signed page request serializes")
            .into_bytes();
            state.unicast_arrival = Some(endpoint_id(81));
            ingest_from(page_request, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            let now = clock::Instant::now();
            let answers: usize = (0..DIGEST_SERVES_PER_WINDOW)
                .filter(|_| {
                    state
                        .serve_budget
                        .admit(endpoint_id(81), Channel::State, now)
                })
                .count();
            assert_eq!(
                answers,
                DIGEST_SERVES_PER_WINDOW - 1,
                "the page request spent one slot, so 7 more answers fit in the window"
            );
            node.endpoint.close().await;
        });
    }

    /// A page request addressed to another key is not this node's to answer, so it spends no answer of the budget.
    #[test]
    fn a_page_request_to_another_key_leaves_the_budget_full() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let asker = Identity::generate();
            let request: Bytes = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::SlicePageRequest {
                    to: Identity::generate().author_key(),
                    channel: Channel::State,
                    index: 0,
                },
                MessageBody::from("{}"),
            )
            .sign(&asker)
            .serialize()
            .expect("a signed page request serializes")
            .into_bytes();
            state.unicast_arrival = Some(endpoint_id(81));
            ingest_from(request, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            let now = clock::Instant::now();
            let answers: usize = (0..DIGEST_SERVES_PER_WINDOW)
                .filter(|_| {
                    state
                        .serve_budget
                        .admit(endpoint_id(81), Channel::State, now)
                })
                .count();
            assert_eq!(
                answers, DIGEST_SERVES_PER_WINDOW,
                "a pull addressed to another key spends no answer, so all 8 fit"
            );
            node.endpoint.close().await;
        });
    }

    /// One endpoint that signs its pulls with two keys spends two answers of its own budget, whatever the keys.
    #[test]
    fn one_endpoint_with_two_keys_spends_one_budget() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            state.unicast_arrival = Some(endpoint_id(81));
            for signer in [Identity::generate(), Identity::generate()] {
                let pull: Bytes = Message::new_frame(
                    &node.mesh,
                    &nick("alice"),
                    MessageKind::SlicePull {
                        to: state.identity.author_key(),
                        channel: Channel::State,
                        keys: vec![],
                    },
                    MessageBody::from("{}"),
                )
                .sign(&signer)
                .serialize()
                .expect("a signed pull serializes")
                .into_bytes();
                ingest_from(pull, &mut state, &mut app, &context).await;
            }
            state.unicast_arrival = None;
            let now = clock::Instant::now();
            let answers: usize = (0..DIGEST_SERVES_PER_WINDOW)
                .filter(|_| {
                    state
                        .serve_budget
                        .admit(endpoint_id(81), Channel::State, now)
                })
                .count();
            assert_eq!(
                answers,
                DIGEST_SERVES_PER_WINDOW - 2,
                "two pulls from one endpoint spend two answers, whatever their keys"
            );
            node.endpoint.close().await;
        });
    }

    /// A pull is for one channel, so a meta frame of the author is live when the pull is for state.
    #[test]
    fn a_pull_of_one_channel_does_not_open_the_other() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let identity = Identity::generate();
            state.peers.insert(identity.author_key());
            for version in 1..=50 {
                let state_bytes = slice_bytes(&node, &identity, Channel::State, version);
                ingest(state_bytes, &mut state, &mut app, &context).await;
                let meta_bytes = slice_bytes(&node, &identity, Channel::Meta, version);
                ingest(meta_bytes, &mut state, &mut app, &context).await;
            }
            let holder = endpoint_id(81);
            state.outstanding_pulls.register(
                holder,
                Channel::State,
                identity.author_key(),
                clock::Instant::now(),
                usize::MAX,
            );
            state.unicast_arrival = Some(holder);
            let meta = slice_bytes(&node, &identity, Channel::Meta, 100);
            ingest_from(meta, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            assert_ne!(
                held_n(&state.docs.to_json(Channel::Meta), &identity),
                Some(100),
                "a meta frame is live when the pull is for state, so the empty bucket refuses it"
            );
            node.endpoint.close().await;
        });
    }

    /// A pull over the serve budget gets no frame, even for a slice that this node holds.
    #[test]
    fn a_refused_pull_gets_no_frames() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let identity = Identity::generate();
            state.peers.insert(identity.author_key());
            let held = slice_bytes(&node, &identity, Channel::State, 1);
            ingest(held, &mut state, &mut app, &context).await;
            let asker = super::Asker {
                endpoint: endpoint_id(81),
                key: Identity::generate().author_key(),
            };
            for _ in 0..DIGEST_SERVES_PER_WINDOW {
                state
                    .serve_budget
                    .admit(asker.endpoint, Channel::State, clock::Instant::now());
            }
            let answer = super::slice_pull_answer(
                asker,
                Channel::State,
                &[identity.author_key()],
                &mut state,
                clock::Instant::now(),
            );
            assert!(
                answer.is_empty(),
                "a pull over the serve budget gets no frame"
            );
            node.endpoint.close().await;
        });
    }

    /// An admitted pull gets the frames of the keys that this node holds, and none for the others.
    #[test]
    fn an_admitted_pull_gets_the_held_frames_of_its_keys() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let identity = Identity::generate();
            state.peers.insert(identity.author_key());
            let held = slice_bytes(&node, &identity, Channel::State, 1);
            ingest(held, &mut state, &mut app, &context).await;
            let asker = super::Asker {
                endpoint: endpoint_id(81),
                key: Identity::generate().author_key(),
            };
            let stranger = Identity::generate().author_key();
            let answer = super::slice_pull_answer(
                asker,
                Channel::State,
                &[identity.author_key(), stranger],
                &mut state,
                clock::Instant::now(),
            );
            assert_eq!(
                answer.len(),
                1,
                "the held key answers, and the stranger has no frame"
            );
            assert_eq!(
                answer[0].key(),
                identity.author_key(),
                "the frame is the one of the held key"
            );
            node.endpoint.close().await;
        });
    }

    /// The four slice kinds name one addressee, so a node that is not the addressee does not take them.
    /// **The engine plumbing does not reach a push subscriber.** A frame that the engine sends to
    /// itself for the digest round, the proof exchange and the link state has no app tag, and the
    /// push gate let any such frame through. A subscriber of the push channel got the raw frames of
    /// the sync of its node, one round for each neighbor and each backfill tick. The control is a
    /// `joined`, which is a presence the subscriber wants.
    #[test]
    fn engine_plumbing_addressed_to_us_is_not_pushed_and_a_joined_is() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let (tx, mut pushed) = broadcast::channel(16);
            let context = HandlerCtx {
                external_msg_tx: Some(&tx),
                ..node.context()
            };
            let us = context.our_pubkey;
            let root = || DigestRoot::new(ContentHash::of(b"root"), 1).expect("one page");
            let entries = vec![DigestEntry::new(us, 1, ContentHash::of(b"row"))];
            let kinds = vec![
                MessageKind::SliceRoot {
                    to: us,
                    state: root(),
                    meta: root(),
                },
                MessageKind::SlicePull {
                    to: us,
                    channel: Channel::State,
                    keys: vec![],
                },
                MessageKind::SlicePageRequest {
                    to: us,
                    channel: Channel::Meta,
                    index: 0,
                },
                MessageKind::SlicePage {
                    to: us,
                    channel: Channel::State,
                    page: DigestPage::build(&entries, 1, 0, 1).expect("a page of one row"),
                },
                MessageKind::ProofRequest { to: us },
                MessageKind::LinkState,
                MessageKind::PeerInfo,
            ];
            let signer = Identity::generate();
            for kind in kinds {
                let shown = format!("{kind}");
                let frame =
                    Message::new_frame(&node.mesh, &nick("alice"), kind, MessageBody::from(""))
                        .sign(&signer);
                maybe_push_inbound(&context, &frame.authored(), true, None);
                assert!(
                    pushed.try_recv().is_err(),
                    "a {shown} frame addressed to us reached the push subscriber"
                );
            }

            let joined = Message::new_joined(&node.mesh, &nick("alice")).sign(&signer);
            maybe_push_inbound(&context, &joined.authored(), true, None);
            assert!(
                pushed.try_recv().is_ok(),
                "a joined frame did not reach the push subscriber"
            );
            node.endpoint.close().await;
        });
    }

    #[test]
    fn a_slice_kind_is_for_its_addressee_only() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let addressee = Identity::generate().author_key();
            let other = Identity::generate().author_key();
            let kinds_to = |to: AuthorKey| {
                let root = || DigestRoot::new(ContentHash::of(b"root"), 1).expect("one page");
                let entries = vec![DigestEntry::new(to, 1, ContentHash::of(b"row"))];
                vec![
                    MessageKind::SliceRoot {
                        to,
                        state: root(),
                        meta: root(),
                    },
                    MessageKind::SlicePull {
                        to,
                        channel: Channel::State,
                        keys: vec![],
                    },
                    MessageKind::SlicePageRequest {
                        to,
                        channel: Channel::Meta,
                        index: 0,
                    },
                    MessageKind::SlicePage {
                        to,
                        channel: Channel::State,
                        page: DigestPage::build(&entries, 1, 0, 1).expect("a page of one row"),
                    },
                ]
            };
            for kind in kinds_to(addressee) {
                let display = kind.to_string();
                let message =
                    Message::new_frame(&node.mesh, &nick("alice"), kind, MessageBody::from("{}"));
                assert!(
                    super::addressed_to_us(&message, &addressee),
                    "the addressee does not take a {display}"
                );
                assert!(
                    !super::addressed_to_us(&message, &other),
                    "a key that is not the addressee takes a {display}"
                );
            }
            node.endpoint.close().await;
        });
    }

    /// A signed slice frame of `identity` on `channel` at `version`, with the value `{"n": version}`.
    fn slice_bytes(node: &Node, identity: &Identity, channel: Channel, version: u64) -> Bytes {
        let body = MessageBody::try_new(&format!(
            r#"{{"version":{version},"value":{{"n":{version}}}}}"#
        ))
        .expect("a slice body");
        Message::new_channel_event(&node.mesh, &nick("twin"), body, channel)
            .sign(identity)
            .serialize()
            .expect("serialize")
            .into_bytes()
    }

    /// The `n` of the slice that `document` holds for `identity`, or `None` when it holds none.
    fn held_n(document: &serde_json::Value, identity: &Identity) -> Option<u64> {
        let hex = String::from_utf8_lossy(&identity.author_key().hex()).into_owned();
        document.get(hex)?.get("n")?.as_u64()
    }

    /// A pulled slice takes no token, so it applies after the bucket of its author is empty.
    #[test]
    fn a_pulled_frame_takes_no_token() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let identity = Identity::generate();
            state.peers.insert(identity.author_key());
            for version in 1..=50 {
                let bytes = slice_bytes(&node, &identity, Channel::State, version);
                ingest(bytes, &mut state, &mut app, &context).await;
            }
            let live = slice_bytes(&node, &identity, Channel::State, 101);
            ingest(live, &mut state, &mut app, &context).await;
            assert_ne!(
                held_n(&state.docs.to_json(Channel::State), &identity),
                Some(101),
                "the bucket is empty, so a live frame is refused"
            );

            let holder = endpoint_id(81);
            state.outstanding_pulls.register(
                holder,
                Channel::State,
                identity.author_key(),
                clock::Instant::now(),
                usize::MAX,
            );
            state.unicast_arrival = Some(holder);
            let pulled = slice_bytes(&node, &identity, Channel::State, 100);
            ingest_from(pulled, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            assert_eq!(
                held_n(&state.docs.to_json(Channel::State), &identity),
                Some(100),
                "the pulled slice applies with no token"
            );
            node.endpoint.close().await;
        });
    }

    /// A pulled slice is not a duplicate of a copy that the store refused before the pull.
    #[test]
    fn a_pulled_frame_skips_the_dedup() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let identity = Identity::generate();
            state.peers.insert(identity.author_key());
            for version in 1..=50 {
                let bytes = slice_bytes(&node, &identity, Channel::State, version);
                ingest(bytes, &mut state, &mut app, &context).await;
            }
            let refused = slice_bytes(&node, &identity, Channel::State, 100);
            ingest(refused.clone(), &mut state, &mut app, &context).await;
            assert_ne!(
                held_n(&state.docs.to_json(Channel::State), &identity),
                Some(100),
                "the bucket is empty, so the first copy is refused"
            );

            let holder = endpoint_id(81);
            state.outstanding_pulls.register(
                holder,
                Channel::State,
                identity.author_key(),
                clock::Instant::now(),
                usize::MAX,
            );
            state.unicast_arrival = Some(holder);
            ingest_from(refused, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            assert_eq!(
                held_n(&state.docs.to_json(Channel::State), &identity),
                Some(100),
                "the answer to a pull is applied, not dropped as a duplicate"
            );
            node.endpoint.close().await;
        });
    }

    /// A slice that a holder sends without a pull is live, so it takes a token and is refused.
    #[test]
    fn an_unasked_frame_is_charged() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let identity = Identity::generate();
            state.peers.insert(identity.author_key());
            for version in 1..=50 {
                let bytes = slice_bytes(&node, &identity, Channel::State, version);
                ingest(bytes, &mut state, &mut app, &context).await;
            }
            state.outstanding_pulls.register(
                endpoint_id(81),
                Channel::State,
                identity.author_key(),
                clock::Instant::now(),
                usize::MAX,
            );
            state.unicast_arrival = Some(endpoint_id(82));
            let unasked = slice_bytes(&node, &identity, Channel::State, 100);
            ingest_from(unasked, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            assert_ne!(
                held_n(&state.docs.to_json(Channel::State), &identity),
                Some(100),
                "a holder with no pull is charged, and the empty bucket refuses the slice"
            );
            node.endpoint.close().await;
        });
    }

    #[test]
    fn a_slice_of_a_key_outside_the_roster_waits_for_its_joined() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            // the app and the test share the record
            let record = Arc::new(Mutex::new(Vec::new()));
            let mut app = MetaRecorder(Arc::clone(&record));
            let stranger = Identity::generate();
            let key = stranger.author_key();
            let frame = gate_slice(&node.mesh, &stranger, 1);
            let event = ChannelEvent {
                channel: Channel::Meta,
                message: &frame,
                surfaceable: true,
                live: true,
            };
            dispatch_channel(event, &mut state, &mut app, &context);
            assert!(
                meta_slot(&state, &key).is_none(),
                "a slice of a key outside the roster is not in the view"
            );
            state.peers.insert(key);
            promote_pending(key, clock::Instant::now(), &mut state, &mut app, &context);
            assert!(
                meta_slot(&state, &key).is_some(),
                "the held slice reaches the view when its key joins"
            );
            let heard = record.lock().expect("the record lock").clone();
            assert_eq!(
                heard,
                vec![key],
                "the meta hook runs for the promoted slice"
            );
            node.endpoint.close().await;
        });
    }

    #[test]
    fn a_pending_slice_expires_after_the_alive_timeout() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = meta_app();
            let stranger = Identity::generate();
            let key = stranger.author_key();
            let frame = gate_slice(&node.mesh, &stranger, 1);
            let event = ChannelEvent {
                channel: Channel::Meta,
                message: &frame,
                surfaceable: true,
                live: true,
            };
            dispatch_channel(event, &mut state, &mut app, &context);
            assert!(
                meta_slot(&state, &key).is_none(),
                "a slice of a key outside the roster is held, not applied"
            );
            state.peers.insert(key);
            let joined = clock::Instant::now() + Duration::from_secs(91);
            promote_pending(key, joined, &mut state, &mut app, &context);
            assert!(
                meta_slot(&state, &key).is_none(),
                "a slice held past the alive timeout is gone when its key joins"
            );
            node.endpoint.close().await;
        });
    }

    #[test]
    fn a_peer_that_leaves_loses_its_slice_from_the_view() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = meta_app();
            let member = Identity::generate();
            let key = member.author_key();
            state.peers.insert(key);
            let frame = gate_slice(&node.mesh, &member, 1);
            let event = ChannelEvent {
                channel: Channel::Meta,
                message: &frame,
                surfaceable: true,
                live: true,
            };
            dispatch_channel(event, &mut state, &mut app, &context);
            assert!(
                meta_slot(&state, &key).is_some(),
                "the peer's slice is in the view"
            );
            let nickname = nick("member");
            lifecycle::end_session(
                key,
                lifecycle::Goodbye::Replaced(&nickname),
                &mut state,
                &mut app,
                &context,
            )
            .await;
            assert!(
                meta_slot(&state, &key).is_none(),
                "the slice of a peer that left is out of the view"
            );
            node.endpoint.close().await;
        });
    }

    #[test]
    fn an_own_frame_is_not_held() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = meta_app();
            let own = Arc::clone(&state.identity);
            let frame = gate_slice(&node.mesh, &own, 1);
            let event = ChannelEvent {
                channel: Channel::Meta,
                message: &frame,
                surfaceable: true,
                live: true,
            };
            dispatch_channel(event, &mut state, &mut app, &context);
            assert!(
                meta_slot(&state, &own.author_key()).is_some(),
                "an echo of an own frame is applied, not held as a stranger"
            );
            node.endpoint.close().await;
        });
    }

    #[test]
    fn the_sweep_expires_a_gone_key_after_the_gone_ttl() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = meta_app();
            let member = Identity::generate();
            let key = member.author_key();
            state.peers.insert(key);
            let gone_ttl = habilis_network_doc::SliceLimits::default().gone_ttl;
            let left_at = clock::Instant::now()
                .checked_sub(gone_ttl + Duration::from_secs(1))
                .expect("an instant past the gone TTL");
            state.docs.forget(&key, left_at);
            let frame = gate_slice(&node.mesh, &member, 1);
            let event = ChannelEvent {
                channel: Channel::Meta,
                message: &frame,
                surfaceable: true,
                live: true,
            };
            dispatch_channel(event, &mut state, &mut app, &context);
            assert!(
                meta_slot(&state, &key).is_none(),
                "a gone key is refused before the sweep expires it"
            );
            heartbeat::tick_sweep(&mut state, &SilentSink);
            dispatch_channel(event, &mut state, &mut app, &context);
            assert!(
                meta_slot(&state, &key).is_some(),
                "the sweep drops the gone key after the gone TTL, and its slice applies again"
            );
            node.endpoint.close().await;
        });
    }

    #[test]
    fn a_lapsed_key_and_a_dropped_key_lose_their_slices() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = meta_app();
            let lapsed = Identity::generate();
            let dropped = Identity::generate();
            state.peers.insert(lapsed.author_key());
            state.peers.insert(dropped.author_key());
            for member in [&lapsed, &dropped] {
                let frame = gate_slice(&node.mesh, member, 1);
                let event = ChannelEvent {
                    channel: Channel::Meta,
                    message: &frame,
                    surfaceable: true,
                    live: true,
                };
                dispatch_channel(event, &mut state, &mut app, &context);
            }
            state.peers.remove(&lapsed.author_key());
            state
                .clock_evidence
                .lapsed_quiet
                .insert(lapsed.author_key());
            state.peers.remove(&dropped.author_key());
            heartbeat::tick_sweep(&mut state, &SilentSink);
            assert!(
                meta_slot(&state, &lapsed.author_key()).is_none(),
                "a lapsed key keeps no slice: the sweep releases it, and it can still return"
            );
            assert!(
                meta_slot(&state, &dropped.author_key()).is_none(),
                "a key that left the roster loses its slice"
            );
            node.endpoint.close().await;
        });
    }

    #[test]
    fn a_new_run_of_a_member_leaves_one_slice_in_the_view() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = meta_app();
            let older = Identity::generate();
            let newer = Identity::generate();
            state.peers.insert(older.author_key());
            state.peers.insert(newer.author_key());
            for member in [&older, &newer] {
                let frame = gate_slice(&node.mesh, member, 1);
                let event = ChannelEvent {
                    channel: Channel::Meta,
                    message: &frame,
                    surfaceable: true,
                    live: true,
                };
                dispatch_channel(event, &mut state, &mut app, &context);
            }
            let nickname = nick("member");
            lifecycle::end_session(
                older.author_key(),
                lifecycle::Goodbye::Replaced(&nickname),
                &mut state,
                &mut app,
                &context,
            )
            .await;
            let view = state.docs.to_json(Channel::Meta);
            assert_eq!(
                view.as_object().map(serde_json::Map::len),
                Some(1),
                "a new run of a member leaves one slice in the view"
            );
            node.endpoint.close().await;
        });
    }
    #[test]
    fn a_slice_of_a_key_that_said_goodbye_is_refused() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = meta_app();
            let member = Identity::generate();
            let key = member.author_key();
            state.peers.insert(key);
            let first = gate_slice(&node.mesh, &member, 1);
            let event = ChannelEvent {
                channel: Channel::Meta,
                message: &first,
                surfaceable: true,
                live: true,
            };
            dispatch_channel(event, &mut state, &mut app, &context);
            let nickname = nick("member");
            lifecycle::end_session(
                key,
                lifecycle::Goodbye::Replaced(&nickname),
                &mut state,
                &mut app,
                &context,
            )
            .await;
            // The store alone answers: the gate would drop the frame before the store sees it.
            let later = gate_slice(&node.mesh, &member, 2);
            let answer = state
                .docs
                .ingest(Channel::Meta, &later, true, clock::Instant::now());
            assert!(
                matches!(
                    answer,
                    habilis_network_doc::SliceIngest::Refused(
                        habilis_network_doc::SliceError::GoneKey
                    )
                ),
                "a replaced run's key is in the gone set, so its later slice is refused"
            );
            node.endpoint.close().await;
        });
    }

    #[test]
    fn a_slice_of_a_key_that_signed_goodbye_is_refused() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = meta_app();
            let member = Identity::generate();
            let key = member.author_key();
            state.peers.insert(key);
            let nickname = nick("member");
            let goodbye = Message::new_left(&node.mesh, &nickname).sign(&member);
            lifecycle::end_session(
                key,
                lifecycle::Goodbye::Signed(&goodbye),
                &mut state,
                &mut app,
                &context,
            )
            .await;
            let later = gate_slice(&node.mesh, &member, 2);
            let answer = state
                .docs
                .ingest(Channel::Meta, &later, true, clock::Instant::now());
            assert!(
                matches!(
                    answer,
                    habilis_network_doc::SliceIngest::Refused(
                        habilis_network_doc::SliceError::GoneKey
                    )
                ),
                "a signed goodbye puts the key in the gone set, so its later slice is refused"
            );
            node.endpoint.close().await;
        });
    }

    #[test]
    fn a_frame_of_a_stranger_that_said_goodbye_is_dropped_not_held() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = meta_app();
            let stranger = Identity::generate();
            let key = stranger.author_key();
            let nickname = nick("stranger");
            let goodbye = Message::new_left(&node.mesh, &nickname).sign(&stranger);
            lifecycle::end_session(
                key,
                lifecycle::Goodbye::Signed(&goodbye),
                &mut state,
                &mut app,
                &context,
            )
            .await;
            let frame = gate_slice(&node.mesh, &stranger, 1);
            let event = ChannelEvent {
                channel: Channel::Meta,
                message: &frame,
                surfaceable: true,
                live: true,
            };
            dispatch_channel(event, &mut state, &mut app, &context);
            assert!(
                state
                    .docs
                    .take_pending(Channel::Meta, &key, clock::Instant::now())
                    .is_none(),
                "a frame of a key that said goodbye waits nowhere, not even in the pending set"
            );
            node.endpoint.close().await;
        });
    }

    #[test]
    fn a_held_frame_older_than_the_join_is_promoted_without_a_surface() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let mut state = fresh_state();
            // The frame is older than the join, so the join horizon hides it.
            state.joined_at = UnixSecs::from(4_000_000_000_i64);
            // the app and the test share the record
            let record = Arc::new(Mutex::new(Vec::new()));
            let mut app = MetaRecorder(Arc::clone(&record));
            let member = Identity::generate();
            let key = member.author_key();
            let frame = gate_slice(&node.mesh, &member, 1);
            let sink = StateChanges::default();
            let context = HandlerCtx {
                sender: &node.sender,
                endpoint: &node.endpoint,
                mesh: &node.mesh,
                author: &node.author,
                identity: &node.identity,
                our_pubkey: node.our_pubkey,
                max_peers: 16,
                rendezvous_id: endpoint_id(9),
                external_msg_tx: None,
                sink: &sink,
            };
            let event = ChannelEvent {
                channel: Channel::Meta,
                message: &frame,
                surfaceable: true,
                live: true,
            };
            dispatch_channel(event, &mut state, &mut app, &context);
            state.peers.insert(key);
            promote_pending(key, clock::Instant::now(), &mut state, &mut app, &context);
            assert!(
                meta_slot(&state, &key).is_some(),
                "the held slice reaches the view when its key joins"
            );
            let heard = record.lock().expect("the record lock").clone();
            assert_eq!(
                heard,
                vec![key],
                "the meta hook runs for the promoted slice"
            );
            assert_eq!(
                sink.count(),
                0,
                "a promoted frame older than the join is not surfaced"
            );
            node.endpoint.close().await;
        });
    }

    #[test]
    fn a_key_that_loses_its_nickname_keeps_its_slice_pending() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = meta_app();
            let member = Identity::generate();
            let key = member.author_key();
            state.peers.insert(key);
            let frame = gate_slice(&node.mesh, &member, 1);
            let event = ChannelEvent {
                channel: Channel::Meta,
                message: &frame,
                surfaceable: true,
                live: true,
            };
            dispatch_channel(event, &mut state, &mut app, &context);
            let nickname = nick("member");
            lifecycle::end_session(
                key,
                lifecycle::Goodbye::Refused(&nickname),
                &mut state,
                &mut app,
                &context,
            )
            .await;
            assert!(
                meta_slot(&state, &key).is_none(),
                "a key that lost its nickname is out of the view"
            );
            assert!(
                state
                    .docs
                    .take_pending(Channel::Meta, &key, clock::Instant::now())
                    .is_some(),
                "its slice waits in the pending set, because the key can return"
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

    /// The seal key of a `PeerInfo` belongs to its signer, and only a key that the node knows keeps
    /// one: a member mints keys for free, so the roster bounds the map. A body with no seal key
    /// changes nothing, and a newer `PeerInfo` of the key replaces the key.
    #[test]
    fn a_peer_info_binds_its_seal_key_to_its_signer_when_the_signer_is_known() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::messages::MessageBody;
            use crate::protocol::{AuthorKey, identity};

            let node = Node::spawn().await;
            let context = node.context();
            let bob = Identity::generate();
            let stranger = Identity::generate();
            let key_of = |who: &Identity| {
                AuthorKey::decode_hex(&identity::encode_pubkey(&who.public()))
                    .expect("a 32-byte key")
            };
            let (bob_key, stranger_key) = (key_of(&bob), key_of(&stranger));
            let peer_info = |seal: Option<x25519_dalek::PublicKey>, signed_by: &Identity| {
                let address = iroh::EndpointAddr::new(endpoint_id(61));
                let mut json = address_json_with_seal(&address);
                match seal {
                    Some(seal) => {
                        json["seal"] =
                            serde_json::Value::String(bs58::encode(seal.as_bytes()).into_string());
                    }
                    None => {
                        json.as_object_mut()
                            .expect("the body is an object")
                            .remove("seal");
                    }
                }
                let body = MessageBody::try_new(&json.to_string()).expect("an address body");
                Message::new_peer_info(&node.mesh, &nick("bob"), body).sign(signed_by)
            };

            let mut state = fresh_state();
            state.peers.insert(bob_key);
            state.names.insert(bob_key, nick("bob"));
            super::handle_peer_info(
                &peer_info(Some(bob.seal_public()), &bob),
                &mut state,
                &context,
            )
            .await;
            assert_eq!(
                state.seal_key_of(&bob_key),
                Some(&bob.seal_public()),
                "the seal key of a known signer is kept"
            );

            super::handle_peer_info(
                &peer_info(Some(bob.seal_public()), &stranger),
                &mut state,
                &context,
            )
            .await;
            assert_eq!(
                state.seal_key_of(&stranger_key),
                None,
                "a key that the node does not know keeps no seal key"
            );

            super::handle_peer_info(&peer_info(None, &bob), &mut state, &context).await;
            assert_eq!(
                state.seal_key_of(&bob_key),
                Some(&bob.seal_public()),
                "a PeerInfo with no seal key is refused and leaves the kept key"
            );

            let newer = Identity::generate().seal_public();
            super::handle_peer_info(&peer_info(Some(newer), &bob), &mut state, &context).await;
            assert_eq!(
                state.seal_key_of(&bob_key),
                Some(&newer),
                "a newer PeerInfo replaces the seal key"
            );
            node.endpoint.close().await;
        });
    }

    /// **A `PeerInfo` that comes before the `joined` frame of its signer keeps its seal key for the
    /// join.** The next `PeerInfo` of the signer is a refresh period away, so the key that is
    /// dropped on arrival leaves the first directed sealed send without a key. The key waits, and
    /// the admission of its signer to the roster applies it.
    #[test]
    fn a_peer_info_before_the_join_of_its_signer_gives_its_seal_key_at_the_join() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::lifecycle::membership_update::{self, MembershipUpdate};
            use crate::protocol::messages::MessageBody;
            use crate::protocol::{AuthorKey, identity};

            let node = Node::spawn().await;
            let context = node.context();
            let bob = Identity::generate();
            let bob_key = AuthorKey::decode_hex(&identity::encode_pubkey(&bob.public()))
                .expect("a 32-byte key");
            let mut json = address_json_with_seal(&iroh::EndpointAddr::new(endpoint_id(62)));
            json["seal"] =
                serde_json::Value::String(bs58::encode(bob.seal_public().as_bytes()).into_string());
            let body = MessageBody::try_new(&json.to_string()).expect("an address body");
            let info = Message::new_peer_info(&node.mesh, &nick("bob"), body).sign(&bob);

            let mut state = fresh_state();
            super::handle_peer_info(&info, &mut state, &context).await;
            assert_eq!(
                state.seal_key_of(&bob_key),
                None,
                "the key of an unknown signer was kept at once"
            );
            assert_eq!(
                state.pending_seal_key_count(),
                1,
                "the key of an unknown signer did not wait for its join"
            );

            let joined = MembershipUpdate {
                returned: false,
                joined_new: true,
                stale: false,
            };
            membership_update::apply(&joined, bob_key, &mut state);
            assert_eq!(
                state.seal_key_of(&bob_key),
                Some(&bob.seal_public()),
                "the join did not give the waiting seal key"
            );
            assert_eq!(
                state.pending_seal_key_count(),
                0,
                "the key still waits after its join"
            );
            node.endpoint.close().await;
        });
    }

    /// **The old body of a `PeerInfo`, with no seal key, binds nothing.** Wire 18.0 is not released,
    /// so the seal key is part of the body. The literal below is the body before the seal key: an
    /// address and a proof. The frame is signed and its address is good, and the receiver still
    /// refuses it: no endpoint, no proof, no key.
    #[test]
    fn a_peer_info_with_no_seal_key_binds_nothing() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::protocol::messages::MessageBody;
            use crate::protocol::{AuthorKey, identity, peer_addr_error};

            let node = Node::spawn().await;
            let context = node.context();
            let bob = Identity::generate();
            let bob_key = AuthorKey::decode_hex(&identity::encode_pubkey(&bob.public()))
                .expect("a 32-byte key");
            let mut old =
                peer_addr_error::endpoint_addr_to_json(&iroh::EndpointAddr::new(endpoint_id(63)));
            old["proof"] = serde_json::Value::String("proof".to_owned());
            assert!(
                old.get("seal").is_none(),
                "the premise: the body has no seal"
            );
            let body = MessageBody::try_new(&old.to_string()).expect("an address body");
            let info = Message::new_peer_info(&node.mesh, &nick("bob"), body).sign(&bob);

            let mut state = fresh_state();
            state.peers.insert(bob_key);
            state.names.insert(bob_key, nick("bob"));
            super::handle_peer_info(&info, &mut state, &context).await;

            assert_eq!(
                state.seal_key_of(&bob_key),
                None,
                "a body with no seal kept a key"
            );
            assert_eq!(
                state.pending_seal_key_count(),
                0,
                "a body with no seal left a key waiting"
            );
            assert!(
                state.known_endpoints.is_empty() && state.peer_endpoints.is_empty(),
                "a body with no seal bound an endpoint"
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
            use crate::protocol::{AuthorKey, identity};
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
                let mut json = address_json_with_seal(&iroh::EndpointAddr::new(bob_endpoint));
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
            state.unicast_arrival = Some(endpoint_id(80));

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

    /// The rendezvous is not a path to the asker. When the address in the roster of the asker is the rendezvous (a
    /// beacon gossips as the rendezvous), it must not hide a usable arrival connection: the rendezvous is left out
    /// of each candidate before the choice, and the arrival is tried.
    #[test]
    fn a_cached_address_that_is_the_rendezvous_does_not_hide_a_usable_arrival() {
        let mut state = fresh_state();
        let asker = Identity::generate().author_key();
        let (rendezvous, arrival) = (endpoint_id(84), endpoint_id(85));
        state.rendezvous_id = Some(rendezvous);
        state.peers.insert(asker);
        state.names.insert(asker, nick("asker"));
        state.place_endpoint(asker, &nick("asker"), iroh::EndpointAddr::new(rendezvous));
        state.direct.insert(rendezvous, DirectState::Direct);
        state.direct.insert(arrival, DirectState::Direct);
        state.unicast_arrival = Some(arrival);

        assert_eq!(
            super::return_path(&state, &asker),
            Some(arrival),
            "the cached address was the rendezvous: it hid the usable arrival and the answer went nowhere"
        );
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
        state.unicast_arrival = Some(new);

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

            let node = Node::spawn().await;
            let context = node.context();
            let twin = nick("twin");
            let (first_endpoint, second_endpoint) = (endpoint_id(51), endpoint_id(52));
            let (first, second) = (Identity::generate(), Identity::generate());
            let mut state = fresh_state();
            for (run, endpoint) in [(&first, first_endpoint), (&second, second_endpoint)] {
                state.names.insert(run.author_key(), twin.clone());
                state.peers.insert(run.author_key());
                let json = address_json_with_seal(&iroh::EndpointAddr::new(endpoint));
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
                let json = address_json_with_seal(&iroh::EndpointAddr::new(endpoint));
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
            use crate::protocol::{AuthorKey, identity};

            let node = Node::spawn().await;
            let context = node.context();
            let bob_endpoint = iroh::SecretKey::generate().public();
            let bob = Identity::generate();
            let bob_signer = AuthorKey::decode_hex(&identity::encode_pubkey(&bob.public()))
                .expect("a 32-byte key");
            let mut json = address_json_with_seal(&iroh::EndpointAddr::new(bob_endpoint));
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
            use crate::protocol::{AuthorKey, identity};
            use crate::transport::proven_endpoints;

            let node = Node::spawn().await;
            let context = node.context();
            let bob_endpoint_key = iroh::SecretKey::generate();
            let bob_endpoint = bob_endpoint_key.public();
            let bob = Identity::generate();
            let bob_signer = AuthorKey::decode_hex(&identity::encode_pubkey(&bob.public()))
                .expect("a 32-byte key");
            let proof = proven_endpoints::sign(&bob_endpoint_key, &node.mesh, &bob_signer);
            let mut json = address_json_with_seal(&iroh::EndpointAddr::new(bob_endpoint));
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

            let mut address = address_json_with_seal(&EndpointAddr::new(author_key.public()));
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
        let deadline = std_Instant::now() + Duration::from_secs(5);
        while std_Instant::now() < deadline {
            if check().await {
                return true;
            }
            tokio_time::sleep(Duration::from_millis(10)).await;
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

        let body = MessageBody::try_new(&address_json_with_seal(address).to_string())
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
        use crate::transport::proven_endpoints;

        let mut address = address_json_with_seal(&iroh::EndpointAddr::new(endpoint_key.public()));
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
    /// the backfill requests of the peer would be answered on gossip until its next `PeerInfo`.
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
            let earlier = now - Duration::from_secs(60);

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
        let parsed = Message::parse(inbound.as_bytes()).expect("parses");
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
                &address_json_with_seal(&iroh::EndpointAddr::new(lower)).to_string(),
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
                &address_json_with_seal(&iroh::EndpointAddr::new(newcomer)).to_string(),
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

    /// A newcomer behind the rendezvous learns our address only from our
    /// `PeerInfo` flood, and the lower endpoint id is the one that dials. Its
    /// first frame to reach us is not always its `joined`: under load its
    /// `State` frame can overtake it. So the flood follows the first frame from a
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

            let mut peer_info_first = fresh_state();
            let json = address_json_with_seal(&iroh::EndpointAddr::new(endpoint_id(7)));
            let body = MessageBody::try_new(&json.to_string()).expect("an address body");
            let first = Message::new_peer_info(&node.mesh, &nick("late"), body).sign(&newcomer);
            ingest(wire(&first), &mut peer_info_first, &mut app, &context).await;
            assert!(
                peer_info_first.peerinfo_flood.is_some(),
                "a newcomer's PeerInfo arrived first, and we never told it our address"
            );

            let mut change_first = fresh_state();
            let change = Message::new_channel_event(
                &node.mesh,
                &nick("late"),
                MessageBody::try_new(r#"{"version":1,"value":{}}"#).expect("a JSON body"),
                Channel::State,
            )
            .sign(&newcomer);
            ingest(wire(&change), &mut change_first, &mut app, &context).await;
            assert!(
                change_first.peerinfo_flood.is_none(),
                "a state frame does not mark its author present"
            );
            node.endpoint.close().await;
        });
    }

    /// An app that records the text of each app frame it is handed.
    // The app and the test share the text of the frames it records.
    struct Recorded(Arc<Mutex<Vec<String>>>);

    #[async_trait::async_trait]
    impl NodeApp for Recorded {
        fn classify(&self, _message: &Authored) -> AppClass {
            AppClass::BEAT.union(AppClass::VALID)
        }

        async fn on_app_frame(
            &mut self,
            frame: InboundApp<'_>,
            _state: &mut EventLoopState,
            _ctx: &HandlerCtx<'_>,
        ) -> bool {
            let text = frame.message.body.as_str().to_owned();
            self.0.lock().expect("no poison").push(text);
            true
        }
    }

    /// A reaped group completes when its author serves the first shard again. The later shard arrived
    /// after the reap, and the repeat of the first shard reaches the store, which completes the group.
    #[test]
    fn a_reaped_shard_group_completes_when_its_first_shard_is_served_again() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let author = Identity::generate();
            let group = ShardGroup::parse_uuid("550e8400-e29b-41d4-a716-446655440000")
                .expect("a valid group");
            let shard = |index: u32, text: &str| {
                let mut message = Message::new_app(
                    &node.mesh,
                    &nick("bob"),
                    AppFrameParams::new(
                        protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                        None,
                        None,
                        MessageBody::from(text),
                    ),
                );
                message.shard = Some(Shard::new(group.clone(), 2).index(index));
                message.sign(&author)
            };
            let wire = |frame: &Verified| frame.serialize().expect("serialize").into_bytes();
            // The app and the test share the frames it records.
            let delivered = Arc::new(Mutex::new(Vec::new()));
            let mut app = Recorded(Arc::clone(&delivered));
            let mut state = fresh_state();

            let first = shard(0, "hello ");
            ingest(wire(&first), &mut state, &mut app, &context).await;
            let reaped_at =
                clock::Instant::now() + consts::REASSEMBLY_STALE + Duration::from_secs(1);
            assert!(
                state.reassembly.sweep_stale(reaped_at) > 0,
                "the partial group was not reaped"
            );
            ingest(wire(&shard(1, "world")), &mut state, &mut app, &context).await;
            ingest(wire(&first), &mut state, &mut app, &context).await;

            assert_eq!(
                *delivered.lock().expect("no poison"),
                ["hello world".to_owned()],
                "the reaped group did not complete when its first shard was served again"
            );
            node.endpoint.close().await;
        });
    }

    /// A repeat of a shard whose group is already surfaced does not reach the lifecycle: it does not
    /// refresh the sighting of its author, as a fresh frame would.
    #[test]
    fn a_shard_of_a_surfaced_group_does_not_refresh_its_author() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let author = Identity::generate();
            let group = ShardGroup::parse_uuid("550e8400-e29b-41d4-a716-446655440000")
                .expect("a valid group");
            let shard = |index: u32, text: &str| {
                let mut message = Message::new_app(
                    &node.mesh,
                    &nick("bob"),
                    AppFrameParams::new(
                        protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                        None,
                        None,
                        MessageBody::from(text),
                    ),
                );
                message.shard = Some(Shard::new(group.clone(), 2).index(index));
                message.sign(&author)
            };
            let wire = |frame: &Verified| frame.serialize().expect("serialize").into_bytes();
            let mut app = Inert;
            let mut state = fresh_state();
            let first = shard(0, "hello ");
            let key = first.key();
            ingest(wire(&first), &mut state, &mut app, &context).await;
            ingest(wire(&shard(1, "world")), &mut state, &mut app, &context).await;
            let surfaced = clock::Instant::now();
            state.last_seen.insert(key, surfaced);
            tokio_time::sleep(Duration::from_millis(5)).await;

            ingest(wire(&first), &mut state, &mut app, &context).await;

            assert_eq!(
                state.last_seen.get(&key),
                Some(&surfaced),
                "a repeat of a surfaced shard refreshed the sighting of its author"
            );
            node.endpoint.close().await;
        });
    }

    /// A group uuid is chosen by its author, so two authors can reuse one. A surfaced group of one
    /// author does not hide the group of the other author.
    #[test]
    fn a_second_author_reusing_a_group_uuid_completes_its_own_group() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let group = ShardGroup::parse_uuid("550e8400-e29b-41d4-a716-446655440000")
                .expect("a valid group");
            let shard = |author: &Identity, index: u32, text: &str| {
                let mut message = Message::new_app(
                    &node.mesh,
                    &nick("bob"),
                    AppFrameParams::new(
                        protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                        None,
                        None,
                        MessageBody::from(text),
                    ),
                );
                message.shard = Some(Shard::new(group.clone(), 2).index(index));
                message.sign(author)
            };
            let wire = |frame: &Verified| frame.serialize().expect("serialize").into_bytes();
            // The app and the test share the frames it records.
            let delivered = Arc::new(Mutex::new(Vec::new()));
            let mut app = Recorded(Arc::clone(&delivered));
            let mut state = fresh_state();
            let (alice, bob) = (Identity::generate(), Identity::generate());

            for (author, first, second) in [(&alice, "alice ", "one"), (&bob, "bob ", "two")] {
                ingest(
                    wire(&shard(author, 0, first)),
                    &mut state,
                    &mut app,
                    &context,
                )
                .await;
                ingest(
                    wire(&shard(author, 1, second)),
                    &mut state,
                    &mut app,
                    &context,
                )
                .await;
            }

            assert_eq!(
                *delivered.lock().expect("no poison"),
                ["alice one".to_owned(), "bob two".to_owned()],
                "the second author's group was hidden by the first author's group uuid"
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

    #[test]
    fn a_copy_that_goes_through_the_restore_still_raises_the_held_event_once() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network::lifecycle",
                "our nickname is held by another member",
            );
            let node = Node::spawn().await;
            let lines = ErrorLines::default();
            let context = HandlerCtx {
                sink: &lines,
                ..node.context()
            };
            let mut state = fresh_state();
            let mut app = Inert;
            let (claimant, other_member) = (Identity::generate(), Identity::generate());
            let (name, mesh_text): (&str, &str) = (node.author.as_ref(), node.mesh.as_ref());
            let proof = other_member.prove(&claimant.author_key(), name, mesh_text, 1);
            let joined: Verified =
                Message::new_joined_with_proof(&node.mesh, &node.author, &proof).sign(&claimant);

            super::restore_lost_proof(&joined, &mut state, &mut app, &context).await;
            super::restore_lost_proof(&joined, &mut state, &mut app, &context).await;

            let seen: Vec<String> = lines
                .0
                .lock()
                .expect("the lines lock is not poisoned")
                .clone();
            let held: usize = seen
                .iter()
                .filter(|line| line.contains("is held by another member"))
                .count();
            assert_eq!(
                held, 1,
                "the copy spent the held signal without a line, or raised it twice: {seen:?}"
            );
            node.endpoint.close().await;
        });
    }

    /// A proof request that came on a cold unlinked arrival is answered by a dial back: the answer
    /// goes to the endpoint of that arrival, and the pool starts the dial to it at once.
    #[test]
    fn a_proof_request_from_a_cold_unlinked_arrival_is_answered_by_a_dial_back() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let asker = Identity::generate();
            let to = state.identity.author_key();
            let request = Message::new_proof_request(&node.mesh, &nick("asker"), to).sign(&asker);
            state.direct.insert(endpoint_id(82), DirectState::Direct);
            state.unicast_arrival = Some(endpoint_id(82));
            let gate = state.unicast_pool.hold_next_dial();

            super::answer_proof_request(&to, &request, &mut state, &context).await;

            assert!(
                state.unicast_pool.is_dialing(endpoint_id(82)),
                "the answer went back by a dial to the cold arrival"
            );
            gate.notify_one();
            node.endpoint.close().await;
        });
    }

    /// The control of the dial back: the asker has a known address that is not the arrival, and the
    /// answer goes to that address by a plain send. The dial back is only to the authenticated
    /// arrival, so nothing dials the known address.
    #[test]
    fn a_proof_request_is_not_dialed_back_to_an_address_that_is_not_the_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let asker = Identity::generate();
            let to = state.identity.author_key();
            let request = Message::new_proof_request(&node.mesh, &nick("asker"), to).sign(&asker);
            state.direct.insert(endpoint_id(82), DirectState::Direct);
            state.direct.insert(endpoint_id(83), DirectState::Direct);
            state.retain_refused_endpoint(
                asker.author_key(),
                iroh::EndpointAddr::new(endpoint_id(83)),
            );
            state.unicast_arrival = Some(endpoint_id(82));

            super::answer_proof_request(&to, &request, &mut state, &context).await;

            assert!(
                !state.unicast_pool.is_dialing(endpoint_id(83)),
                "the answer goes to the known address by a plain send, not by a dial back"
            );
            node.endpoint.close().await;
        });
    }

    /// A root that arrives by broadcast, with no unicast connection, notes nothing.
    #[test]
    fn a_root_that_arrives_by_broadcast_notes_nothing() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let alice = Identity::generate();
            state.peers.insert(alice.author_key());
            state.names.insert(alice.author_key(), nick("alice"));
            state.bind_peer_endpoint(
                alice.author_key(),
                nick("alice"),
                iroh::EndpointAddr::new(endpoint_id(83)),
            );
            let elsewhere =
                DigestRoot::new(ContentHash::of(b"elsewhere"), 1).expect("a root of one page");
            let root: Bytes = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::SliceRoot {
                    to: state.identity.author_key(),
                    state: elsewhere.clone(),
                    meta: elsewhere,
                },
                MessageBody::from("{}"),
            )
            .sign(&alice)
            .serialize()
            .expect("a signed root serializes")
            .into_bytes();
            state.unicast_arrival = None;
            ingest_from(root, &mut state, &mut app, &context).await;
            assert_eq!(
                requests_after_settle(&mut state),
                0,
                "a root that arrived by broadcast notes no difference"
            );
            node.endpoint.close().await;
        });
    }

    /// A page that arrives by broadcast, with no unicast connection, registers no pull, even for a page asked for.
    #[test]
    fn a_page_that_arrives_by_broadcast_registers_no_pull() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let alice = Identity::generate();
            let carol = Identity::generate();
            state.peers.insert(alice.author_key());
            state.names.insert(alice.author_key(), nick("alice"));
            state.bind_peer_endpoint(
                alice.author_key(),
                nick("alice"),
                iroh::EndpointAddr::new(endpoint_id(83)),
            );
            state.peers.insert(carol.author_key());
            let now = clock::Instant::now();
            let elsewhere =
                DigestRoot::new(ContentHash::of(b"elsewhere"), 1).expect("a root of one page");
            state.digest_round.note_root(
                alice.author_key(),
                endpoint_id(83),
                Channel::State,
                &elsewhere,
                false,
                now,
            );
            state.digest_round.advance(now, |_| true, |_, _| false);
            let page = DigestPage::build(
                &[DigestEntry::new(
                    carol.author_key(),
                    1,
                    ContentHash::of(b"row"),
                )],
                1,
                0,
                1,
            )
            .expect("a page of one row");
            let own = state.identity.author_key();
            let signed = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::SlicePage {
                    to: own,
                    channel: Channel::State,
                    page,
                },
                MessageBody::from("{}"),
            )
            .sign(&alice);
            let frame: Bytes = signed
                .serialize()
                .expect("a signed page serializes")
                .into_bytes();
            state.unicast_arrival = None;
            ingest_from(frame, &mut state, &mut app, &context).await;
            assert!(
                !state.outstanding_pulls.take(
                    endpoint_id(83),
                    Channel::State,
                    carol.author_key(),
                    now
                ),
                "a page that arrived by broadcast registers no pull"
            );
            node.endpoint.close().await;
        });
    }

    /// A key that the pull table refused is pulled on the next differing root. With the table full, a page that lists
    /// the key opens no pull; once the table has room, a second root and the page again open it.
    #[test]
    fn a_key_refused_by_a_full_pull_table_is_pulled_on_the_next_root() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let holder = Identity::generate();
            let wanted = Identity::generate();
            state.peers.insert(holder.author_key());
            state.peers.insert(wanted.author_key());
            let filler = |index: usize| -> AuthorKey {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(
                    &u64::try_from(index)
                        .expect("an index fits 64 bits")
                        .to_be_bytes(),
                );
                AuthorKey::from(bytes)
            };
            let own = state.identity.author_key();
            let own_meta = state.docs.digest(Channel::Meta);
            let in_roster = |_: &AuthorKey| true;
            let matches_nothing = |_: Channel, _: &ContentHash| false;
            let start = clock::Instant::now();
            for index in 0..DIGEST_PULLS_OPEN {
                assert!(
                    state.outstanding_pulls.register(
                        endpoint_id(90),
                        Channel::State,
                        filler(index),
                        start,
                        usize::MAX
                    ),
                    "the table takes pulls up to its total cap"
                );
            }
            let elsewhere =
                DigestRoot::new(ContentHash::of(b"elsewhere"), 1).expect("a root of one page");
            let root = || root_frame(&node.mesh, &holder, own, &elsewhere, &own_meta);
            let page = DigestPage::build(
                &[DigestEntry::new(
                    wanted.author_key(),
                    1,
                    ContentHash::of(b"row"),
                )],
                1,
                0,
                1,
            )
            .expect("a page of one row");
            let answer = || page_frame(&node.mesh, &holder, own, &page);
            state.unicast_arrival = Some(endpoint_id(81));
            let first_root = root();
            ingest_from(first_root, &mut state, &mut app, &context).await;
            let first_due = clock::Instant::now() + DIGEST_SETTLE + DIGEST_SETTLE_JITTER;
            state
                .digest_round
                .advance(first_due, in_roster, matches_nothing);
            let first_page = answer();
            ingest_from(first_page, &mut state, &mut app, &context).await;
            assert_eq!(
                state.digest_round.reading_count(),
                0,
                "the page ended the reading of the holder"
            );
            assert!(
                !state.outstanding_pulls.take(
                    endpoint_id(81),
                    Channel::State,
                    wanted.author_key(),
                    first_due
                ),
                "a full table opens no pull for the listed key"
            );
            state
                .outstanding_pulls
                .expire(clock::Instant::now() + DIGEST_PULL_TTL);
            let second_root = root();
            ingest_from(second_root, &mut state, &mut app, &context).await;
            let second_due = clock::Instant::now() + DIGEST_SETTLE + DIGEST_SETTLE_JITTER;
            state
                .digest_round
                .advance(second_due, in_roster, matches_nothing);
            assert_eq!(
                state.digest_round.reading_count(),
                1,
                "the next differing root reads the holder again"
            );
            let second_page = answer();
            ingest_from(second_page, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            assert!(
                state.outstanding_pulls.take(
                    endpoint_id(81),
                    Channel::State,
                    wanted.author_key(),
                    second_due
                ),
                "once the table has room, the next root and page open the pull of the key"
            );
            node.endpoint.close().await;
        });
    }

    /// A lapsed key that returns: its waiting frame is applied when it is seen again, and a later version comes back
    /// through the round. It is never in the gone set, because the sweep released it and did not forget it. The test
    /// sets the lapse by hand, and `release_strangers` is the call that the sweep makes.
    #[test]
    fn a_lapsed_key_returns_and_its_slices_come_back() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let alice = Identity::generate();
            let key = alice.author_key();
            state.peers.insert(key);
            let slice = |version: u64, value: &str| -> Bytes {
                let body = MessageBody::try_new(&format!(
                    r#"{{"version":{version},"value":{{"a":{value}}}}}"#
                ))
                .expect("a slice body");
                Message::new_channel_event(&node.mesh, &nick("alice"), body, Channel::State)
                    .sign(&alice)
                    .serialize()
                    .expect("a signed slice serializes")
                    .into_bytes()
            };
            ingest_from(slice(1, "1"), &mut state, &mut app, &context).await;
            assert!(
                state.docs.held_keys().contains(&key),
                "alice's v1 slice is held while she is a peer"
            );
            state.peers.remove(&key);
            state.clock_evidence.lapsed_quiet.insert(key);
            state.release_strangers();
            assert!(
                !state.docs.held_keys().contains(&key),
                "the sweep releases a lapsed key's slice"
            );
            assert!(
                !state.docs.is_gone(Channel::State, &key),
                "the sweep releases the key and does not forget it"
            );
            ingest_from(slice(2, "2"), &mut state, &mut app, &context).await;
            assert!(
                !state.docs.held_keys().contains(&key),
                "a lapsed key's v2 frame waits in pending"
            );
            let presence: Bytes = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::Presence {
                    subtype: habilis_network_protocol::PresenceSubtype::Alive,
                },
                MessageBody::from("{}"),
            )
            .sign(&alice)
            .serialize()
            .expect("a signed presence serializes")
            .into_bytes();
            ingest_from(presence, &mut state, &mut app, &context).await;
            assert!(
                state.docs.held_keys().contains(&key),
                "alice's return applies her waiting v2 frame"
            );
            let elsewhere =
                DigestRoot::new(ContentHash::of(b"elsewhere"), 1).expect("a root of one page");
            let root: Bytes = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::SliceRoot {
                    to: state.identity.author_key(),
                    state: elsewhere.clone(),
                    meta: elsewhere,
                },
                MessageBody::from("{}"),
            )
            .sign(&alice)
            .serialize()
            .expect("a signed root serializes")
            .into_bytes();
            state.unicast_arrival = Some(endpoint_id(83));
            ingest_from(root, &mut state, &mut app, &context).await;
            let later = clock::Instant::now() + DIGEST_SETTLE + DIGEST_SETTLE_JITTER;
            // every holder is in the roster, and no root matches the store
            state.digest_round.advance(later, |_| true, |_, _| false);
            let page =
                DigestPage::build(&[DigestEntry::new(key, 3, ContentHash::of(b"v3"))], 1, 0, 1)
                    .expect("a page of one row");
            let answer: Bytes = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::SlicePage {
                    to: state.identity.author_key(),
                    channel: Channel::State,
                    page,
                },
                MessageBody::from("{}"),
            )
            .sign(&alice)
            .serialize()
            .expect("a signed page serializes")
            .into_bytes();
            ingest_from(answer, &mut state, &mut app, &context).await;
            assert!(
                state
                    .outstanding_pulls
                    .is_open(endpoint_id(83), Channel::State, key),
                "the round opened the pull of the returned key"
            );
            ingest_from(slice(3, "3"), &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            assert!(
                !state
                    .outstanding_pulls
                    .take(endpoint_id(83), Channel::State, key, later),
                "the v3 answer used the pull that the round opened"
            );
            let view = state.view(Channel::State);
            let v3_held: bool = view
                .as_object()
                .is_some_and(|slices| slices.values().any(|slot| slot["a"] == 3));
            assert!(v3_held, "the pulled v3 slice reaches the view");
            assert!(
                !state.docs.is_gone(Channel::State, &key),
                "alice is not gone after her return"
            );
            node.endpoint.close().await;
        });
    }

    /// A key that lapsed and returns gets its slice back by the digest round: its root differs, its page is read, and
    /// the pull of its key is registered.
    #[test]
    fn a_returned_key_is_pulled_from_a_differing_page() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let alice = Identity::generate();
            let key = alice.author_key();
            state.peers.insert(key);
            state.clock_evidence.lapsed_quiet.insert(key);
            state.peers.remove(&key);
            state.release_strangers();
            state.clock_evidence.lapsed_quiet.remove(&key);
            state.peers.insert(key);
            let elsewhere =
                DigestRoot::new(ContentHash::of(b"elsewhere"), 1).expect("a root of one page");
            let root: Bytes = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::SliceRoot {
                    to: state.identity.author_key(),
                    state: elsewhere.clone(),
                    meta: elsewhere,
                },
                MessageBody::from("{}"),
            )
            .sign(&alice)
            .serialize()
            .expect("a signed root serializes")
            .into_bytes();
            state.unicast_arrival = Some(endpoint_id(83));
            ingest_from(root, &mut state, &mut app, &context).await;
            let later = clock::Instant::now() + DIGEST_SETTLE + DIGEST_SETTLE_JITTER;
            let requests = state.digest_round.advance(later, |_| true, |_, _| false);
            assert_eq!(
                requests.len(),
                2,
                "the round asks for the first page of each channel of the returned key's digest"
            );
            let page = DigestPage::build(
                &[DigestEntry::new(key, 2, ContentHash::of(b"row"))],
                1,
                0,
                1,
            )
            .expect("a page of one row");
            let answer: Bytes = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::SlicePage {
                    to: state.identity.author_key(),
                    channel: Channel::State,
                    page,
                },
                MessageBody::from("{}"),
            )
            .sign(&alice)
            .serialize()
            .expect("a signed page serializes")
            .into_bytes();
            ingest_from(answer, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            assert!(
                state
                    .outstanding_pulls
                    .take(endpoint_id(83), Channel::State, key, later),
                "the pull of the returned key is registered"
            );
            node.endpoint.close().await;
        });
    }

    /// A frame of a key that lapsed quiet waits in the pending set: it is not applied, so the view does not hold it.
    #[test]
    fn a_frame_of_a_lapsed_key_waits_in_the_pending_set() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let alice = Identity::generate();
            state.clock_evidence.lapsed_quiet.insert(alice.author_key());
            let body = MessageBody::try_new(r#"{"version":1,"value":{"a":1}}"#).expect("a body");
            let frame: Bytes =
                Message::new_channel_event(&node.mesh, &nick("alice"), body, Channel::State)
                    .sign(&alice)
                    .serialize()
                    .expect("a signed slice serializes")
                    .into_bytes();
            ingest_from(frame, &mut state, &mut app, &context).await;
            assert!(
                !state.docs.held_keys().contains(&alice.author_key()),
                "a lapsed key's frame is not applied"
            );
            assert!(
                state
                    .docs
                    .take_pending(Channel::State, &alice.author_key(), clock::Instant::now())
                    .is_some(),
                "a lapsed key's frame waits in the pending set"
            );
            node.endpoint.close().await;
        });
    }

    /// A key that lapsed quiet keeps no slice: the sweep that lapses it releases the slice that it held.
    #[test]
    fn a_lapsed_key_keeps_no_slice() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let alice = Identity::generate();
            state.peers.insert(alice.author_key());
            let body = MessageBody::try_new(r#"{"version":1,"value":{"a":1}}"#).expect("a body");
            let frame: Bytes =
                Message::new_channel_event(&node.mesh, &nick("alice"), body, Channel::State)
                    .sign(&alice)
                    .serialize()
                    .expect("a signed slice serializes")
                    .into_bytes();
            ingest_from(frame, &mut state, &mut app, &context).await;
            assert!(
                state.docs.held_keys().contains(&alice.author_key()),
                "alice's slice is held while she is in the roster"
            );
            state.peers.remove(&alice.author_key());
            state.clock_evidence.lapsed_quiet.insert(alice.author_key());
            state.release_strangers();
            assert!(
                !state.docs.held_keys().contains(&alice.author_key()),
                "a lapsed key keeps no slice after the sweep"
            );
            node.endpoint.close().await;
        });
    }

    /// The signed `SliceRoot` that `holder` sends to `to`, with its State and Meta digests.
    fn root_frame(
        mesh: &MeshId,
        holder: &Identity,
        to: AuthorKey,
        state: &DigestRoot,
        meta: &DigestRoot,
    ) -> Bytes {
        let kind = MessageKind::SliceRoot {
            to,
            state: state.clone(),
            meta: meta.clone(),
        };
        let signed =
            Message::new_frame(mesh, &nick("holder"), kind, MessageBody::from("{}")).sign(holder);
        signed
            .serialize()
            .expect("a signed root serializes")
            .into_bytes()
    }

    /// The signed `SlicePage` of the State channel that `holder` sends to `to`.
    fn page_frame(mesh: &MeshId, holder: &Identity, to: AuthorKey, page: &DigestPage) -> Bytes {
        let kind = MessageKind::SlicePage {
            to,
            channel: Channel::State,
            page: page.clone(),
        };
        let signed =
            Message::new_frame(mesh, &nick("holder"), kind, MessageBody::from("{}")).sign(holder);
        signed
            .serialize()
            .expect("a signed page serializes")
            .into_bytes()
    }

    /// The differences that the round would read once the settle of the latest one has ended.
    fn requests_after_settle(state: &mut EventLoopState) -> usize {
        let later = clock::Instant::now() + DIGEST_SETTLE + DIGEST_SETTLE_JITTER;
        state
            .digest_round
            .advance(later, |_| true, |_, _| false)
            .len()
    }

    /// A root from a roster peer that names this node, sent by unicast, notes the difference of both channels.
    #[test]
    fn a_root_from_a_roster_peer_notes_a_difference() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let alice = Identity::generate();
            state.peers.insert(alice.author_key());
            let elsewhere =
                DigestRoot::new(ContentHash::of(b"elsewhere"), 1).expect("a root of one page");
            let root: Bytes = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::SliceRoot {
                    to: state.identity.author_key(),
                    state: elsewhere.clone(),
                    meta: elsewhere,
                },
                MessageBody::from("{}"),
            )
            .sign(&alice)
            .serialize()
            .expect("a signed root serializes")
            .into_bytes();
            state.unicast_arrival = Some(endpoint_id(83));
            ingest_from(root, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            assert_eq!(
                requests_after_settle(&mut state),
                2,
                "both channels of the roster peer's root are noted"
            );
            node.endpoint.close().await;
        });
    }

    /// A root that names another key is not this node's to note: the round stays empty.
    #[test]
    fn a_root_for_another_key_notes_nothing() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let alice = Identity::generate();
            state.peers.insert(alice.author_key());
            let elsewhere =
                DigestRoot::new(ContentHash::of(b"elsewhere"), 1).expect("a root of one page");
            let root: Bytes = Message::new_frame(
                &node.mesh,
                &nick("alice"),
                MessageKind::SliceRoot {
                    to: Identity::generate().author_key(),
                    state: elsewhere.clone(),
                    meta: elsewhere,
                },
                MessageBody::from("{}"),
            )
            .sign(&alice)
            .serialize()
            .expect("a signed root serializes")
            .into_bytes();
            state.unicast_arrival = Some(endpoint_id(83));
            ingest_from(root, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            assert_eq!(
                requests_after_settle(&mut state),
                0,
                "a root for another key notes no difference"
            );
            node.endpoint.close().await;
        });
    }

    /// A root from a key that is not in the roster notes nothing.
    #[test]
    fn a_root_from_a_stranger_notes_nothing() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let stranger = Identity::generate();
            let elsewhere =
                DigestRoot::new(ContentHash::of(b"elsewhere"), 1).expect("a root of one page");
            let root: Bytes = Message::new_frame(
                &node.mesh,
                &nick("stranger"),
                MessageKind::SliceRoot {
                    to: state.identity.author_key(),
                    state: elsewhere.clone(),
                    meta: elsewhere,
                },
                MessageBody::from("{}"),
            )
            .sign(&stranger)
            .serialize()
            .expect("a signed root serializes")
            .into_bytes();
            state.unicast_arrival = Some(endpoint_id(83));
            ingest_from(root, &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            assert_eq!(
                requests_after_settle(&mut state),
                0,
                "a root from a stranger notes no difference"
            );
            node.endpoint.close().await;
        });
    }

    /// A page that this node asked for registers the pulls of its keys. A page that it did not ask for registers
    /// none.
    #[test]
    fn a_page_is_pulled_only_when_it_was_asked_for() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = Node::spawn().await;
            let context = node.context();
            let mut state = fresh_state();
            let mut app = Inert;
            let alice = Identity::generate();
            let carol = Identity::generate();
            state.peers.insert(alice.author_key());
            state.peers.insert(carol.author_key());
            let page = DigestPage::build(
                &[DigestEntry::new(
                    carol.author_key(),
                    1,
                    ContentHash::of(b"row"),
                )],
                1,
                0,
                1,
            )
            .expect("a page of one row");
            let own = state.identity.author_key();
            let frame = |digest: DigestPage| -> Bytes {
                let signed = Message::new_frame(
                    &node.mesh,
                    &nick("alice"),
                    MessageKind::SlicePage {
                        to: own,
                        channel: Channel::State,
                        page: digest,
                    },
                    MessageBody::from("{}"),
                )
                .sign(&alice);
                signed
                    .serialize()
                    .expect("a signed page serializes")
                    .into_bytes()
            };
            let now = clock::Instant::now();
            state.unicast_arrival = Some(endpoint_id(83));
            ingest_from(frame(page.clone()), &mut state, &mut app, &context).await;
            assert!(
                !state.outstanding_pulls.take(
                    endpoint_id(83),
                    Channel::State,
                    carol.author_key(),
                    now
                ),
                "a page that was not asked for registers no pull"
            );
            let elsewhere =
                DigestRoot::new(ContentHash::of(b"elsewhere"), 1).expect("a root of one page");
            state.digest_round.note_root(
                alice.author_key(),
                endpoint_id(83),
                Channel::State,
                &elsewhere,
                false,
                now,
            );
            state.digest_round.advance(now, |_| true, |_, _| false);
            ingest_from(frame(page), &mut state, &mut app, &context).await;
            state.unicast_arrival = None;
            assert!(
                state.outstanding_pulls.take(
                    endpoint_id(83),
                    Channel::State,
                    carol.author_key(),
                    now
                ),
                "a page that was asked for registers the pull of its key"
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

/// A repeated chat broadcast frame reaches the app once: the seen set drops the repeat.
#[cfg(test)]
mod repeat_tests {
    use std::sync::{Arc, Mutex};

    use iroh::endpoint::presets;
    use iroh_gossip::net::Gossip;
    use iroh_gossip::proto;

    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::state::EventLoopState;
    use crate::gossip::app::{AppClass, InboundApp, NodeApp};
    use crate::gossip::event::SilentSink;
    use crate::protocol::identity::Identity;
    use crate::protocol::messages::{AppFrameParams, Authored};
    use crate::protocol::{AppTag, MeshId, Message, MessageBody};
    use crate::testing::{endpoint_id, fresh_state, nick};
    use crate::transport::MeshSender;

    /// Counts the chat frames the app is handed.
    struct Counting(Arc<Mutex<usize>>);

    #[async_trait::async_trait]
    impl NodeApp for Counting {
        fn classify(&self, _message: &Authored) -> AppClass {
            AppClass::PUSH.union(AppClass::VALID)
        }

        async fn on_app_frame(
            &mut self,
            _frame: InboundApp<'_>,
            _state: &mut EventLoopState,
            _ctx: &HandlerCtx<'_>,
        ) -> bool {
            *self.0.lock().expect("the counter lock") += 1;
            false
        }
    }

    #[test]
    fn a_repeated_chat_broadcast_is_surfaced_once() {
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
            let peer = Identity::generate();
            let reader_nick = nick("reader");
            let sink = SilentSink;
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
                sink: &sink,
            };
            let chat = Message::new_app(
                &mesh,
                &nick("peer"),
                AppFrameParams::new(
                    AppTag::try_new("app_msg").expect("a valid app tag"),
                    None,
                    None,
                    MessageBody::from("\"hello\""),
                ),
            )
            .sign(&peer);
            let bytes = chat.serialize().expect("serialize").into_bytes();
            let mut state = fresh_state();
            // Shared with the app, which counts the frames it is handed.
            let surfaced = Arc::new(Mutex::new(0));
            let mut app = Counting(Arc::clone(&surfaced));
            super::ingest(bytes.clone(), &mut state, &mut app, &context).await;
            super::ingest(bytes, &mut state, &mut app, &context).await;
            let count = *surfaced.lock().expect("the counter lock");
            assert_eq!(
                count, 1,
                "a repeated chat frame must reach the app once, got {count}"
            );
            endpoint.close().await;
        });
    }
}

#[cfg(test)]
mod dedup_counter_tests {
    use iroh::endpoint::presets;
    use iroh_gossip::net::Gossip;
    use iroh_gossip::proto;

    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::state::EventLoopState;
    use crate::gossip::app::{AppClass, InboundApp, NodeApp};
    use crate::gossip::event::{NodeEvent, NodeSink, SilentSink};
    use crate::lifecycle;
    use crate::protocol::identity::Identity;
    use crate::protocol::messages::{Authored, Verified};
    use crate::protocol::{AuthorKey, MeshId, Message, MessageKind, PresenceSubtype};
    use crate::testing::{address_json_with_seal, endpoint_id, fresh_state, nick};
    use crate::transport::MeshSender;
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

    /// [`reader_after_on`] for a reader that starts as `initial`.
    fn reader_with(initial: EventLoopState, arrivals: Vec<Bytes>) -> EventLoopState {
        reader_with_sink(initial, arrivals, &SilentSink)
    }

    /// [`reader_with`] with the sink that receives the events of the arrivals.
    fn reader_with_sink(
        initial: EventLoopState,
        arrivals: Vec<Bytes>,
        sink: &dyn NodeSink,
    ) -> EventLoopState {
        reader_full(initial, arrivals, sink, None)
    }

    /// [`reader_with_sink`], and then, with an endpoint: that endpoint becomes a linked neighbour, and a frame
    /// from it is taken to have arrived on a unicast connection, so the asks that waited for a path are tried.
    fn reader_full(
        initial: EventLoopState,
        arrivals: Vec<Bytes>,
        sink: &dyn NodeSink,
        path_up: Option<lifecycle::PathSign>,
    ) -> EventLoopState {
        reader_run(initial, arrivals, sink, path_up, &[])
    }

    /// [`reader_with_sink`] for a test whose subject is a WARN: each `(target, text)` is expected from the run.
    fn reader_expecting(
        initial: EventLoopState,
        arrivals: Vec<Bytes>,
        sink: &dyn NodeSink,
        expected: &[(&str, &str)],
    ) -> EventLoopState {
        reader_run(initial, arrivals, sink, None, expected)
    }

    fn reader_run(
        initial: EventLoopState,
        arrivals: Vec<Bytes>,
        sink: &dyn NodeSink,
        path_up: Option<lifecycle::PathSign>,
        expected: &[(&str, &str)],
    ) -> EventLoopState {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            for (target, text) in expected {
                ::habilis_network_test_tracing::expect_warn(target, text);
            }
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
            for bytes in arrivals {
                super::ingest_from(bytes, &mut reader, &mut app, &context).await;
            }
            if let Some(sign) = path_up {
                if let lifecycle::PathSign::LinkUp(up) = sign {
                    reader.linked_endpoints.insert(up);
                }
                lifecycle::retry_deferred_asks(&mut reader, &context, Some(sign)).await;
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

    /// An alive frame of a session, as the bytes that arrive.
    fn alive_of(session: &Identity, nickname: &str) -> Bytes {
        let frame = Message::new_alive(&MeshId::from("test"), &nick(nickname)).sign(session);
        frame.serialize().expect("serialize").into_bytes()
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
        let frame = left.serialize().expect("serialize").into_bytes();

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

    /// The `PeerInfo` of a session that the roster gate refuses still gives its address: the session is
    /// asked for its proof over a warm path, and it has none without the address. The frame binds no
    /// hint and adds no roster entry.
    #[test]
    fn a_refused_session_peer_info_registers_the_address_for_the_proof_request() {
        use crate::protocol::messages::MessageBody;

        let bound = Identity::generate();
        let intruder = Identity::generate();
        let initial = state_with_bound_nickname(&bound, "alice");
        let json = address_json_with_seal(&iroh::EndpointAddr::new(endpoint_id(61)));
        let body = MessageBody::try_new(&json.to_string()).expect("an address body");
        let peer_info =
            Message::new_peer_info(&MeshId::from("test"), &nick("alice"), body).sign(&intruder);
        let frame = peer_info.serialize().expect("serialize").into_bytes();

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

        let session = Identity::generate();
        let address = iroh::EndpointAddr::new(endpoint_id(62));
        let mut initial = fresh_state();
        initial.linked_endpoints.insert(endpoint_id(62));
        let json = address_json_with_seal(&address);
        let body = MessageBody::try_new(&json.to_string()).expect("an address body");
        let peer_info =
            Message::new_peer_info(&MeshId::from("test"), &nick("carol"), body).sign(&session);
        let info = peer_info.serialize().expect("serialize").into_bytes();

        let reader = reader_with(initial, vec![alive_of(&session, "carol"), info]);

        assert_eq!(
            reader.ask_dial_addrs,
            vec![Some(address)],
            "the proof request went before the pool remembered the address of its endpoint"
        );
    }

    /// A joined frame of a session, as the bytes that arrive on the gossip plane, with the proof of
    /// `member` for its `run`.
    fn joined_of(session: &Identity, member: &Identity, nickname: &str, run: u64) -> Bytes {
        let proof = member.prove(
            &session.author_key(),
            nickname,
            MeshId::from("test").as_ref(),
            run,
        );
        let frame = Message::new_joined_with_proof(&MeshId::from("test"), &nick(nickname), &proof)
            .sign(session);
        frame.serialize().expect("serialize").into_bytes()
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
        let second = joined_of(&new, &member, "alice", 2);
        let reader = reader_with(initial, vec![second]);

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
        let joined = proved.serialize().expect("serialize").into_bytes();

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

    /// A sink that counts the lines that say that a newer run of our member is active.
    #[derive(Default)]
    struct SupersededLines(Mutex<usize>);

    impl NodeSink for SupersededLines {
        fn emit(&self, event: NodeEvent) {
            if let NodeEvent::Error(text) = event
                && text.contains("newer run of this member")
            {
                *self.0.lock().expect("the count lock is not poisoned") += 1;
            }
        }
    }

    /// A sink that counts the lines that say that our nickname is held by another member.
    #[derive(Default)]
    struct HeldLines(Mutex<usize>);

    impl NodeSink for HeldLines {
        fn emit(&self, event: NodeEvent) {
            if let NodeEvent::Error(text) = event
                && text.contains("is held by another member")
            {
                *self.0.lock().expect("the count lock is not poisoned") += 1;
            }
        }
    }

    /// The claimant of a nickname must learn that another member holds it, once, whatever the order of the
    /// frames of that member: its alive frame (refused under our nickname), its `joined` frame with the proof,
    /// the same `joined` frame again (a duplicate), and an old copy of a `joined` frame with the same proof
    /// (stamped 3 days ago, a different frame). Every order of the four gives exactly one line.
    #[test]
    fn the_claimant_of_a_nickname_is_told_once_whatever_the_order_of_the_frames_of_the_other_member()
     {
        let (member, session) = (Identity::generate(), Identity::generate());
        let alive = alive_of(&session, "reader");
        let joined = joined_of(&session, &member, "reader", 1);
        let old = old_joined_of(&session, &member, "reader", 3 * 86_400);
        let frames = [alive, joined.clone(), joined, old];
        let mut orders = 0_usize;
        for first in 0..4 {
            for second in (0..4).filter(|index| *index != first) {
                for third in (0..4).filter(|index| *index != first && *index != second) {
                    let fourth = 6 - first - second - third;
                    let arrivals: Vec<Bytes> = [first, second, third, fourth]
                        .iter()
                        .map(|index| frames[*index].clone())
                        .collect();
                    let lines = HeldLines::default();

                    reader_expecting(
                        fresh_state(),
                        arrivals,
                        &lines,
                        &[(
                            "habilis_network::lifecycle",
                            "our nickname is held by another member",
                        )],
                    );

                    let told = *lines.0.lock().expect("the count lock is not poisoned");
                    assert_eq!(
                        told, 1,
                        "the order {first}, {second}, {third}, {fourth} gave {told} lines that our nickname is held"
                    );
                    orders += 1;
                }
            }
        }
        assert_eq!(orders, 24, "every order of the four frames was tried");
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
    /// or a backfill answer hands out long after its author spoke.
    fn old_joined_of(
        session: &Identity,
        member: &Identity,
        nickname: &str,
        age_secs: i64,
    ) -> Bytes {
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
        frame.serialize().expect("serialize").into_bytes()
    }

    /// A `joined` frame of `member` for `run`, stamped `age_secs` seconds ago.
    fn old_joined_run_of(session: &Identity, member: &Identity, run: u64, age_secs: i64) -> Bytes {
        use crate::protocol::UnixSecs;
        let proof = member.prove(
            &session.author_key(),
            "alice",
            MeshId::from("test").as_ref(),
            run,
        );
        let mut message =
            Message::new_joined_with_proof(&MeshId::from("test"), &nick("alice"), &proof);
        message.timestamp = UnixSecs::from(UnixSecs::now().as_secs() - age_secs);
        let frame = message.sign(session);
        frame.serialize().expect("serialize").into_bytes()
    }

    /// The end that waits for a claimant stays until a frame of that claimant under the PROVED nickname comes. A
    /// frame of the same session under another nickname (`bob`) is admitted, and it must not use up the wait:
    /// the later frame under `alice` would then leave the other session in the roster, with no end.
    #[test]
    fn a_frame_under_another_nickname_does_not_use_up_the_wait_of_a_claimant() {
        let member = Identity::generate();
        let (member_session, other_session) = (Identity::generate(), Identity::generate());
        let waiting = reader_with(
            fresh_state(),
            vec![
                alive_of(&other_session, "alice"),
                old_joined_of(&member_session, &member, "alice", 3 * 86_400),
            ],
        );
        assert!(
            waiting.peers.contains(&other_session.author_key()),
            "the old frame ended nothing: the end waits for its sender"
        );

        let as_bob = reader_with(waiting, vec![alive_of(&member_session, "bob")]);
        assert!(
            as_bob.peers.contains(&other_session.author_key()),
            "a frame under another nickname ended the other session"
        );

        let as_alice = reader_with(as_bob, vec![alive_of(&member_session, "alice")]);

        assert!(
            !as_alice.peers.contains(&other_session.author_key()),
            "the wait was used up by the frame under another nickname: the other session stays in the roster"
        );
    }

    /// A member that restored a lower run counter has a live session at run 3. An unseen historical `joined`
    /// frame of the same member at run 9 (stamped 3 days ago) must not replace it: the live session would end,
    /// with the frames that wait for it, for a session that is not there. A FRESH `joined` of a real restart at a
    /// higher run is presence, and it replaces the old session at once: that case must stay as it is.
    #[test]
    fn a_historical_joined_of_a_member_with_a_higher_run_does_not_replace_its_live_session() {
        let member = Identity::generate();
        let (live, historical, restart) = (
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        );
        let first = reader_with(fresh_state(), vec![joined_of(&live, &member, "alice", 3)]);
        assert!(
            first.peers.contains(&live.author_key()),
            "the live session is in the roster"
        );

        let replayed = reader_with(
            first,
            vec![old_joined_run_of(&historical, &member, 9, 3 * 86_400)],
        );

        assert!(
            replayed.peers.contains(&live.author_key()),
            "a historical joined of the same member at a higher run ended its live session"
        );
        assert!(
            !replayed.peers.contains(&historical.author_key()),
            "the sender of a historical frame entered the roster"
        );

        let restarted = reader_with(replayed, vec![joined_of(&restart, &member, "alice", 9)]);

        assert!(
            restarted.peers.contains(&restart.author_key())
                && !restarted.peers.contains(&live.author_key()),
            "a fresh joined of a real restart at a higher run did not replace the old session at once"
        );
    }

    /// The cached answer of a real NEWER session (run 9) is one frame for its whole run, stamped when it was first
    /// signed: for a session that runs long it is OLD, and it proves no presence. While run 3 of the same member is
    /// live, the frame must not replace it, and its proof must not be lost: it is kept inactive, and it admits its
    /// own session. The nickname is bound to the SAME member by run 3, so the alive frames of run 9 are admitted by
    /// the kept proof, run 9 enters the roster, and then it replaces run 3. Without that, run 9 is refused for good
    /// (it has no proof) and its answers are dropped (it is not in the roster): a deadlock.
    #[test]
    fn the_old_answer_of_a_real_newer_run_is_kept_and_its_session_is_admitted_when_it_shows_presence()
     {
        let member = Identity::generate();
        let (live, newer) = (Identity::generate(), Identity::generate());
        let first = reader_with(fresh_state(), vec![joined_of(&live, &member, "alice", 3)]);
        assert!(
            first.peers.contains(&live.author_key()),
            "the live run 3 is in the roster"
        );

        let answered = reader_with(
            first,
            vec![old_joined_run_of(&newer, &member, 9, 3 * 86_400)],
        );

        assert!(
            answered.peers.contains(&live.author_key()),
            "the old answer of run 9 ended the live run 3"
        );
        let shown = reader_with(answered, vec![alive_of(&newer, "alice")]);

        assert!(
            shown.peers.contains(&newer.author_key()),
            "the newer session was refused although its answer proved its member: its proof was lost"
        );
        assert!(
            !shown.peers.contains(&live.author_key()),
            "run 3 stays beside run 9 after run 9 showed presence"
        );
    }

    /// The old answer of a NEWER run of OUR OWN member (this node was restarted elsewhere) is kept inactive, as any
    /// old answer is. The gate of our own nickname admits the alive frames of that session on the kept proof, and when
    /// the session shows presence the proof is active before the report: this node is told once that it is superseded.
    #[test]
    fn the_pending_proof_of_a_newer_run_of_our_member_admits_it_and_the_supersession_is_reported() {
        use crate::protocol::UnixSecs;
        let lines = SupersededLines::default();
        let state = fresh_state();
        let member = state
            .member_identity
            .clone()
            .expect("a test state has a member key");
        let newer = Identity::generate();
        let mesh = MeshId::from("test");
        let proof = member.prove(&newer.author_key(), "reader", mesh.as_ref(), 6);
        let mut old = Message::new_joined_with_proof(&mesh, &nick("reader"), &proof);
        old.timestamp = UnixSecs::from(UnixSecs::now().as_secs() - 3 * 86_400);
        let signed: Verified = old.sign(&newer);
        let old_answer = signed.serialize().expect("serialize").into_bytes();
        let alive = alive_of(&newer, "reader");

        let shown = reader_expecting(
            state,
            vec![old_answer, alive],
            &lines,
            &[(
                "habilis_network::lifecycle",
                "a newer run of our member is active",
            )],
        );

        let told = *lines.0.lock().expect("the count lock is not poisoned");
        assert!(
            shown.peers.contains(&newer.author_key()),
            "the newer run of our member was refused although its answer proved it"
        );
        assert_eq!(told, 1, "this node was not told once that it is superseded");
    }

    /// The one cached answer of a session is a duplicate when it comes again. If the pending proof of that session was
    /// dropped (the cap of its class, a forget) while the session is refused and so not in the roster, the duplicate
    /// gives the proof back as a pending proof, and nothing more: it binds nothing and replaces nothing. Else the
    /// session stays refused for good: it has no proof, and its only answer is dropped as a duplicate.
    #[test]
    fn a_duplicate_answer_gives_back_the_pending_proof_of_a_session_that_is_not_in_the_roster() {
        let member = Identity::generate();
        let (live, newer) = (Identity::generate(), Identity::generate());
        let (live_key, newer_key) = (live.author_key(), newer.author_key());
        let answer = old_joined_run_of(&newer, &member, 9, 3 * 86_400);
        let first = reader_with(fresh_state(), vec![joined_of(&live, &member, "alice", 3)]);
        let mut kept = reader_with(first, vec![answer.clone()]);
        assert!(
            kept.proofs.has_pending(&newer_key),
            "the old answer is kept pending"
        );
        kept.proofs.forget(&newer_key);

        let restored = reader_with(kept, vec![answer]);

        assert!(
            restored.proofs.has_pending(&newer_key),
            "the duplicate answer did not give back the pending proof of a session that is not in the roster"
        );
        assert!(
            restored.proofs.proof_of(&newer_key).is_none() && restored.peers.contains(&live_key),
            "the restored proof bound the nickname or replaced the live run 3"
        );
        let shown = reader_with(restored, vec![alive_of(&newer, "alice")]);
        assert!(
            shown.peers.contains(&newer_key),
            "the session of the restored proof was refused"
        );
    }

    /// A session that is not a live peer claims a bound nickname when a member of the roster holds that nickname by its
    /// proof: that is what gives its first proof request a place in the reserve of the claims. A live peer, and a
    /// session under a free nickname, do not claim one.
    #[test]
    fn a_session_claims_a_bound_nickname_only_when_a_member_of_the_roster_holds_it() {
        let member = Identity::generate();
        let (live, newer, stranger) = (
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        );
        let state = reader_with(fresh_state(), vec![joined_of(&live, &member, "alice", 3)]);

        assert!(
            state.claims_bound_nickname(&newer.author_key(), &nick("alice"), &nick("reader")),
            "a session that is no peer and claims the nickname of a member of the roster is a claim"
        );
        assert!(
            !state.claims_bound_nickname(&live.author_key(), &nick("alice"), &nick("reader")),
            "a live peer is no claim"
        );
        assert!(
            !state.claims_bound_nickname(&stranger.author_key(), &nick("bob"), &nick("reader")),
            "a free nickname is no claim"
        );
    }

    /// A quiet peer whose clock stepped back returns after a run of rising frames (the roster rule of `observe`).
    /// The check before `observe` is pure and reads the last frame of the run as stale, so a pending proof of that peer
    /// was not activated when the peer entered the roster. The proof is activated right after `observe`: the peer
    /// that is back holds its nickname.
    #[test]
    fn the_pending_proof_of_a_peer_whose_clock_stepped_back_is_activated_when_the_run_returns_it() {
        use crate::lifecycle::membership_update::STEP_BACK_FRAMES;
        use crate::protocol::UnixSecs;
        use crate::util::clock::Instant;
        use std::time::Duration;
        let (member, session) = (Identity::generate(), Identity::generate());
        let key = session.author_key();
        let mut state = fresh_state();
        state.quiet.insert(key);
        state.names.insert(key, nick("alice"));
        let heard = Instant::now()
            .checked_sub(Duration::from_secs(100))
            .expect("the monotonic clock has run past 100 s since boot");
        state.quiet_since.insert(key, heard);
        // its newest stamp is an hour ahead of the new base of its clock
        state
            .peer_stamp
            .insert(key, UnixSecs::now() + Duration::from_hours(1));
        let mut state = reader_with(
            state,
            vec![old_joined_run_of(&session, &member, 1, 3 * 86_400)],
        );
        assert!(
            state.proofs.has_pending(&key) && state.proofs.proof_of(&key).is_none(),
            "the old answer of the quiet peer is kept pending"
        );

        for index in 0..STEP_BACK_FRAMES {
            let mut alive = Message::new_alive(&MeshId::from("test"), &nick("alice"));
            alive.timestamp = UnixSecs::now() + Duration::from_secs(u64::from(index) * 20);
            let signed: Verified = alive.sign(&session);
            let frame = signed.serialize().expect("serialize").into_bytes();
            state = reader_with(state, vec![frame]);
            // the next frame comes one alive interval later on our clock
            if let Some(run) = state.clock_evidence.step_back.get_mut(&key) {
                run.at = run
                    .at
                    .checked_sub(Duration::from_secs(20))
                    .expect("the monotonic clock has run past 20 s since boot");
            }
        }

        assert!(
            state.peers.contains(&key),
            "the run of frames did not return the peer"
        );
        assert!(
            state.proofs.proof_of(&key).is_some(),
            "the peer is back in the roster and its proof is still pending: the nickname is not bound"
        );
    }

    /// An old `joined` frame of a QUIET session does not bind the nickname: a quiet session counts as held in the
    /// roster, so a proof that is kept for it would refuse the frames of a live session of another member under
    /// that nickname, whose arrival has not proved anything yet. The kept proof does nothing until its session
    /// proves presence; then it binds and ends the other session.
    #[test]
    fn an_old_joined_of_a_quiet_session_does_not_bind_the_nickname_against_a_live_session() {
        let (member, quiet, live) = (
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        );
        let mut initial = fresh_state();
        initial.quiet.insert(quiet.author_key());
        initial.names.insert(quiet.author_key(), nick("alice"));
        let with_live = reader_with(initial, vec![alive_of(&live, "alice")]);
        assert!(
            with_live.peers.contains(&live.author_key()),
            "the live session under the free nickname is in the roster"
        );

        let mut after_old = reader_with(
            with_live,
            vec![old_joined_run_of(&quiet, &member, 1, 3 * 86_400)],
        );

        let again: Verified = Message::new_alive(&MeshId::from("test"), &nick("alice")).sign(&live);
        assert!(
            after_old.admits_session(&again, &nick("reader")),
            "an old joined of a quiet session bound the nickname: the live session was refused"
        );
        assert!(
            after_old.proofs.proof_of(&quiet.author_key()).is_none(),
            "the proof of a quiet sender that proved no presence is active"
        );
    }

    /// A duplicate `joined` of a QUIET session gives its proof back only to a session that is live. A quiet
    /// session that got its proof back would bind the nickname (it counts as held in the roster), and the live
    /// session of another member under that nickname would be refused and ended.
    #[test]
    fn a_duplicate_joined_of_a_quiet_session_does_not_end_a_live_session() {
        let member = Identity::generate();
        let (quiet, live) = (Identity::generate(), Identity::generate());
        let frame = joined_of(&quiet, &member, "alice", 1);
        let mut state = reader_with(fresh_state(), vec![frame.clone()]);
        assert!(
            state.proofs.proof_of(&quiet.author_key()).is_some(),
            "the proof of the session is held after its frame"
        );
        state.peers.remove(&quiet.author_key());
        state.quiet.insert(quiet.author_key());
        state.proofs.forget(&quiet.author_key());
        state.peers.insert(live.author_key());
        state.names.insert(live.author_key(), nick("alice"));

        let after = reader_with(state, vec![frame]);

        assert!(
            after.peers.contains(&live.author_key()),
            "a duplicate joined of a quiet session ended a live session"
        );
        assert!(
            after.proofs.proof_of(&quiet.author_key()).is_none(),
            "a quiet session got its proof back from a duplicate joined"
        );
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

    /// The presence events that reach the sink, in order: the key of the session, and what the event says
    /// (`joined`, `left` or another kind of presence).
    #[derive(Default)]
    struct PresenceOrder(Mutex<Vec<(AuthorKey, &'static str)>>);

    impl NodeSink for PresenceOrder {
        fn emit(&self, event: NodeEvent) {
            if let NodeEvent::Presence { peer, message, .. } = event {
                let label = if let MessageKind::Presence { subtype } = message.kind {
                    if subtype == PresenceSubtype::Joined {
                        "joined"
                    } else if subtype == PresenceSubtype::Left {
                        "left"
                    } else {
                        "alive"
                    }
                } else {
                    "other"
                };
                let mut seen = self.0.lock().expect("the order lock is not poisoned");
                seen.push((peer, label));
            }
        }
    }

    /// An intruder that was shown ends with a `left`, and the `left` comes before the arrival of the member that
    /// proved the name. The operator read `joined` for the intruder: every `joined` that was shown gets its
    /// `left`, as for the older run that a newer run replaces. With the `left` after the arrival, a reader
    /// that keys by nickname would take the name for gone while its member is there.
    #[test]
    fn the_end_of_a_surfaced_intruder_writes_a_left_line_before_the_arrival_of_the_member() {
        let (alice, intruder_session) = (Identity::generate(), Identity::generate());
        let alice_session = Identity::generate();
        let mut initial = fresh_state();
        initial.peers.insert(intruder_session.author_key());
        initial.surfaced.insert(intruder_session.author_key());
        initial
            .names
            .insert(intruder_session.author_key(), nick("alice"));
        let events = PresenceOrder::default();

        let reader = reader_with_sink(
            initial,
            vec![joined_of(&alice_session, &alice, "alice", 1)],
            &events,
        );

        assert!(
            !reader.peers.contains(&intruder_session.author_key()),
            "the intruder is ended"
        );
        let seen = events.0.lock().expect("the order lock is not poisoned");
        assert_eq!(
            *seen,
            vec![
                (intruder_session.author_key(), "left"),
                (alice_session.author_key(), "joined")
            ],
            "the intruder that was shown must get a `left` line, and before the arrival of the member"
        );
    }

    /// Both sessions were shown before the proof (neither had proved the name): the stream read `joined` twice.
    /// The proof of the member ends the intruder, with a `left`, and the member is there: a reader that keys by
    /// nickname must not read the name as gone, so the `joined` of the member is shown again after the `left`.
    #[test]
    fn the_end_of_a_surfaced_intruder_shows_the_member_again_when_the_member_was_shown_too() {
        let (alice, intruder_session) = (Identity::generate(), Identity::generate());
        let alice_session = Identity::generate();
        let mut initial = fresh_state();
        for session in [&alice_session, &intruder_session] {
            initial.peers.insert(session.author_key());
            initial.surfaced.insert(session.author_key());
            initial.names.insert(session.author_key(), nick("alice"));
        }
        let events = PresenceOrder::default();

        let reader = reader_with_sink(
            initial,
            vec![joined_of(&alice_session, &alice, "alice", 1)],
            &events,
        );

        assert!(
            reader.peers.contains(&alice_session.author_key())
                && !reader.peers.contains(&intruder_session.author_key()),
            "the member stays and the intruder is ended"
        );
        let seen = events.0.lock().expect("the order lock is not poisoned");
        assert_eq!(
            *seen,
            vec![
                (intruder_session.author_key(), "left"),
                (alice_session.author_key(), "joined")
            ],
            "a `left` for the intruder with no `joined` of the member after it reads as a name that is gone"
        );
    }

    /// One proof can end several shown intruders. Each gets its `left`, and the `joined` of the member is shown
    /// again ONCE, after them: N identical `joined` lines for one proof would only be noise.
    #[test]
    fn the_member_is_shown_again_once_for_a_proof_that_ends_two_shown_intruders() {
        let alice = Identity::generate();
        let alice_session = Identity::generate();
        let intruders = [Identity::generate(), Identity::generate()];
        let mut initial = fresh_state();
        for session in [&alice_session, &intruders[0], &intruders[1]] {
            initial.peers.insert(session.author_key());
            initial.surfaced.insert(session.author_key());
            initial.names.insert(session.author_key(), nick("alice"));
        }
        let events = PresenceOrder::default();

        let reader = reader_with_sink(
            initial,
            vec![joined_of(&alice_session, &alice, "alice", 1)],
            &events,
        );

        let intruder_keys: Vec<AuthorKey> = intruders.iter().map(Identity::author_key).collect();
        let all_ended = intruder_keys.iter().all(|key| !reader.peers.contains(key));
        assert!(
            reader.peers.contains(&alice_session.author_key()) && all_ended,
            "the member stays and both intruders are ended"
        );
        let seen = events.0.lock().expect("the order lock is not poisoned");
        let lefts: Vec<AuthorKey> = seen
            .iter()
            .filter(|(_, label)| *label == "left")
            .map(|(key, _)| *key)
            .collect();
        let joined: Vec<AuthorKey> = seen
            .iter()
            .filter(|(_, label)| *label == "joined")
            .map(|(key, _)| *key)
            .collect();
        assert_eq!(
            lefts.len(),
            2,
            "each shown intruder gets its `left`: {seen:?}"
        );
        assert_eq!(
            joined,
            vec![alice_session.author_key()],
            "the member is shown again once for one proof: {seen:?}"
        );
        assert_eq!(
            seen.last().map(|(_, label)| *label),
            Some("joined"),
            "the `joined` of the member comes after the two `left` lines: {seen:?}"
        );
    }

    /// An intruder that was never shown (the join horizon, or a frame that came as backlog) gets no `left`: the
    /// operator never read a `joined` for it, and the rule that a `left` is for a session that was shown stays.
    #[test]
    fn the_end_of_an_intruder_that_was_never_shown_writes_no_left_line() {
        let (alice, intruder_session) = (Identity::generate(), Identity::generate());
        let alice_session = Identity::generate();
        let mut initial = fresh_state();
        initial.peers.insert(intruder_session.author_key());
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
            "no left line for a session that was never shown"
        );
    }

    /// A `left` frame of a session, as the bytes that arrive on the gossip plane.
    fn left_of(session: &Identity, nickname: &str) -> Bytes {
        let frame = Message::new_left(&MeshId::from("test"), &nick(nickname)).sign(session);
        frame.serialize().expect("serialize").into_bytes()
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

    /// The goodbye of a session that IS in the roster and has an endpoint retained for it (it shares its nickname with
    /// another live key, which holds the dial hint) tears down the pool state of that endpoint too: its pooled
    /// connection and its dial-failure cooldown go, and the shared-endpoint check stays.
    #[test]
    fn the_goodbye_of_a_roster_session_tears_down_the_pool_state_of_its_retained_endpoint() {
        let session = Identity::generate();
        let (retained, shared) = (endpoint_id(66), endpoint_id(67));
        let mut initial = fresh_state();
        initial.peers.insert(session.author_key());
        initial.names.insert(session.author_key(), nick("carol"));
        initial.retain_refused_endpoint(session.author_key(), iroh::EndpointAddr::new(retained));
        let other = Identity::generate().author_key();
        initial.retain_refused_endpoint(other, iroh::EndpointAddr::new(shared));
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            initial.unicast_pool.note_dial_failure(retained).await;
            initial.unicast_pool.note_dial_failure(shared).await;
        });

        let reader = reader_with(initial, vec![left_of(&session, "carol")]);

        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            assert!(
                !reader.unicast_pool.is_cooling(retained).await,
                "the retained endpoint of a roster session that left kept its pool state"
            );
            assert!(
                reader.unicast_pool.is_cooling(shared).await,
                "the endpoint of another retained key lost its pool state"
            );
        });
    }

    /// The goodbye of a session whose retained endpoint is still LINKED does not close the pooled connection or the
    /// multihop origin of that endpoint: routes run through that neighbor while the link lives. The endpoint takes the
    /// orphan path, and its teardown follows when the link has ended.
    #[test]
    fn the_goodbye_of_a_session_does_not_tear_down_a_linked_endpoint_before_its_link_ends() {
        let session = Identity::generate();
        let linked = endpoint_id(68);
        let mut initial = fresh_state();
        initial.peers.insert(session.author_key());
        initial.names.insert(session.author_key(), nick("carol"));
        initial.retain_refused_endpoint(session.author_key(), iroh::EndpointAddr::new(linked));
        initial.linked_endpoints.insert(linked);
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            initial.unicast_pool.note_dial_failure(linked).await;
        });

        let reader = reader_with(initial, vec![left_of(&session, "carol")]);

        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            assert!(
                reader.unicast_pool.is_cooling(linked).await,
                "the goodbye closed the pool state of an endpoint that is still linked"
            );
        });
        assert!(
            reader.orphaned_endpoints.contains(&linked),
            "the linked endpoint did not take the orphan path: nothing closes it when the link ends"
        );
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
        let frames: Vec<Bytes> = (0..50).map(|_| alive_of(&session, "alice")).collect();

        let reader = reader_with(initial, frames);

        assert_eq!(
            reader.proof_requests_signed.load(Ordering::Relaxed),
            0,
            "no request was signed for an address that no warm path reaches"
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
            Some(lifecycle::PathSign::LinkUp(endpoint)),
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

    /// A session whose only address is the rendezvous has no target: an ask that went there would
    /// draw an answer that hides which member sent it (`proof_ask_target`). The ask waits in the map
    /// of the asks that wait for a path, as one with no address at all does, so the sweep sends it
    /// once a real address comes. It is not dropped: the next alive frame is 30 s away, and a
    /// session that sends no more of them would never be asked again.
    #[test]
    fn an_ask_whose_only_address_is_the_rendezvous_waits_for_a_real_one() {
        let session = Identity::generate();
        let rendezvous = endpoint_id(9);
        let mut initial = fresh_state();
        initial.rendezvous_id = Some(rendezvous);
        initial.peers.insert(session.author_key());
        initial.names.insert(session.author_key(), nick("alice"));
        initial.place_endpoint(
            session.author_key(),
            &nick("alice"),
            iroh::EndpointAddr::new(rendezvous),
        );

        let after = reader_full(
            initial,
            vec![alive_of(&session, "alice")],
            &SilentSink,
            None,
        );

        assert_eq!(
            (
                after.proofs.deferred_len(),
                after.proof_requests_signed.load(Ordering::Relaxed)
            ),
            (1, 0),
            "the ask waits for an address that is not the rendezvous, and nothing is signed"
        );
    }

    /// A frame that comes on a unicast connection from the endpoint of a session that waits shows that the
    /// endpoint can reach us, and the endpoint id of that connection is authenticated by the transport. The
    /// session may have no gossip link and no connection of ours to it (it dialed us), so the ask goes by a
    /// dial back in the background, as the send to a linked neighbour does. The limits of the retry stay: one
    /// try for each gap, and only the session whose address is that endpoint.
    #[test]
    fn an_ask_that_waited_goes_by_a_dial_back_when_a_unicast_frame_comes_from_its_endpoint() {
        let session = Identity::generate();
        let (endpoint, other) = (endpoint_id(7), endpoint_id(9));
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

        let from_it = reader_full(
            waiting(),
            vec![alive_of(&session, "alice")],
            &SilentSink,
            Some(lifecycle::PathSign::Unicast(endpoint)),
        );
        let from_another = reader_full(
            waiting(),
            vec![alive_of(&session, "alice")],
            &SilentSink,
            Some(lifecycle::PathSign::Unicast(other)),
        );

        assert_eq!(
            from_it.proof_requests_signed.load(Ordering::Relaxed),
            1,
            "a unicast frame from the endpoint of the waiting session did not send its ask"
        );
        assert_eq!(
            from_another.proof_requests_signed.load(Ordering::Relaxed),
            0,
            "a unicast frame from another endpoint sent the ask of this session"
        );
        // `proof_requests_signed` counts at the signature, before the send: it is true even if the send was refused.
        // The retry clock of the session starts only for a request that went out, so it shows that it was sent.
        let (key, name) = (session.author_key(), nick("alice"));
        assert!(
            !from_it.asks_for_session(&key, &name, &nick("reader")),
            "the request was signed but the send was refused: the retry clock of the session did not start"
        );
        assert!(
            from_another.asks_for_session(&key, &name, &nick("reader")),
            "a session that no request was sent to has its retry clock started"
        );
    }

    /// A session that the roster gate refuses (it claims a nickname that another member holds) is not in the
    /// roster, so the roster has no name for it. Its ask waits for a path as any ask does, and it keeps the
    /// nickname that the session claimed: when the path comes up the request goes, and does not die for want
    /// of a roster entry. The restart of a member whose alive frame came before its address is this case.
    #[test]
    fn an_ask_for_a_refused_session_that_waited_goes_when_the_path_comes_up() {
        use crate::protocol::messages::MessageBody;

        let bound = Identity::generate();
        let session = Identity::generate();
        let endpoint = endpoint_id(65);
        let json = address_json_with_seal(&iroh::EndpointAddr::new(endpoint));
        let body = MessageBody::try_new(&json.to_string()).expect("an address body");
        let peer_info =
            Message::new_peer_info(&MeshId::from("test"), &nick("alice"), body).sign(&session);
        let info = peer_info.serialize().expect("serialize").into_bytes();
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
            Some(lifecycle::PathSign::LinkUp(endpoint)),
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

    /// A peer that makes fresh session keys (they are free) sets off one ask for each key to its own endpoint. The
    /// proof requests have a budget before they are signed: 8 for each endpoint in a window. The asks over the
    /// budget wait in the map of the deferred asks (the same map), and another endpoint is not starved.
    #[test]
    fn twenty_fresh_sessions_at_one_endpoint_sign_the_budget_of_that_endpoint_and_no_more() {
        let (flooder, calm) = (endpoint_id(70), endpoint_id(71));
        let mut initial = fresh_state();
        initial.linked_endpoints.insert(flooder);
        initial.linked_endpoints.insert(calm);
        let mut arrivals: Vec<Bytes> = Vec::new();
        for (count, endpoint, prefix) in [(20, flooder, "flood"), (3, calm, "calm")] {
            for index in 0..count {
                let session = Identity::generate();
                let name = format!("{prefix}-{index}");
                initial.peers.insert(session.author_key());
                initial.names.insert(session.author_key(), nick(&name));
                initial.place_endpoint(
                    session.author_key(),
                    &nick(&name),
                    iroh::EndpointAddr::new(endpoint),
                );
                arrivals.push(alive_of(&session, &name));
            }
        }

        let reader = reader_with(initial, arrivals);

        assert_eq!(
            reader.proof_requests_signed.load(Ordering::Relaxed),
            8 + 3,
            "20 fresh sessions at one endpoint signed more than its budget of 8, or another endpoint was starved"
        );
        assert_eq!(
            reader.proofs.deferred_len(),
            12,
            "the asks over the budget wait in the map of the deferred asks"
        );
    }

    /// The budget in all, for asks that come from endpoints that have asked already: 20 endpoints with 8 fresh
    /// sessions each. The first ask of each endpoint is guaranteed (it counts in the budget in all, and it needs
    /// no room in it), and the others need the budget in all, which is 64 for each window. The first 8 endpoints
    /// use it up (64 asks); the 12 endpoints that come after get only their guaranteed first ask: 64 + 12 signed, and
    /// the other 84 asks wait in the map of the deferred asks (64 at most: the oldest are dropped).
    #[test]
    fn twenty_endpoints_with_eight_fresh_sessions_each_sign_the_budget_in_all_and_each_first_ask() {
        let mut initial = fresh_state();
        let mut arrivals: Vec<Bytes> = Vec::new();
        for endpoint_index in 0..20u8 {
            let endpoint = endpoint_id(100 + endpoint_index);
            initial.linked_endpoints.insert(endpoint);
            for index in 0..8u8 {
                let session = Identity::generate();
                let name = format!("spread-{endpoint_index}-{index}");
                initial.peers.insert(session.author_key());
                initial.names.insert(session.author_key(), nick(&name));
                initial.place_endpoint(
                    session.author_key(),
                    &nick(&name),
                    iroh::EndpointAddr::new(endpoint),
                );
                arrivals.push(alive_of(&session, &name));
            }
        }

        let reader = reader_with(initial, arrivals);

        assert_eq!(
            reader.proof_requests_signed.load(Ordering::Relaxed),
            64 + 12,
            "20 endpoints with 8 sessions each did not sign the budget in all plus the first ask of the last 12"
        );
    }

    /// 80 endpoints with one fresh session each (a mesh of 80 honest members that ask in one window): each is the
    /// first ask of its endpoint, so each is guaranteed, and all 80 are signed. Before the guarantee the budget in
    /// all allowed 64 of them and deferred 16 (the old test `eighty_endpoints_with_one_fresh_session_each_sign_the_
    /// budget_in_all_and_no_more` asserted 64 signed and 16 waiting).
    #[test]
    fn eighty_endpoints_with_one_fresh_session_each_are_all_asked() {
        let mut initial = fresh_state();
        let mut arrivals: Vec<Bytes> = Vec::new();
        for index in 0..80u8 {
            let (session, endpoint) = (Identity::generate(), endpoint_id(100 + index));
            let name = format!("spread-{index}");
            initial.linked_endpoints.insert(endpoint);
            initial.peers.insert(session.author_key());
            initial.names.insert(session.author_key(), nick(&name));
            initial.place_endpoint(
                session.author_key(),
                &nick(&name),
                iroh::EndpointAddr::new(endpoint),
            );
            arrivals.push(alive_of(&session, &name));
        }

        let reader = reader_with(initial, arrivals);

        assert_eq!(
            reader.proof_requests_signed.load(Ordering::Relaxed),
            80,
            "80 endpoints with one session each were not all asked: a first ask is guaranteed"
        );
        assert_eq!(
            reader.proofs.deferred_len(),
            0,
            "no ask waits: the first ask of each endpoint needs no room in the budget in all"
        );
    }

    /// One attacker with 8 endpoints that have a path to us floods 200 fresh sessions and uses the whole budget in
    /// all. An honest session at ANOTHER endpoint, with its own budget, must still be asked in that window: the
    /// first ask of each endpoint is guaranteed, so it is not deferred by the budget, and the push-out of the shared
    /// map of deferred asks cannot reach it. Its retry clock shows that the request went out.
    #[test]
    fn an_honest_session_is_asked_while_one_attacker_with_eight_endpoints_uses_the_budget_in_all() {
        let mut initial = fresh_state();
        let mut arrivals: Vec<Bytes> = Vec::new();
        for endpoint_index in 0..8u8 {
            let endpoint = endpoint_id(110 + endpoint_index);
            initial.linked_endpoints.insert(endpoint);
            for index in 0..25u8 {
                let session = Identity::generate();
                let name = format!("fresh-{endpoint_index}-{index}");
                initial.peers.insert(session.author_key());
                initial.names.insert(session.author_key(), nick(&name));
                initial.place_endpoint(
                    session.author_key(),
                    &nick(&name),
                    iroh::EndpointAddr::new(endpoint),
                );
                arrivals.push(alive_of(&session, &name));
            }
        }
        let honest = Identity::generate();
        let honest_endpoint = endpoint_id(130);
        initial.linked_endpoints.insert(honest_endpoint);
        initial.peers.insert(honest.author_key());
        initial.names.insert(honest.author_key(), nick("honest"));
        initial.place_endpoint(
            honest.author_key(),
            &nick("honest"),
            iroh::EndpointAddr::new(honest_endpoint),
        );
        arrivals.push(alive_of(&honest, "honest"));

        let reader = reader_with(initial, arrivals);

        assert!(
            !reader.asks_for_session(&honest.author_key(), &nick("honest"), &nick("reader")),
            "the honest session was not asked: the attacker used the budget in all and the ask was deferred"
        );
    }

    /// A `joined` frame whose proof is refused for a held nickname, as the verified frame and its bytes.
    fn proof_frame_of(session: &Identity, member: &Identity, forged: bool) -> (Verified, Bytes) {
        let mesh = MeshId::from("test");
        let mut proof = member.prove(&session.author_key(), "alice", mesh.as_ref(), 1);
        if forged {
            // a run that the member did not sign: the signature of the proof no longer verifies
            proof.run += 1;
        }
        let frame = Message::new_joined_with_proof(&mesh, &nick("alice"), &proof).sign(session);
        let bytes = frame.serialize().expect("serialize").into_bytes();
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
}
