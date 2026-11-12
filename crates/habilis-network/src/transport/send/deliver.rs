//! The cross-plane send decision: deliver a message on the plane its addressing chooses.

use crate::daemon::state::Standing;
use anyhow::{Context, Result};
use iroh::EndpointId;
use tokio::sync::oneshot;

use super::route::Route;
use crate::daemon::state::EventLoopState;
use crate::protocol::AuthorKey;
use crate::protocol::messages::{Verified, WireFrame, sole_addressee};
use crate::transport::outbox::Resend;
use crate::transport::pool::{COOLDOWN_REFUSED, UnicastPool, WarmSend};
use crate::transport::probe::PathKind;
use crate::transport::{MeshSender, webrtc};

use crate::util::clock;

use crate::transport::{Delivered, Lane, SendError};

use n0_future::task;
/// Route one already-signed, already-serialized message. `bytes` MUST be
/// `msg.serialize()` — the same wire form gossip uses.
///
/// It returns at once: it never waits on a dial, on the wait for a direct path, or on a write.
/// It takes the state by shared reference, so it cannot prove the addressee by its multihop route.
/// Only the directed send of the engine does that before it calls here (`Messaging::Send` and
/// `SendToKey`). A caller of this function can see a send held for up to one sweep (10 s) to an
/// unwatched peer on a multihop route.
/// A broadcast, a frame held for a direct path, a refused frame, and a send to a warm connection
/// give their verdict here. A directed message to a cold peer, or to a warm peer whose connection
/// reads relay, is sent by a task, and the verdict comes through [`Delivered::Pending`].
///
/// # Errors
/// Propagates a gossip broadcast failure, a refused path, or a cold peer on the dial-failure
/// cooldown. A directed message whose addressee has no dialable endpoint (its `PeerInfo`
/// hasn't arrived, or its advertised endpoint is the rendezvous pseudo-node)
/// is undeliverable — the error names which; callers retry once a real
/// endpoint is learned. A dial or a write that fails comes through the handle.
///
/// # Examples
///
/// It delivers a signed message to the peers that its addressing names, and it reports whether the send is done or still pending. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::EventLoopState;
/// use habilis_network::ops::{Delivered, MeshSender, deliver};
/// use habilis_network::protocol::{Verified, messages::WireFrame};
/// use habilis_network::runtime::SendError;
///
/// # async fn demo(message: &Verified, bytes: WireFrame, state: &EventLoopState, sender: &MeshSender) -> Result<Delivered, SendError> {
/// deliver(message, bytes, state, sender).await
/// # }
/// ```
pub async fn deliver(
    message: &Verified,
    bytes: WireFrame,
    state: &EventLoopState,
    sender: &MeshSender,
) -> Result<Delivered, SendError> {
    match resolve(message, bytes, state)? {
        Resend::Broadcast(bytes) => {
            broadcast(sender, bytes)
                .await
                .map_err(SendError::internal)?;
            Ok(Delivered::Done)
        }
        Resend::Unicast(eid, bytes) => send_unicast(eid, bytes, &state.unicast_pool)
            .await
            .map_err(SendError::internal),
    }
}

/// The routing decision of [`deliver`], without the send: which plane carries
/// `msg`, so that a caller that must not wait can queue it for another task.
///
/// # Errors
/// The same as [`deliver`] for a message that has no path now: held for a
/// direct path, or its addressee has no known endpoint.
pub(crate) fn resolve(
    message: &Verified,
    bytes: WireFrame,
    state: &EventLoopState,
) -> Result<Resend, SendError> {
    match super::route::route(message, state) {
        Route::Broadcast => Ok(Resend::Broadcast(bytes)),
        Route::Unicast(eid) => Ok(Resend::Unicast(eid, bytes)),
        Route::Held(eid) => Err(SendError::Held { eid }),
        Route::Undeliverable => Err(undeliverable(sole_addressee(&message.kind), state)),
    }
}

/// Why a directed message has no endpoint to go to.
fn undeliverable(addressee: Option<&AuthorKey>, state: &EventLoopState) -> SendError {
    let name = addressee.map_or_else(|| "<none>".to_owned(), ToString::to_string);
    // Two distinct causes hide behind one route: waiting on PeerInfo
    // is retryable, an addressee advertising the rendezvous is not.
    let via_rendezvous = addressee
        .and_then(|key| state.address_of(key))
        .is_some_and(|address| state.rendezvous_id == Some(address.id));
    let cause = if via_rendezvous {
        "its advertised endpoint is the rendezvous pseudo-node, never a directed target"
    } else {
        "no known endpoint (PeerInfo not yet received)"
    };
    SendError::Undeliverable(format!("directed message to {name} undeliverable: {cause}"))
}

/// Send a frame that this node signed, unchanged, by unicast to `to` alone. Its use is the repair
/// of an own frame for 1 peer: a broadcast shard that the peer missed goes to the peer that asks,
/// and no other member receives it again. The bytes MUST be `message.serialize()`.
///
/// It checks, in this order, that the frame is one this node signed ([`SendError::ForeignFrame`]),
/// that the frame is a broadcast or is directed to `to` ([`SendError::OtherAddressee`]), and that
/// `to` has an endpoint to go to, by the directed rules of [`deliver`] ([`SendError::Undeliverable`]
/// or [`SendError::Held`]). The payload path check applies as it does for [`deliver`], and the
/// send waits on nothing: a cold peer is dialed by a task, and the verdict comes through
/// [`Delivered::Pending`].
///
/// # Errors
/// One of the refusals above, or the failure of a send to a warm connection.
///
/// # Examples
///
/// It repairs one frame of this node for one peer. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::EventLoopState;
/// use habilis_network::ops::{Delivered, deliver_to};
/// use habilis_network::protocol::{AuthorKey, Verified, messages::WireFrame};
/// use habilis_network::runtime::SendError;
///
/// # async fn demo(to: &AuthorKey, message: &Verified, bytes: WireFrame, state: &EventLoopState) -> Result<Delivered, SendError> {
/// deliver_to(to, message, bytes, state).await
/// # }
/// ```
pub async fn deliver_to(
    to: &AuthorKey,
    message: &Verified,
    bytes: WireFrame,
    state: &EventLoopState,
) -> Result<Delivered, SendError> {
    let Resend::Unicast(eid, bytes) = resolve_to(to, message, bytes, state)? else {
        unreachable!("a route to one key is never a broadcast");
    };
    send_unicast(eid, bytes, &state.unicast_pool)
        .await
        .map_err(SendError::internal)
}

/// The decision of [`deliver_to`], without the send.
///
/// # Errors
/// The same as [`deliver_to`] for a frame that is refused or has no path now.
pub(crate) fn resolve_to(
    to: &AuthorKey,
    message: &Verified,
    bytes: WireFrame,
    state: &EventLoopState,
) -> Result<Resend, SendError> {
    if message.key() != state.identity.author_key() {
        return Err(SendError::ForeignFrame);
    }
    if sole_addressee(&message.kind).is_some_and(|addressee| addressee != to) {
        return Err(SendError::OtherAddressee);
    }
    match super::route::route_to_key(to, state) {
        Route::Unicast(eid) => Ok(Resend::Unicast(eid, bytes)),
        Route::Held(eid) => Err(SendError::Held { eid }),
        Route::Undeliverable | Route::Broadcast => Err(undeliverable(Some(to), state)),
    }
}

/// [`deliver_to`] for a caller on the event loop: it returns whether the send was accepted, as
/// [`deliver_in_background`] does, and it never waits on a dial or a write.
///
/// # Examples
///
/// It repairs one frame of this node for one peer in the background. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::EventLoopState;
/// use habilis_network::ops::deliver_to_in_background;
/// use habilis_network::protocol::{AuthorKey, Verified, messages::WireFrame};
///
/// # async fn demo(to: &AuthorKey, message: &Verified, bytes: WireFrame, state: &EventLoopState) -> bool {
/// deliver_to_in_background(to, message, bytes, state).await
/// # }
/// ```
pub async fn deliver_to_in_background(
    to: &AuthorKey,
    message: &Verified,
    bytes: WireFrame,
    state: &EventLoopState,
) -> bool {
    deliver_to(to, message, bytes, state).await.is_ok()
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
/// - it is held for a direct path: the peer is not proven direct and the
///   relay carries no payload.
/// - it is cold and on the per-peer dial-failure cooldown.
/// - the gossip broadcast failed.
///
/// A `false` send is not queued: the caller tries again later.
///
/// Like [`deliver`], it cannot prove the addressee by its multihop route. Only the directed send of
/// the engine does (`Messaging::Send` and `SendToKey`), so a send to an unwatched peer on a
/// multihop route can be held for up to one sweep (10 s).
///
/// `true` does not prove delivery: a background dial or write can still fail,
/// and is only logged. A warm connection whose selected path reads relay gives
/// `true` too. The send then waits on a task for up to the path-select budget,
/// and if no direct path comes, it fails with the relay refusal and is only
/// logged. The caller gets no `false` and must not rely on a retry.
///
/// `true` is also optimistic in one case: an inline dial to the same peer can
/// fail between the cooldown check and the background dial, and the background
/// dial then stops on the new cooldown.
///
/// A background dial can outlive its peer's `Left`. If the peer rejoins at a
/// new address while a stale dial is still running, that dial's failure puts
/// the peer on the cooldown, and directed sends to it return `false` for up
/// to the dial budget plus the cooldown.
///
/// # Examples
///
/// It delivers a signed message in the background, and it says whether the message was accepted. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::EventLoopState;
/// use habilis_network::ops::{MeshSender, deliver_in_background};
/// use habilis_network::protocol::{Verified, messages::WireFrame};
///
/// # async fn demo(message: &Verified, bytes: WireFrame, state: &EventLoopState, sender: &MeshSender) -> bool {
/// deliver_in_background(message, bytes, state, sender).await
/// # }
/// ```
pub async fn deliver_in_background(
    message: &Verified,
    bytes: WireFrame,
    state: &EventLoopState,
    sender: &MeshSender,
) -> bool {
    deliver(message, bytes, state, sender).await.is_ok()
}

/// Whether a frame can be sent to `eid` by unicast now, with no dial and no wait: its direct path
/// is proven, or the frame being handled came by unicast from `eid`. The unicast acceptor admits
/// a connection only on a selected path that is not the relay when the relay is lookup-only, so
/// that arrival proves what a probe would, before the probe of the node reads it, and the reply
/// goes back on it. The exception is for the frame at hand: `unicast_arrival` is set only while
/// an unicast frame is handled, so a send outside a reply, and any other endpoint, keep the check
/// of the path as before.
pub(crate) fn can_unicast(eid: EndpointId, state: &EventLoopState) -> bool {
    !super::route::unproven(eid, state) || state.unicast_arrival == Some(eid)
}

/// A frame held for a lane peer is the reason to open its session: the peer has no IP path, and
/// a send could not dial it without one. So is a frame held for a pair that lost its direct path
/// and reads as the relay. Call this when a send failed with [`SendError::Held`]; any other error,
/// and a peer that has an IP path and no relay reading, change nothing.
pub(crate) fn note_held(state: &mut EventLoopState, error: &SendError) {
    let SendError::Held { eid } = error else {
        return;
    };
    want_lane_if_needed(state, *eid);
}

/// The same reason as [`note_held`], for a frame that is not held: a directed frame to a peer
/// whose direct path is not proven yet, on a mesh where the relay is lookup only. The send dials
/// the peer and waits for a direct path. A peer that has no IP path, or that turns out relay-only,
/// needs a lane session, so it is asked now and not on the next retry pass. Returns whether the
/// frame is such a frame, and the peer is a candidate for the offer.
pub(crate) fn note_unproven(state: &mut EventLoopState, message: &Verified) -> bool {
    let Some(key) = sole_addressee(&message.kind) else {
        return false;
    };
    let Some(eid) = super::route::directed_endpoint(key, state) else {
        return false;
    };
    if !super::route::unproven(eid, state) {
        return false;
    }
    want_lane_if_needed(state, eid);
    true
}

fn want_lane_if_needed(state: &mut EventLoopState, eid: EndpointId) {
    let needs_lane = state.member_address_of(eid).is_some_and(|address| {
        webrtc::session_policy::pair_needs_lane(&address, state.local_udp_transport)
    });
    // A pair that lost its direct path reads as the relay: if its offer failed, nobody would
    // offer again, so the parked frame asks.
    let reads_as_relay = state.pair_path_kind(eid) == Some(PathKind::Relay);
    if needs_lane || reads_as_relay {
        state.want_lane_session(eid, clock::Instant::now());
    }
}

/// The roster's `transport` column. A directed frame to a known peer takes a
/// unicast connect; we label it `unicast` when a *direct* path is expected (the
/// peer is in our gossip mesh) and `multihop` otherwise — a best-effort hint,
/// since the actual path is chosen by iroh at connect time. `RelayOnly` means that a probe proved
/// the pair relay-only on a mesh whose relay is lookup only: a pair that no probe has read is not
/// labeled by its state, and it reads `unicast` or `multihop`.
pub(crate) fn lane_for(key: &AuthorKey, state: &EventLoopState) -> Lane {
    let Some(eid) = super::route::directed_endpoint(key, state) else {
        return Lane::Unreachable;
    };
    if super::route::held(eid, state) {
        return Lane::RelayOnly;
    }
    if directly_meshed(key, state) {
        Lane::Unicast
    } else {
        Lane::Multihop
    }
}

/// Whether `key` is a known peer in our live gossip mesh — the signal that a
/// *direct* unicast path is expected rather than a multihop one.
fn directly_meshed(key: &AuthorKey, state: &EventLoopState) -> bool {
    state.standing.contains(&Standing::Meshed)
        && super::route::directed_endpoint(key, state).is_some()
}

/// Warm pooled connection first (steady state, no dial — an optimistic
/// fire-and-forget handoff; a write that fails on a dead connection redials
/// and resends once in the background). A cold peer, and a warm peer whose connection reads relay,
/// are served on a task of its own, so that the caller never waits on the dial, the path wait or
/// the write. A connection that reads relay can be a young one whose direct path is still
/// forming, so the task waits for the path like the dial of a cold peer and shares that wait with
/// the sends that follow. The error of the dial or of the wait is the send's outcome, through the
/// handle — there is no fallback. A cold peer on the dial-failure cooldown is refused at once. A
/// warm connection needs no dial, so the cooldown does not apply to it.
pub(super) async fn send_unicast(
    eid: EndpointId,
    bytes: WireFrame,
    pool: &UnicastPool,
) -> Result<Delivered> {
    let warm = pool.send_if_warm(eid, bytes.clone().into_bytes()).await;
    match warm {
        WarmSend::Sent => Ok(Delivered::Done),
        WarmSend::Cold | WarmSend::Refused => {
            if warm == WarmSend::Cold && pool.is_cooling(eid).await {
                return Err(anyhow::anyhow!("{COOLDOWN_REFUSED}")
                    .context(format!("unicast dial to {eid} failed")));
            }
            // The guard of the dial of this peer is taken here, before the spawn: a second send
            // finds this dial in flight even when it ends at once.
            let registration = pool.register_dial(eid);
            let (outcome_tx, outcome) = oneshot::channel();
            let pool = pool.clone();
            task::spawn(async move {
                let sent = pool
                    .send_registered(registration, eid, bytes.into_bytes())
                    .await
                    .with_context(|| format!("unicast dial to {eid} failed"));
                if let Err(Err(error)) = outcome_tx.send(sent) {
                    tracing::debug!(target: "habilis_network::gossip", %eid, %error, "background send not delivered");
                }
            });
            Ok(Delivered::Pending(outcome))
        }
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
    bytes: WireFrame,
    state: &EventLoopState,
) -> bool {
    send_courtesy(eid, bytes, state, false).await
}

/// [`send_best_effort`] for an endpoint that just sent an authenticated unicast frame: it gets the dial in the
/// background that a linked neighbour gets. The endpoint id of that connection is checked by the transport, so
/// the endpoint is as proven as a link would prove it. The caller keeps its own limits on how often it sends.
pub(crate) async fn send_dialing_back(
    eid: EndpointId,
    bytes: WireFrame,
    state: &EventLoopState,
) -> bool {
    send_courtesy(eid, bytes, state, true).await
}

async fn send_courtesy(
    eid: EndpointId,
    bytes: WireFrame,
    state: &EventLoopState,
    dial_back: bool,
) -> bool {
    // Never dial inline: that would let anyone who can be pinged back choose
    // how long this daemon stops answering, once per identity. A linked
    // neighbor still gets a dial, off the loop — its address is proven by the
    // link, and a link can come up with neither side holding a unicast
    // connection, which left a peer linked only by gossip unanswerable.
    match state
        .unicast_pool
        .send_if_warm(eid, bytes.clone().into_bytes())
        .await
    {
        WarmSend::Sent => true,
        WarmSend::Cold if dial_back || state.linked_endpoints.contains(&eid) => {
            state
                .unicast_pool
                .dial_and_send_in_background(eid, bytes.into_bytes())
                .await
        }
        WarmSend::Cold | WarmSend::Refused => false,
    }
}

async fn broadcast(sender: &MeshSender, bytes: WireFrame) -> Result<()> {
    sender
        .broadcast(bytes)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))
}
