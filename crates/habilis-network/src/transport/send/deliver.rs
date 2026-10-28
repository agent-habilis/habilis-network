//! The cross-plane send decision: deliver a message on the plane its addressing chooses.

use anyhow::{Context, Result};
use iroh::EndpointId;
use tokio::sync::oneshot;

use super::route::Route;
use crate::daemon::state::EventLoopState;
use crate::protocol::Nickname;
use crate::protocol::message::{Verified, WireFrame, sole_addressee};
use crate::transport::outbox::Resend;
use crate::transport::pool::{COOLDOWN_REFUSED, UnicastPool, WarmSend};
use crate::transport::probe::PathKind;
use crate::transport::{MeshSender, webrtc};

use crate::util::clock;

use crate::transport::{Delivered, Lane, SendError};

/// Route one already-signed, already-serialized message. `bytes` MUST be
/// `msg.serialize()` — the same wire form gossip uses.
///
/// It returns at once: it never waits on a dial, on the wait for a direct path, or on a write.
/// A broadcast, a frame held for a direct path, a refused frame, and a send to a warm connection
/// give their verdict here. A directed message to a cold peer is sent by a task, and the verdict
/// comes through [`Delivered::Pending`].
///
/// # Errors
/// Propagates a gossip broadcast failure, a refused path, or a cold peer on the dial-failure
/// cooldown. A directed message whose addressee has no dialable endpoint (its `PeerInfo`
/// hasn't arrived, or its advertised endpoint is the rendezvous pseudo-node)
/// is undeliverable — the error names which; callers retry once a real
/// endpoint is learned. A dial or a write that fails comes through the handle.
pub async fn deliver(
    msg: &Verified,
    bytes: WireFrame,
    state: &EventLoopState,
    sender: &MeshSender,
) -> Result<Delivered, SendError> {
    match resolve(msg, bytes, state)? {
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
    msg: &Verified,
    bytes: WireFrame,
    state: &EventLoopState,
) -> Result<Resend, SendError> {
    match super::route::route(msg, state) {
        Route::Broadcast => Ok(Resend::Broadcast(bytes)),
        Route::Unicast(eid) => Ok(Resend::Unicast(eid, bytes)),
        Route::Held(eid) => Err(SendError::Held { eid }),
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
            Err(SendError::Undeliverable(format!(
                "directed message to {name} undeliverable: {cause}"
            )))
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
    msg: &Verified,
    bytes: WireFrame,
    state: &EventLoopState,
    sender: &MeshSender,
) -> bool {
    deliver(msg, bytes, state, sender).await.is_ok()
}

/// Where an answer to the digest signed by `signer` can go
/// point-to-point: the endpoint that key proved in its `PeerInfo`, when it is
/// a linked gossip neighbor with a usable path. Proven, because a nickname is
/// a label any signer can claim, and one answer is up to a whole resend budget
/// of frames aimed at whoever holds that endpoint. Linked, because every
/// holder that hears a digest answers it: the asker's link count bounds how
/// many answers reach its unicast inbox. `None` means answer on gossip.
pub(crate) fn unicast_answer_target(
    signer: &crate::protocol::AuthorKey,
    state: &EventLoopState,
) -> Option<EndpointId> {
    let eid = state
        .proven_endpoints
        .get(signer)
        .filter(|eid| state.rendezvous_id != Some(*eid))?;
    (state.linked_endpoints.contains(&eid) && !super::route::held(eid, state)).then_some(eid)
}

/// A frame held for a lane peer is the reason to open its session: the peer has no IP path, and
/// a send could not dial it without one. So is a frame held for a pair that lost its direct path
/// and reads as the relay. Call this when a send failed with [`SendError::Held`]; any other error,
/// and a peer that has an IP path and no relay reading, change nothing.
pub(crate) fn note_held(state: &mut EventLoopState, error: &SendError) {
    let SendError::Held { eid } = error else {
        return;
    };
    let needs_lane = state
        .peer_endpoints
        .values()
        .find(|addr| addr.id == *eid)
        .is_some_and(|addr| {
            webrtc::session_policy::pair_needs_lane(addr, state.local_udp_transport)
        });
    // A pair that lost its direct path reads as the relay: if its offer failed, nobody would
    // offer again, so the parked frame asks.
    let reads_as_relay = state.pair_path_kind(*eid) == Some(PathKind::Relay);
    if needs_lane || reads_as_relay {
        state.want_lane_session(*eid, clock::Instant::now());
    }
}

/// The roster's `transport` column. A directed frame to a known peer takes a
/// unicast connect; we label it `unicast` when a *direct* path is expected (the
/// peer is in our gossip mesh) and `multihop` otherwise — a best-effort hint,
/// since the actual path is chosen by iroh at connect time.
pub(crate) fn lane_for(nick: &Nickname, state: &EventLoopState) -> Lane {
    let Some(eid) = super::route::directed_endpoint(nick, state) else {
        return Lane::Unreachable;
    };
    if super::route::held(eid, state) {
        return Lane::RelayOnly;
    }
    if directly_meshed(nick, state) {
        Lane::Unicast
    } else {
        Lane::Multihop
    }
}

/// Whether `nick` is a known peer in our live gossip mesh — the signal that a
/// *direct* unicast path is expected rather than a multihop one.
fn directly_meshed(nick: &Nickname, state: &EventLoopState) -> bool {
    state.meshed && super::route::directed_endpoint(nick, state).is_some()
}

/// Warm pooled connection first (steady state, no dial — an optimistic
/// fire-and-forget handoff; a write that fails on a dead connection redials
/// and resends once in the background). A cold peer is dialed on a task of its own, so that the
/// caller never waits on the dial, the path wait or the write. The dial error is the send's
/// outcome, through the handle — there is no fallback. A cold peer on the dial-failure cooldown is
/// refused at once.
async fn send_unicast(eid: EndpointId, bytes: WireFrame, pool: &UnicastPool) -> Result<Delivered> {
    match pool.send_if_warm(eid, bytes.clone().into_bytes()).await {
        WarmSend::Sent => Ok(Delivered::Done),
        WarmSend::Refused => Err(anyhow::anyhow!("{}", crate::transport::RELAY_REFUSED)),
        WarmSend::Cold => {
            if pool.is_cooling(eid).await {
                return Err(anyhow::anyhow!("{COOLDOWN_REFUSED}")
                    .context(format!("unicast dial to {eid} failed")));
            }
            // The guard of the dial of this peer is taken here, before the spawn: a second send
            // finds this dial in flight even when it ends at once.
            let registration = pool.register_dial(eid);
            let (outcome_tx, outcome) = oneshot::channel();
            let pool = pool.clone();
            n0_future::task::spawn(async move {
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
        WarmSend::Cold if state.linked_endpoints.contains(&eid) => {
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
