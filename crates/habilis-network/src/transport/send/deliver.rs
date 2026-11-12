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

use crate::transport;
use n0_future::task;
/// Route one already-signed, already-serialized message. `bytes` MUST be
/// `msg.serialize()` — the same wire form gossip uses.
///
/// It returns at once: it never waits on a dial, on the wait for a direct path, or on a write.
/// A broadcast, a frame held for a direct path, a refused frame, and a send to a warm connection
/// give their verdict here. A directed message to a cold peer is sent by a task, and the verdict
/// comes through [`Delivered::Pending`]. On Windows, a warm connection with no direct path
/// selected gives its verdict through [`Delivered::Pending`], after a wait of up to the
/// path-select budget.
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
        Route::Undeliverable => {
            let addressee = sole_addressee(&message.kind);
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
///   the path-select budget. On Windows this case returns `true`: the send waits on a task, and
///   a refusal at the end is only logged.
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

/// Where an answer to the digest signed by `signer` can go
/// point-to-point: the endpoint that key proved in its `PeerInfo`, when it is
/// a linked gossip neighbor with a usable path. Proven, because a nickname is
/// a label any signer can claim, and one answer is up to a whole resend budget
/// of frames aimed at whoever holds that endpoint. Linked, because every
/// holder that hears a digest answers it: the asker's link count bounds how
/// many answers reach its unicast inbox. `None` means answer on gossip.
pub(crate) fn unicast_answer_target(
    signer: &AuthorKey,
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
    let needs_lane = state.member_address_of(*eid).is_some_and(|address| {
        webrtc::session_policy::pair_needs_lane(&address, state.local_udp_transport)
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
/// and resends once in the background). A cold peer is dialed on a task of its own, so that the
/// caller never waits on the dial, the path wait or the write. The dial error is the send's
/// outcome, through the handle — there is no fallback. A cold peer on the dial-failure cooldown is
/// refused at once.
async fn send_unicast(eid: EndpointId, bytes: WireFrame, pool: &UnicastPool) -> Result<Delivered> {
    match pool.send_if_warm(eid, bytes.clone().into_bytes()).await {
        WarmSend::Sent => Ok(Delivered::Done),
        #[cfg(not(windows))]
        WarmSend::Refused => Err(anyhow::anyhow!("{}", transport::RELAY_REFUSED)),
        // Windows only (#45). A probe can pool a connection before iroh opens the selected path
        // on it, and the connection then reads as no path selected. Here the send waits for a
        // direct path as a cold send does, up to `PATH_SELECT_TIMEOUT`, and fails with the same
        // refusal if none is selected.
        #[cfg(windows)]
        WarmSend::Refused => Ok(Delivered::Pending(send_after_path_wait(eid, bytes, pool))),
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

/// The send of a warm connection that has no direct path selected yet, on a task. The guard of
/// the dial is taken first, as for a cold send, so a second send to the peer that also finds no
/// direct path waits for this one. A send that finds a direct path does not wait, so the order
/// of the two is not guaranteed. The wait counts as a dial attempt. The error is not given a
/// context: a send that finds no direct path fails with the bare refusal.
#[cfg(windows)]
fn send_after_path_wait(
    eid: EndpointId,
    bytes: WireFrame,
    pool: &UnicastPool,
) -> transport::PendingSend {
    let registration = pool.register_dial(eid);
    let (outcome_tx, outcome) = oneshot::channel();
    let pool = pool.clone();
    task::spawn(async move {
        let sent = pool
            .send_registered(registration, eid, bytes.into_bytes())
            .await;
        if let Err(Err(error)) = outcome_tx.send(sent) {
            tracing::debug!(target: "habilis_network::gossip", %eid, %error, "background send not delivered");
        }
    });
    outcome
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
