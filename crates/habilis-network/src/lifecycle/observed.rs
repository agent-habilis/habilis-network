use crate::daemon::ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::gossip::event::NodeEvent;
use crate::protocol::identity::Identity;
use crate::protocol::message::Verified;
use crate::protocol::{MeshId, Message, MessageKind};

use super::membership;

use crate::util::clock::Instant;

/// What [`observe`] computed for one received message: whether it is
/// past our join horizon (surfaceable) and how it changed the roster.
/// Returned to the gossip router, which needs both for the inbound-push
/// gate and the presence/msg dispatch.
pub(crate) struct Observed {
    pub surfaceable: bool,
    pub update: membership::MembershipUpdate,
}

/// Heartbeat + membership + surfacing + join-horizon for one received
/// message. Called by the gossip router *before* kind dispatch. All
/// membership/presentation side effects live here (lifecycle layer);
/// the gossip layer never touches the roster directly.
pub(crate) fn observe(
    message: &Verified,
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
) -> Observed {
    let update = membership::compute_for(message, state);
    // Implicit heartbeat: any received message updates last_seen. Not a stale one: a copy of a
    // departed key's frame says nothing about whoever holds the nickname now.
    if !update.stale {
        match state.last_seen.get_mut(message.author.as_str()) {
            Some(seen) => *seen = Instant::now(),
            None => {
                state
                    .last_seen
                    .insert(message.author.clone(), Instant::now());
            }
        }
    }
    membership::apply(&update, &message.author, state);

    // Join horizon: the node still relays/logs everything (anti-entropy
    // keeps the mesh's set uniform), but a message stamped before we
    // joined is never *surfaced* to the operator/agent. Computed here
    // (not just before the inbound push) because the arrival-surfacing
    // decisions below need it too.
    let surfaceable = message.timestamp >= state.joined_at;

    if update.returned && surfaceable {
        state.surfaced.insert(message.author.clone());
        ctx.sink.emit(NodeEvent::PeerReturn {
            nickname: message.author.clone(),
        });
        tracing::info!(target: "habilis_network::lifecycle", nickname = %message.author, "peer returned");
    }

    // Make `joined` as reliable as membership. A peer's own `joined`
    // presence is a one-shot broadcast that can be lost in the
    // convergence window; `PeerInfo` is re-sent on every `NeighborUp`
    // and flooded by receivers, so a peer first learned via *any*
    // non-presence message reliably surfaces a `joined` here. The
    // real `Presence::Joined` keeps its own emit + roster re-announce
    // in `handle_presence`; gating on `!Presence` avoids a double.
    //
    // Surfacing is gated on `surfaceable` + `surfaced`, NOT on
    // `joined_new`: `joined_new` (the roster concept) is consumed by
    // the *first* received message even when it is non-surfaceable
    // pre-join backlog, so keying off it would swallow the legitimate
    // arrival of a still-present peer whose first fresh message lands
    // after some old relayed one. `!surfaced.contains` keeps
    // this exactly-once instead.
    if surfaceable
        && !update.returned
        && !update.stale
        && !state.surfaced.contains(message.author.as_str())
        && !matches!(message.kind, MessageKind::Presence { .. })
    {
        state.surfaced.insert(message.author.clone());
        ctx.sink
            .emit(synthetic_arrival(ctx.mesh, ctx.identity, message));
        tracing::info!(target: "habilis_network::lifecycle", nickname = %message.author, "peer joined");
    }

    Observed {
        surfaceable,
        update,
    }
}

/// The presence this node surfaces for a peer's first arrival. This node signs the
/// `joined` that reports it, so the proof names this node, and the nickname stays the
/// peer's. `peer` is the key of the frame that triggered it, which is the peer's own.
pub(crate) fn synthetic_arrival(
    mesh: &MeshId,
    identity: &Identity,
    triggering: &Verified,
) -> NodeEvent {
    let arrival = Message::new_joined(mesh, &triggering.author).sign(identity);
    NodeEvent::Presence {
        msg: Box::new(arrival.authored()),
        peer: triggering.key(),
        synthetic: true,
    }
}
