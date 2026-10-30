use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::gossip::app::NodeApp;
use crate::gossip::event::NodeEvent;
use crate::protocol::messages::Verified;
use crate::protocol::{Message, PresenceSubtype};

use super::membership_update;

use crate::gossip;
use crate::util::clock::Instant;

/// A received `Presence` frame plus the roster delta [`membership_update::observe`]
/// already computed for it, passed to [`handle_presence`]. Constructed by
/// [`crate::gossip::recv::ingest`], across the `gossip`/`lifecycle` module
/// boundary — hence `pub(crate)` rather than module-private.
pub(crate) struct PresenceEvent<'message> {
    pub(crate) message: &'message Verified,
    pub(crate) subtype: PresenceSubtype,
    pub(crate) update: &'message membership_update::MembershipUpdate,
    pub(crate) surfaceable: bool,
}

pub(crate) async fn handle_presence(
    event: PresenceEvent<'_>,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    let PresenceEvent {
        message,
        subtype,
        update,
        surfaceable,
    } = event;
    if subtype == PresenceSubtype::Alive {
        return;
    }
    if subtype == PresenceSubtype::Left {
        // A key says goodbye once per run. A second copy is a replay that a peer still held, and
        // the nickname may belong to a new key by now: the replay must not take it away.
        if state.key_said_goodbye(message.key()) {
            return;
        }
        state.note_left(&message.author, message.key(), message.timestamp);
        state.drop_departed_presence(&message.key());
        if state.peers.remove(message.author.as_str()) {
            state.write_peer_count();
        }
        // A graceful goodbye, unlike a silence timeout, drops the dial hint —
        // and with it the warm unicast connection and any dial cooldown, so a
        // rejoin re-dials cold.
        if let Some(endpoint_id) = state.forget_peer_endpoint(message.author.as_str()) {
            state.unicast_pool.forget(endpoint_id.id).await;
            // Its advertised links go too, or routes keep running through a peer
            // that said goodbye until its vector ages out.
            #[cfg(feature = "multihop")]
            if let Some(handle) = state.multihop.as_ref() {
                let _ = handle.remove_origin(habilis_network_iroh_multihop_transport::AppId::new(
                    endpoint_id.id,
                ));
            }
        }
        state.quiet.remove(message.author.as_str());
        // Only announce a departure for a peer whose arrival we
        // surfaced — keeps the join-horizon view symmetric. A `left`
        // for a peer known only through pre-join backlog (or one we
        // already showed going quiet) is dropped.
        if state.surfaced.remove(message.author.as_str()) {
            context.sink.emit(NodeEvent::Presence {
                message: Box::new(message.authored()),
                peer: message.key(),
                synthetic: false,
            });
            tracing::info!(target: "habilis_network::lifecycle", nickname = %message.author, "peer left");
        }
        // App cleanup last, with the roster already consistent. Gated on
        // `surfaceable`: a relayed pre-join `Left` must never cancel live
        // work — the same join-horizon symmetry as the announcement above.
        if surfaceable {
            app.on_peer_left(&message.author, state, context).await;
        }
    } else if subtype == PresenceSubtype::Joined && !update.stale {
        // Every `joined` re-floods our `PeerInfo`, newcomer and rejoin
        // alike. A newcomer linked to the *rendezvous*, so no `NeighborUp`
        // fires on this loop to re-send it and our arrival flood predates
        // them; a rejoin across a beacon epoch may have lost it the same way
        // (both observed native↔browser in the mesh matrix: a roster entry
        // with no endpoint binding reads "unreachable" forever). Throttled
        // by `joined_refloods_peerinfo`.
        let now = Instant::now();
        if state.joined_refloods_peerinfo(update.joined_new, now) {
            gossip::broadcast_peer_info(state, context).await;
            state.last_sent_at = now;
        }
        if update.joined_new {
            // Re-announce so late joiners seed their roster. Retained locally: a
            // re-announce mints a fresh id, so without this each one becomes
            // another message we can never acknowledge and every peer re-sends to
            // us forever (see `gossip::recv::retain_own_broadcast`).
            let joined = Message::new_joined(context.mesh, context.author).sign(context.identity);
            gossip::broadcast_msg(context.sender, &joined).await;
            gossip::retain_own_broadcast(state, &joined);
            state.last_sent_at = Instant::now();
            // Suppress "has joined" when we already printed "came back"
            // from the quiet check, or when this `joined` predates
            // our own join (relayed backlog).
            if surfaceable && !update.returned {
                state.surfaced.insert(message.author.clone());
                context.sink.emit(NodeEvent::Presence {
                    message: Box::new(message.authored()),
                    peer: message.key(),
                    synthetic: false,
                });
                tracing::info!(target: "habilis_network::lifecycle", nickname = %message.author, "peer joined (announced)");
            }
        }
    }
}
