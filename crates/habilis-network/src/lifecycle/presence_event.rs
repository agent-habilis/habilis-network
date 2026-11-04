use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::gossip::app::NodeApp;
use crate::gossip::event::NodeEvent;
use crate::protocol::PresenceSubtype;
use crate::protocol::messages::Verified;

use super::membership_update;

use crate::gossip;
use crate::util::clock::Instant;

/// A received `Presence` frame plus the roster delta `membership_update::observe`
/// already computed for it, passed to [`handle_presence`]. Constructed by
/// `crate::gossip::recv::ingest`, across the `gossip`/`lifecycle` module
/// boundary — hence `pub(crate)` rather than module-private.
#[derive(Debug, Clone)]
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
        // A key says goodbye once per run. A second copy is a replay that a peer still held.
        let key = message.key();
        if state.key_said_goodbye(key) {
            return;
        }
        state.drop_departed_presence(&key);
        // The roster is keyed by author key, so a goodbye ends that key and no other: another key
        // under the same nickname stays a peer. Any key can sign a goodbye under any nickname, and
        // the goodbye of a key that is not in the roster removes nothing. It is kept apart from
        // the goodbyes of peers, so a flood of them cannot evict those.
        let was_peer = state.peers.contains(&key) || state.quiet.contains(&key);
        if !was_peer {
            state.note_stranger_left(key);
            return;
        }
        state.note_left(key);
        let was_surfaced = state.surfaced.contains(&key);
        let left_endpoint = state.forget_key(key);
        if let Some(endpoint_id) = left_endpoint
            && !state.endpoint_is_bound(endpoint_id.id)
        {
            // A graceful goodbye, unlike a silence timeout, drops the dial hint, and with it the
            // warm unicast connection and any dial cooldown, so a rejoin re-dials cold.
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
        // Only announce a departure for a peer whose arrival we
        // surfaced — keeps the join-horizon view symmetric. A `left`
        // for a peer known only through pre-join backlog (or one we
        // already showed going quiet) is dropped.
        if was_surfaced {
            context.sink.emit(NodeEvent::Presence {
                message: Box::new(message.authored()),
                peer: key,
                synthetic: false,
            });
            tracing::info!(target: "habilis_network::lifecycle", nickname = %message.author, "peer left");
        }
        state.write_peer_count();
        // App cleanup last, with the roster already consistent. The app tracks peers by nickname,
        // so it hears of the departure when no other key holds the nickname. Gated on
        // `surfaceable`: a relayed pre-join `Left` must never cancel live work — the same
        // join-horizon symmetry as the announcement above.
        if surfaceable && !state.nickname_is_held(&message.author) {
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
        // Suppress "has joined" when we already printed "came back" from the quiet check, or
        // when this `joined` predates our own join (relayed backlog). Gated on `surfaced`: a
        // synthetic arrival may have shown this peer already. A peer that is in the roster from
        // backlog, and not shown yet, is shown by its fresh `joined`: the roster entry is not an
        // arrival. A `joined` too old to prove presence does not put a peer in the roster, so it
        // shows none.
        let in_roster = state.peers.contains(&message.key());
        if surfaceable && !update.returned && in_roster && state.surfaced.insert(message.key()) {
            state.clock_evidence.returned_unshown.remove(&message.key());
            state.write_peer_count();
            context.sink.emit(NodeEvent::Presence {
                message: Box::new(message.authored()),
                peer: message.key(),
                synthetic: false,
            });
            tracing::info!(target: "habilis_network::lifecycle", nickname = %message.author, "peer joined (announced)");
        }
    }
}
