use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::{EventLoopState, Standing};
use crate::gossip::app::NodeApp;
use crate::gossip::event::NodeEvent;
use crate::protocol::messages::Verified;
use crate::protocol::{Message, Nickname, PresenceSubtype};
use iroh::EndpointId;

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

/// The presence that reports a departure. The roster knows the key by `departed`, and a goodbye can
/// name another nickname. Then this node signs the `left` that reports it, as it does for an
/// arrival, so that the proof names the peer that was removed.
fn departure(message: &Verified, departed: &Nickname, context: &HandlerCtx<'_>) -> NodeEvent {
    let key = message.key();
    if message.author == *departed {
        return NodeEvent::Presence {
            message: Box::new(message.authored()),
            peer: key,
            synthetic: false,
        };
    }
    let left = Message::new_left(context.mesh, departed).sign(context.identity);
    NodeEvent::Presence {
        message: Box::new(left.authored()),
        peer: key,
        synthetic: true,
    }
}

/// End the pooled connection, the dial cooldown and the multihop origin of each endpoint that no
/// nickname binds. A graceful goodbye, unlike a silence timeout, drops the dial hint, and with it
/// the warm unicast connection, so a rejoin re-dials cold. The advertised links go too, or routes
/// keep running through a peer that said goodbye until its vector ages out.
async fn end_unbound_endpoints(state: &mut EventLoopState, endpoints: Vec<EndpointId>) {
    let unbound: Vec<_> = endpoints
        .into_iter()
        .filter(|endpoint_id| !state.endpoint_is_bound(*endpoint_id))
        .collect();
    for endpoint_id in unbound {
        state.unicast_pool.forget(endpoint_id).await;
        #[cfg(feature = "multihop")]
        if let Some(handle) = state.multihop.as_ref() {
            let _ = handle.remove_origin(habilis_network_iroh_multihop_transport::AppId::new(
                endpoint_id,
            ));
        }
    }
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
        // the goodbyes of peers, so a flood of them cannot evict those. A key that outlived the
        // quiet TTL is still in the roster: it keeps its name and its dial hint.
        let was_peer = state.peers.contains(&key)
            || state.quiet.contains(&key)
            || state.clock_evidence.lapsed_quiet.contains(&key);
        if !was_peer {
            state.note_stranger_left(key);
            // A `PeerInfo` can bind a hint before the roster admits its key, and the hint of a
            // key that said goodbye must not stay routable.
            let stranger_hints = state.forget_hints_of(key);
            let hinted = stranger_hints.iter().map(|hint| hint.id);
            end_unbound_endpoints(state, hinted.collect()).await;
            return;
        }
        state.note_left(key);
        let was_surfaced = state.surfaced.contains(&key);
        // The roster knows the key by the nickname it recorded, and a goodbye can name any
        // nickname. `forget_key` drops the record, so read it first.
        let departed = state.names.get(&key).unwrap_or(&message.author).clone();
        // A key that renamed left one endpoint for each nickname it used, and it can have proved an
        // endpoint without owning a hint, when another key held its nickname. Each one is torn
        // down, unless a nickname still binds it. `forget_key` drops the trust, so read it first.
        let proved = state.proven_endpoints.trusted(&key);
        let left_hints = state.forget_key(key);
        let hinted = left_hints.iter().map(|hint| hint.id);
        let left_endpoints: Vec<_> = hinted.chain(proved).collect();
        end_unbound_endpoints(state, left_endpoints).await;
        // Only announce a departure for a peer whose arrival we
        // surfaced — keeps the join-horizon view symmetric. A `left`
        // for a peer known only through pre-join backlog (or one we
        // already showed going quiet) is dropped.
        if was_surfaced {
            context.sink.emit(departure(message, &departed, context));
            tracing::info!(target: "habilis_network::lifecycle", nickname = %departed, "peer left");
        }
        state.write_peer_count();
        // A departure is a flush edge: the frames to the key that left are gone from the buffer
        // (`forget_key`), and the rest go now.
        if state.standing.contains(&Standing::Meshed) && !state.pending_outbound.is_empty() {
            gossip::flush_pending(state, context, "peer left").await;
        }
        // App cleanup last, with the roster already consistent. The app hears of every key that
        // leaves, whoever else holds its nickname. Not gated on `surfaceable`: the key was in the
        // roster, so a goodbye ends it whatever the clock of its sender says. The join horizon
        // hides a line from the user, and it does not hide a fact from the app.
        app.on_peer_left(&key, &departed, state, context).await;
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
