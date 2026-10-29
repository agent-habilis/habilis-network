//! Re-grafting the peers that fell out of the view.

use super::grafts;

use iroh::EndpointId;

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::{DirectState, EventLoopState};
use crate::transport::webrtc;
use crate::util::clock::Instant;

/// Graft again the proven peers whose link went down about a second ago (see
/// [`EventLoopState::plan_regraft_on_link_loss`]). The reclaim ticker calls this, because
/// the heal tick would leave the pair apart for 10 to 15 s.
pub(crate) async fn regraft_due(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    for peer in state.take_regrafts_due(Instant::now()) {
        let Some(address) = state
            .peer_endpoints
            .values()
            .find(|address| address.id == peer)
            .cloned()
        else {
            continue;
        };
        state.note_relink(peer, Instant::now());
        crate::lookup::add_peer_addr(&state.address_book, address.clone());
        state.unicast_pool.note_addr(&address);
        tracing::debug!(target: crate::transport::LOG_TARGET, %peer, "the link went down: grafting the proven peer again");
        if grafts::ensure_direct(state, context, peer, &address) {
            grafts::graft_proven(state, context, peer).await;
        }
    }
}

/// The member that the fill tick grafts next, among the free ones: a member that
/// is not linked, not the rendezvous and not on its relink cooldown. The natives
/// come before every browser, each group ordered by id, and `pick` indexes the
/// first group and wraps. A fixed pick would send every member below G to the
/// same few peers, and a full peer evicts a random neighbor on each join, so the
/// caller passes a random one. `None` once the active view holds `max_peers` (G)
/// links, or when nobody is free.
pub(crate) fn next_fill(
    state: &EventLoopState,
    max_peers: usize,
    rendezvous_id: EndpointId,
    now: Instant,
    pick: usize,
) -> Option<iroh::EndpointAddr> {
    if state.linked_endpoints.len() >= max_peers {
        return None;
    }
    let mut free: Vec<&iroh::EndpointAddr> = state
        .peer_endpoints
        .values()
        .filter(|address| address.id != rendezvous_id)
        .filter(|address| !state.linked_endpoints.contains(&address.id))
        .filter(|address| !state.relink_on_cooldown(address.id, now))
        .filter(|address| !state.graft_blocked(address.id, now))
        .collect();
    free.sort_unstable_by_key(|address| {
        (webrtc::lane_needs::needs_webrtc_lane(address), address.id)
    });
    let first_group = free.first().map_or(0, |first| {
        free.iter()
            .take_while(|address| {
                webrtc::lane_needs::needs_webrtc_lane(address)
                    == webrtc::lane_needs::needs_webrtc_lane(first)
            })
            .count()
    });
    free.get(pick.checked_rem(first_group)?)
        .map(|address| (*address).clone())
}

/// Graft one member toward G: the gossip active view is a target, not only a
/// cap. The attempt starts the member's relink cooldown, so a member that did
/// not link waits out the window before it is tried again, and the next tick
/// takes the next member.
pub(crate) async fn fill_active_view(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    let now = Instant::now();
    let pick = rand::Rng::random_range(&mut rand::rng(), 0..usize::MAX);
    let Some(address) = next_fill(state, context.max_peers, context.rendezvous_id, now, pick)
    else {
        return;
    };
    graft_one(state, context, address, now).await;
}

/// The member that a reclaim tick asks for a link when this node lost every one: the member
/// that the fill tick would pick, and none while the node holds a link or the window is closed.
pub(crate) fn isolated_candidate(
    state: &EventLoopState,
    max_peers: usize,
    rendezvous_id: EndpointId,
    now: Instant,
    pick: usize,
) -> Option<iroh::EndpointAddr> {
    if !state.isolated_refill_due(now) {
        return None;
    }
    next_fill(state, max_peers, rendezvous_id, now, pick)
}

/// A node that lost every link asks one other known peer per reclaim tick (400 ms) while the
/// fast window is open, with a low priority request that evicts nobody. The lost peers are
/// asked by the regraft, and they are full; the heal tick, 15 s later, was the first attempt to
/// reach a peer with a free slot. The relink cooldown sends each tick to another peer.
pub(crate) async fn refill_isolated(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    let now = Instant::now();
    let pick = rand::Rng::random_range(&mut rand::rng(), 0..usize::MAX);
    let Some(address) =
        isolated_candidate(state, context.max_peers, context.rendezvous_id, now, pick)
    else {
        return;
    };
    tracing::info!(target: crate::transport::LOG_TARGET, peer = %address.id, "no link left: asking another known peer");
    graft_one(state, context, address, now).await;
}

/// Ask `addr` for a link now, and start its relink cooldown.
pub(crate) async fn graft_one(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    address: iroh::EndpointAddr,
    now: Instant,
) {
    state.note_relink(address.id, now);
    crate::lookup::add_peer_addr(&state.address_book, address.clone());
    state.unicast_pool.note_addr(&address);
    tracing::debug!(target: crate::transport::LOG_TARGET, peer = %address.id, linked = state.linked_endpoints.len(), "filling the active view");
    if grafts::ensure_direct(state, context, address.id, &address) {
        grafts::graft_proven(state, context, address.id).await;
    }
}

/// The peers one `retry_direct` pass probes, in a fixed order.
pub(crate) fn retry_candidates(
    state: &EventLoopState,
    rendezvous_id: EndpointId,
    max_peers: usize,
    distrust_links: bool,
) -> Vec<iroh::EndpointAddr> {
    retry_candidates_at(
        state,
        rendezvous_id,
        max_peers,
        distrust_links,
        Instant::now(),
    )
}

/// [`retry_candidates`] at `now`.
pub(crate) fn retry_candidates_at(
    state: &EventLoopState,
    rendezvous_id: EndpointId,
    max_peers: usize,
    distrust_links: bool,
    now: Instant,
) -> Vec<iroh::EndpointAddr> {
    // A graft is the reason for a session, and none runs at G.
    if !distrust_links && state.linked_endpoints.len() >= max_peers {
        return Vec::new();
    }
    let mut peers: Vec<iroh::EndpointAddr> = state
        .peer_endpoints
        .values()
        .filter(|address| address.id != rendezvous_id)
        .filter(|address| distrust_links || !state.linked_endpoints.contains(&address.id))
        .filter(|address| {
            state.direct.get(&address.id) != Some(&DirectState::Pending)
                || (webrtc::lane_needs::needs_webrtc_lane(address)
                    && state
                        .webrtc
                        .as_ref()
                        .is_some_and(|handle| handle.has_session(&address.id)))
        })
        .filter(|address| !state.relink_on_cooldown(address.id, now))
        .filter(|address| !state.graft_blocked(address.id, now))
        .cloned()
        .collect();
    peers.sort_unstable_by_key(|address| address.id);
    peers
}
