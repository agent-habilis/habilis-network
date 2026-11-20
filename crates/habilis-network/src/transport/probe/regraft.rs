//! Re-grafting the peers that fell out of the view.

use super::grafts;

use iroh::EndpointId;

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::{DirectState, EventLoopState};
use crate::transport::webrtc;
use crate::util::clock::Instant;

use crate::{lookup, transport};
/// Graft again the proven peers whose link went down about a second ago (see
/// [`EventLoopState::plan_regraft_on_link_loss`]). The reclaim ticker calls this, because
/// the heal tick would leave the pair apart for 10 to 15 s.
pub(crate) async fn regraft_due(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    for peer in state.take_regrafts_due(Instant::now()) {
        let Some(address) = state.member_address_of(peer) else {
            continue;
        };
        state.note_relink(peer, Instant::now());
        lookup::add_peer_addr(&state.address_book, address.clone());
        state.unicast_pool.note_addr(&address);
        tracing::debug!(target: transport::LOG_TARGET, %peer, "the link went down: grafting the proven peer again");
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
/// caller passes a random one. `None` once the active view holds `max_connections` (G)
/// links, or when nobody is free.
pub(crate) fn next_fill(
    state: &EventLoopState,
    max_connections: usize,
    rendezvous_id: EndpointId,
    now: Instant,
    pick: usize,
) -> Option<iroh::EndpointAddr> {
    if state.linked_endpoints.len() >= max_connections {
        return None;
    }
    let peer_addresses = state.member_addresses();
    let candidates = peer_addresses.iter().filter(|address| {
        address.id != rendezvous_id && !state.linked_endpoints.contains(&address.id)
    });
    let cooled = candidates.filter(|address| !state.relink_on_cooldown(address.id, now));
    let cooled: Vec<&iroh::EndpointAddr> = cooled.collect();
    let mut free: Vec<&iroh::EndpointAddr> = cooled
        .iter()
        .copied()
        .filter(|address| !state.graft_blocked(address.id, now))
        .collect();
    // Every free peer refused lately, and the node is short of G with no link gained: it asks one of
    // them with a high priority request (see `graft_request`).
    if free.is_empty() && state.forced_neighbor_ready(now) {
        free = cooled;
    }
    free.sort_unstable_by_key(|address| {
        (webrtc::lane_needs::needs_webrtc_lane(address), address.id)
    });
    let first_group: usize = free.first().map_or(0, |first| {
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
    let Some(address) = next_fill(
        state,
        context.max_connections,
        context.rendezvous_id,
        now,
        pick,
    ) else {
        return;
    };
    graft_one(state, context, address, now).await;
}

/// The member that a reclaim tick asks for a link when this node lost every one: the member
/// that the fill tick would pick, and none while the node holds a link or the window is closed.
pub(crate) fn isolated_candidate(
    state: &EventLoopState,
    max_connections: usize,
    rendezvous_id: EndpointId,
    now: Instant,
    pick: usize,
) -> Option<iroh::EndpointAddr> {
    if !state.isolated_refill_due(now) {
        return None;
    }
    next_fill(state, max_connections, rendezvous_id, now, pick)
}

/// A node that lost every link asks one other known peer per reclaim tick (400 ms) while the
/// fast window is open, with a low priority request that evicts nobody. The lost peers are
/// asked by the regraft, and they are full; the heal tick, 15 s later, was the first attempt to
/// reach a peer with a free slot. The relink cooldown sends each tick to another peer.
pub(crate) async fn refill_isolated(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    let now = Instant::now();
    let pick = rand::Rng::random_range(&mut rand::rng(), 0..usize::MAX);
    let Some(address) = isolated_candidate(
        state,
        context.max_connections,
        context.rendezvous_id,
        now,
        pick,
    ) else {
        return;
    };
    tracing::info!(target: transport::LOG_TARGET, peer = %address.id, "no link left: asking another known peer");
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
    lookup::add_peer_addr(&state.address_book, address.clone());
    state.unicast_pool.note_addr(&address);
    tracing::debug!(target: transport::LOG_TARGET, peer = %address.id, linked = state.linked_endpoints.len(), "filling the active view");
    if grafts::ensure_direct(state, context, address.id, &address) {
        grafts::graft_proven(state, context, address.id).await;
    }
}

/// The peers one `retry_direct` pass probes, in a fixed order.
pub(crate) fn retry_candidates(
    state: &EventLoopState,
    rendezvous_id: EndpointId,
    max_connections: usize,
    distrust_links: bool,
) -> Vec<iroh::EndpointAddr> {
    retry_candidates_at(
        state,
        rendezvous_id,
        max_connections,
        distrust_links,
        Instant::now(),
    )
}

/// [`retry_candidates`] at `now`.
pub(crate) fn retry_candidates_at(
    state: &EventLoopState,
    rendezvous_id: EndpointId,
    max_connections: usize,
    distrust_links: bool,
    now: Instant,
) -> Vec<iroh::EndpointAddr> {
    // A graft is the reason for a session, and none runs at G.
    if !distrust_links && state.linked_endpoints.len() >= max_connections {
        return Vec::new();
    }
    let peer_addresses = state.member_addresses();
    let candidates = peer_addresses.iter().filter(|address| {
        address.id != rendezvous_id
            && (distrust_links || !state.linked_endpoints.contains(&address.id))
    });
    let webrtc_session = |address: &iroh::EndpointAddr| {
        state
            .webrtc
            .as_ref()
            .is_some_and(|handle| handle.has_session(&address.id))
    };
    let direct_ok = candidates.filter(|address| {
        state.direct.get(&address.id) != Some(&DirectState::Pending)
            || (webrtc::lane_needs::needs_webrtc_lane(address) && webrtc_session(address))
    });
    let cooled: Vec<&iroh::EndpointAddr> = direct_ok
        .filter(|address| !state.relink_on_cooldown(address.id, now))
        .collect();
    let mut peers: Vec<iroh::EndpointAddr> = cooled
        .iter()
        .copied()
        .filter(|address| !state.graft_blocked(address.id, now))
        .cloned()
        .collect();
    // The same rule as in `next_fill`: with no relay payload this is the only path that grafts,
    // and it forces one random refusing peer, as `next_fill` does.
    if peers.is_empty() && state.forced_neighbor_ready(now) {
        let pick = rand::Rng::random_range(&mut rand::rng(), 0..usize::MAX);
        peers = pick
            .checked_rem(cooled.len())
            .and_then(|index| cooled.get(index))
            .map(|address| (*address).clone())
            .into_iter()
            .collect();
    }
    peers.sort_unstable_by_key(|address| address.id);
    peers
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::EndpointAddr;

    use super::{next_fill, retry_candidates_at};
    use crate::daemon::state::EventLoopState;
    use crate::testing;
    use crate::transport::probe::graft_request::{GraftRequest, GraftTarget, graft_request};
    use crate::util::clock::Instant;
    use crate::util::tuning::FORCE_NEIGHBOR_AFTER;

    const TARGET: usize = 4;

    /// The one free peer of the node, and the rendezvous.
    fn peer() -> iroh::EndpointId {
        testing::endpoint_id(1)
    }

    fn rendezvous() -> iroh::EndpointId {
        testing::endpoint_id(99)
    }

    /// A node one link short of G since `start` and with no jitter, whose only free peer was
    /// asked at `start` and refused: that peer is in its wait when the window ends.
    fn node_whose_only_free_peer_refused(start: Instant) -> EventLoopState {
        let mut state = testing::fresh_state();
        for seed in 0..TARGET - 1 {
            state.link(testing::endpoint_id(
                u8::try_from(seed).expect("a small seed") + 10,
            ));
        }
        state.force_jitter = 0.0;
        state.note_link_count(TARGET - 1, TARGET, start);
        state
            .peer_endpoints
            .insert(testing::nick("free-peer"), EndpointAddr::new(peer()));
        let target = GraftTarget {
            peer: peer(),
            rendezvous: rendezvous(),
        };
        assert_eq!(
            graft_request(&mut state, target, TARGET, start, true),
            GraftRequest::Neighbor,
            "the first ask is a low priority request"
        );
        state.settle_graft_backoff(start + Duration::from_secs(21));
        state
    }

    #[test]
    fn the_fill_tick_picks_the_refusing_peer_when_the_window_ends() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let state = node_whose_only_free_peer_refused(start);
        let early = start + FORCE_NEIGHBOR_AFTER.saturating_sub(Duration::from_secs(1));
        assert_eq!(
            next_fill(&state, TARGET, rendezvous(), early, 0),
            None,
            "before the window the refusing peer is left alone"
        );
        let due = start + FORCE_NEIGHBOR_AFTER;
        assert_eq!(
            next_fill(&state, TARGET, rendezvous(), due, 0).map(|address| address.id),
            Some(peer()),
            "when the window ends the refusing peer is picked, so that the request is forced"
        );
    }

    #[test]
    fn the_probe_path_offers_one_of_two_refusing_peers_when_the_window_ends() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = node_whose_only_free_peer_refused(start);
        let second = testing::endpoint_id(2);
        state
            .peer_endpoints
            .insert(testing::nick("second-peer"), EndpointAddr::new(second));
        let target = GraftTarget {
            peer: second,
            rendezvous: rendezvous(),
        };
        assert_eq!(
            graft_request(&mut state, target, TARGET, start, true),
            GraftRequest::Neighbor,
            "the first ask of the second peer is a low priority request"
        );
        let linked = &state.linked_endpoints;
        state.graft_backoff.settle(
            start + Duration::from_secs(21),
            |endpoint| linked.contains(endpoint),
            0.0,
        );
        let due = start + FORCE_NEIGHBOR_AFTER;
        let offered = retry_candidates_at(&state, rendezvous(), TARGET, false, due);
        assert_eq!(
            offered.len(),
            1,
            "one refusing peer is forced, not every refusing peer"
        );
    }

    #[test]
    fn the_probe_path_offers_the_refusing_peer_when_the_window_ends() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let state = node_whose_only_free_peer_refused(start);
        let early = start + FORCE_NEIGHBOR_AFTER.saturating_sub(Duration::from_secs(1));
        assert!(
            retry_candidates_at(&state, rendezvous(), TARGET, false, early).is_empty(),
            "before the window the refusing peer is left alone"
        );
        let due = start + FORCE_NEIGHBOR_AFTER;
        let offered: Vec<_> = retry_candidates_at(&state, rendezvous(), TARGET, false, due)
            .into_iter()
            .map(|address| address.id)
            .collect();
        assert_eq!(
            offered,
            vec![peer()],
            "when the window ends the refusing peer is offered, so that the request is forced"
        );
    }
}
