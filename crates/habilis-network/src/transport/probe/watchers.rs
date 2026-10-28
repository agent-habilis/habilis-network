//! The watchers that keep the probe in step with the paths.

use super::nudge_addrs::NudgeAddrs;
use super::pair_to_climb::PairToClimb;
use super::path_action::PathAction;
use super::path_change::{NO_PATH_GRACE, PathChange};
use super::path_kind::PathKind;
use super::step::StepInput;
use super::{kinds, pair_to_climb, step};

use crate::transport::UdpTransport;
use std::collections::HashMap;

use futures_util::StreamExt as _;
use iroh::EndpointId;

use crate::daemon::ctx::HandlerCtx;
use crate::daemon::state::{DirectState, EventLoopState};
use crate::transport::webrtc;
use crate::util::clock::Instant;

#[cfg(feature = "multihop")]
use crate::transport::underlay_webrtc;

/// Start a path watcher for every raced peer not yet watched: a peer with UDP
/// on both ends, on a node running `WebRTC`, where this node offers (the lower
/// id). Only the offerer can race again, and its detach reaches the answerer
/// as a close. Selection is per remote in iroh, so the pooled connection
/// answers for the gossip link too.
///
/// Direct connections are on demand (decision D4): the watcher follows the
/// pooled connection that a send opened, and dials none of its own. A pair that
/// was never sent to, or whose connection the pool closed for want of a send,
/// has nothing to watch and stays where it is until the next send. A gossip
/// link on such a pair is not watched either: a direct path that it loses is
/// found by the relay policy on the link, and the peer is probed again from the
/// alive tick.
///
/// Who races again a pair that loses IP: the lower id, through this watcher. When
/// the higher id is the one that sends, there is no watcher at all, and the higher
/// id offers by itself once the admission table reads the relay for a pair that it
/// holds as proven (`negotiate_session`, `waits_for_the_offer`).
pub(crate) fn ensure_watchers(
    state: &mut EventLoopState,
    local: EndpointId,
    rendezvous: EndpointId,
) {
    if state.webrtc.is_none() || state.local_udp_transport == UdpTransport::Absent {
        return;
    }
    let peers: Vec<EndpointId> = state
        .peer_endpoints
        .values()
        // The rendezvous serves no unicast, so it has no pooled connection
        // to watch; `retry_candidates` skips it for the same reason.
        .filter(|addr| addr.id != rendezvous && !webrtc::needs_webrtc_lane(addr) && local < addr.id)
        .map(|addr| addr.id)
        .collect();
    for peer in peers {
        let Some(conn) = state.unicast_pool.used_connection(peer) else {
            // Nothing to watch: the pair was never sent to, or the pool closed
            // its connection, and the watcher went with it. The last path kind it
            // reported must go too, or every alive tick connects to the peer
            // again to nudge it.
            state.path_watchers.remove(&peer);
            state.path_kinds.remove(&peer);
            continue;
        };
        if state.path_watchers.get(&peer) == Some(&Some(conn.stable_id())) {
            continue;
        }
        state.path_watchers.insert(peer, Some(conn.stable_id()));
        tracing::debug!(target: crate::transport::LOG_TARGET, %peer, "watching the selected path");
        let tx = state.path_changes.clone();
        n0_future::task::spawn(async move {
            // iroh punches UDP again only on the client side of a
            // connection; a server-side one would never see UDP return.
            debug_assert!(conn.side().is_client(), "a watched connection is ours");
            let conn_id = conn.stable_id();
            // Subscribe first, then read: a path selected before the
            // subscription is reported by the first read, not missed.
            let mut events = conn.path_events();
            let mut last = None;
            tracing::debug!(target: crate::transport::LOG_TARGET, %peer, paths = ?kinds::path_list(&conn), "watcher started");
            loop {
                // A closed connection reads as no path; that is not a loss to
                // race over, and a replacement gets a watcher of its own.
                if conn.close_reason().is_some() {
                    return;
                }
                let mut kind = kinds::selected_kind(&conn);
                if kind == PathKind::None {
                    // Between two path events the selection can read empty for
                    // a moment; only a loss that lasts is one.
                    n0_future::time::sleep(NO_PATH_GRACE).await;
                    kind = kinds::selected_kind(&conn);
                }
                if last != Some(kind) {
                    last = Some(kind);
                    if tx
                        .send(PathChange {
                            peer,
                            kind,
                            conn_id,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                if events.next().await.is_none() {
                    return;
                }
            }
        });
    }
}

/// Record `peer` as proven direct again; whether frames parked while it was
/// not now need a flush. The race's offer round restores `Direct` through
/// [`graft_proven`], but UDP can come back before any round attaches.
pub(crate) fn mark_proven(state: &mut EventLoopState, peer: EndpointId) -> bool {
    let was = state.direct.insert(peer, DirectState::Direct);
    was != Some(DirectState::Direct) && state.meshed && !state.pending_outbound.is_empty()
}

/// Once per alive tick, nudge every watched peer riding `WebRTC`. A nudge is
/// a connect, and each one makes iroh try the UDP punch again and re-run path
/// selection; without it iroh retries every 60 s. When UDP answers, the
/// watcher sees it selected and the session is detached.
pub(crate) fn nudge_webrtc_riders(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    for peer in webrtc_riders(state) {
        let endpoint = ctx.endpoint.clone();
        n0_future::task::spawn(async move {
            webrtc::nudge(&endpoint, peer).await;
        });
    }
    nudge_climbing_pairs(state, ctx, false);
}

/// A pair on the relay, or on gossip, that the topology can now route: dial with the route. The
/// watcher does this when the path is lost, but a route learned later is then missing, and
/// nothing else runs a lookup for a pair that already has a session or no offer to make.
///
/// The alive tick calls this with `only_changed` false, as the backstop: every pair that has
/// something to carry is dialed. A link-state vector that changed the topology calls it with
/// `only_changed` true, so that a route that comes in between two ticks is dialed at once. The
/// guard is on the route, not on the dial: a route that a link-state event dialed already is not
/// dialed again by another event, and the alive tick dials it as the backstop. No in-flight guard,
/// by design: each dial is bounded by `DIAL_TIMEOUT`.
pub(crate) fn nudge_climbing_pairs(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    only_changed: bool,
) {
    let pairs: Vec<PairToClimb> = state
        .peer_endpoints
        .values()
        .filter(|addr| addr.id != ctx.rendezvous_id)
        .filter_map(|addr| {
            let kind = kinds::pair_kind(
                state.path_kinds.get(&addr.id).copied(),
                state.webrtc_admission.selected_kind(addr.id),
            )?;
            // The relay and gossip are the two rungs that a route can still climb from.
            matches!(kind, PathKind::Relay | PathKind::Gossip).then(|| {
                let has_session = state
                    .webrtc
                    .as_ref()
                    .is_some_and(|handle| handle.has_session(&addr.id));
                PairToClimb {
                    peer: addr.id,
                    kind,
                    has_session,
                    route: route_to(state, addr.id),
                }
            })
        })
        .collect();
    let gossip_on = state.gossip_handle.is_some();
    for (peer, addrs) in
        pair_to_climb::plan_relay_dials(pairs, &mut state.route_dialed, only_changed, gossip_on)
    {
        tracing::debug!(
            target: crate::transport::LOG_TARGET,
            %peer,
            only_changed,
            session = addrs.session,
            route = addrs.route.is_some(),
            "dialing a pair on the relay"
        );
        let endpoint = ctx.endpoint.clone();
        n0_future::task::spawn(async move {
            webrtc::nudge_with(&endpoint, peer, &addrs).await;
        });
    }
}

/// Pure: the route dialed for a pair is only kept while the pair reads as the relay: a pair that
/// fell back to the relay later gets its route dialed again. The planner's `retain` is the rule;
/// this forgets a watched pair at the report, one pass earlier.
pub(crate) fn forget_route_unless_climbing(
    route_dialed: &mut HashMap<EndpointId, iroh::TransportAddr>,
    peer: EndpointId,
    kind: PathKind,
) {
    if !matches!(kind, PathKind::Relay | PathKind::Gossip) {
        route_dialed.remove(&peer);
    }
}

/// The multihop route to `peer` that the topology has now, as a dialable
/// address. `None` off a host, or without a route.
#[cfg(feature = "multihop")]
pub(crate) fn route_to(state: &EventLoopState, peer: EndpointId) -> Option<iroh::TransportAddr> {
    state
        .multihop
        .as_ref()
        .and_then(|handle| {
            handle.route_addr(habilis_network_iroh_multihop_transport::AppId::new(peer))
        })
        .map(iroh::TransportAddr::Custom)
}

#[cfg(not(feature = "multihop"))]
pub(crate) fn route_to(_state: &EventLoopState, _peer: EndpointId) -> Option<iroh::TransportAddr> {
    None
}

/// The peers that an alive tick nudges: those whose last reported path is a
/// `WebRTC` session.
pub(crate) fn webrtc_riders(state: &EventLoopState) -> Vec<EndpointId> {
    state
        .path_kinds
        .iter()
        .filter(|(_, kind)| **kind == PathKind::WebRtc)
        .map(|(peer, _)| *peer)
        .collect()
}

/// Apply a watcher's report (requirements 3 and 4): drop the session once UDP
/// is selected again, and race again once the direct path is gone. A lost
/// path moves a proven peer to `RelayOnly`, not `Pending`: frames park, and
/// the alive tick keeps retrying it if this round fails.
pub(crate) async fn on_path_change(
    change: PathChange,
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
) {
    let PathChange {
        peer,
        kind,
        conn_id,
    } = change;
    match state.path_watchers.get(&peer) {
        Some(Some(watched)) if *watched == conn_id => {}
        // A replaced connection's watcher.
        _ => return,
    }
    tracing::debug!(target: crate::transport::LOG_TARGET, %peer, ?kind, "selected path changed");
    state.path_kinds.insert(peer, kind);
    forget_route_unless_climbing(&mut state.route_dialed, peer, kind);
    // The pair may have just reached WebRTC, or IP: the underlay opens or drops its
    // session now, not at the alive tick.
    #[cfg(feature = "multihop")]
    underlay_webrtc::tick_now(state);
    // The fast path of the gossip drop rule for a watched pair: the table reads the pair from
    // all of its connections, so that this path and the sweep never disagree on what to tell
    // the gossip transport.
    state.webrtc_admission.sync_gossip();
    let Some(handle) = state.webrtc.clone() else {
        return;
    };
    let has_session = handle.has_session(&peer);
    let ladder = step(StepInput {
        kind,
        has_session,
        route: route_to(state, peer),
        gossip_on: state.gossip_handle.is_some(),
    });
    let action = ladder.action;
    match action {
        PathAction::Proven | PathAction::Detach => {
            if action == PathAction::Detach {
                let _ = handle.detach(&peer);
                tracing::info!(target: crate::transport::LOG_TARGET, %peer, "udp selected again; webrtc session detached");
            }
            if mark_proven(state, peer) {
                crate::gossip::flush_pending(state, ctx, "direct path back").await;
            }
        }
        PathAction::Rerace => {
            if matches!(kind, PathKind::Multihop | PathKind::Gossip) {
                // Off the relay, so frames may flow; but the pair has no lane yet.
                if mark_proven(state, peer) {
                    crate::gossip::flush_pending(state, ctx, "path off the relay").await;
                }
                tracing::info!(target: crate::transport::LOG_TARGET, %peer, ?kind, "pair is off the relay; racing for a lane");
            } else {
                if state.direct.get(&peer) == Some(&DirectState::Direct) {
                    state.direct.insert(peer, DirectState::RelayOnly);
                }
                tracing::info!(target: crate::transport::LOG_TARGET, %peer, ?kind, detector = "watcher", "direct path lost; racing again");
            }
            if let Some(addrs) = ladder.nudge {
                // One dial carries what iroh may not know yet: the session's
                // address moves a connection onto the session's path, and the
                // multihop route is learned by no lookup while another path is
                // selected.
                let endpoint = ctx.endpoint.clone();
                n0_future::task::spawn(async move {
                    webrtc::nudge_with(&endpoint, peer, &addrs).await;
                });
            }
            if !has_session
                && let Some(addr) = state
                    .peer_endpoints
                    .values()
                    .find(|addr| addr.id == peer)
                    .cloned()
            {
                webrtc::negotiate_session(state, ctx, peer, addr);
            }
        }
    }
}

/// Pure: the addresses that a nudge dial names for `peer`.
pub(crate) fn nudge_known(peer: EndpointId, addrs: &NudgeAddrs) -> Vec<iroh::TransportAddr> {
    let mut known = Vec::new();
    if addrs.session {
        known.push(iroh::TransportAddr::Custom(
            habilis_network_iroh_webrtc_transport::custom_addr(peer),
        ));
    }
    known.extend(addrs.route.clone());
    if addrs.gossip {
        known.push(iroh::TransportAddr::Custom(
            habilis_network_iroh_gossip_transport::gossip_addr(peer),
        ));
    }
    known
}

/// Pure: the peers that a multihop route proves, though no watcher reports them. A pair with an
/// IP-less end has no path watcher (`ensure_watchers` skips it), and its session is its proof
/// (`ensure_direct`); when the session is refused or gone, the pair can still ride a multihop
/// route, and nothing else reads that. A peer is returned when it is not proven, has no watcher,
/// and its selected path is multihop (not gossip: the recursion rule closes gossip links on that
/// rung, so it proves nothing). A peer that is watched is left to its watcher, which also
/// revokes; here nothing is revoked.
pub(crate) fn proven_by_route(
    peers: impl IntoIterator<Item = EndpointId>,
    direct: &HashMap<EndpointId, DirectState>,
    watched: &HashMap<EndpointId, Option<usize>>,
    kind_of: impl Fn(EndpointId) -> Option<PathKind>,
) -> Vec<EndpointId> {
    let mut proven: Vec<EndpointId> = peers
        .into_iter()
        .filter(|peer| {
            direct.get(peer) != Some(&DirectState::Direct)
                && !watched.contains_key(peer)
                && kind_of(*peer) == Some(PathKind::Multihop)
        })
        .collect();
    proven.sort_unstable();
    proven
}

/// Mark the pairs that [`proven_by_route`] returns, and flush what waited for them. Runs on the
/// sweep tick.
pub(crate) async fn prove_routed_pairs(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    let peers: Vec<EndpointId> = state
        .peer_endpoints
        .values()
        .map(|addr| addr.id)
        .filter(|id| *id != ctx.rendezvous_id)
        .collect();
    let proven = proven_by_route(peers, &state.direct, &state.path_watchers, |peer| {
        state.pair_path_kind(peer)
    });
    let mut flush = false;
    for peer in proven {
        tracing::info!(target: crate::transport::LOG_TARGET, %peer, "pair is off the relay on a multihop route; proven");
        flush |= mark_proven(state, peer);
        // The proof must not remove the trigger of the session: a held frame used to open it, and a
        // pair that is proven is no longer held. A multihop route has no lane of its own, so the
        // pair keeps racing for one, as the watcher's report of a multihop path does.
        state.want_lane_session(peer, Instant::now());
        let has_session = state
            .webrtc
            .as_ref()
            .is_some_and(|handle| handle.has_session(&peer));
        if !has_session
            && let Some(addr) = state
                .peer_endpoints
                .values()
                .find(|addr| addr.id == peer)
                .cloned()
        {
            webrtc::negotiate_session(state, ctx, peer, addr);
        }
    }
    if flush {
        crate::gossip::flush_pending(state, ctx, "path off the relay").await;
    }
}
