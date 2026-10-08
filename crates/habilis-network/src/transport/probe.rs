//! Probe, then graft: on a mesh whose relay is lookup only, a peer joins our
//! gossip overlay only once a direct path to it is proven.
//!
//! iroh opens the first connection to a peer behind NAT over the relay and
//! punches a direct path *inside* it; a gossip link opened on that connection
//! would carry every frame relayed until the punch lands — and, for a `WebRTC`
//! peer, for the life of the link, since a custom-transport path is never
//! added to a live connection. So the graft waits: an IP peer is probed with
//! the unicast pool's own connection until iroh selects a non-relay path, a
//! browser peer until its `WebRTC` session is attached. Both bounded — a
//! peer that never proves a direct path stays `RelayOnly`, retried on the
//! alive tick, and is never grafted through the relay.

use std::collections::HashMap;

use futures_util::StreamExt as _;
use iroh::EndpointId;
use iroh::endpoint::Connection;

use super::path::{PROBE_DEADLINE, wait_direct};
use super::webrtc::needs_webrtc_lane;
use crate::daemon::ctx::HandlerCtx;
use crate::daemon::state::{DirectState, EventLoopState};
use crate::util::clock::Instant;

/// A probe's verdict, reported back to the event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectOutcome {
    pub(crate) peer: EndpointId,
    pub(crate) direct: bool,
    /// The session came from an offer of the peer that this node answered. The answerer grafts and
    /// flushes only when a frame is held for the peer, see [`DirectOutcome::applies`].
    pub(crate) answered: bool,
}

impl DirectOutcome {
    /// Whether the loop acts on this outcome at `now`. An answered session is not a verdict of
    /// this node's own probe: it matters only when a frame is held for the peer, which waits for
    /// the attach to be flushed.
    pub(crate) fn applies(self, state: &EventLoopState, now: Instant) -> bool {
        !self.answered || state.lane_session_wanted(self.peer, now)
    }
}

/// Which kind of path iroh has selected to a peer, as the race sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathKind {
    Ip,
    WebRtc,
    /// A multihop route through other members. It is not on the relay, but a
    /// pair on it has no lane of its own: an IP path or a `WebRTC` session ranks
    /// above it.
    Multihop,
    /// The gossip rung: frames of the mesh topic carry the pair's QUIC. It is not on the relay
    /// either, and it ranks below multihop and above the relay.
    Gossip,
    Relay,
    None,
}

/// What a change of the selected path asks of the race.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathAction {
    /// A direct path is selected: the peer is proven direct again, which
    /// frees frames parked while it was not.
    Proven,
    /// UDP is back: the session only holds a direct-peer slot now.
    Detach,
    /// The direct path is gone: race again.
    Rerace,
}

/// How long "no path selected" must last before a watcher reports it. iroh
/// can leave the selection empty between a path's `Abandoned` and the next
/// `Established` (fork `remote_state.rs:650-651`, `:1516-1517`); seen in the
/// e2e as a 2 ms blip, each of which started a whole new race.
const NO_PATH_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// A watcher's report: `kind` is now the selected path to `peer`, on the
/// pooled connection `conn_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PathChange {
    pub(crate) peer: EndpointId,
    pub(crate) kind: PathKind,
    pub(crate) conn_id: usize,
}

fn path_list(conn: &Connection) -> Vec<String> {
    conn.paths()
        .iter()
        .map(|path| {
            format!(
                "{:?}{}",
                path.remote_addr(),
                if path.is_selected() { " selected" } else { "" }
            )
        })
        .collect()
}

pub(crate) fn selected_kind(conn: &Connection) -> PathKind {
    conn.paths()
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .map_or(PathKind::None, |path| {
            if path.is_ip() {
                PathKind::Ip
            } else if path.is_relay() {
                PathKind::Relay
            } else if let iroh::TransportAddr::Custom(addr) = path.remote_addr() {
                custom_kind(addr.id())
            } else {
                // A kind of address that iroh does not have today.
                PathKind::Multihop
            }
        })
}

/// Pure: the kind of a custom path by the id of its transport.
pub(crate) fn custom_kind(id: u64) -> PathKind {
    if id == habilis_network_iroh_webrtc_transport::WEBRTC_TRANSPORT_ID {
        PathKind::WebRtc
    } else if id == habilis_network_iroh_gossip_transport::GOSSIP_TRANSPORT_ID {
        PathKind::Gossip
    } else {
        PathKind::Multihop
    }
}

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
    if state.webrtc.is_none() || !state.local_udp_transport {
        return;
    }
    let peers: Vec<EndpointId> = state
        .peer_endpoints
        .values()
        // The rendezvous serves no unicast, so it has no pooled connection
        // to watch; `retry_candidates` skips it for the same reason.
        .filter(|addr| addr.id != rendezvous && !needs_webrtc_lane(addr) && local < addr.id)
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
        tracing::debug!(target: super::LOG_TARGET, %peer, "watching the selected path");
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
            tracing::debug!(target: super::LOG_TARGET, %peer, paths = ?path_list(&conn), "watcher started");
            loop {
                // A closed connection reads as no path; that is not a loss to
                // race over, and a replacement gets a watcher of its own.
                if conn.close_reason().is_some() {
                    return;
                }
                let mut kind = selected_kind(&conn);
                if kind == PathKind::None {
                    // Between two path events the selection can read empty for
                    // a moment; only a loss that lasts is one.
                    n0_future::time::sleep(NO_PATH_GRACE).await;
                    kind = selected_kind(&conn);
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
            super::webrtc::nudge(&endpoint, peer).await;
        });
    }
    nudge_routable_relay_pairs(state, ctx, false);
}

/// A pair on the relay, or on gossip, that the topology can now route: dial with the route. The watcher does
/// this when the path is lost, but a route learned later is then missing, and nothing else runs
/// a lookup for a pair that already has a session or no offer to make.
///
/// The alive tick calls this with `only_changed` false, as the backstop: every pair that has
/// something to carry is dialed. A link-state vector that changed the topology calls it with
/// `only_changed` true, so that a route that comes in between two ticks is dialed at once. The
/// guard is on the route, not on the dial: a route that a link-state event dialed already is not
/// dialed again by another event, and the alive tick dials it as the backstop. No in-flight guard,
/// by design: each dial is bounded by `DIAL_TIMEOUT`.
pub(crate) fn nudge_routable_relay_pairs(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    only_changed: bool,
) {
    let pairs: Vec<PairToClimb> = state
        .peer_endpoints
        .values()
        .filter(|addr| addr.id != ctx.rendezvous_id)
        .filter_map(|addr| {
            let kind = pair_kind(
                state.path_kinds.get(&addr.id).copied(),
                state.webrtc_admission.selected_kind(addr.id),
            )?;
            // The relay and gossip are the two rungs that a route can still climb from.
            matches!(kind, PathKind::Relay | PathKind::Gossip).then(|| {
                let has_session = state
                    .webrtc
                    .as_ref()
                    .is_some_and(|handle| handle.has_session(&addr.id));
                (addr.id, kind, has_session, route_to(state, addr.id))
            })
        })
        .collect();
    let gossip_on = state.gossip_handle.is_some();
    for (peer, addrs) in plan_relay_dials(pairs, &mut state.route_dialed, only_changed, gossip_on) {
        tracing::debug!(
            target: super::LOG_TARGET,
            %peer,
            only_changed,
            session = addrs.session,
            route = addrs.route.is_some(),
            "dialing a pair on the relay"
        );
        let endpoint = ctx.endpoint.clone();
        n0_future::task::spawn(async move {
            super::webrtc::nudge_with(&endpoint, peer, &addrs).await;
        });
    }
}

/// Pure: the route dialed for a pair is only kept while the pair reads as the relay: a pair that
/// fell back to the relay later gets its route dialed again. The planner's `retain` is the rule;
/// this forgets a watched pair at the report, one pass earlier.
fn forget_route_unless_climbing(
    route_dialed: &mut HashMap<EndpointId, iroh::TransportAddr>,
    peer: EndpointId,
    kind: PathKind,
) {
    if !matches!(kind, PathKind::Relay | PathKind::Gossip) {
        route_dialed.remove(&peer);
    }
}

/// A pair that a route can still climb from: the peer, the kind of its selected path (the relay or
/// gossip), whether it has a session, and the route that the topology has for it.
pub(crate) type PairToClimb = (EndpointId, PathKind, bool, Option<iroh::TransportAddr>);

/// Pure: the dials of one pass over the pairs that read as the relay or as gossip, as `(peer,
/// kind, has a session, route)`. A pair is dialed when it has a session address or a route to carry. With
/// `only_changed` a pair is dialed only for a route that differs from the one dialed for it last,
/// and a pair with no route is not dialed at all. `route_dialed` remembers the route of each dial,
/// and keeps it only for the pairs of this pass: a pair that left the relay (it climbed, or it
/// is gone) is forgotten, so that a pair that falls back with the same route is dialed again.
pub(crate) fn plan_relay_dials(
    pairs: impl IntoIterator<Item = PairToClimb>,
    route_dialed: &mut HashMap<EndpointId, iroh::TransportAddr>,
    only_changed: bool,
    gossip_on: bool,
) -> Vec<(EndpointId, NudgeAddrs)> {
    let pairs: Vec<_> = pairs.into_iter().collect();
    route_dialed.retain(|peer, _| pairs.iter().any(|(climbing, ..)| climbing == peer));
    let mut dials = Vec::new();
    for (peer, kind, has_session, route) in pairs {
        let input = StepInput {
            kind,
            has_session,
            route: route.clone(),
            gossip_on,
        };
        let Some(addrs) = step(input).nudge else {
            continue;
        };
        let already_dialed = route.is_some() && route_dialed.get(&peer) == route.as_ref();
        if only_changed && (route.is_none() || already_dialed) {
            continue;
        }
        if let Some(route) = route {
            route_dialed.insert(peer, route);
        }
        dials.push((peer, addrs));
    }
    dials
}

/// The multihop route to `peer` that the topology has now, as a dialable
/// address. `None` off a host, or without a route.
#[cfg(feature = "multihop")]
fn route_to(state: &EventLoopState, peer: EndpointId) -> Option<iroh::TransportAddr> {
    state
        .multihop
        .as_ref()
        .and_then(|handle| handle.route_addr(peer))
        .map(iroh::TransportAddr::Custom)
}

#[cfg(not(feature = "multihop"))]
fn route_to(_state: &EventLoopState, _peer: EndpointId) -> Option<iroh::TransportAddr> {
    None
}

/// The peers that an alive tick nudges: those whose last reported path is a
/// `WebRTC` session.
fn webrtc_riders(state: &EventLoopState) -> Vec<EndpointId> {
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
    tracing::debug!(target: super::LOG_TARGET, %peer, ?kind, "selected path changed");
    state.path_kinds.insert(peer, kind);
    forget_route_unless_climbing(&mut state.route_dialed, peer, kind);
    // The pair may have just reached WebRTC, or IP: the underlay opens or drops its
    // session now, not at the alive tick.
    #[cfg(feature = "multihop")]
    crate::transport::underlay_webrtc::tick_now(state);
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
                tracing::info!(target: super::LOG_TARGET, %peer, "udp selected again; webrtc session detached");
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
                tracing::info!(target: super::LOG_TARGET, %peer, ?kind, "pair is off the relay; racing for a lane");
            } else {
                if state.direct.get(&peer) == Some(&DirectState::Direct) {
                    state.direct.insert(peer, DirectState::RelayOnly);
                }
                tracing::info!(target: super::LOG_TARGET, %peer, ?kind, detector = "watcher", "direct path lost; racing again");
            }
            if let Some(addrs) = ladder.nudge {
                // One dial carries what iroh may not know yet: the session's
                // address moves a connection onto the session's path, and the
                // multihop route is learned by no lookup while another path is
                // selected.
                let endpoint = ctx.endpoint.clone();
                n0_future::task::spawn(async move {
                    super::webrtc::nudge_with(&endpoint, peer, &addrs).await;
                });
            }
            if !has_session
                && let Some(addr) = state
                    .peer_endpoints
                    .values()
                    .find(|addr| addr.id == peer)
                    .cloned()
            {
                super::webrtc::negotiate_session(state, ctx, peer, addr);
            }
        }
    }
}

/// Pure: the race's answer to `selected` becoming the selected path.
pub(crate) fn path_action(selected: PathKind, has_session: bool) -> PathAction {
    match selected {
        PathKind::Ip if has_session => PathAction::Detach,
        // A pair on multihop or on gossip is off the relay but has no lane: race for one.
        PathKind::Relay | PathKind::None | PathKind::Multihop | PathKind::Gossip => {
            PathAction::Rerace
        }
        PathKind::Ip | PathKind::WebRtc => PathAction::Proven,
    }
}

/// What a nudge dials besides the bare id, so that iroh learns the addresses of
/// the paths that a pair can still climb to. One dial can carry both.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct NudgeAddrs {
    /// The pair's `WebRTC` session address.
    pub(crate) session: bool,
    /// The multihop route to the peer, from the topology.
    pub(crate) route: Option<iroh::TransportAddr>,
    /// The gossip address of the peer.
    pub(crate) gossip: bool,
}

/// What [`step`] reads, by name: the kind of the selected path, whether the pair has a session,
/// the multihop route that the topology has now (`None` if it has none), and whether the mesh
/// has gossip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StepInput {
    pub(crate) kind: PathKind,
    pub(crate) has_session: bool,
    pub(crate) route: Option<iroh::TransportAddr>,
    pub(crate) gossip_on: bool,
}

/// The answer to a pair whose selected path is `kind`: the race action and what
/// to dial to help iroh climb the ladder. Pure; the one place that decides both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Step {
    pub(crate) action: PathAction,
    pub(crate) nudge: Option<NudgeAddrs>,
}

/// Pure: [`Step`] for a pair on `kind`, with `has_session` and the multihop
/// `route` that the topology has now (`None` if it has none).
///
/// A pair on the relay needs the route in a dial: iroh runs the address lookup
/// only while no path or the relay is selected, and the lookup answers only if
/// the topology has a route at that moment, so an address that the lookup missed
/// is never learned later without one. A pair with a session needs the session
/// address in a dial to move its connection onto the session's path. A pair
/// already on multihop needs no route.
pub(crate) fn step(input: StepInput) -> Step {
    let StepInput {
        kind,
        has_session,
        route,
        gossip_on,
    } = input;
    let action = path_action(kind, has_session);
    let route = match kind {
        PathKind::Relay | PathKind::None | PathKind::Gossip => route,
        PathKind::Ip | PathKind::WebRtc | PathKind::Multihop => None,
    };
    let gossip = gossip_on && matches!(kind, PathKind::Relay | PathKind::None) && route.is_none();
    let climbing = matches!(
        kind,
        PathKind::Relay | PathKind::None | PathKind::Multihop | PathKind::Gossip
    );
    let nudge = (climbing && (has_session || route.is_some() || gossip)).then_some(NudgeAddrs {
        session: has_session,
        route,
        gossip,
    });
    Step { action, nudge }
}

/// Pure: whether the gossip transport may carry frames to a pair whose selected path is `kind`.
/// The admission table calls it on the best path of each peer (see `gossip_view`).
pub(crate) fn allow_for(kind: PathKind) -> bool {
    !matches!(kind, PathKind::Ip | PathKind::WebRtc | PathKind::Multihop)
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

/// Pure: the kind that stands for a peer whose connections read as `kinds`: the best of them, in
/// the order of the ladder (IP, a session, multihop, the relay), and `None` when no connection has
/// a selected path yet. iroh selects a path per connection, and a link that is still on the relay
/// can sit beside a connection that is already direct: the first reading must not speak for the
/// pair. The order is the ladder's: do not reorder it (`path_action` relies on `[WebRtc, Ip]`
/// reading IP).
pub(crate) fn best_kind(kinds: impl IntoIterator<Item = PathKind>) -> Option<PathKind> {
    let rank = |kind: &PathKind| match kind {
        PathKind::Ip => 0,
        PathKind::WebRtc => 1,
        PathKind::Multihop => 2,
        PathKind::Gossip => 3,
        PathKind::Relay => 4,
        PathKind::None => 5,
    };
    kinds
        .into_iter()
        .filter(|kind| *kind != PathKind::None)
        .min_by_key(rank)
}

/// Pure: whether any connection with a selected path reads as something below IP. A session
/// that one connection rides is in use, whatever the others read: [`best_kind`] would read IP
/// for `[Ip, WebRtc]`, and the session must stay.
pub(crate) fn any_not_ip(kinds: impl IntoIterator<Item = PathKind>) -> bool {
    kinds
        .into_iter()
        .any(|kind| !matches!(kind, PathKind::Ip | PathKind::None))
}

/// Pure: the kind of a pair's selected path, from the watcher's last report if it
/// has one, else from any live connection of the admission table. A pair that only
/// gossips has no pooled connection and so no watcher, but its gossip connection
/// is in the table.
pub(crate) fn pair_kind(watched: Option<PathKind>, admitted: Option<PathKind>) -> Option<PathKind> {
    watched.filter(|kind| *kind != PathKind::None).or(admitted)
}

/// Pure: may a peer be grafted, from what is known right now? A `WebRTC`
/// pair needs its session attached; an IP pair needs a proven direct path.
pub(crate) fn may_graft(known_direct: bool, has_session: bool, needs_webrtc: bool) -> bool {
    if needs_webrtc {
        has_session
    } else {
        known_direct
    }
}

/// Whether `peer` may be grafted right now. `false` means a probe is in
/// flight or a `WebRTC` session is still being negotiated; the loop grafts on
/// the [`DirectOutcome`] that follows, or the alive tick retries.
pub(crate) fn ensure_direct(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    peer: EndpointId,
    peer_addr: &iroh::EndpointAddr,
) -> bool {
    if state.relay_transport {
        return true;
    }
    let needs_webrtc = needs_webrtc_lane(peer_addr) || needs_webrtc_lane(&ctx.endpoint.addr());
    let has_session = state
        .webrtc
        .as_ref()
        .is_some_and(|handle| handle.has_session(&peer));
    let known = state.direct.get(&peer).copied();
    if may_graft(
        known == Some(DirectState::Direct),
        has_session,
        needs_webrtc,
    ) {
        state.direct.insert(peer, DirectState::Direct);
        return true;
    }
    if needs_webrtc || known == Some(DirectState::Pending) {
        // A browser peer proves itself through `negotiate_session`; an IP peer's probe is already
        // running. A graft is the one proactive reason for a session (the exception of plan D4 for
        // gossip links), as a held frame is: a cold pair that nobody sends to would stay `Pending`
        // for ever, and no member would link to another.
        state.direct.entry(peer).or_insert(DirectState::Pending);
        if needs_webrtc {
            state.want_lane_session(peer, Instant::now());
            super::webrtc::negotiate_session(state, ctx, peer, peer_addr.clone());
        }
        return false;
    }
    state.direct.insert(peer, DirectState::Pending);
    let pool = state.unicast_pool.clone();
    let tx = state.direct_proven.clone();
    n0_future::task::spawn(async move {
        let direct = match pool.probe_connection(peer).await {
            Ok(conn) => wait_direct(&conn, PROBE_DEADLINE).await,
            Err(error) => {
                tracing::debug!(target: super::LOG_TARGET, %peer, %error, "direct-path probe could not connect");
                false
            }
        };
        // The graft that follows a proven path forms its link inside the probe
        // hold, and the probe's own connection goes after it unless a send took it.
        pool.probe_done(peer).await;
        let _ = tx.send(DirectOutcome {
            peer,
            direct,
            answered: false,
        });
    });
    false
}

/// Apply a probe's verdict: a proven peer is grafted, an unproven one is
/// recorded `RelayOnly` for the alive tick to retry, unless it proved itself
/// another way while the probe ran.
pub(crate) async fn on_outcome(
    outcome: DirectOutcome,
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
) {
    if !outcome.applies(state, Instant::now()) {
        return;
    }
    let DirectOutcome { peer, direct, .. } = outcome;
    if direct {
        graft_proven(state, ctx, peer).await;
    } else if state.demote_unproven(peer) {
        tracing::info!(target: super::LOG_TARGET, %peer, "no direct path within the probe deadline; peer stays relay-only");
    } else {
        tracing::debug!(target: super::LOG_TARGET, %peer, "late probe verdict ignored; the peer is no longer pending");
    }
}

/// How a graft asks for a link.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GraftRequest {
    /// Always accepted: a peer with a full view drops a neighbor to make room.
    Join,
    /// Low priority: a peer with a full view refuses and keeps its neighbors.
    Neighbor,
    /// No request: the peer refused lately and its wait runs.
    Skip,
}

/// The request that grafts `peer`. The rendezvous gets a `Join`, because a low
/// priority request to a peer that holds a tombstone for us is refused for ever.
/// Every other graft only fills a view, and must not make a full one drop a neighbor.
///
/// A peer that refused a `Neighbor` request lately is skipped by a paced graft, for the wait of
/// its backoff (`GraftBackoff`). The `PeerInfo` graft is not held, but its request is recorded
/// too, so that its silence reads as a refusal.
///
/// A low priority request evicts nobody, so a node that arrives when every other node is
/// full gets no link from it. A `paced` graft (the fill tick, a proven direct path) asks
/// with a `Join` instead when the node is starved: it held two or more links fewer than G
/// for `STARVED_SECS`, at most once per `STARVED_SECS`. A `PeerInfo` graft is not paced.
pub(crate) fn graft_request(
    state: &mut EventLoopState,
    peer: EndpointId,
    rendezvous_id: EndpointId,
    max_peers: usize,
    now: Instant,
    paced: bool,
) -> GraftRequest {
    if peer == rendezvous_id {
        return GraftRequest::Join;
    }
    state.note_link_count(state.linked_endpoints.len(), max_peers, now);
    if paced && state.starved_join_due(now) {
        // A `Join` is not refused, so it ignores the backoff of the peer.
        GraftRequest::Join
    } else if paced && state.graft_backoff.is_blocked(&peer, now) {
        tracing::debug!(target: super::LOG_TARGET, %peer, "graft skipped: the peer refused lately");
        GraftRequest::Skip
    } else {
        state.graft_backoff.asked(peer, now);
        GraftRequest::Neighbor
    }
}

/// Ask gossip for the link to `peer`, in the way [`graft_request`] says.
pub(crate) async fn request_graft(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    peer: EndpointId,
    paced: bool,
) -> Result<(), iroh_gossip::api::ApiError> {
    if peer != ctx.rendezvous_id && state.rides_gossip_rung(peer) {
        tracing::debug!(target: super::LOG_TARGET, %peer, "graft skipped: the pair rides the gossip rung");
        return Ok(());
    }
    match graft_request(
        state,
        peer,
        ctx.rendezvous_id,
        ctx.max_peers,
        Instant::now(),
        paced,
    ) {
        GraftRequest::Join => ctx.sender.join_peers(vec![peer]).await,
        GraftRequest::Neighbor => ctx.sender.neighbor_peers(vec![peer]).await,
        GraftRequest::Skip => Ok(()),
    }
}

/// Record `peer` as `Direct`, graft it if it is not linked already and there
/// is room, and flush any frame parked for it.
pub(crate) async fn graft_proven(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    peer: EndpointId,
) {
    state.note_path_proven(peer);
    // A session to the rendezvous that attached after this node let go of it
    // must not graft it again: every graft of the rendezvous waits for
    // `rendezvous_wanted`.
    if peer == ctx.rendezvous_id && !state.rendezvous_wanted() {
        return;
    }
    if !state.linked_endpoints.contains(&peer) && state.linked_endpoints.len() < ctx.max_peers {
        state.note_relink(peer, Instant::now());
        if let Err(error) = request_graft(state, ctx, peer, true).await {
            tracing::warn!(target: super::LOG_TARGET, %peer, %error, "graft request failed");
        }
    }
    if state.meshed && !state.pending_outbound.is_empty() {
        crate::gossip::flush_pending(state, ctx, "direct path proven").await;
    }
}

/// The alive-tick retry: every known peer that is neither linked nor mid-probe
/// gets another `ensure_direct`, subject to the relink cooldown. While the relay
/// may carry payload there is no probe to hold a graft, so the tick fills the
/// active view instead, one member per tick (see [`fill_active_view`]). The
/// rendezvous is skipped: it accepts no unicast, so it cannot be probed; its
/// link is gated on the beacon's side.
///
/// With `distrust_links` (the re-bridge after a resume or starvation) every
/// link and proven path is stale by definition, so linked peers are retried
/// too and their `Direct` verdicts are forgotten first, or `ensure_direct`
/// would trust the pre-sleep answer.
pub(crate) async fn retry_direct(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    distrust_links: bool,
) {
    // Every alive tick, so that the clock of a starved node does not outlive its cause.
    let now = Instant::now();
    state.note_link_count(state.linked_endpoints.len(), ctx.max_peers, now);
    state.settle_graft_backoff(now);
    if state.relay_transport {
        fill_active_view(state, ctx).await;
        return;
    }
    // The lane offers are paced: a browser pays an ICE gathering budget per round. The members
    // left out are not touched, so that no `Pending` mark hides them from the next pass.
    let (lane, rest): (Vec<_>, Vec<_>) =
        retry_candidates(state, ctx.rendezvous_id, ctx.max_peers, distrust_links)
            .into_iter()
            .partition(|addr| is_lane_offer(state, ctx, addr));
    for addr in rest {
        retry_one(state, ctx, addr, distrust_links).await;
    }
    let pick = lane_pick();
    for addr in plan_lane_offers(lane, state.webrtc_admission.in_flight(), pick) {
        retry_one(state, ctx, addr, distrust_links).await;
    }
}

/// The members of `lane` that a pass offers a session to: at most
/// [`LANE_OFFERS_IN_FLIGHT`](crate::util::tuning::LANE_OFFERS_IN_FLIGHT) less the `in_flight`
/// rounds. The natives come before every browser and each group is ordered by id, as in
/// [`next_fill`]; `pick` is the random start in each group, so that the members of a mesh do not
/// all offer to the same few. The others are left as they are: no mark, no want.
pub(crate) fn plan_lane_offers(
    lane: Vec<iroh::EndpointAddr>,
    in_flight: usize,
    pick: usize,
) -> Vec<iroh::EndpointAddr> {
    let budget = crate::util::tuning::LANE_OFFERS_IN_FLIGHT.saturating_sub(in_flight);
    let (mut browsers, mut natives): (Vec<_>, Vec<_>) =
        lane.into_iter().partition(needs_webrtc_lane);
    let mut ordered = Vec::new();
    for group in [&mut natives, &mut browsers] {
        group.sort_unstable_by_key(|addr| addr.id);
        if let Some(start) = pick.checked_rem(group.len()) {
            group.rotate_left(start);
        }
        ordered.append(group);
    }
    ordered.truncate(budget);
    ordered
}

/// The random start of a pass over the lane members.
pub(crate) fn lane_pick() -> usize {
    rand::random::<u32>() as usize
}

/// The candidates of a retry pass that need an offered session: a lane pair, and no session yet.
fn is_lane_offer(state: &EventLoopState, ctx: &HandlerCtx<'_>, addr: &iroh::EndpointAddr) -> bool {
    (needs_webrtc_lane(addr) || needs_webrtc_lane(&ctx.endpoint.addr()))
        && !state
            .webrtc
            .as_ref()
            .is_some_and(|handle| handle.has_session(&addr.id))
}

/// One member of a retry pass: `ensure_direct`, and the graft if the path is proven.
async fn retry_one(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    addr: iroh::EndpointAddr,
    distrust_links: bool,
) {
    if distrust_links {
        state.direct.remove(&addr.id);
    }
    if ensure_direct(state, ctx, addr.id, &addr) {
        graft_proven(state, ctx, addr.id).await;
    }
}

/// Offer a session to the lane members that a pass left out, as far as the rounds in flight
/// allow. The event loop calls this when a round ends, whatever its end (see
/// [`SignalAdmission::slot_freed`](super::admission::SignalAdmission::slot_freed)), so that the
/// next members do not wait for the alive tick. The members are not served in a fair order: the
/// random start spreads the load, and nothing more is promised.
pub(crate) async fn top_up_lane_offers(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    if state.relay_transport || state.webrtc.is_none() {
        return;
    }
    let lane: Vec<_> = retry_candidates(state, ctx.rendezvous_id, ctx.max_peers, false)
        .into_iter()
        .filter(|addr| is_lane_offer(state, ctx, addr))
        .collect();
    let pick = lane_pick();
    for addr in plan_lane_offers(lane, state.webrtc_admission.in_flight(), pick) {
        retry_one(state, ctx, addr, false).await;
    }
}

/// Graft again the proven peers whose link went down about a second ago (see
/// [`EventLoopState::plan_regraft_on_link_loss`]). The reclaim ticker calls this, because
/// the heal tick would leave the pair apart for 10 to 15 s.
pub(crate) async fn regraft_due(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    for peer in state.take_regrafts_due(Instant::now()) {
        let Some(addr) = state
            .peer_endpoints
            .values()
            .find(|addr| addr.id == peer)
            .cloned()
        else {
            continue;
        };
        state.note_relink(peer, Instant::now());
        let _ = crate::lookup::add_peer_addr(ctx.endpoint, addr.clone());
        state.unicast_pool.note_addr(&addr);
        tracing::debug!(target: super::LOG_TARGET, %peer, "the link went down: grafting the proven peer again");
        if ensure_direct(state, ctx, peer, &addr) {
            graft_proven(state, ctx, peer).await;
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
fn next_fill(
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
        .filter(|addr| addr.id != rendezvous_id)
        .filter(|addr| !state.linked_endpoints.contains(&addr.id))
        .filter(|addr| !state.relink_on_cooldown(addr.id, now))
        .filter(|addr| !state.graft_blocked(addr.id, now))
        .collect();
    free.sort_unstable_by_key(|addr| (needs_webrtc_lane(addr), addr.id));
    let first_group = free.first().map_or(0, |first| {
        free.iter()
            .take_while(|addr| needs_webrtc_lane(addr) == needs_webrtc_lane(first))
            .count()
    });
    free.get(pick.checked_rem(first_group)?)
        .map(|addr| (*addr).clone())
}

/// Graft one member toward G: the gossip active view is a target, not only a
/// cap. The attempt starts the member's relink cooldown, so a member that did
/// not link waits out the window before it is tried again, and the next tick
/// takes the next member.
async fn fill_active_view(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    let now = Instant::now();
    let pick = rand::Rng::random_range(&mut rand::rng(), 0..usize::MAX);
    let Some(addr) = next_fill(state, ctx.max_peers, ctx.rendezvous_id, now, pick) else {
        return;
    };
    state.note_relink(addr.id, now);
    let _ = crate::lookup::add_peer_addr(ctx.endpoint, addr.clone());
    state.unicast_pool.note_addr(&addr);
    tracing::debug!(target: super::LOG_TARGET, peer = %addr.id, linked = state.linked_endpoints.len(), "filling the active view");
    if ensure_direct(state, ctx, addr.id, &addr) {
        graft_proven(state, ctx, addr.id).await;
    }
}

/// The peers one `retry_direct` pass probes, in a fixed order.
fn retry_candidates(
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
fn retry_candidates_at(
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
        .filter(|addr| addr.id != rendezvous_id)
        .filter(|addr| distrust_links || !state.linked_endpoints.contains(&addr.id))
        .filter(|addr| {
            state.direct.get(&addr.id) != Some(&DirectState::Pending)
                || (needs_webrtc_lane(addr)
                    && state
                        .webrtc
                        .as_ref()
                        .is_some_and(|handle| handle.has_session(&addr.id)))
        })
        .filter(|addr| !state.relink_on_cooldown(addr.id, now))
        .filter(|addr| !state.graft_blocked(addr.id, now))
        .cloned()
        .collect();
    peers.sort_unstable_by_key(|addr| addr.id);
    peers
}

#[cfg(test)]
mod tests {
    use iroh::EndpointAddr;

    use super::{
        GraftRequest, PathKind, StepInput, ensure_watchers, graft_request, may_graft,
        retry_candidates, retry_candidates_at, webrtc_riders,
    };
    use crate::daemon::state::EventLoopState;
    use crate::testing::{endpoint_id, fresh_state, nick};

    // A graft that only fills a view must not make a full view drop a neighbor, so it asks
    // with low priority. The rendezvous may hold a tombstone for this node, which refuses a
    // low priority request for ever, so it is asked with a `Join`.
    #[test]
    fn a_graft_asks_with_low_priority_except_for_the_rendezvous() {
        let mut state = fresh_state();
        let rendezvous = endpoint_id(3);
        let now = crate::util::clock::Instant::now();
        assert_eq!(
            graft_request(&mut state, endpoint_id(4), rendezvous, 4, now, true),
            GraftRequest::Neighbor
        );
        assert_eq!(
            graft_request(&mut state, rendezvous, rendezvous, 4, now, true),
            GraftRequest::Join
        );
    }

    // With no eviction, a member that arrives when every other member is full gets no link.
    // After STARVED_SECS below G - 1 links, a paced graft asks with a `Join` once, and then
    // waits STARVED_SECS again.
    #[test]
    fn a_starved_node_falls_back_to_a_join_once_per_window() {
        use std::time::Duration;
        let mut state = fresh_state();
        let (rendezvous, peer) = (endpoint_id(3), endpoint_id(4));
        let start = crate::util::clock::Instant::now();
        let window = Duration::from_secs(crate::util::tuning::STARVED_SECS);
        // G = 4 and two links: G - 2.
        state.linked_endpoints.insert(endpoint_id(10));
        state.linked_endpoints.insert(endpoint_id(11));

        let ask =
            |node: &mut EventLoopState, at| graft_request(node, peer, rendezvous, 4, at, true);
        assert_eq!(
            ask(&mut state, start),
            GraftRequest::Neighbor,
            "not yet starved"
        );
        assert_eq!(
            ask(
                &mut state,
                start + window.saturating_sub(Duration::from_secs(1))
            ),
            GraftRequest::Neighbor
        );
        assert_eq!(
            ask(&mut state, start + window),
            GraftRequest::Join,
            "starved for the window"
        );
        assert_eq!(
            ask(&mut state, start + window + Duration::from_secs(1)),
            GraftRequest::Neighbor,
            "one fallback per window"
        );
        assert_eq!(
            ask(&mut state, start + window * 2),
            GraftRequest::Join,
            "and again after a window"
        );
    }

    /// A peer that refused a `Neighbor` request is left alone by the paced grafts for the wait of
    /// its backoff: the retry pass does not probe it, and the fill does not pick it. The request
    /// that is not paced (the `PeerInfo` graft, one per `PeerInfo`) is not held, but it is
    /// recorded as asked, so that its silence reads as a refusal too.
    #[test]
    fn a_peer_that_refused_is_skipped_by_the_paced_grafts_but_not_the_peer_info_graft() {
        use std::time::Duration;
        let mut state = fresh_state();
        let (rendezvous, refuser, other) = (endpoint_id(3), endpoint_id(4), endpoint_id(5));
        let native =
            |id| EndpointAddr::new(id).with_ip_addr("127.0.0.1:4000".parse().expect("addr"));
        state
            .peer_endpoints
            .insert(nick("refuser"), native(refuser));
        state.peer_endpoints.insert(nick("other"), native(other));
        let start = crate::util::clock::Instant::now();

        // The request is not paced: it goes out and is recorded.
        assert_eq!(
            graft_request(&mut state, refuser, rendezvous, 8, start, false),
            GraftRequest::Neighbor
        );
        let later = start + Duration::from_secs(crate::util::tuning::GRAFT_REFUSED_AFTER_SECS + 1);
        state.settle_graft_backoff(later);

        assert_eq!(
            graft_request(&mut state, refuser, rendezvous, 8, later, true),
            GraftRequest::Skip,
            "a paced graft leaves the peer that refused"
        );
        assert_eq!(
            graft_request(&mut state, refuser, rendezvous, 8, later, false),
            GraftRequest::Neighbor,
            "the PeerInfo graft is not held"
        );
        assert_eq!(
            graft_request(&mut state, other, rendezvous, 8, later, true),
            GraftRequest::Neighbor,
            "another peer is asked"
        );
        let ids: Vec<_> = retry_candidates(&state, rendezvous, 8, false)
            .into_iter()
            .map(|addr| addr.id)
            .collect();
        assert_eq!(
            ids,
            [other],
            "the retry pass does not probe the peer that refused"
        );
        assert_eq!(
            super::next_fill(&state, 8, rendezvous, later, 0).map(|addr| addr.id),
            Some(other),
            "the fill does not pick it either"
        );
    }

    /// The starved fallback ignores the backoff. A peer that holds a tombstone for this node (it saw
    /// a `Disconnect` with `left = true`) refuses every `Neighbor` request for ever. A `Join` is
    /// the only way past it, and it is never refused. Do not make the fallback honor the backoff.
    #[test]
    fn the_starved_fallback_ignores_the_backoff_for_a_peer_with_a_tombstone() {
        use std::time::Duration;
        let mut state = fresh_state();
        let (rendezvous, tombstone) = (endpoint_id(3), endpoint_id(4));
        state.peer_endpoints.insert(
            nick("tombstone"),
            EndpointAddr::new(tombstone).with_ip_addr("127.0.0.1:4000".parse().expect("addr")),
        );
        let start = crate::util::clock::Instant::now();
        let window = Duration::from_secs(crate::util::tuning::STARVED_SECS);
        // G = 4 and two links: starved once the window has passed.
        state.linked_endpoints.insert(endpoint_id(10));
        state.linked_endpoints.insert(endpoint_id(11));
        assert_eq!(
            graft_request(&mut state, tombstone, rendezvous, 4, start, false),
            GraftRequest::Neighbor
        );
        let refused =
            start + Duration::from_secs(crate::util::tuning::GRAFT_REFUSED_AFTER_SECS + 1);
        state.settle_graft_backoff(refused);
        assert_eq!(
            graft_request(&mut state, tombstone, rendezvous, 4, refused, true),
            GraftRequest::Skip,
            "before the window: the backoff holds"
        );

        let starved = start + window + Duration::from_secs(1);
        assert_eq!(
            retry_candidates_at(&state, rendezvous, 8, false, starved)
                .first()
                .map(|addr| addr.id),
            Some(tombstone),
            "a starved node asks every peer"
        );
        assert_eq!(
            graft_request(&mut state, tombstone, rendezvous, 4, starved, true),
            GraftRequest::Join,
            "the fallback is a Join, whatever the backoff says"
        );
    }

    /// The link coming up, or a new address of the peer, ends the backoff.
    #[test]
    fn a_neighbor_up_or_a_new_address_ends_the_backoff() {
        use std::time::Duration;
        let mut state = fresh_state();
        let (rendezvous, peer) = (endpoint_id(3), endpoint_id(4));
        let addr = |port: u16| {
            EndpointAddr::new(peer).with_ip_addr(format!("127.0.0.1:{port}").parse().expect("addr"))
        };
        let start = crate::util::clock::Instant::now();
        let later = start + Duration::from_secs(crate::util::tuning::GRAFT_REFUSED_AFTER_SECS + 1);
        let refuse = |node: &mut EventLoopState| {
            node.graft_backoff = crate::transport::graft_backoff::GraftBackoff::default();
            let _ = graft_request(node, peer, rendezvous, 8, start, false);
            node.settle_graft_backoff(later);
            assert!(node.graft_blocked(peer, later), "refused");
        };

        refuse(&mut state);
        state.link(peer);
        assert!(!state.graft_blocked(peer, later), "the link came up");

        state.unlink(peer);
        refuse(&mut state);
        state.note_peer_endpoint(nick("peer"), addr(4000));
        assert!(
            state.graft_blocked(peer, later),
            "the first address is not a change"
        );
        state.note_peer_endpoint(nick("peer"), addr(4000));
        assert!(
            state.graft_blocked(peer, later),
            "the same address again is not a change"
        );
        state.note_peer_endpoint(nick("peer"), addr(4001));
        assert!(!state.graft_blocked(peer, later), "a new address");
    }

    /// A proven path is new information: the peer that refused a `Neighbor` request before it
    /// is asked again, so the graft that follows the proof is not skipped.
    #[test]
    fn a_proven_path_ends_the_backoff() {
        use std::time::Duration;
        let mut state = fresh_state();
        let (rendezvous, peer) = (endpoint_id(3), endpoint_id(4));
        let start = crate::util::clock::Instant::now();
        let later = start + Duration::from_secs(crate::util::tuning::GRAFT_REFUSED_AFTER_SECS + 1);
        let _ = graft_request(&mut state, peer, rendezvous, 8, start, false);
        state.settle_graft_backoff(later);
        assert_eq!(
            graft_request(&mut state, peer, rendezvous, 8, later, true),
            GraftRequest::Skip,
            "refused: the paced graft is skipped"
        );

        state.note_path_proven(peer);
        state.settle_graft_backoff(later);
        assert_eq!(
            graft_request(&mut state, peer, rendezvous, 8, later, true),
            GraftRequest::Neighbor,
            "the proof ends the wait, and the old ask is not read as a refusal again"
        );
    }

    /// A node whose active view holds G links offers no session to the other members: a graft
    /// is the reason for a session, and none runs at G. The re-bridge after a resume still
    /// retries every peer.
    #[test]
    fn a_node_at_g_retries_nobody_unless_it_distrusts_its_links() {
        let mut state = fresh_state();
        let rendezvous = endpoint_id(3);
        let (linked, unlinked) = (endpoint_id(4), endpoint_id(5));
        for (name, id) in [("linked", linked), ("unlinked", unlinked)] {
            state
                .peer_endpoints
                .insert(nick(name), EndpointAddr::new(id));
        }
        state.linked_endpoints.insert(linked);
        let ids = |max_peers: usize, distrust_links: bool| -> Vec<_> {
            retry_candidates(&state, rendezvous, max_peers, distrust_links)
                .into_iter()
                .map(|addr| addr.id)
                .collect()
        };

        assert_eq!(ids(2, false), vec![unlinked], "below G: the free member");
        assert!(ids(1, false).is_empty(), "at G: nobody");
        let mut every_peer = vec![linked, unlinked];
        every_peer.sort_unstable();
        assert_eq!(ids(1, true), every_peer, "the re-bridge asks every peer");
    }

    /// A session stays while any connection of the pair rides it or the relay: `best_kind` reads
    /// IP for `[Ip, WebRtc]`, `any_not_ip` does not let that detach the session.
    #[test]
    fn a_session_stays_while_any_connection_reads_below_ip() {
        use super::any_not_ip;
        use PathKind::{Ip, Multihop, None, Relay, WebRtc};

        assert!(!any_not_ip([]), "no connection");
        assert!(!any_not_ip([Ip, Ip]), "all IP: the session goes");
        assert!(
            !any_not_ip([Ip, None]),
            "a connection without a path counts for nothing"
        );
        assert!(any_not_ip([Ip, WebRtc]), "one rides the session");
        assert!(any_not_ip([Ip, Relay]), "one is still on the relay");
        assert!(any_not_ip([Multihop, Ip]), "one rides a route");
    }

    fn native_shaped(seed: u8) -> EndpointAddr {
        EndpointAddr::new(endpoint_id(seed)).with_ip_addr("127.0.0.1:4000".parse().expect("addr"))
    }

    fn browser_shaped(seed: u8) -> EndpointAddr {
        EndpointAddr::new(endpoint_id(seed))
            .with_relay_url("https://relay.invalid".parse().expect("relay url"))
    }

    /// A pass offers a session to at most `LANE_OFFERS_IN_FLIGHT` less the rounds in flight.
    #[test]
    fn a_pass_starts_at_most_the_budget_of_lane_offers() {
        use super::plan_lane_offers;
        use crate::util::tuning::LANE_OFFERS_IN_FLIGHT;

        let lane: Vec<EndpointAddr> = (1..=12).map(browser_shaped).collect();
        let planned = |in_flight: usize| plan_lane_offers(lane.clone(), in_flight, 0).len();

        assert_eq!(
            planned(0),
            LANE_OFFERS_IN_FLIGHT,
            "twelve members, none in flight"
        );
        assert_eq!(planned(3), LANE_OFFERS_IN_FLIGHT - 3, "three rounds run");
        assert_eq!(planned(LANE_OFFERS_IN_FLIGHT), 0, "the budget is spent");
        assert_eq!(
            planned(LANE_OFFERS_IN_FLIGHT + 5),
            0,
            "more rounds than the budget"
        );
        let few: Vec<EndpointAddr> = (1..=2).map(browser_shaped).collect();
        assert_eq!(
            plan_lane_offers(few, 0, 0).len(),
            2,
            "fewer members than the budget"
        );
    }

    /// The natives come before the browsers, each group by id, from a random start.
    #[test]
    fn the_lane_offers_go_to_natives_first_from_a_random_start() {
        use super::plan_lane_offers;

        let natives: Vec<EndpointAddr> = (1..=6).map(native_shaped).collect();
        let browsers: Vec<EndpointAddr> = (11..=16).map(browser_shaped).collect();
        let mut lane = browsers.clone();
        lane.extend(natives.clone());
        let mut native_ids: Vec<_> = natives.iter().map(|addr| addr.id).collect();
        native_ids.sort_unstable();

        for pick in 0..native_ids.len() {
            let ids: Vec<_> = plan_lane_offers(lane.clone(), 0, pick)
                .iter()
                .map(|addr| addr.id)
                .collect();
            let expected: Vec<_> = (0..4)
                .map(|offset| native_ids[(pick + offset) % 6])
                .collect();
            assert_eq!(ids, expected, "four natives from the start {pick}");
        }
        let all: Vec<_> = plan_lane_offers(lane.clone(), 0, 0)
            .iter()
            .map(|addr| addr.id)
            .collect();
        assert!(
            all.iter().all(|id| native_ids.contains(id)),
            "no browser while natives wait"
        );
    }

    #[test]
    fn a_node_with_g_minus_one_links_is_not_starved() {
        use std::time::Duration;
        let mut state = fresh_state();
        let (rendezvous, peer) = (endpoint_id(3), endpoint_id(4));
        let start = crate::util::clock::Instant::now();
        for seed in 10..13 {
            state.linked_endpoints.insert(endpoint_id(seed));
        }
        let late = start + Duration::from_secs(crate::util::tuning::STARVED_SECS * 2);
        assert_eq!(
            graft_request(&mut state, peer, rendezvous, 4, start, true),
            GraftRequest::Neighbor
        );
        assert_eq!(
            graft_request(&mut state, peer, rendezvous, 4, late, true),
            GraftRequest::Neighbor
        );
    }

    #[test]
    fn a_link_that_comes_back_to_g_minus_one_stops_the_clock() {
        use std::time::Duration;
        let mut state = fresh_state();
        let (rendezvous, peer) = (endpoint_id(3), endpoint_id(4));
        let start = crate::util::clock::Instant::now();
        let window = Duration::from_secs(crate::util::tuning::STARVED_SECS);
        state.linked_endpoints.insert(endpoint_id(10));
        assert_eq!(
            graft_request(&mut state, peer, rendezvous, 4, start, true),
            GraftRequest::Neighbor
        );
        // A link comes in: G - 1 = 3 links. The clock stops.
        state.linked_endpoints.insert(endpoint_id(11));
        state.linked_endpoints.insert(endpoint_id(12));
        assert_eq!(
            graft_request(&mut state, peer, rendezvous, 4, start + window / 2, true),
            GraftRequest::Neighbor
        );
        // The links go away again: the clock starts at the next look, not in the past.
        state.linked_endpoints.clear();
        assert_eq!(
            graft_request(&mut state, peer, rendezvous, 4, start + window, true),
            GraftRequest::Neighbor
        );
        assert_eq!(
            graft_request(
                &mut state,
                peer,
                rendezvous,
                4,
                start + (window * 2).saturating_sub(Duration::from_secs(1)),
                true
            ),
            GraftRequest::Neighbor
        );
    }

    #[test]
    fn a_peer_info_graft_never_falls_back_to_a_join() {
        use std::time::Duration;
        let mut state = fresh_state();
        let (rendezvous, peer) = (endpoint_id(3), endpoint_id(4));
        let start = crate::util::clock::Instant::now();
        let late = start + Duration::from_secs(crate::util::tuning::STARVED_SECS * 3);
        assert_eq!(
            graft_request(&mut state, peer, rendezvous, 4, start, false),
            GraftRequest::Neighbor
        );
        assert_eq!(
            graft_request(&mut state, peer, rendezvous, 4, late, false),
            GraftRequest::Neighbor
        );
    }

    // The pool closes a connection that nothing sent on, and the watcher is
    // dropped with it. The last path kind it reported must go too, or every
    // alive tick connects to the peer again to nudge it.
    #[test]
    fn a_webrtc_peer_with_no_pooled_connection_is_no_longer_nudged() {
        use habilis_network_iroh_webrtc_transport::{WebRtcHandle, WebRtcTransport};

        let mut state = fresh_state();
        let (local, peer) = {
            let (one, two) = (endpoint_id(1), endpoint_id(2));
            if one < two { (one, two) } else { (two, one) }
        };
        let rendezvous = endpoint_id(3);
        state.webrtc = Some(WebRtcHandle::new(WebRtcTransport::new(local)));
        state.local_udp_transport = true;
        state
            .peer_endpoints
            .insert(nick("peer"), EndpointAddr::new(peer));
        state.path_kinds.insert(peer, PathKind::WebRtc);
        assert_eq!(webrtc_riders(&state), vec![peer], "it rides a session");

        ensure_watchers(&mut state, local, rendezvous);

        assert!(
            webrtc_riders(&state).is_empty(),
            "a peer with no pooled connection must not be nudged on every tick"
        );
    }

    // `linked_endpoints` is not cleared on the resume edge, so a re-bridge
    // that trusted it skipped exactly the peers it exists to re-dial.
    #[test]
    fn a_re_bridge_keeps_linked_peers_as_candidates() {
        let mut state = fresh_state();
        state.relay_transport = false;
        let rendezvous = endpoint_id(1);
        let linked = endpoint_id(2);
        let unlinked = endpoint_id(3);
        for (name, id) in [
            ("beacon", rendezvous),
            ("linked", linked),
            ("unlinked", unlinked),
        ] {
            state
                .peer_endpoints
                .insert(nick(name), EndpointAddr::new(id));
        }
        state.linked_endpoints.insert(linked);
        let ids = |distrust_links: bool| -> Vec<_> {
            retry_candidates(&state, rendezvous, 8, distrust_links)
                .into_iter()
                .map(|addr| addr.id)
                .collect()
        };

        assert_eq!(
            ids(false),
            [unlinked],
            "the alive tick leaves a linked peer alone"
        );
        let mut expected = [linked, unlinked];
        expected.sort_unstable();
        assert_eq!(
            ids(true),
            expected,
            "the re-bridge re-dials the linked peer too"
        );
    }

    #[test]
    fn a_path_change_detaches_on_udp_and_races_again_on_loss() {
        use super::{PathAction, PathKind, path_action};
        assert_eq!(path_action(PathKind::Ip, true), PathAction::Detach);
        assert_eq!(path_action(PathKind::Ip, false), PathAction::Proven);
        assert_eq!(path_action(PathKind::WebRtc, true), PathAction::Proven);
        assert_eq!(path_action(PathKind::Relay, false), PathAction::Rerace);
        assert_eq!(path_action(PathKind::Relay, true), PathAction::Rerace);
        assert_eq!(path_action(PathKind::None, false), PathAction::Rerace);
    }

    fn a_route() -> iroh::TransportAddr {
        let peer = endpoint_id(7);
        iroh::TransportAddr::Custom(habilis_network_iroh_webrtc_transport::custom_addr(peer))
    }

    // A pair on multihop is off the relay but has no lane: it races for one, and
    // it needs no route in a dial because it already rides one.
    #[test]
    fn a_pair_on_multihop_races_for_a_lane_without_a_route_in_the_dial() {
        use super::{NudgeAddrs, PathAction, step};
        assert_eq!(
            super::path_action(PathKind::Multihop, false),
            PathAction::Rerace
        );
        let without_session = step(StepInput {
            kind: PathKind::Multihop,
            has_session: false,
            route: Some(a_route()),
            gossip_on: false,
        });
        assert_eq!(without_session.action, PathAction::Rerace);
        assert_eq!(without_session.nudge, None, "the offer's attach nudges");
        let with_session = step(StepInput {
            kind: PathKind::Multihop,
            has_session: true,
            route: Some(a_route()),
            gossip_on: false,
        });
        assert_eq!(
            with_session.nudge,
            Some(NudgeAddrs {
                session: true,
                route: None,
                gossip: false
            }),
            "the session's address moves the connection onto the session"
        );
    }

    // A pair on the relay learns a multihop route only from a dial that carries
    // it: iroh runs the lookup only while no path or the relay is selected, and the
    // lookup answers only if the topology has the route at that moment.
    #[test]
    fn a_pair_on_the_relay_is_nudged_with_the_route_the_topology_has() {
        use super::{NudgeAddrs, PathAction, step};
        let nothing = step(StepInput {
            kind: PathKind::Relay,
            has_session: false,
            route: None,
            gossip_on: false,
        });
        assert_eq!(nothing.action, PathAction::Rerace);
        assert_eq!(
            nothing.nudge, None,
            "no route and no session: nothing to teach"
        );
        let route_only = step(StepInput {
            kind: PathKind::Relay,
            has_session: false,
            route: Some(a_route()),
            gossip_on: false,
        });
        assert_eq!(
            route_only.nudge,
            Some(NudgeAddrs {
                session: false,
                route: Some(a_route()),
                gossip: false
            })
        );
        let both = step(StepInput {
            kind: PathKind::Relay,
            has_session: true,
            route: Some(a_route()),
            gossip_on: false,
        });
        assert_eq!(
            both.nudge,
            Some(NudgeAddrs {
                session: true,
                route: Some(a_route()),
                gossip: false
            }),
            "one dial carries both addresses"
        );
        let session_only = step(StepInput {
            kind: PathKind::Relay,
            has_session: true,
            route: None,
            gossip_on: false,
        });
        assert_eq!(
            session_only.nudge,
            Some(NudgeAddrs {
                session: true,
                route: None,
                gossip: false
            })
        );
    }

    #[test]
    fn a_pair_on_a_lane_is_nudged_with_nothing() {
        use super::{PathAction, step};
        for (kind, has_session, action) in [
            (PathKind::Ip, false, PathAction::Proven),
            (PathKind::Ip, true, PathAction::Detach),
            (PathKind::WebRtc, true, PathAction::Proven),
        ] {
            let decided = step(StepInput {
                kind,
                has_session,
                route: Some(a_route()),
                gossip_on: false,
            });
            assert_eq!(decided.action, action);
            assert_eq!(decided.nudge, None, "{kind:?} needs no dial");
        }
    }

    // The gossip rung is a kind of its own: a pair on it is not a multihop pair, whichever
    // transport id the custom address has.
    #[test]
    fn a_custom_path_is_classed_by_the_id_of_its_transport() {
        use super::custom_kind;
        use habilis_network_iroh_gossip_transport::GOSSIP_TRANSPORT_ID;
        use habilis_network_iroh_webrtc_transport::WEBRTC_TRANSPORT_ID;
        assert_eq!(custom_kind(GOSSIP_TRANSPORT_ID), PathKind::Gossip);
        // The multihop crate is optional here: any other id is read as multihop.
        assert_eq!(custom_kind(0x6d68), PathKind::Multihop);
        assert_eq!(custom_kind(WEBRTC_TRANSPORT_ID), PathKind::WebRtc);
    }

    // The ladder of the engine: gossip is below multihop and above the relay.
    #[test]
    fn gossip_ranks_below_multihop_and_above_the_relay() {
        assert_eq!(
            super::best_kind([PathKind::Relay, PathKind::Gossip]),
            Some(PathKind::Gossip)
        );
        assert_eq!(
            super::best_kind([PathKind::Gossip, PathKind::Multihop]),
            Some(PathKind::Multihop)
        );
        assert_eq!(
            super::best_kind([PathKind::Gossip, PathKind::Ip]),
            Some(PathKind::Ip)
        );
        assert_eq!(
            super::best_kind([PathKind::Gossip, PathKind::None]),
            Some(PathKind::Gossip)
        );
    }

    // A pair on gossip is off the relay but has no lane, like a pair on multihop: it races for
    // one. It has a rung to climb, like a pair on the relay, so it learns the multihop route
    // from a dial: with via-third paths gossip is selected first, and would never climb. It
    // already has the gossip address.
    #[test]
    fn a_pair_on_gossip_races_for_a_lane_and_is_nudged_with_the_route_and_the_session() {
        use super::{NudgeAddrs, PathAction, step};
        assert_eq!(
            super::path_action(PathKind::Gossip, false),
            PathAction::Rerace
        );
        assert_eq!(
            super::path_action(PathKind::Gossip, true),
            PathAction::Rerace
        );
        let nudge = |has_session: bool, route: Option<iroh::TransportAddr>| {
            step(StepInput {
                kind: PathKind::Gossip,
                has_session,
                route,
                gossip_on: true,
            })
        };
        assert_eq!(nudge(false, None).nudge, None, "nothing to teach");
        assert_eq!(
            nudge(false, Some(a_route())).nudge,
            Some(NudgeAddrs {
                session: false,
                route: Some(a_route()),
                gossip: false
            }),
            "the route, and no gossip address: the pair is on it"
        );
        assert_eq!(
            nudge(true, Some(a_route())).nudge,
            Some(NudgeAddrs {
                session: true,
                route: Some(a_route()),
                gossip: false
            }),
            "one dial carries the session and the route"
        );
        assert_eq!(nudge(false, Some(a_route())).action, PathAction::Rerace);
    }

    // The pass over the pairs that can climb includes a pair on gossip, with its own kind, and
    // forgets the route of a pair that climbed.
    #[test]
    fn a_pair_on_gossip_is_dialed_for_its_route_and_forgotten_when_it_climbs() {
        use super::{forget_route_unless_climbing, plan_relay_dials};
        use std::collections::HashMap;

        let bob = endpoint_id(2);
        let mut dialed = HashMap::new();
        let dials = plan_relay_dials(
            [(bob, PathKind::Gossip, false, Some(a_route()))],
            &mut dialed,
            true,
            true,
        );
        assert_eq!(dials.len(), 1, "a route to carry");
        assert_eq!(dials[0].1.route, Some(a_route()));
        assert!(!dials[0].1.gossip, "the pair is on gossip already");
        forget_route_unless_climbing(&mut dialed, bob, PathKind::Gossip);
        assert!(dialed.contains_key(&bob), "still climbing");
        forget_route_unless_climbing(&mut dialed, bob, PathKind::Multihop);
        assert!(!dialed.contains_key(&bob), "it climbed");
    }

    // The gossip address is handed out by the selected path, not by the addresses that are
    // known: only a pair on the relay or on no path, with no route, and with gossip on.
    #[test]
    fn the_gossip_address_goes_only_to_a_pair_on_the_relay_with_no_route() {
        use super::{NudgeAddrs, step};
        let gossip_only = Some(NudgeAddrs {
            session: false,
            route: None,
            gossip: true,
        });
        for kind in [PathKind::Relay, PathKind::None] {
            assert_eq!(
                step(StepInput {
                    kind,
                    has_session: false,
                    route: None,
                    gossip_on: true
                })
                .nudge,
                gossip_only,
                "{kind:?}"
            );
            assert_eq!(
                step(StepInput {
                    kind,
                    has_session: false,
                    route: None,
                    gossip_on: false
                })
                .nudge,
                None,
                "{kind:?} with gossip off"
            );
            assert_eq!(
                step(StepInput {
                    kind,
                    has_session: false,
                    route: Some(a_route()),
                    gossip_on: true
                })
                .nudge,
                Some(NudgeAddrs {
                    session: false,
                    route: Some(a_route()),
                    gossip: false
                }),
                "{kind:?}: a route is preferred to the gossip address"
            );
        }
        assert_eq!(
            step(StepInput {
                kind: PathKind::Relay,
                has_session: true,
                route: None,
                gossip_on: true
            })
            .nudge,
            Some(NudgeAddrs {
                session: true,
                route: None,
                gossip: true
            }),
            "one dial carries the session and the gossip address"
        );
        for kind in [
            PathKind::Ip,
            PathKind::WebRtc,
            PathKind::Multihop,
            PathKind::Gossip,
        ] {
            assert!(
                !step(StepInput {
                    kind,
                    has_session: true,
                    route: None,
                    gossip_on: true
                })
                .nudge
                .is_some_and(|addrs| addrs.gossip),
                "{kind:?} gets no gossip address"
            );
        }
    }

    #[test]
    fn a_nudge_dials_the_gossip_address_of_the_peer_when_it_names_it() {
        use super::{NudgeAddrs, nudge_known};
        use habilis_network_iroh_gossip_transport::gossip_addr;
        let peer = endpoint_id(9);
        let gossip = iroh::TransportAddr::Custom(gossip_addr(peer));
        let with = NudgeAddrs {
            session: false,
            route: None,
            gossip: true,
        };
        assert_eq!(nudge_known(peer, &with), vec![gossip]);
        let without = NudgeAddrs {
            gossip: false,
            ..with
        };
        assert!(nudge_known(peer, &without).is_empty());
    }

    // The drop rule: frames go only to a pair that no higher rung carries.
    #[test]
    fn the_gossip_transport_is_allowed_only_for_a_pair_that_no_higher_rung_carries() {
        use super::allow_for;
        for kind in [PathKind::Ip, PathKind::WebRtc, PathKind::Multihop] {
            assert!(!allow_for(kind), "{kind:?}");
        }
        for kind in [PathKind::Relay, PathKind::None, PathKind::Gossip] {
            assert!(allow_for(kind), "{kind:?}");
        }
    }

    // The real `selected_kind`, on a real connection whose only transport is gossip.
    #[tokio::test]
    async fn a_connection_on_the_gossip_path_reads_as_the_gossip_kind() {
        use habilis_network_iroh_gossip_transport::memory::MemoryHub;
        use habilis_network_iroh_gossip_transport::{GossipHandle, gossip_addr};
        use iroh::endpoint::{Connection, presets};
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};
        use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};

        const ALPN: &[u8] = b"habilis-network/test-gossip-kind/0";
        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                connection.closed().await;
                Ok(())
            }
        }
        let (alice_key, bob_key) = (
            SecretKey::from_bytes(&[21; 32]),
            SecretKey::from_bytes(&[22; 32]),
        );
        let hub = MemoryHub::new();
        let (alice_handle, bob_handle) = (
            GossipHandle::new(alice_key.public()),
            GossipHandle::new(bob_key.public()),
        );
        hub.join(&alice_handle);
        hub.join(&bob_handle);
        let bind = |key: SecretKey, handle: GossipHandle| async move {
            Endpoint::builder(presets::Minimal)
                .secret_key(key)
                .relay_mode(RelayMode::Disabled)
                .add_custom_transport(handle.custom_transport())
                .clear_ip_transports()
                .clear_relay_transports()
                .bind()
                .await
                .expect("bind a gossip-only endpoint")
        };
        let (alice, bob) = (
            bind(alice_key, alice_handle).await,
            bind(bob_key, bob_handle).await,
        );
        let _router = Router::builder(bob.clone()).accept(ALPN, Hold).spawn();

        let connection = alice
            .connect(
                EndpointAddr::from_parts(bob.id(), [TransportAddr::Custom(gossip_addr(bob.id()))]),
                ALPN,
            )
            .await
            .expect("connect over the gossip path");

        assert_eq!(super::selected_kind(&connection), PathKind::Gossip);
    }

    // The watcher is dropped when the pool idles a connection out, but the gossip
    // connection stays in the admission table and still knows the path.
    #[test]
    fn the_admission_table_answers_for_a_pair_the_watcher_no_longer_reports() {
        use super::pair_kind;
        assert_eq!(
            pair_kind(None, Some(PathKind::Multihop)),
            Some(PathKind::Multihop)
        );
        assert_eq!(
            pair_kind(Some(PathKind::None), Some(PathKind::Relay)),
            Some(PathKind::Relay),
            "a watcher that reads no path does not hide the table"
        );
        assert_eq!(
            pair_kind(Some(PathKind::WebRtc), Some(PathKind::Relay)),
            Some(PathKind::WebRtc),
            "the watcher's report comes first"
        );
        assert_eq!(pair_kind(None, None), None);
    }

    // A route that arrives between two alive ticks is dialed at once, and only once: the climb of a
    // pair to multihop waited for the next tick because nothing dialed when the topology changed.
    #[test]
    fn a_new_route_is_dialed_once_and_a_changed_route_again() {
        use super::plan_relay_dials;
        use iroh::TransportAddr;
        use std::collections::HashMap;

        let route =
            |port: u16| TransportAddr::Ip(format!("127.0.0.1:{port}").parse().expect("addr"));
        let bob = endpoint_id(2);
        let mut dialed = HashMap::new();

        let first = plan_relay_dials(
            [(bob, PathKind::Relay, false, Some(route(1)))],
            &mut dialed,
            true,
            false,
        );
        assert_eq!(first.len(), 1, "a new route is dialed");
        assert_eq!(first[0].0, bob);
        assert_eq!(first[0].1.route, Some(route(1)), "with the route");

        let same = plan_relay_dials(
            [(bob, PathKind::Relay, false, Some(route(1)))],
            &mut dialed,
            true,
            false,
        );
        assert!(same.is_empty(), "the same route is not dialed again");

        let changed = plan_relay_dials(
            [(bob, PathKind::Relay, false, Some(route(2)))],
            &mut dialed,
            true,
            false,
        );
        assert_eq!(changed.len(), 1, "a changed route is dialed");
        assert_eq!(changed[0].1.route, Some(route(2)));

        let tick = plan_relay_dials(
            [(bob, PathKind::Relay, false, Some(route(2)))],
            &mut dialed,
            false,
            false,
        );
        assert_eq!(
            tick.len(),
            1,
            "the alive tick is the backstop: it dials the same route again"
        );
    }

    // A pair with a session and no route has something to carry (the session address), which the
    // alive tick dials; a link-state vector says nothing about it, so it does not.
    #[test]
    fn a_pair_with_a_session_and_no_route_is_dialed_by_the_tick_only() {
        use super::plan_relay_dials;
        use std::collections::HashMap;

        let bob = endpoint_id(2);
        let mut dialed = HashMap::new();
        assert!(
            plan_relay_dials(
                [(bob, PathKind::Relay, true, None)],
                &mut dialed,
                true,
                false
            )
            .is_empty(),
            "an event with no route dials nothing"
        );
        let tick = plan_relay_dials(
            [(bob, PathKind::Relay, true, None)],
            &mut dialed,
            false,
            false,
        );
        assert_eq!(tick.len(), 1, "the tick nudges the session onto its path");
        assert!(tick[0].1.session);
        assert!(
            plan_relay_dials(
                [(bob, PathKind::Relay, false, None)],
                &mut dialed,
                false,
                false
            )
            .is_empty(),
            "no session and no route: nothing to carry"
        );
    }

    // A pair that climbed (it reads IP in the next pass, so it is not among the pairs) and falls back
    // to the relay with the same route is dialed again; a pair that is gone is forgotten too. The
    // forget in on_path_change reaches only the pairs that are watched.
    #[test]
    fn a_pair_that_left_the_relay_and_fell_back_is_dialed_again_for_the_same_route() {
        use super::plan_relay_dials;
        use iroh::TransportAddr;
        use std::collections::HashMap;

        let route = TransportAddr::Ip("127.0.0.1:1".parse().expect("addr"));
        let (bob, carol) = (endpoint_id(2), endpoint_id(3));
        let mut dialed = HashMap::new();

        let first = plan_relay_dials(
            [
                (bob, PathKind::Relay, false, Some(route.clone())),
                (carol, PathKind::Relay, false, Some(route.clone())),
            ],
            &mut dialed,
            true,
            false,
        );
        assert_eq!(first.len(), 2, "both pairs are dialed for their route");

        // Bob climbed: he is not among the pairs of this pass. Carol is gone from the roster.
        let none = plan_relay_dials([], &mut dialed, true, false);
        assert!(none.is_empty());
        assert!(
            dialed.is_empty(),
            "the pairs that left the relay are forgotten"
        );

        let again = plan_relay_dials(
            [(bob, PathKind::Relay, false, Some(route))],
            &mut dialed,
            true,
            false,
        );
        assert_eq!(
            again.len(),
            1,
            "bob fell back to the relay with the same route: dialed again"
        );
    }

    // The route that was dialed is forgotten once the pair leaves the relay, so a pair that falls back
    // to the relay later is dialed with its route again.
    #[test]
    fn the_dialed_route_is_forgotten_once_the_pair_reads_ip() {
        use super::forget_route_unless_climbing;
        use iroh::TransportAddr;
        use std::collections::HashMap;

        let bob = endpoint_id(2);
        let mut dialed =
            HashMap::from([(bob, TransportAddr::Ip("127.0.0.1:1".parse().expect("addr")))]);
        forget_route_unless_climbing(&mut dialed, bob, PathKind::Relay);
        assert!(dialed.contains_key(&bob), "still on the relay: kept");
        forget_route_unless_climbing(&mut dialed, bob, PathKind::Ip);
        assert!(!dialed.contains_key(&bob), "the pair reads IP: forgotten");
    }

    // iroh selects a path per connection: a gossip link that is still on the relay can sit beside a
    // connection that is already direct, and the pair reads as its best one.
    #[test]
    fn a_peer_reads_as_the_best_kind_of_its_connections() {
        use super::best_kind;
        assert_eq!(
            best_kind([PathKind::Relay, PathKind::Ip]),
            Some(PathKind::Ip),
            "a connection on UDP beats a link on the relay, whichever comes first"
        );
        assert_eq!(
            best_kind([PathKind::WebRtc, PathKind::Ip]),
            Some(PathKind::Ip),
            "UDP ranks above a session: a session beside UDP is the one to detach"
        );
        assert_eq!(
            best_kind([PathKind::Relay, PathKind::Multihop, PathKind::WebRtc]),
            Some(PathKind::WebRtc),
            "a session ranks above multihop and the relay"
        );
        assert_eq!(
            best_kind([PathKind::Relay, PathKind::Multihop]),
            Some(PathKind::Multihop)
        );
        assert_eq!(
            best_kind([PathKind::None, PathKind::Relay]),
            Some(PathKind::Relay),
            "a connection with no selected path says nothing"
        );
        assert_eq!(best_kind([PathKind::None]), None);
        assert_eq!(best_kind([]), None);
    }

    // UDP can come back before a new session attaches, and nothing else
    // writes `Direct` then: the peer's directed frames stayed parked.
    #[test]
    fn a_direct_path_proves_a_relay_only_peer_again() {
        use crate::daemon::state::DirectState;
        let mut state = fresh_state();
        state.meshed = true;
        let bob = endpoint_id(2);
        state.direct.insert(bob, DirectState::RelayOnly);
        assert!(!super::mark_proven(&mut state, bob), "nothing parked yet");
        assert_eq!(state.direct.get(&bob), Some(&DirectState::Direct));
    }

    // Direct connections are on demand (decision D4): the watcher follows a
    // pooled connection that a send opened, and dials none of its own. A pair
    // that was never sent to has nothing to watch, and stays where it is.
    #[tokio::test]
    async fn a_peer_nothing_was_sent_to_is_not_dialed_to_be_watched() {
        use habilis_network_iroh_webrtc_transport::{WebRtcHandle, WebRtcTransport};
        use iroh::TransportAddr;
        let mut state = fresh_state();
        let mut ids = [endpoint_id(1), endpoint_id(2), endpoint_id(3)];
        ids.sort_unstable();
        let [local, rendezvous, bob] = ids;
        state.webrtc = Some(WebRtcHandle::new(WebRtcTransport::new(local)));
        state.local_udp_transport = true;
        state.peer_endpoints.insert(
            nick("bob"),
            EndpointAddr::from_parts(
                bob,
                [TransportAddr::Ip("127.0.0.1:1".parse().expect("addr"))],
            ),
        );
        ensure_watchers(&mut state, local, rendezvous);
        assert!(
            !state.path_watchers.contains_key(&bob),
            "no pooled connection, nothing to watch, and no dial to make one"
        );
    }

    // The rendezvous serves no unicast: it is never watched, even when a
    // connection to it exists. A peer with a pooled connection is watched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_rendezvous_is_not_watched() {
        use habilis_network_iroh_webrtc_transport::{WebRtcHandle, WebRtcTransport};
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};
        use iroh::{RelayMode, SecretKey, endpoint::presets};

        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                conn.closed().await;
                Ok(())
            }
        }
        let bind = |key: Option<SecretKey>| async move {
            let mut builder = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Disabled)
                .clear_address_lookup();
            if let Some(key) = key {
                builder = builder.secret_key(key);
            }
            builder.bind().await.expect("bind a loopback endpoint")
        };
        let client = bind(None).await;
        // The watcher only follows higher ids: take both keys above the client's.
        // The id of the client is random: with 255 seeds a high id left fewer than two keys.
        let mut keys = (1u16..=u16::MAX)
            .map(|seed| {
                let mut bytes = [0u8; 32];
                bytes[..2].copy_from_slice(&seed.to_le_bytes());
                SecretKey::from_bytes(&bytes)
            })
            .filter(|key| key.public() > client.id());
        let bob = bind(keys.next()).await;
        let beacon = bind(keys.next()).await;
        let routers: Vec<Router> = [&bob, &beacon]
            .into_iter()
            .map(|server| {
                Router::builder(server.clone())
                    .accept(crate::transport::UNICAST_ALPN, Hold)
                    .spawn()
            })
            .collect();
        let mut state = fresh_state();
        state.webrtc = Some(WebRtcHandle::new(WebRtcTransport::new(client.id())));
        state.local_udp_transport = true;
        state.unicast_pool = crate::transport::UnicastPool::new(client.clone(), false);
        for (name, server) in [("bob", &bob), ("beacon", &beacon)] {
            crate::lookup::add_peer_addr(&client, server.addr()).expect("register");
            state.peer_endpoints.insert(nick(name), server.addr());
            state
                .unicast_pool
                .warm_or_dial(server.id())
                .await
                .expect("a send dials the peer");
        }

        ensure_watchers(&mut state, client.id(), beacon.id());

        assert!(
            state.path_watchers.contains_key(&bob.id()),
            "a peer with a pooled connection is watched"
        );
        assert!(!state.path_watchers.contains_key(&beacon.id()));
        for router in routers {
            router.shutdown().await.expect("shutdown");
        }
        client.close().await;
    }

    // G is a target, not only a cap: while the active view is below G, one
    // member is grafted per tick. Native members come before browsers, and
    // within each group the order is fixed.
    #[test]
    fn the_fill_tick_picks_a_native_member_that_is_not_linked_yet() {
        use iroh::TransportAddr;
        let mut state = fresh_state();
        let rendezvous = endpoint_id(1);
        let ids: Vec<_> = (2u8..=6).map(endpoint_id).collect();
        let native = |id| {
            EndpointAddr::from_parts(
                id,
                [TransportAddr::Ip("127.0.0.1:1".parse().expect("addr"))],
            )
        };
        let browser = |id| {
            EndpointAddr::new(id).with_relay_url("https://relay.invalid".parse().expect("url"))
        };
        // ids[0] is a browser, ids[1] is linked, ids[2] is cooling down,
        // ids[3] and ids[4] are native and free.
        state
            .peer_endpoints
            .insert(nick("beacon"), native(rendezvous));
        state
            .peer_endpoints
            .insert(nick("browser"), browser(ids[0]));
        state.peer_endpoints.insert(nick("linked"), native(ids[1]));
        state.peer_endpoints.insert(nick("cooling"), native(ids[2]));
        state.peer_endpoints.insert(nick("free-a"), native(ids[3]));
        state.peer_endpoints.insert(nick("free-b"), native(ids[4]));
        state.linked_endpoints.insert(ids[1]);
        let now = crate::util::clock::Instant::now();
        state.note_relink(ids[2], now);
        let mut free = [ids[3], ids[4]];
        free.sort_unstable();

        let next = super::next_fill(&state, 8, rendezvous, now, 0).map(|addr| addr.id);
        assert_eq!(
            next,
            Some(free[0]),
            "the lowest native member that is free, not the browser, the linked, \
             the cooling or the rendezvous"
        );
        assert_eq!(
            super::next_fill(&state, 1, rendezvous, now, 0).map(|addr| addr.id),
            None,
            "a full view grafts nobody"
        );
    }

    // On a mesh whose relay may carry payload there is no probe to hold a graft,
    // and a `PeerInfo` is not repeated: the alive tick fills the view, one member
    // per tick, and a member that was just tried waits out its cooldown.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_alive_tick_fills_one_member_per_tick_on_a_relay_transport_mesh() {
        use crate::protocol::MeshId;
        use crate::protocol::identity::{Identity, encode_pubkey};
        use iroh::{RelayMode, TransportAddr, endpoint::presets};

        let endpoint = iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .bind()
            .await
            .expect("bind a loopback endpoint");
        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let sender = crate::transport::MeshSender::new(gossip_sender);
        let mesh = MeshId::from("test");
        let identity = Identity::generate();
        let our_pubkey = encode_pubkey(&identity.public());
        let author = nick("alice");
        let sink = crate::gossip::event::SilentSink;
        let rendezvous = endpoint_id(1);
        let ctx = crate::daemon::ctx::HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &author,
            identity: &identity,
            our_pubkey: &our_pubkey,
            max_peers: 8,
            rendezvous_id: rendezvous,
            external_msg_tx: None,
            sink: &sink,
        };
        let mut state = fresh_state();
        state.relay_transport = true;
        let ids: Vec<_> = (2u8..=4).map(endpoint_id).collect();
        for (index, id) in ids.iter().enumerate() {
            state.peer_endpoints.insert(
                nick(&format!("peer{index}")),
                EndpointAddr::from_parts(
                    *id,
                    [TransportAddr::Ip("127.0.0.1:1".parse().expect("addr"))],
                ),
            );
        }
        let mut ordered = ids.clone();
        ordered.sort_unstable();
        let tried = |view: &EventLoopState| {
            let now = crate::util::clock::Instant::now();
            ordered
                .iter()
                .filter(|id| view.relink_on_cooldown(**id, now))
                .count()
        };

        super::retry_direct(&mut state, &ctx, false).await;
        assert_eq!(tried(&state), 1, "one member per tick");
        super::retry_direct(&mut state, &ctx, false).await;
        assert_eq!(tried(&state), 2, "the next tick takes the next member");
        endpoint.close().await;
    }

    // Every member below G picks from the same free natives. Always taking the
    // lowest id sends all of them to the same few peers, and a full peer evicts a
    // random neighbor on each join. The pick spreads them: it indexes the free
    // natives in their fixed order, and wraps.
    #[test]
    fn the_fill_tick_spreads_its_picks_over_the_free_natives() {
        use iroh::TransportAddr;
        let mut state = fresh_state();
        let rendezvous = endpoint_id(1);
        let ids: Vec<_> = (2u8..=5).map(endpoint_id).collect();
        for (index, id) in ids.iter().enumerate() {
            state.peer_endpoints.insert(
                nick(&format!("peer{index}")),
                EndpointAddr::from_parts(
                    *id,
                    [TransportAddr::Ip("127.0.0.1:1".parse().expect("addr"))],
                ),
            );
        }
        let mut ordered = ids.clone();
        ordered.sort_unstable();
        let now = crate::util::clock::Instant::now();
        let pick = |pick| super::next_fill(&state, 8, rendezvous, now, pick).map(|addr| addr.id);

        assert_eq!(pick(0), Some(ordered[0]));
        assert_eq!(pick(1), Some(ordered[1]));
        assert_eq!(pick(3), Some(ordered[3]));
        assert_eq!(pick(4), Some(ordered[0]), "the pick wraps");
    }

    #[test]
    fn ip_peer_needs_a_proven_direct_path() {
        assert!(may_graft(true, false, false));
        assert!(!may_graft(false, true, false));
    }

    #[test]
    fn webrtc_peer_needs_its_session_not_a_path() {
        assert!(may_graft(false, true, true));
        assert!(!may_graft(true, false, true));
    }
}
