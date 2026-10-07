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
            } else if matches!(path.remote_addr(), iroh::TransportAddr::Custom(addr)
                if addr.id() == habilis_network_iroh_webrtc_transport::WEBRTC_TRANSPORT_ID)
            {
                PathKind::WebRtc
            } else {
                PathKind::Multihop
            }
        })
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
pub(crate) fn nudge_webrtc_riders(state: &EventLoopState, ctx: &HandlerCtx<'_>) {
    for peer in webrtc_riders(state) {
        let endpoint = ctx.endpoint.clone();
        n0_future::task::spawn(async move {
            super::webrtc::nudge(&endpoint, peer).await;
        });
    }
    // A pair on the relay that the topology can now route: dial with the route.
    // The watcher does this when the path is lost, but a route learned later
    // (link-state comes every 15 s) is then missing, and nothing else runs a
    // lookup for a pair that already has a session or no offer to make.
    // No in-flight guard in both loops, by design: each dial is bounded by `DIAL_TIMEOUT`.
    for addr in state
        .peer_endpoints
        .values()
        .filter(|addr| addr.id != ctx.rendezvous_id)
    {
        let kind = pair_kind(
            state.path_kinds.get(&addr.id).copied(),
            state.webrtc_admission.selected_kind(addr.id),
        );
        if kind != Some(PathKind::Relay) {
            continue;
        }
        let has_session = state
            .webrtc
            .as_ref()
            .is_some_and(|handle| handle.has_session(&addr.id));
        if let Some(addrs) = step(PathKind::Relay, has_session, route_to(state, addr.id)).nudge {
            let (endpoint, peer) = (ctx.endpoint.clone(), addr.id);
            n0_future::task::spawn(async move {
                super::webrtc::nudge_with(&endpoint, peer, &addrs).await;
            });
        }
    }
}

/// The multihop route to `peer` that the topology has now, as a dialable
/// address. `None` off a host, or without a route.
#[cfg(feature = "host")]
fn route_to(state: &EventLoopState, peer: EndpointId) -> Option<iroh::TransportAddr> {
    state
        .multihop
        .as_ref()
        .and_then(|handle| handle.route_addr(peer))
        .map(iroh::TransportAddr::Custom)
}

#[cfg(not(feature = "host"))]
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
    let Some(handle) = state.webrtc.clone() else {
        return;
    };
    let has_session = handle.has_session(&peer);
    let ladder = step(kind, has_session, route_to(state, peer));
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
            if kind == PathKind::Multihop {
                // Off the relay, so frames may flow; but the pair has no lane yet.
                if mark_proven(state, peer) {
                    crate::gossip::flush_pending(state, ctx, "multihop path").await;
                }
                tracing::info!(target: super::LOG_TARGET, %peer, "pair is on multihop; racing for a lane");
            } else {
                if state.direct.get(&peer) == Some(&DirectState::Direct) {
                    state.direct.insert(peer, DirectState::RelayOnly);
                }
                tracing::info!(target: super::LOG_TARGET, %peer, ?kind, "direct path lost; racing again");
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
        // A pair on multihop is off the relay but has no lane: race for one.
        PathKind::Relay | PathKind::None | PathKind::Multihop => PathAction::Rerace,
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
pub(crate) fn step(kind: PathKind, has_session: bool, route: Option<iroh::TransportAddr>) -> Step {
    let action = path_action(kind, has_session);
    let route = match kind {
        PathKind::Relay | PathKind::None => route,
        PathKind::Ip | PathKind::WebRtc | PathKind::Multihop => None,
    };
    let climbing = matches!(kind, PathKind::Relay | PathKind::None | PathKind::Multihop);
    let nudge = (climbing && (has_session || route.is_some())).then_some(NudgeAddrs {
        session: has_session,
        route,
    });
    Step { action, nudge }
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
        // A browser peer proves itself through `negotiate_session`; an IP
        // peer's probe is already running.
        state.direct.entry(peer).or_insert(DirectState::Pending);
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
        let _ = tx.send(DirectOutcome { peer, direct });
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
    let DirectOutcome { peer, direct } = outcome;
    if direct {
        graft_proven(state, ctx, peer).await;
    } else if state.demote_unproven(peer) {
        tracing::info!(target: super::LOG_TARGET, %peer, "no direct path within the probe deadline; peer stays relay-only");
    } else {
        tracing::debug!(target: super::LOG_TARGET, %peer, "late probe verdict ignored; the peer is no longer pending");
    }
}

/// Record `peer` as `Direct`, graft it if it is not linked already and there
/// is room, and flush any frame parked for it.
pub(crate) async fn graft_proven(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    peer: EndpointId,
) {
    state.direct.insert(peer, DirectState::Direct);
    // A session to the rendezvous that attached after this node let go of it
    // must not graft it again: every graft of the rendezvous waits for
    // `rendezvous_wanted`.
    if peer == ctx.rendezvous_id && !state.rendezvous_wanted() {
        return;
    }
    if !state.linked_endpoints.contains(&peer) && state.linked_endpoints.len() < ctx.max_peers {
        state.note_relink(peer, Instant::now());
        if let Err(error) = ctx.sender.join_peers(vec![peer]).await {
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
    if state.relay_transport {
        fill_active_view(state, ctx).await;
        return;
    }
    for addr in retry_candidates(state, ctx.rendezvous_id, distrust_links) {
        if distrust_links {
            state.direct.remove(&addr.id);
        }
        if ensure_direct(state, ctx, addr.id, &addr) {
            graft_proven(state, ctx, addr.id).await;
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
    distrust_links: bool,
) -> Vec<iroh::EndpointAddr> {
    let now = Instant::now();
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
        .cloned()
        .collect();
    peers.sort_unstable_by_key(|addr| addr.id);
    peers
}

#[cfg(test)]
mod tests {
    use iroh::EndpointAddr;

    use super::{PathKind, ensure_watchers, may_graft, retry_candidates, webrtc_riders};
    use crate::daemon::state::EventLoopState;
    use crate::testing::{endpoint_id, fresh_state, nick};

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
            retry_candidates(&state, rendezvous, distrust_links)
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
        let without_session = step(PathKind::Multihop, false, Some(a_route()));
        assert_eq!(without_session.action, PathAction::Rerace);
        assert_eq!(without_session.nudge, None, "the offer's attach nudges");
        let with_session = step(PathKind::Multihop, true, Some(a_route()));
        assert_eq!(
            with_session.nudge,
            Some(NudgeAddrs {
                session: true,
                route: None
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
        let nothing = step(PathKind::Relay, false, None);
        assert_eq!(nothing.action, PathAction::Rerace);
        assert_eq!(
            nothing.nudge, None,
            "no route and no session: nothing to teach"
        );
        let route_only = step(PathKind::Relay, false, Some(a_route()));
        assert_eq!(
            route_only.nudge,
            Some(NudgeAddrs {
                session: false,
                route: Some(a_route())
            })
        );
        let both = step(PathKind::Relay, true, Some(a_route()));
        assert_eq!(
            both.nudge,
            Some(NudgeAddrs {
                session: true,
                route: Some(a_route())
            }),
            "one dial carries both addresses"
        );
        let session_only = step(PathKind::Relay, true, None);
        assert_eq!(
            session_only.nudge,
            Some(NudgeAddrs {
                session: true,
                route: None
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
            let decided = step(kind, has_session, Some(a_route()));
            assert_eq!(decided.action, action);
            assert_eq!(decided.nudge, None, "{kind:?} needs no dial");
        }
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
        let mut keys = (1u8..=255)
            .map(|seed| SecretKey::from_bytes(&[seed; 32]))
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
