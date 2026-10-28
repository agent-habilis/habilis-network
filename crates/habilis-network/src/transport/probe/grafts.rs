//! Grafting a peer once its direct path is proven.

use super::direct_outcome::DirectOutcome;
use super::graft_request::{GraftRequest, GraftTarget};
use super::{graft_request, lanes, regraft};

use iroh::EndpointId;

use crate::daemon::ctx::HandlerCtx;
use crate::daemon::state::{DirectState, EventLoopState};
use crate::transport::payload_path::{PROBE_DEADLINE, wait_direct};
use crate::transport::webrtc;
use crate::util::clock::Instant;

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
    if state.relay_transport.relay_allowed() {
        return true;
    }
    let needs_webrtc =
        webrtc::needs_webrtc_lane(peer_addr) || webrtc::needs_webrtc_lane(&ctx.endpoint.addr());
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
            webrtc::negotiate_session(state, ctx, peer, peer_addr.clone());
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
                tracing::debug!(target: crate::transport::LOG_TARGET, %peer, %error, "direct-path probe could not connect");
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
        tracing::info!(target: crate::transport::LOG_TARGET, %peer, "no direct path within the probe deadline; peer stays relay-only");
    } else {
        tracing::debug!(target: crate::transport::LOG_TARGET, %peer, "late probe verdict ignored; the peer is no longer pending");
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
        tracing::debug!(target: crate::transport::LOG_TARGET, %peer, "graft skipped: the pair rides the gossip rung");
        return Ok(());
    }
    match graft_request(
        state,
        GraftTarget {
            peer,
            rendezvous: ctx.rendezvous_id,
        },
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
            tracing::warn!(target: crate::transport::LOG_TARGET, %peer, %error, "graft request failed");
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
    if state.relay_transport.relay_allowed() {
        regraft::fill_active_view(state, ctx).await;
        return;
    }
    // The lane offers are paced: a browser pays an ICE gathering budget per round. The members
    // left out are not touched, so that no `Pending` mark hides them from the next pass.
    let (lane, rest): (Vec<_>, Vec<_>) =
        regraft::retry_candidates(state, ctx.rendezvous_id, ctx.max_peers, distrust_links)
            .into_iter()
            .partition(|addr| lanes::is_lane_offer(state, ctx, addr));
    for addr in rest {
        lanes::retry_one(state, ctx, addr, distrust_links).await;
    }
    let pick = lanes::lane_pick();
    for addr in lanes::plan_lane_offers(lane, state.webrtc_admission.in_flight(), pick) {
        lanes::retry_one(state, ctx, addr, distrust_links).await;
    }
}
