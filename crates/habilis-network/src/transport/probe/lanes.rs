//! The lane offers of the probe.

use super::{grafts, regraft};
use crate::util::tuning;

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::transport::webrtc;

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
    let budget = tuning::LANE_OFFERS_IN_FLIGHT.saturating_sub(in_flight);
    let (mut browsers, mut natives): (Vec<_>, Vec<_>) = lane
        .into_iter()
        .partition(webrtc::lane_needs::needs_webrtc_lane);
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
pub(crate) fn is_lane_offer(
    state: &EventLoopState,
    ctx: &HandlerCtx<'_>,
    addr: &iroh::EndpointAddr,
) -> bool {
    (webrtc::lane_needs::needs_webrtc_lane(addr)
        || webrtc::lane_needs::needs_webrtc_lane(&ctx.endpoint.addr()))
        && !state
            .webrtc
            .as_ref()
            .is_some_and(|handle| handle.has_session(&addr.id))
}

/// One member of a retry pass: `ensure_direct`, and the graft if the path is proven.
pub(crate) async fn retry_one(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    addr: iroh::EndpointAddr,
    distrust_links: bool,
) {
    if distrust_links {
        state.direct.remove(&addr.id);
    }
    if grafts::ensure_direct(state, ctx, addr.id, &addr) {
        grafts::graft_proven(state, ctx, addr.id).await;
    }
}

/// Offer a session to the lane members that a pass left out, as far as the rounds in flight
/// allow. The event loop calls this when a round ends, whatever its end (see
/// [`SignalAdmission::slot_freed`](crate::transport::admission::SignalAdmission::slot_freed)), so that the
/// next members do not wait for the alive tick. The members are not served in a fair order: the
/// random start spreads the load, and nothing more is promised.
pub(crate) async fn top_up_lane_offers(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    if state.relay_transport.relay_allowed() || state.webrtc.is_none() {
        return;
    }
    let lane: Vec<_> = regraft::retry_candidates(state, ctx.rendezvous_id, ctx.max_peers, false)
        .into_iter()
        .filter(|addr| is_lane_offer(state, ctx, addr))
        .collect();
    let pick = lane_pick();
    for addr in plan_lane_offers(lane, state.webrtc_admission.in_flight(), pick) {
        retry_one(state, ctx, addr, false).await;
    }
}
