//! Negotiating one WebRTC session with a peer.

use super::offer::Offer;
use super::{nudge_acceptor, offer, retry, session_policy};
use crate::daemon::ctx::HandlerCtx;

use iroh::{EndpointAddr, EndpointId};

use crate::transport::LOG_TARGET;

use crate::daemon::state;
use crate::daemon::state::DirectState;
use crate::transport::probe;
use crate::util::clock;

pub(crate) fn negotiate_session(
    state: &mut state::EventLoopState,
    ctx: &HandlerCtx<'_>,
    peer: EndpointId,
    addr: EndpointAddr,
) {
    let Some(handle) = state.webrtc.clone() else {
        // No transport registered: the beacon, or a multihop peer.
        return;
    };
    // A cold pair stays where it is until the next send.
    if retry::held_back(state, &addr) {
        tracing::debug!(target: LOG_TARGET, %peer, "no send yet; leaving this pair alone");
        return;
    }
    // A pair where both ends run UDP races the punch: the data channel gives
    // 6× less throughput at 36× the latency (docs/architecture.md §11), so it is worth a
    // JSEP round only while UDP has not won. Once it has, nothing is offered,
    // and a round that finishes after it is detached (`spawn_offer_round`).
    //
    // **Either** end lacking IP makes the lane the pair's only direct path,
    // and testing only the remote is a bug: the lower id dials, so when a
    // browser is the lower id it is the browser that evaluates this. It would
    // see the native peer's IP, skip, and the native — waiting to be dialled —
    // would never offer. The pair would silently never get a channel.
    let needs_lane = session_policy::pair_needs_lane(&addr, state.local_udp_transport);
    let kind = state.pair_path_kind(peer);
    let proven = state.direct.get(&peer) == Some(&DirectState::Direct);
    if !session_policy::wants_session(needs_lane, kind, proven) {
        if kind == Some(probe::PathKind::Ip) {
            if session_policy::detach_session_under_udp(state, peer, needs_lane) {
                return;
            }
            tracing::debug!(
                target: LOG_TARGET,
                %peer,
                "udp already selected; leaving this pair on iroh's own transports"
            );
        } else {
            tracing::debug!(
                target: LOG_TARGET,
                %peer,
                ?kind,
                "pair proven direct; leaving it on iroh's own transports"
            );
        }
        return;
    }
    // The higher id waits to be dialled, so one offer crosses per pair. Unless a frame is held for
    // the peer: that frame cannot wait for an offer that the lower id has no reason to make. If
    // both offer at once, the lower id wins (see `WebRtcSignalAcceptor::accept`).
    let local = ctx.endpoint.id();
    let frame_held = state.lane_session_wanted(peer, clock::Instant::now());
    if session_policy::waits_for_the_offer(local > peer, frame_held, kind, proven) {
        return;
    }
    // A pair that reads as the relay is not direct, whatever the proof says: take the proof back,
    // so that a frame is parked for the session and not refused on the relay. Not while a session
    // is attached: a session carries the pair whatever one connection reads (a connection opened
    // before the attach reads the relay until a path event moves it), so the connection that reads
    // as relay is nudged onto the session, and the proof stands.
    let reads_as_relay = session_policy::reads_below_a_session(kind, proven);
    let has_session = handle.has_session(&peer);
    if reads_as_relay && has_session {
        let endpoint = ctx.endpoint.clone();
        n0_future::task::spawn(async move { nudge_acceptor::nudge_session(&endpoint, peer).await });
    }
    let demoted = reads_as_relay && !has_session;
    if demoted {
        state.direct.insert(peer, DirectState::RelayOnly);
        tracing::info!(
            target: LOG_TARGET,
            %peer,
            detector = "admission",
            "direct path lost; racing again"
        );
    }
    // Every other gate — already have a session, already negotiating, at the
    // cap, cooling off after a refusal — is one synchronous decision under one
    // lock. That is what lets in-flight rounds count against the cap: this
    // function is called in a tight loop by `retry_sessions` with nothing
    // awaited between calls, so a check that read only `session_count()` saw
    // the same zero twenty times and spawned twenty dials.
    let guard = match state.webrtc_admission.try_admit_offer(peer, &handle) {
        Ok(guard) => guard,
        Err(reason) => {
            tracing::debug!(target: LOG_TARGET, %peer, ?reason, "not negotiating");
            return;
        }
    };

    let offer = if needs_lane {
        Offer::Lane
    } else if demoted {
        Offer::AfterLoss
    } else {
        Offer::UdpRace
    };
    offer::spawn_offer_round(state, ctx, peer, addr, handle, guard, offer);
}
