//! The policy of when a WebRTC session is wanted, kept, or detached.

use super::lane_needs;
use super::udp_transport::UdpTransport;
use crate::daemon::handler_ctx::HandlerCtx;

use iroh::{EndpointAddr, EndpointId};

use crate::transport::LOG_TARGET;

use crate::daemon::state;
use crate::transport::probe;

/// Whether a pair needs the lane: **either** end lacking IP is enough. The
/// remote is judged by its advertised address, this node by what it knows
/// about itself.
#[must_use]
pub fn pair_needs_lane(remote: &EndpointAddr, local_has_udp_transport: UdpTransport) -> bool {
    lane_needs::needs_webrtc_lane(remote)
        || lane_needs::local_needs_webrtc_lane(local_has_udp_transport)
}

/// Whether a pair runs a `WebRTC` round: a pair that needs the lane always
/// does; a pair with UDP on both ends races the UDP punch, until UDP wins.
/// A UDP pair already `proven` direct with no session has proved its UDP
/// path, so a cold or idled-out pool (which reads as "UDP not selected")
/// does not start the race again on every alive tick.
///
/// `kind` is the selected path of the pair, if known. A pair on multihop is proven
/// off the relay, but it has no lane of its own: a session ranks above multihop,
/// so `proven` does not count while the pair rides it.
pub(crate) fn wants_session(
    pair_needs_lane: bool,
    kind: Option<probe::PathKind>,
    proven: bool,
) -> bool {
    let udp_selected = kind == Some(probe::PathKind::Ip);
    let proven = proven && !proof_is_stale(kind, proven);
    pair_needs_lane || !(udp_selected || proven)
}

/// Detach the session of `peer` when UDP is selected again for a pair that does not need the
/// lane. Only the lower id has a path watcher, and only on a pooled connection that a send
/// opened (decision D4), so a pair that only gossips has no one to report UDP's return. The
/// reading of the admission table is the sign, and it must hold for every live connection of
/// the pair: a connection that still rides the session keeps it. Returns whether a session was
/// detached.
pub(crate) fn detach_session_under_udp(
    state: &mut state::EventLoopState,
    peer: EndpointId,
    needs_lane: bool,
) -> bool {
    let Some(handle) = state.webrtc.clone() else {
        return false;
    };
    if needs_lane
        || state.pair_path_kind(peer) != Some(probe::PathKind::Ip)
        || state.webrtc_admission.any_connection_not_ip(peer)
        || !handle.detach(&peer)
    {
        return false;
    }
    tracing::info!(
        target: LOG_TARGET,
        %peer,
        detector = "admission",
        "udp selected again; webrtc session detached"
    );
    probe::mark_proven(state, peer);
    true
}

/// [`detach_session_under_udp`] for every session holder, on the fast ticker: the alive tick
/// (30 s) would leave a session under a selected UDP path for that long.
pub(crate) async fn detach_sessions_under_udp(
    state: &mut state::EventLoopState,
    context: &HandlerCtx<'_>,
) {
    let Some(handle) = state.webrtc.clone() else {
        return;
    };
    if handle.session_count() == 0 {
        return;
    }
    let holders: Vec<(EndpointId, bool)> = state
        .peer_endpoints
        .values()
        .filter(|address| address.id != context.rendezvous_id && handle.has_session(&address.id))
        .map(|address| {
            (
                address.id,
                pair_needs_lane(address, state.local_udp_transport),
            )
        })
        .collect();
    for (peer, needs_lane) in holders {
        if detach_session_under_udp(state, peer, needs_lane)
            && state.meshed
            && !state.pending_outbound.is_empty()
        {
            crate::gossip::flush_pending(state, context, "direct path back").await;
        }
    }
}

/// Whether the proof of a direct path is stale: the pair was `proven` direct, and its selected
/// path now reads as the relay, as multihop or as gossip, all below a session. Only a path
/// watcher takes a proof back, and only the lower id has one, so the reading of the admission
/// table is the only sign of the loss that a pair can have.
pub(crate) fn proof_is_stale(kind: Option<probe::PathKind>, proven: bool) -> bool {
    proven
        && matches!(
            kind,
            Some(probe::PathKind::Multihop | probe::PathKind::Gossip | probe::PathKind::Relay)
        )
}

/// Whether a proven pair reads as a path that a session replaces and that no peer-to-peer
/// transport carries: the relay, or the gossip rung (the recursion rule closes a gossip link on
/// it).
pub(crate) fn reads_below_a_session(kind: Option<probe::PathKind>, proven: bool) -> bool {
    proof_is_stale(kind, proven)
        && matches!(kind, Some(probe::PathKind::Relay | probe::PathKind::Gossip))
}

/// Whether this node leaves the offer of a session to its peer. The higher id waits to be
/// dialled, so that one offer crosses per pair, unless a frame is held for the peer or the
/// proof of a direct path is stale.
///
/// The proof is stale when the pair was `proven` direct and the selected path reads as the
/// relay. Only the lower id has a path watcher (`ensure_watchers`), so a higher id that sends
/// is the only one that can see the direct path go, and nobody else would offer. A crossing
/// is settled in favour of the lower id (see `WebRtcSignalAcceptor::accept`).
pub(crate) fn waits_for_the_offer(
    local_is_higher: bool,
    frame_held: bool,
    kind: Option<probe::PathKind>,
    proven: bool,
) -> bool {
    local_is_higher && !frame_held && !proof_is_stale(kind, proven)
}

/// Whether *this* node's rendezvous graft must wait for a data-channel
/// session: a lane-needing node on a lookup-only mesh. With the relay allowed
/// as a transport nothing needs holding.
pub(crate) fn node_graft_needs_session(
    relay_transport: bool,
    has_udp_transport: UdpTransport,
) -> bool {
    !relay_transport && lane_needs::local_needs_webrtc_lane(has_udp_transport)
}
