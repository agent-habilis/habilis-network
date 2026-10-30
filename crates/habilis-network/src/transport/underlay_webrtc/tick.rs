//! The tick of the WebRTC underlay: one pass that dials, keeps and reports underlays.

use super::plan;
use super::plan::Plan;
use super::underlay_web_rtc::UnderlayWebRtc;
use crate::transport::webrtc;

use iroh::EndpointId;

use crate::transport::LOG_TARGET;

use crate::daemon::state;

use crate::lookup::EndpointError;
use n0_future::{task, time};
/// [`tick`] now, when the engine learns something that changes the neighbors or
/// their paths (a neighbor came up, a path changed), without waiting for the alive
/// tick. A hop that stays on the relay is withdrawn from the vector after 20 s,
/// so a session offered 30 s late would come too late for the route it carries.
/// It does nothing for a node that has no underlay leg.
pub(crate) fn tick_now(state: &state::EventLoopState) {
    if let Some(underlay) = state.underlay_webrtc.as_ref() {
        tick(state, underlay);
    }
}

/// The members that the underlay can name, less the denied ones. The underlay address of a
/// member is in its signed link-vector, and a member we hold no vector from yet is skipped: it
/// gets one on a later tick.
fn neighbors_of(
    state: &state::EventLoopState,
    multihop: &habilis_network_iroh_multihop_transport::MultihopHandle,
) -> Vec<(EndpointId, iroh::EndpointAddr)> {
    let mut neighbors: Vec<(EndpointId, iroh::EndpointAddr)> = Vec::new();
    for peer_address in state.peer_endpoints.values() {
        let member = peer_address.id;
        if let Some(address) =
            multihop.underlay_addr_of(habilis_network_iroh_multihop_transport::AppId::new(member))
        {
            neighbors.push((member, address));
        }
    }
    plan::undenied(neighbors, |member| state.webrtc_admission.is_denied(member))
}

/// One alive tick: offer a session to each neighbor that needs one, and drop the
/// sessions that no neighbor needs. A neighbor needs one when its application
/// path is `WebRTC`; see the module note.
pub(crate) fn tick(state: &state::EventLoopState, underlay: &UnderlayWebRtc) {
    let Some(multihop) = state.multihop() else {
        return;
    };
    let neighbors = neighbors_of(state, multihop);
    underlay
        .allowed
        .replace(neighbors.iter().map(|(_, address)| address.id).collect());

    let wanted_addrs = plan::wanted_underlays(&neighbors, state.local_udp_transport, |member| {
        state.pair_path_kind(member)
    });
    let wanted: Vec<EndpointId> = wanted_addrs.iter().map(|address| address.id).collect();
    let kept = plan::kept_underlays(&neighbors, |member| state.pair_path_kind(member));
    let held: Vec<_> = underlay.handle.live_peer_ids().collect();
    let Plan { dial, detach } = plan(
        underlay.endpoint.id(),
        &wanted,
        &kept,
        &held,
        underlay.admission.room(),
    );
    let describe = |member: &EndpointId| {
        (
            member.fmt_short().to_string(),
            state.pair_path_kind(*member),
        )
    };
    let kinds: Vec<_> = neighbors
        .iter()
        .map(|(member, _)| describe(member))
        .collect();
    let local = underlay.endpoint.id().fmt_short();
    let linked = state.linked_endpoints.len();
    let members = neighbors.len();
    let wanted_count = wanted.len();
    let kept_count = kept.len();
    let held_count = held.len();
    let dial_count = dial.len();
    let detach_count = detach.len();
    tracing::debug!(
        target: LOG_TARGET,
        local = %local,
        linked,
        members,
        kinds = ?kinds,
        wanted = wanted_count,
        kept = kept_count,
        held = held_count,
        dial = dial_count,
        detach = detach_count,
        "underlay tick"
    );

    for peer in &wanted {
        if !held.contains(peer) && !dial.contains(peer) {
            tracing::debug!(target: LOG_TARGET, %peer, "wanted, but the neighbor is the one that offers");
        }
    }
    for peer in detach {
        if underlay.handle.detach(&peer) {
            tracing::debug!(target: LOG_TARGET, %peer, "underlay session detached: its member left the roster, or the pair is on IP");
        }
    }
    for peer in dial {
        let Some(address) = wanted_addrs.iter().find(|address| address.id == peer) else {
            continue;
        };
        let guard = match underlay.admission.try_admit(peer, &underlay.handle) {
            Ok(guard) => guard,
            Err(reason) => {
                tracing::debug!(target: LOG_TARGET, %peer, ?reason, "not offering an underlay session");
                continue;
            }
        };
        let (endpoint, book, handle, admission) = (
            underlay.endpoint.clone(),
            underlay.book.clone(),
            underlay.handle.clone(),
            underlay.admission.clone(),
        );
        let address = address.clone();
        let ice = state.webrtc_ice;
        let epoch = guard.epoch();
        let task = task::spawn(async move {
            let _guard = guard;
            match Box::pin(webrtc::dial_signal::dial_signal(
                &endpoint, &book, address, &handle, ice,
            ))
            .await
            {
                Ok(()) => {
                    admission.note_success(peer);
                    // The acceptor of the other side nudges when it takes the
                    // session; the dialer must too. An underlay connection that
                    // was dialed before the session learns the address of the
                    // session only from a dial that names it, and iroh does not
                    // ask the lookup again for a remote it already knows.
                    webrtc::nudge_acceptor::nudge_session(&endpoint, peer).await;
                }
                Err(error) => {
                    if matches!(error, EndpointError::CapRefused { .. }) {
                        admission.note_refused(peer);
                    }
                    tracing::debug!(target: LOG_TARGET, %peer, %error, "underlay webrtc offer failed");
                    // The guard of the round is held for the delay: its end rings the table, and
                    // the loop ticks and offers again (see `event_loop`). A second turn-away in
                    // a row is noted as a refusal: the peer waits, and the round ends at once.
                    if matches!(error, EndpointError::NotANeighbor { .. })
                        && admission.note_not_a_neighbor(peer)
                    {
                        time::sleep(plan::REFUSAL_RETRY).await;
                    }
                }
            }
        });
        underlay.admission.track(peer, epoch, task.abort_handle());
    }
}

/// The members whose underlay holds a live session with us, by member id. `neighbors` pairs each
/// member with its underlay address, and `held` are the underlay ids with a live session.
pub(crate) fn members_with_session(
    neighbors: &[(EndpointId, iroh::EndpointAddr)],
    held: &[EndpointId],
) -> Vec<EndpointId> {
    let sessions = neighbors
        .iter()
        .filter(|(_, address)| held.contains(&address.id));
    sessions.map(|(member, _)| *member).collect()
}

/// The members with a live session on our underlay, by member id: the edges of the routing graph
/// that a session carries, whether or not a gossip link to the member is up. Empty when the
/// node has no multihop handle.
pub(crate) fn held_members(
    state: &state::EventLoopState,
    underlay: &UnderlayWebRtc,
) -> Vec<EndpointId> {
    let Some(multihop) = state.multihop() else {
        return Vec::new();
    };
    let live: Vec<_> = underlay.handle.live_peer_ids().collect();
    members_with_session(&neighbors_of(state, multihop), &live)
}
