//! The retry tick: re-attempts the sessions a peer still lacks.

use super::{lane_needs, negotiate_session, session_policy};
use crate::daemon::handler_ctx::HandlerCtx;

use iroh::{EndpointAddr, EndpointId};

use crate::transport::LOG_TARGET;

use crate::daemon::state;
use crate::daemon::state::DirectState;
use crate::transport::probe;
use crate::util::{clock, tuning};

/// Re-attempt negotiation with every known peer we hold no session with.
///
/// Driven by a periodic tick rather than by `PeerInfo`, because `PeerInfo` is
/// the *arrival* signal and stops re-flooding once a pair is linked. A single
/// failed round would otherwise be permanent — the pair keeps a working relay
/// link and silently never gets a direct path, which is the failure mode that
/// looks like everything is fine.
///
/// Cheap: a map walk plus a `has_session` check per peer. The per-peer in-flight
/// guard and the cap inside [`negotiate_session`] do the rest of the work.
pub(crate) fn retry_sessions(state: &mut state::EventLoopState, context: &HandlerCtx<'_>) {
    if state.webrtc.is_none() {
        return;
    }
    // First let go of what nothing uses, so that a slot frees before this pass
    // decides who gets one.
    detach_idle_sessions_at(state, clock::Instant::now());
    // Collected first: `negotiate_session` needs `&mut state`, so the borrow of
    // `peer_endpoints` cannot be held across the calls.
    // The peer's own advertised address, not one rebuilt from its id: a
    // rebuilt address carries no transports, so every peer looked like it
    // needed the browser lane and this pass opened a data channel with all of
    // them. The cheap disqualifiers run before the clone — a peer whose
    // session is already attached (admission would refuse it with
    // `HaveSession` anyway) or a pure-IP pair costs a map walk, nothing more.
    // Judged by the address snapshot on purpose, unlike `negotiate_session`:
    // a browser's own address reads as "unknown" here, so its retry pass
    // covers relay-only peers (other tabs) and leaves natives to dial it.
    // Read through `local_needs_webrtc_lane` the pass re-offered to every
    // native each tick, colliding with the native's own dial.
    let own_addr = context.endpoint.addr();
    let own_needs_lane = lane_needs::needs_webrtc_lane(&own_addr);
    let mut peers: Vec<EndpointAddr> = state
        .peer_endpoints
        .values()
        .filter(|address| address.id != context.rendezvous_id)
        .filter(|address| {
            session_policy::wants_session(
                own_needs_lane || lane_needs::needs_webrtc_lane(address),
                state.pair_path_kind(address.id),
                state.direct.get(&address.id) == Some(&DirectState::Direct),
            )
        })
        .filter(|address| {
            !state
                .webrtc
                .as_ref()
                .is_some_and(|handle| handle.has_session(&address.id))
        })
        .filter(|address| !held_back(state, address))
        .cloned()
        .collect();
    // Sorted because the cap now bites here: in a mesh larger than the ceiling
    // this pass decides *which* peers get direct sessions, and `HashMap`
    // iteration order would make that differ run to run on one machine.
    peers.sort_unstable_by_key(|address| address.id);
    // The lane offers are paced like those of `retry_direct`: one helper decides how many a
    // pass starts and which, so that the two passes do not add up to a round per member.
    let (lane, rest): (Vec<_>, Vec<_>) = peers
        .into_iter()
        .partition(|address| own_needs_lane || lane_needs::needs_webrtc_lane(address));
    let pick = probe::lane_pick();
    let lane = probe::plan_lane_offers(lane, state.webrtc_admission.in_flight(), pick);
    let mut offers: Vec<EndpointAddr> = rest;
    offers.extend(lane);
    for address in offers {
        negotiate_session::negotiate_session(state, context, address.id, address);
    }
}

/// Whether the pair with `addr` waits for a send before it is offered a
/// session (decision D4: direct connections are on demand). It does when the
/// peer is no gossip neighbor and the pool holds no connection that a send opened,
/// so nothing was sent to it within the idle window. A pair that needs the lane
/// waits too (decision D11), unless a frame is held for it: its session is the only
/// direct path it has, and that frame is the send that asks for it. A gossip
/// neighbor keeps its session proactive, because the gossip link is always on.
///
/// One more pair is not held back: on a mesh whose relay is lookup only, a pair
/// whose direct-path probe failed (`RelayOnly`). A directed frame to it is parked,
/// never dialed, so no send ever opens a connection, and its gossip graft waits
/// for a proven direct path. A pair behind NAT, with addresses but no punched
/// path, would wait for ever. A session is its way out.
pub(crate) fn held_back(state: &state::EventLoopState, address: &EndpointAddr) -> bool {
    let probe_failed = !state.relay_transport.relay_allowed()
        && state.direct.get(&address.id) == Some(&DirectState::RelayOnly);
    let linked = state.linked_endpoints.contains(&address.id);
    let wanted = state.lane_session_wanted(address.id, clock::Instant::now());
    // A peer that evicted us lately is left alone by every proactive dial, and the offer of a
    // session is one. A held frame is a send, and a send dials at once.
    let evicted_us = !linked && !wanted && state.webrtc_admission.evicted_recently(address.id);
    evicted_us
        || (!linked
            && !wanted
            && !probe_failed
            && state.unicast_pool.used_connection(address.id).is_none())
}

/// Detach the sessions that nothing has held for
/// [`DIRECT_IDLE_BACKSTOP`](crate::util::tuning::DIRECT_IDLE_BACKSTOP)
/// (decision D11: the ceiling frees a place for a newcomer, this frees what nobody uses).
/// A detached pair holds no pooled connection, so [`held_back`] leaves it alone until a send dials the
/// peer.
///
/// The last use is the one of the ledger of the admission table. A round in flight holds a peer,
/// and so does a live gossip connection, so a gossip neighbor never idles out. A pair detaches its
/// session a window after its last send, plus one tick of the retry pass. A peer whose address is
/// not known keeps its session: see [`held_back`]. Returns the peers detached.
pub(crate) fn detach_idle_sessions_at(
    state: &mut state::EventLoopState,
    now: clock::Instant,
) -> Vec<EndpointId> {
    let Some(handle) = &state.webrtc else {
        return Vec::new();
    };
    let window = tuning::DIRECT_IDLE_BACKSTOP;
    let mut detached = Vec::new();
    for peer in state.webrtc_admission.idle_sessions(now, window) {
        let kept = state.linked_endpoints.contains(&peer)
            || !state
                .peer_endpoints
                .values()
                .any(|address| address.id == peer);
        if kept || !handle.detach(&peer) {
            continue;
        }
        tracing::debug!(target: LOG_TARGET, %peer, "detached an idle session");
        detached.push(peer);
    }
    detached
}
