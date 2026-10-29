//! Negotiating a WebRTC session through the rendezvous.

use super::offer::Offer;
use super::{lane_needs, offer};
use crate::daemon::handler_ctx::HandlerCtx;

use habilis_network_iroh_webrtc_transport::WebRtcHandle;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::{EndpointAddr, EndpointId};

use crate::transport::LOG_TARGET;

use crate::daemon::state;

use iroh::address_lookup;
/// Whether the periodic heal legs may graft-dial the rendezvous at all.
///
/// A webrtc-shaped node on a lookup-only mesh must never graft on a timer:
/// the beacon's accept gate holds a relay-only connection and closes it
/// after its deadline, so a timer graft costs a whole hold for nothing. (It
/// no longer wedges the link: the pinned iroh-gossip drops a peer whose
/// connection died before the handshake and redials on the next send.)
/// `has_session` is no defence either: the rival re-check rebuilds the
/// rendezvous endpoint, leaving a session that is locally held but dead on
/// the other end. The only safe
/// trigger is the **attach event itself** — a JSEP round that just completed
/// is the liveness proof — so [`negotiate_rendezvous_session`] reports it
/// through the loop's `DirectOutcome` channel and the graft fires there,
/// within the freshly proven window.
///
/// An IP-capable node joins that rule once it falls back to offering: a
/// beacon it could not punch to in a whole heal interval is a tab, and a
/// timer graft there is the same doomed dial.
pub(crate) fn rendezvous_graftable(state: &state::EventLoopState) -> bool {
    state.rendezvous_wanted()
        && !state.rendezvous_graft_needs_session
        && !state.rendezvous_offer_fallback
}

/// Offer a `WebRTC` session to the **rendezvous** itself.
///
/// On a mesh whose relay is lookup only, the rendezvous link — like every
/// link — is admitted only on a non-relay path, and a browser-shaped peer
/// (no IP transports) has exactly one way to produce one: the data channel.
/// The beacon answers JSEP for precisely this case, so the tab offers.
///
/// Unlike [`negotiate_session`], the lower-id rule does not apply — the
/// beacon holds no address for a tab and can never be the dialer — and the
/// peer-address lane check is skipped: the rendezvous address is a bare
/// registered id, which reads as "unknown", not "browser". Everything else
/// (admission, the in-flight guard, the cap, the cooldown) is shared.
///
/// A no-op unless: the relay is lookup only, this node is browser-shaped,
/// and the rendezvous link is down. Driven by the heal tick, which runs
/// exactly while that link is down.
pub(crate) fn negotiate_rendezvous_session(
    state: &mut state::EventLoopState,
    context: &HandlerCtx<'_>,
) {
    if !state.rendezvous_wanted() {
        // A session to the rendezvous that this node does not want. The main
        // case is the release: gossip closes the link, and this detaches the
        // session once the link is down. The other is a joiner whose links to
        // members came up before its graft to the rendezvous landed. Either
        // would hold one of the beacon's slots for ever.
        if !state.rendezvous_linked
            && let Some(handle) = state.webrtc.as_ref()
            && handle.detach(&context.rendezvous_id)
        {
            tracing::debug!(target: LOG_TARGET, "detached a rendezvous session that is no longer wanted");
        }
        return;
    }
    if state.relay_transport.relay_allowed() || state.rendezvous_linked {
        return;
    }
    let Some(handle) = state.webrtc.clone() else {
        return;
    };
    if !lane_needs::local_needs_webrtc_lane(state.local_udp_transport)
        && !state.rendezvous_offer_fallback
    {
        // An IP-capable peer normally reaches the rendezvous by punching
        // inside the bootstrap connection — the data channel would be a
        // worse path — so the punch gets the first heal tick. But IP
        // capability says nothing about the *beacon*: a browser-held
        // rendezvous has no UDP to punch to, and without this fallback an
        // IP-capable native could never join a tab's mesh (observed in the
        // browser-first matrix cells). Still linkless next tick: offer.
        // Never on a mesh whose rendezvous cannot answer: a private beacon is
        // native by construction, and the fallback would hold the grafts with
        // nothing to release it.
        if state.rendezvous_answers_jsep {
            state.rendezvous_offer_fallback = true;
        }
        return;
    }
    let rendezvous = context.rendezvous_id;
    // A held session with an *unlinked* rendezvous is stale: the beacon's
    // rival re-check releases and re-claims the rendezvous on a fresh
    // endpoint, whose session table starts empty, and this heal tick only
    // runs while the link is down. Without a detach, admission would refuse
    // every re-offer with `HaveSession` and the peer would stay wedged for
    // the life of the process.
    //
    // But not on the *first* tick that sees it: this tick also re-grafts,
    // and the graft dial is what turns the session into a link. Detaching
    // here unconditionally killed the session moments before every dial —
    // a phase lock in which no dial ever saw an attached session. So a held
    // session gets one full tick to produce the link; only one that is
    // still linkless on the next tick is torn down and re-negotiated.
    if handle.has_session(&rendezvous) {
        if !state.rendezvous_session_stale {
            state.rendezvous_session_stale = true;
            return;
        }
        if handle.detach(&rendezvous) {
            tracing::debug!(target: LOG_TARGET, %rendezvous, "detached a stale rendezvous session before re-offering");
        }
    }
    state.rendezvous_session_stale = false;
    offer_to_rendezvous(state, context, handle, Offer::Rendezvous);
}

/// Offer a `WebRTC` session to the rendezvous while its gossip link is up on the relay.
///
/// The relay policy closes that link after [`PROBE_DEADLINE`](crate::transport::payload_path::PROBE_DEADLINE), and
/// the offer of [`negotiate_rendezvous_session`] comes only after the close. This one comes at
/// the edge, so a session that attaches inside the deadline gives the link a direct path and the
/// link stays. No fallback grace: IP is lost, not unknown. A session that is held is left alone,
/// and the stale-session detach of the heal tick does not run here.
pub(crate) fn offer_rendezvous_on_path_loss(
    state: &mut state::EventLoopState,
    context: &HandlerCtx<'_>,
) {
    if !state.rendezvous_wanted()
        || state.relay_transport.relay_allowed()
        || !state.rendezvous_linked
    {
        return;
    }
    let Some(handle) = state.webrtc.clone() else {
        return;
    };
    if handle.has_session(&context.rendezvous_id) {
        return;
    }
    offer_to_rendezvous(state, context, handle, Offer::RendezvousLinked);
}

/// The address that an offer to the rendezvous dials: the id with every address the book holds for
/// it. A dial by the bare id carries no ip address, so iroh opens only the custom path first and the
/// connection waits for the first retransmit onto the ip path it learns meanwhile. The peers already
/// dial with an explicit address; this was the one dial that did not.
pub(crate) fn rendezvous_dial_target(book: &MemoryLookup, rendezvous: EndpointId) -> EndpointAddr {
    book.get_endpoint_info(rendezvous).map_or_else(
        || EndpointAddr::new(rendezvous),
        address_lookup::EndpointInfo::into_endpoint_addr,
    )
}

pub(crate) fn offer_to_rendezvous(
    state: &mut state::EventLoopState,
    context: &HandlerCtx<'_>,
    handle: WebRtcHandle,
    offer: Offer,
) {
    let rendezvous = context.rendezvous_id;
    let guard = match state.webrtc_admission.try_admit(rendezvous, &handle) {
        Ok(guard) => guard,
        Err(reason) => {
            tracing::debug!(target: LOG_TARGET, %rendezvous, ?reason, "not negotiating with the rendezvous");
            return;
        }
    };
    let target = rendezvous_dial_target(&state.address_book, rendezvous);
    offer::spawn_offer_round(state, context, rendezvous, target, handle, guard, offer);
}

/// A rendezvous offer made off the heal tick: when the loop starts, and when
/// the rendezvous link drops. The heal tick that otherwise makes it is a whole
/// interval away, and until it runs a browser-shaped node has no path onto a
/// lookup-only mesh; a beacon that re-checks inside that window finds nobody
/// negotiating and sheds.
///
/// Only a node that already offers: one that needs the lane, or an IP-capable
/// node whose fallback is armed. An IP-capable node's first call arms the
/// fallback, which holds its timer grafts, so only the heal tick may make it:
/// the punch must first have had a heal interval to land.
pub(crate) fn offer_rendezvous_off_tick(
    state: &mut state::EventLoopState,
    context: &HandlerCtx<'_>,
) {
    if offers_off_tick(state) {
        negotiate_rendezvous_session(state, context);
    }
}

pub(crate) fn offers_off_tick(state: &state::EventLoopState) -> bool {
    lane_needs::local_needs_webrtc_lane(state.local_udp_transport)
        || state.rendezvous_offer_fallback
}
