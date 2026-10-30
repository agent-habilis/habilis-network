//! The plane a message's addressing chooses, and the rule that picks it.

use crate::daemon::state::DirectState;
use crate::protocol::Nickname;

use crate::daemon::state::EventLoopState;
use crate::protocol::messages::{Verified, sole_addressee};
use iroh::EndpointId;

/// The chosen transport for a message — a **pure** decision so both planes are
/// unit-testable without touching the network.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Route {
    /// No sole addressee: gossip is the transport, structurally.
    Broadcast,
    /// Directed to a known endpoint: unicast only. The underlying iroh
    /// connection uses a direct path when one exists, else the registered
    /// multihop transport — the send decision doesn't distinguish.
    Unicast(EndpointId),
    /// Directed to a known endpoint whose only path is the relay, on a mesh
    /// where the relay carries no payload: parked until a direct path is
    /// proven, never sent relayed.
    Held(EndpointId),
    /// Directed with no known endpoint: an error, never gossip.
    Undeliverable,
}

pub(super) fn route(message: &Verified, state: &EventLoopState) -> Route {
    let Some(nick) = sole_addressee(&message.kind) else {
        return Route::Broadcast;
    };
    match directed_endpoint(nick, state) {
        Some(eid) if held(eid, state) => Route::Held(eid),
        Some(eid) => Route::Unicast(eid),
        None => Route::Undeliverable,
    }
}

/// Whether a directed frame to `eid` is parked right now: the relay is lookup
/// only and no direct path to the peer is proven yet. An unprobed peer is
/// held too — the alive tick probes every known peer, so the hold is short.
pub(super) fn held(eid: EndpointId, state: &EventLoopState) -> bool {
    !state.relay_transport.relay_allowed() && state.direct.get(&eid) != Some(&DirectState::Direct)
}

/// The endpoint a directed message to `nick` can be sent to, or `None` for an
/// addressee we hold no endpoint for or the rendezvous pseudo-node (never a
/// directed target). Reachability is left to iroh's connect (direct or multihop).
pub(super) fn directed_endpoint(nick: &Nickname, state: &EventLoopState) -> Option<EndpointId> {
    let eid = state.peer_endpoints.get(nick)?.id;
    if state.rendezvous_id == Some(eid) {
        return None;
    }
    Some(eid)
}
