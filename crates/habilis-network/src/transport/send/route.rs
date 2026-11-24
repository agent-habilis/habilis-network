//! The plane a message's addressing chooses, and the rule that picks it.

use crate::daemon::state::DirectState;

use crate::daemon::state::EventLoopState;
use crate::protocol::AuthorKey;
use crate::protocol::messages::{Verified, sole_addressee};
use iroh::EndpointId;

/// The chosen transport for a message — a **pure** decision so both planes are
/// unit-testable without touching the network.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(super) enum Route {
    /// No sole addressee: gossip is the transport, structurally.
    Broadcast,
    /// Directed to a known endpoint: unicast only. The underlying iroh
    /// connection uses a direct path when one exists, else the registered
    /// multihop transport — the send decision doesn't distinguish.
    Unicast(EndpointId),
    /// Directed with no known endpoint: an error, never gossip.
    Undeliverable,
}

pub(super) fn route(message: &Verified, state: &EventLoopState) -> Route {
    let Some(key) = sole_addressee(&message.kind) else {
        return Route::Broadcast;
    };
    route_to_key(key, state)
}

/// The directed rules for a frame that goes to `key` alone: unicast to its endpoint, or
/// undeliverable. It never gives [`Route::Broadcast`].
pub(super) fn route_to_key(key: &AuthorKey, state: &EventLoopState) -> Route {
    match directed_endpoint(key, state) {
        Some(eid) => Route::Unicast(eid),
        None => Route::Undeliverable,
    }
}

/// Whether the relay is lookup only and no probe has shown a direct path to `eid`: the pair is
/// not proven, whether it is unread, in flight or relay-only. A send does not refuse on this
/// alone (see [`relay_only`]); a reply that must not dial reads it, and a send that dials asks for a
/// lane session by it.
pub(super) fn unproven(eid: EndpointId, state: &EventLoopState) -> bool {
    !state.relay_transport.relay_allowed() && state.direct.get(&eid) != Some(&DirectState::Direct)
}

/// Whether a probe stored the pair as relay-only on a mesh whose relay is lookup only. It labels
/// the roster column ([`super::lane_for`]) and refuses nothing: the state lags the connection, so
/// the live path of the connection decides what may go out.
pub(super) fn relay_only(eid: EndpointId, state: &EventLoopState) -> bool {
    !state.relay_transport.relay_allowed()
        && state.direct.get(&eid) == Some(&DirectState::RelayOnly)
}

/// The endpoint a directed message to `key` can be sent to, or `None` for a key we hold no
/// endpoint for, and for the rendezvous pseudo-node (never a directed target). The sources are
/// the ones of [`EventLoopState::address_of`]. Reachability is left to iroh's connect (direct or
/// multihop).
pub(crate) fn directed_endpoint(key: &AuthorKey, state: &EventLoopState) -> Option<EndpointId> {
    let eid = state.address_of(key)?.id;
    if state.rendezvous_id == Some(eid) {
        return None;
    }
    Some(eid)
}
