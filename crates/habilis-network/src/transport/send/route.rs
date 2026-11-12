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
    /// Directed to a known endpoint whose only path a probe proved to be the relay, on a mesh
    /// where the relay carries no payload: refused until a direct path is proven, never sent
    /// relayed. The caller retries the send.
    Held(EndpointId),
    /// Directed with no known endpoint: an error, never gossip.
    Undeliverable,
}

pub(super) fn route(message: &Verified, state: &EventLoopState) -> Route {
    let Some(key) = sole_addressee(&message.kind) else {
        return Route::Broadcast;
    };
    match directed_endpoint(key, state) {
        Some(eid) if held(eid, state) => Route::Held(eid),
        Some(eid) => Route::Unicast(eid),
        None => Route::Undeliverable,
    }
}

/// Whether the relay is lookup only and no probe has shown a direct path to `eid`: the pair is
/// not proven, whether it is unread, in flight or relay-only. A send does not refuse on this
/// alone (see [`held`]); a reply that must not dial reads it, and a send that dials asks for a
/// lane session by it.
pub(super) fn unproven(eid: EndpointId, state: &EventLoopState) -> bool {
    !state.relay_transport.relay_allowed() && state.direct.get(&eid) != Some(&DirectState::Direct)
}

/// Whether a directed frame to `eid` is refused right now: the relay is lookup
/// only and a probe proved that the pair has no direct path. A pair that no probe has read, or
/// whose probe is in flight, is not held: the send dials it and waits for a direct path within
/// the path-select budget, and the live path of the connection refuses a payload that would go
/// out on the relay. The state read here lags the connection, so it must not refuse on its own
/// what the connection has not shown.
pub(super) fn held(eid: EndpointId, state: &EventLoopState) -> bool {
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
