//! The pairs that still need a relay to climb to a direct path.

use super::nudge_addrs::NudgeAddrs;
use super::path_kind::PathKind;
use super::step;
use super::step::StepInput;

use std::collections::HashMap;

use iroh::EndpointId;

/// A pair that a route can still climb from: the peer, the kind of its selected path (the relay or
/// gossip), whether it has a session, and the route that the topology has for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PairToClimb {
    pub(crate) peer: EndpointId,
    pub(crate) kind: PathKind,
    pub(crate) has_session: bool,
    pub(crate) route: Option<iroh::TransportAddr>,
}

/// Pure: the dials of one pass over the pairs that read as the relay or as gossip, as `(peer,
/// kind, has a session, route)`. A pair is dialed when it has a session address or a route to carry. With
/// `only_changed` a pair is dialed only for a route that differs from the one dialed for it last,
/// and a pair with no route is not dialed at all. `route_dialed` remembers the route of each dial,
/// and keeps it only for the pairs of this pass: a pair that left the relay (it climbed, or it
/// is gone) is forgotten, so that a pair that falls back with the same route is dialed again.
pub(crate) fn plan_relay_dials(
    pairs: impl IntoIterator<Item = PairToClimb>,
    route_dialed: &mut HashMap<EndpointId, iroh::TransportAddr>,
    only_changed: bool,
    gossip_on: bool,
) -> Vec<(EndpointId, NudgeAddrs)> {
    let pairs: Vec<_> = pairs.into_iter().collect();
    route_dialed.retain(|peer, _| pairs.iter().any(|climbing| climbing.peer == *peer));
    let mut dials = Vec::new();
    for PairToClimb {
        peer,
        kind,
        has_session,
        route,
    } in pairs
    {
        let input = StepInput {
            kind,
            has_session,
            route: route.clone(),
            gossip_on,
        };
        let Some(addrs) = step(input).nudge else {
            continue;
        };
        let already_dialed = route.is_some() && route_dialed.get(&peer) == route.as_ref();
        if only_changed && (route.is_none() || already_dialed) {
            continue;
        }
        if let Some(route) = route {
            route_dialed.insert(peer, route);
        }
        dials.push((peer, addrs));
    }
    dials
}

/// Pure: the pinned peers that the topology has no route to now. A pinned connection exists only
/// for its route, so the connection of such a peer closes and the next send follows the normal
/// rule: a free unit dials direct, a full ceiling with a route pins, and a full ceiling with none
/// evicts. `pinned` holds each pinned peer with whether a route to it exists.
pub(crate) fn lost_pinned(pinned: impl IntoIterator<Item = (EndpointId, bool)>) -> Vec<EndpointId> {
    let mut lost: Vec<EndpointId> = pinned
        .into_iter()
        .filter(|(_, has_route)| !has_route)
        .map(|(peer, _)| peer)
        .collect();
    lost.sort_unstable();
    lost
}

#[cfg(test)]
mod tests {
    use super::lost_pinned;
    use crate::testing;

    #[test]
    fn a_pinned_peer_with_no_route_is_lost_and_one_with_a_route_is_kept() {
        let _guard = ::habilis_network_test_tracing::init();
        let (kept, lost, also_lost) = (
            testing::endpoint_id(1),
            testing::endpoint_id(2),
            testing::endpoint_id(3),
        );
        let mut expected = vec![lost, also_lost];
        expected.sort_unstable();
        assert_eq!(
            lost_pinned([(kept, true), (lost, false), (also_lost, false)]),
            expected,
            "only the pinned peers with no route are lost"
        );
        assert!(
            lost_pinned([(kept, true)]).is_empty(),
            "a pinned peer with a route is kept"
        );
    }
}
