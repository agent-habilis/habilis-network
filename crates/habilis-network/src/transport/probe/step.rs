//! One step of the probe: its input and what it decides.

use super::nudge_addrs::NudgeAddrs;
use super::path_action;
use super::path_action::PathAction;
use super::path_kind::PathKind;

/// What [`step`] reads, by name: the kind of the selected path, whether the pair has a session,
/// the multihop route that the topology has now (`None` if it has none), and whether the mesh
/// has gossip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StepInput {
    pub(crate) kind: PathKind,
    pub(crate) has_session: bool,
    pub(crate) route: Option<iroh::TransportAddr>,
    pub(crate) gossip_on: bool,
}

/// The answer to a pair whose selected path is `kind`: the race action and what
/// to dial to help iroh climb the ladder. Pure; the one place that decides both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Step {
    pub(crate) action: PathAction,
    pub(crate) nudge: Option<NudgeAddrs>,
}

/// Pure: [`Step`] for a pair on `kind`, with `has_session` and the multihop
/// `route` that the topology has now (`None` if it has none).
///
/// A pair on the relay needs the route in a dial: iroh runs the address lookup
/// only while no path or the relay is selected, and the lookup answers only if
/// the topology has a route at that moment, so an address that the lookup missed
/// is never learned later without one. A pair with a session needs the session
/// address in a dial to move its connection onto the session's path. A pair
/// already on multihop needs no route.
pub(crate) fn step(input: StepInput) -> Step {
    let StepInput {
        kind,
        has_session,
        route,
        gossip_on,
    } = input;
    let action = path_action(kind, has_session);
    let route = match kind {
        PathKind::Relay | PathKind::Nostr | PathKind::None | PathKind::Gossip => route,
        PathKind::Ip | PathKind::WebRtc | PathKind::Multihop => None,
    };
    let gossip = gossip_on
        && matches!(kind, PathKind::Relay | PathKind::Nostr | PathKind::None)
        && route.is_none();
    let climbing = matches!(
        kind,
        PathKind::Relay | PathKind::Nostr | PathKind::None | PathKind::Multihop | PathKind::Gossip
    );
    let nudge = (climbing && (has_session || route.is_some() || gossip)).then_some(NudgeAddrs {
        session: has_session,
        route,
        gossip,
    });
    Step { action, nudge }
}

#[cfg(test)]
mod tests {
    use super::{NudgeAddrs, PathKind, Step, StepInput};
    use crate::transport::probe;
    use crate::transport::probe::path_action::PathAction;
    use habilis_network_iroh_gossip_transport as gossip_transport;

    /// A pair on Nostr climbs like a pair on the relay: a route or a gossip address in a dial
    /// moves it up. Nostr is the lowest rung, so there is always a rung above it.
    #[test]
    fn a_pair_on_nostr_is_nudged_up_the_ladder() {
        let _guard = ::habilis_network_test_tracing::init();
        let route = iroh::TransportAddr::Custom(gossip_transport::gossip_addr(
            iroh::SecretKey::from_bytes(&[3; 32]).public(),
        ));
        let on_gossip = probe::step(StepInput {
            kind: PathKind::Nostr,
            has_session: false,
            route: None,
            gossip_on: true,
        });
        assert_eq!(
            on_gossip,
            Step {
                action: PathAction::Rerace,
                nudge: Some(NudgeAddrs {
                    session: false,
                    route: None,
                    gossip: true
                }),
            },
            "a pair on Nostr is nudged onto the gossip rung"
        );
        let with_route = probe::step(StepInput {
            kind: PathKind::Nostr,
            has_session: false,
            route: Some(route.clone()),
            gossip_on: true,
        });
        assert_eq!(
            with_route.nudge,
            Some(NudgeAddrs {
                session: false,
                route: Some(route),
                gossip: false
            }),
            "a pair on Nostr gets the route that the topology has"
        );
    }
}
