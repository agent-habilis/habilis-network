//! What the prober does next for a path.

use super::path_kind::PathKind;

/// What a change of the selected path asks of the race.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathAction {
    /// A direct path is selected: the peer is proven direct again, which
    /// frees frames parked while it was not.
    Proven,
    /// UDP is back: the session only holds a direct-peer slot now.
    Detach,
    /// The direct path is gone: race again.
    Rerace,
}

/// Pure: the race's answer to `selected` becoming the selected path.
pub(crate) fn path_action(selected: PathKind, has_session: bool) -> PathAction {
    match selected {
        PathKind::Ip if has_session => PathAction::Detach,
        // A pair on multihop or on gossip is off the relay but has no lane: race for one. A pair on
        // Nostr is on the last fallback and is no peer-to-peer path at all.
        PathKind::Relay
        | PathKind::Nostr
        | PathKind::None
        | PathKind::Multihop
        | PathKind::Gossip => PathAction::Rerace,
        PathKind::Ip | PathKind::WebRtc => PathAction::Proven,
    }
}

#[cfg(test)]
mod tests {
    use super::{PathAction, PathKind, path_action};

    /// Nostr is below the relay: the pair is not proven direct, and the race goes on.
    #[test]
    fn a_pair_on_nostr_races_again() {
        let _guard = ::habilis_network_test_tracing::init();
        for has_session in [false, true] {
            assert_eq!(
                path_action(PathKind::Nostr, has_session),
                PathAction::Rerace,
                "a Nostr path is no direct path (session {has_session})"
            );
        }
    }
}
