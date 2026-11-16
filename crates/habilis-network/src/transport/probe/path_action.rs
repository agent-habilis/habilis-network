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
        // A pair on multihop or on gossip is off the relay but has no lane: race for one.
        PathKind::Relay | PathKind::None | PathKind::Multihop | PathKind::Gossip => {
            PathAction::Rerace
        }
        PathKind::Ip | PathKind::WebRtc => PathAction::Proven,
    }
}
