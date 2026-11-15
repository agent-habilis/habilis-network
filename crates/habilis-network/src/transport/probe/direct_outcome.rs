//! The outcome of a direct probe of one peer.

use iroh::EndpointId;

use crate::daemon::state::EventLoopState;
use crate::util::clock::Instant;

/// A probe's verdict, reported back to the event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectOutcome {
    pub(crate) peer: EndpointId,
    pub(crate) direct: bool,
    /// The session came from an offer of the peer that this node answered. The answerer grafts and
    /// flushes only when a frame is held for the peer, see [`DirectOutcome::applies`].
    pub(crate) answered: bool,
}

impl DirectOutcome {
    /// Whether the loop acts on this outcome at `now`. An answered session is not a verdict of
    /// this node's own probe: it matters only when a frame is held for the peer, which waits for
    /// the attach to be flushed.
    pub(crate) fn applies(self, state: &EventLoopState, now: Instant) -> bool {
        !self.answered || state.lane_session_wanted(self.peer, now)
    }
}
