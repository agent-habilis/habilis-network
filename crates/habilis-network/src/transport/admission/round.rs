//! One admission round.

use n0_future::task::AbortHandle;

/// A signalling round holding a peer's negotiation slot.
#[derive(Debug, Clone)]
pub(crate) enum Round {
    /// The slot is claimed; the task is not spawned yet.
    Admitted,
    /// The task that holds the slot, which shutdown can cancel.
    Running(AbortHandle),
}
