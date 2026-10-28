//! The delivery outcome of one message: which plane took it.

use crate::transport::PendingSend;

/// What `deliver` did with a frame.
#[derive(Debug)]
#[must_use = "a dropped Pending handle loses the verdict of the send"]
#[non_exhaustive]
pub enum Delivered {
    /// Sent, or handed to a warm connection: nothing is left to wait for.
    Done,
    /// A unicast leg runs on a task of its own. Its outcome comes through the handle.
    Pending(PendingSend),
}
