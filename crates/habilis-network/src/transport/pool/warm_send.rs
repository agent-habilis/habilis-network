//! A warm connection a send can use right away, or the dial that will make one.

/// What `UnicastPool::send_if_warm` did with the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WarmSend {
    /// Handed to a warm connection.
    Sent,
    /// No warm connection: the caller dials inline.
    Cold,
    /// A warm connection exists, but its selected path reads relay and the relay is lookup
    /// only. The path can still be forming, so a caller serves it like `Cold`: the dial finds
    /// the same connection and waits for a direct path.
    Refused,
}
