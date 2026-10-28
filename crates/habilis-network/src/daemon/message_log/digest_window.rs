use crate::protocol::DedupKey;

use super::Bound;

/// One anti-entropy digest window: the inclusive `[lo, hi]` range of
/// [`Bound`]s it covers and the compact dedup keys the sender holds
/// in that range. The window is a contiguous slice of the log in bound order, so
/// the ids it lists are **every** message the sender holds in the range. A
/// receiver can then re-send only real gaps, and advertising a sub-window of a
/// large log never makes peers perpetually re-send what the sender already has.
pub(crate) struct DigestWindow {
    pub lo: Bound,
    pub hi: Bound,
    pub ids: Vec<DedupKey>,
    /// The window holds the first message of the log: nothing sorts before it.
    pub from_start: bool,
}
