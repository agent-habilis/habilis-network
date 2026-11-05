//! The stamp of a write: the Lamport time of its change and the tag of its actor.

/// Which write made the value of a leaf, in an order that every node agrees on: the Lamport time
/// of the change first, and the tag of its actor (8 bytes, in hex) to break a tie. A write that
/// its author made after it saw another write has the higher stamp, whatever the order of their
/// keys, which the op ids of automerge do not promise across epochs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct Stamp {
    /// The Lamport time of the change that wrote the value.
    pub time: u64,
    /// The tag of the actor that wrote it, 8 bytes in hex.
    pub tag: String,
}

impl Stamp {
    /// The stamp of a write at `time` by the actor with `tag`.
    #[must_use]
    pub fn new(time: u64, tag: String) -> Self {
        Self { time, tag }
    }
}
