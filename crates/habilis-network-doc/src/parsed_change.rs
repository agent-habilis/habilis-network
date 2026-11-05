//! A change body, read back.

use crate::{SeedMark, Stamp};

/// A change body, read back: the change bytes, the epoch, and the seed mark of a seed root.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParsedChange {
    /// The automerge change bytes.
    pub bytes: Vec<u8>,
    /// The epoch of the change, 0 when the body has none.
    pub epoch: u64,
    /// The mark of a seed root, `None` for any other change.
    pub seed: Option<SeedMark>,
    /// The Lamport time of the change, `None` when the body has none.
    pub time: Option<u64>,
    /// The stamps of the writes that a seed or a replay frame carries, one for each leaf of the
    /// change, in the order of the paths of the leaves. Empty for any other change.
    pub origins: Vec<Stamp>,
}
