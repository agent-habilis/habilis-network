//! The mark of the root frame of a state seed.

use serde::{Deserialize, Serialize};

/// What the root frame of a state seed says about the chain that it starts: how many frames the
/// chain has, the root included, and the hash of the last change (hex). A node adopts a seed only
/// when it holds a chain that matches this mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SeedMark {
    /// The number of frames of the chain, the root included.
    #[serde(rename = "n")]
    pub frames: u32,
    /// The hash of the last change of the chain, in hex.
    #[serde(rename = "l")]
    pub last: String,
    /// The cut vector: for each writer of the old epoch, a tag of 8 bytes of its actor (hex) and
    /// the highest sequence number of its changes that the seed holds. A change of the old epoch
    /// above it is not in the seed.
    #[serde(rename = "c", default, skip_serializing_if = "Vec::is_empty")]
    pub cut: Vec<(String, u64)>,
}

impl SeedMark {
    /// A mark for a chain of `frames` frames whose last change has the hash `last`, in hex.
    #[must_use]
    pub fn new(frames: u32, last: String) -> Self {
        Self {
            frames,
            last,
            cut: Vec::new(),
        }
    }

    /// The same mark with a cut vector.
    #[must_use]
    pub fn with_cut(mut self, cut: Vec<(String, u64)>) -> Self {
        self.cut = cut;
        self
    }
}
