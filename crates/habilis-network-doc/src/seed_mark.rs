//! The mark of the root frame of a state seed.

use serde::{Deserialize, Serialize};

/// What the root frame of a state seed says about the chain that it starts: how many frames the
/// chain has, the root included, and the hash of the last change (hex). A node adopts a seed only
/// when it holds a chain that matches this mark. A mark with any other key is no mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SeedMark {
    /// The number of frames of the chain, the root included.
    #[serde(rename = "n")]
    pub frames: u32,
    /// The hash of the last change of the chain, in hex.
    #[serde(rename = "l")]
    pub last: String,
}

impl SeedMark {
    /// A mark for a chain of `frames` frames whose last change has the hash `last`, in hex.
    #[must_use]
    pub fn new(frames: u32, last: String) -> Self {
        Self { frames, last }
    }
}
