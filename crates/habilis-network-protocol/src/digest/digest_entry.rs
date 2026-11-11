use crate::{AuthorKey, ContentHash};

/// One author in a digest page: its key, its version, and the hash of its signed frame.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DigestEntry {
    key: AuthorKey,
    version: u64,
    hash: ContentHash,
}

impl DigestEntry {
    /// Makes the entry of `key` at `version`, whose signed frame hashes to `hash`.
    #[must_use]
    pub fn new(key: AuthorKey, version: u64, hash: ContentHash) -> Self {
        Self { key, version, hash }
    }

    /// The author key of the entry.
    #[must_use]
    pub fn key(&self) -> AuthorKey {
        self.key
    }

    /// The version of the entry.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The hash of the signed frame of the entry.
    #[must_use]
    pub fn hash(&self) -> ContentHash {
        self.hash
    }
}
