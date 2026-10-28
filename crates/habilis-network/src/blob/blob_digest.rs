use crate::protocol::identity;

use super::HASH_LEN;

/// The SHA-256 of a blob's bytes: the name it is stored, ticketed and fetched
/// under. Prints as lowercase hex, the same text as its spool file name.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlobDigest([u8; HASH_LEN]);

impl BlobDigest {
    /// Wrap the 32 bytes of a SHA-256.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, borrowed.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl std::fmt::Display for BlobDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        identity::write_hex(formatter, &self.0)
    }
}

impl std::fmt::Debug for BlobDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "BlobDigest({self})")
    }
}
