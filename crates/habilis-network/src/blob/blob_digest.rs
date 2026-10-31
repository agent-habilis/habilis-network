use crate::protocol::identity;

use super::HASH_LEN;

use std::fmt;
/// The SHA-256 of a blob's bytes: the name it is stored, ticketed and fetched
/// under. Prints as lowercase hex, the same text as its spool file name.
///
/// # Examples
///
/// A blob digest is the SHA-256 of a blob, and it reads back as bytes. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::ops::blob::BlobDigest;
///
/// # fn demo(digest: &BlobDigest) -> usize {
/// digest.as_bytes().len()
/// # }
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlobDigest([u8; HASH_LEN]);

impl From<[u8; HASH_LEN]> for BlobDigest {
    fn from(bytes: [u8; HASH_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl BlobDigest {
    /// The raw bytes, borrowed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Make a blob digest from its bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for BlobDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        identity::write_hex(formatter, &self.0)
    }
}

impl fmt::Debug for BlobDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BlobDigest({self})")
    }
}
