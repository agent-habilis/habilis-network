//! The content hash of a message.

use sha2::Sha256;

/// The SHA-256 of the canonical bytes of a message: its id for another author's `prev`
/// backlink, for the DAG `parents`, and for fork detection. It is recomputed on receive and
/// never trusted off the wire.
///
/// On the wire, and in the signed bytes of the message that names it, the hash is its
/// 64-character lowercase hex text, so [`Display`](std::fmt::Display) is part of the format.
///
/// A raw array does not stand in for the hash:
///
/// ```compile_fail,E0308
/// use habilis_network_protocol::ContentHash;
///
/// let _ = ContentHash::from_bytes([0u8; 32]) == [0u8; 32];
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    /// The SHA-256 of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        use sha2::Digest;
        Self(Sha256::digest(bytes).into())
    }

    /// Wrap 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, borrowed.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Read the 64-character lowercase hex form, the only one the wire carries. `None` for any
    /// other length, for an uppercase digit, and for a non-hex character.
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        crate::identity::decode_lower_hex_32(hex).map(Self)
    }

    /// The 64 ASCII bytes of the lowercase hex form, on the stack: what the signed bytes of a
    /// message carry for its `prev` and, inside a JSON array, for each of its `parents`.
    #[must_use]
    pub fn hex(&self) -> [u8; 64] {
        crate::identity::encode_lower_hex_32(&self.0)
    }
}

// Hex, so a log line and an assertion failure stay readable.
impl std::fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ContentHash({self})")
    }
}

impl std::fmt::Display for ContentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        crate::identity::write_hex(f, &self.0)
    }
}

/// The hex text, as a JSON string: the form of `prev` and of each of `parents` on the wire and
/// in the signed bytes of a message.
impl serde::Serialize for ContentHash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::ContentHash;
    use habilis_network_test_tracing::test;

    /// SHA-256 of the empty string.
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn it_hashes_with_sha256_and_prints_its_hex() {
        let hash = ContentHash::of(b"");
        assert_eq!(hash.to_string(), EMPTY);
        assert_eq!(format!("{hash:?}"), format!("ContentHash({EMPTY})"));
        assert_eq!(hash.hex().as_slice(), EMPTY.as_bytes());
    }

    #[test]
    fn it_reads_only_lowercase_64_char_hex() {
        assert_eq!(ContentHash::from_hex(EMPTY), Some(ContentHash::of(b"")));
        assert!(ContentHash::from_hex(&EMPTY.to_uppercase()).is_none());
        assert!(ContentHash::from_hex(&EMPTY[..62]).is_none());
        assert!(ContentHash::from_hex(&format!("{EMPTY}00")).is_none());
        assert!(ContentHash::from_hex(&"é".repeat(32)).is_none());
    }

    #[test]
    fn it_orders_by_its_bytes() {
        assert!(ContentHash::from_bytes([1; 32]) < ContentHash::from_bytes([2; 32]));
    }
}
