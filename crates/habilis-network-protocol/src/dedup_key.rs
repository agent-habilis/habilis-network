//! The key that names a message in the dedup set, the message log, and the
//! anti-entropy digest.

/// `SHA-256(pubkey ‖ id)[..16]` of a message, from [`Message::dedup_key`].
///
/// It is not the message id and not the UUID bytes of the id: the key binds the
/// author's public key to the id, so a forged message that reuses a victim's id
/// gets another key. The password verifier of a mesh is also 16 bytes, which is
/// why the two are not the same type.
///
/// A raw array does not stand in for the key, so a swap with another 16-byte value fails to
/// compile:
///
/// ```compile_fail,E0308
/// use habilis_network_protocol::DedupKey;
///
/// let _ = DedupKey::MIN == [0u8; 16];
/// ```
///
/// [`Message::dedup_key`]: crate::Message::dedup_key
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DedupKey([u8; 16]);

impl DedupKey {
    /// The lowest key. With [`DedupKey::MAX`] it makes a bound that takes in every key.
    pub const MIN: Self = Self([0; 16]);
    /// The highest key.
    pub const MAX: Self = Self([u8::MAX; 16]);

    /// Wrap 16 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, borrowed.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The raw bytes, owned.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

// Hex, so a log line and an assertion failure stay readable. A derived `Debug`
// prints a 16-element byte array.
impl std::fmt::Debug for DedupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DedupKey({self})")
    }
}

impl std::fmt::Display for DedupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        crate::identity::write_hex(f, &self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::DedupKey;

    #[test]
    fn the_bounds_take_in_every_key() {
        let key = DedupKey::from_bytes([7; 16]);
        assert!(DedupKey::MIN < key && key < DedupKey::MAX);
        assert_eq!(DedupKey::MIN.to_bytes(), [0; 16]);
        assert_eq!(DedupKey::MAX.to_bytes(), [u8::MAX; 16]);
    }

    #[test]
    fn it_orders_by_its_bytes() {
        let mut low = [0u8; 16];
        low[15] = 1;
        let mut high = [0u8; 16];
        high[0] = 1;
        assert!(DedupKey::from_bytes(low) < DedupKey::from_bytes(high));
    }

    #[test]
    fn it_prints_as_hex() {
        let key = DedupKey::from_bytes([0xab; 16]);
        assert_eq!(key.to_string(), "ab".repeat(16));
        assert_eq!(format!("{key:?}"), format!("DedupKey({})", "ab".repeat(16)));
    }
}
