//! The key that names a message in the dedup set, the message log, and the
//! anti-entropy digest.

use crate::identity;
use std::fmt;
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

impl From<[u8; 16]> for DedupKey {
    /// Wrap 16 raw bytes.
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl DedupKey {
    /// The lowest key. With [`DedupKey::MAX`] it makes a bound that takes in every key.
    pub const MIN: Self = Self([0; 16]);
    /// The highest key.
    pub const MAX: Self = Self([u8::MAX; 16]);

    /// The raw bytes, borrowed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The raw bytes, owned.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

// Hex, so a log line and an assertion failure stay readable. A derived `Debug`
// prints a 16-element byte array.
impl fmt::Debug for DedupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DedupKey({self})")
    }
}

impl fmt::Display for DedupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        identity::write_hex(f, &self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::DedupKey;

    #[test]
    fn the_bounds_take_in_every_key() {
        let _guard = ::habilis_network_test_tracing::init();
        let key = DedupKey::from([7; 16]);
        assert!(
            DedupKey::MIN < key && key < DedupKey::MAX,
            "every key lies between the min and max bounds"
        );
        assert_eq!(
            DedupKey::MIN.to_bytes(),
            [0; 16],
            "the min bound is all zeros"
        );
        assert_eq!(
            DedupKey::MAX.to_bytes(),
            [u8::MAX; 16],
            "the max bound is all ff bytes"
        );
    }

    #[test]
    fn it_orders_by_its_bytes() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut low = [0u8; 16];
        low[15] = 1;
        let mut high = [0u8; 16];
        high[0] = 1;
        assert!(
            DedupKey::from(low) < DedupKey::from(high),
            "dedup keys order by their bytes"
        );
    }

    #[test]
    fn it_prints_as_hex() {
        let _guard = ::habilis_network_test_tracing::init();
        let key = DedupKey::from([0xab; 16]);
        assert_eq!(
            key.to_string(),
            "ab".repeat(16),
            "a dedup key prints as hex"
        );
        assert_eq!(
            format!("{key:?}"),
            format!("DedupKey({})", "ab".repeat(16)),
            "a dedup key debug prints its hex"
        );
    }
}
