//! The key of the author of a message.

use iroh_base::PublicKey;

/// The 32 bytes of the Ed25519 key that signed a message, from `Message::author_key`.
///
/// On the wire the key is its 64-character lowercase hex text. The signed bytes of a message
/// also hold that text, not the raw bytes, so [`Display`](std::fmt::Display) is part of the
/// format: change it and every signature breaks.
///
/// It is not an `iroh_base::PublicKey`, because that type rejects a 32-byte string that is
/// not a point of the curve, and a message carries the string before it is verified. Holding
/// a `PublicKey` inside would make a non-point key a parse error: a change on the parse side
/// of the wire, with a named decision, not a type swap.
///
/// A raw array does not stand in for the key:
///
/// ```compile_fail,E0308
/// use habilis_network_protocol::AuthorKey;
///
/// let _ = AuthorKey::from_bytes([0u8; 32]) == [0u8; 32];
/// ```
///
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AuthorKey([u8; 32]);

impl AuthorKey {
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

    /// The raw bytes, owned.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Read the 64-character lowercase hex form, the only one the wire carries. `None` for any
    /// other length, for an uppercase digit, and for a non-hex character.
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        crate::identity::decode_lower_hex_32(hex).map(Self)
    }

    /// The 64 ASCII bytes of the lowercase hex form, on the stack: what the signed bytes carry
    /// and what the dedup key hashes, written for every inbound message without an allocation.
    #[must_use]
    pub fn hex(&self) -> [u8; 64] {
        crate::identity::encode_lower_hex_32(&self.0)
    }

    /// Whether `hex` is this key in the form of [`Display`](std::fmt::Display). It does not
    /// allocate, so a per-message check can use it.
    #[must_use]
    pub fn matches_hex(&self, hex: &str) -> bool {
        self.hex().as_slice() == hex.as_bytes()
    }

    /// The key as a curve point, for signature verification. `None` if the bytes are not one.
    #[must_use]
    pub fn public_key(&self) -> Option<PublicKey> {
        PublicKey::from_bytes(&self.0).ok()
    }
}

// Hex, so a log line and an assertion failure stay readable.
impl std::fmt::Debug for AuthorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthorKey({self})")
    }
}

impl std::fmt::Display for AuthorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        crate::identity::write_hex(f, &self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorKey;

    const HEX: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

    #[test]
    fn it_round_trips_through_its_hex_text() {
        let key = AuthorKey::from_hex(HEX).expect("a lowercase 64-char string");
        assert_eq!(key.to_string(), HEX);
        assert_eq!(key.as_bytes()[0], 0xea);
        assert_eq!(key.to_bytes()[31], 0x2c);
        assert_eq!(format!("{key:?}"), format!("AuthorKey({HEX})"));
    }

    #[test]
    fn it_rejects_what_the_wire_rejects() {
        assert!(AuthorKey::from_hex("").is_none());
        assert!(AuthorKey::from_hex(&HEX[..62]).is_none(), "short");
        assert!(AuthorKey::from_hex(&format!("{HEX}00")).is_none(), "long");
        assert!(
            AuthorKey::from_hex(&HEX.to_uppercase()).is_none(),
            "uppercase"
        );
        assert!(AuthorKey::from_hex(&"zz".repeat(32)).is_none(), "not hex");
        assert!(AuthorKey::from_hex(&"é".repeat(32)).is_none(), "multibyte");
    }

    #[test]
    fn hex_is_the_display_text_as_bytes() {
        let key = AuthorKey::from_hex(HEX).unwrap();
        assert_eq!(key.hex().as_slice(), HEX.as_bytes());
        assert_eq!(key.hex().as_slice(), key.to_string().as_bytes());
    }

    #[test]
    fn matches_hex_agrees_with_display() {
        let key = AuthorKey::from_hex(HEX).unwrap();
        assert!(key.matches_hex(HEX));
        assert!(!key.matches_hex(&HEX.to_uppercase()));
        assert!(!key.matches_hex(&HEX[..62]));
        assert!(!key.matches_hex(&format!("{}00", &HEX[..62])));
        assert!(!key.matches_hex(""));
    }

    #[test]
    fn it_orders_by_its_bytes() {
        let low = AuthorKey::from_bytes([1; 32]);
        let high = AuthorKey::from_bytes([2; 32]);
        assert!(low < high);
    }

    #[test]
    fn a_string_that_is_not_a_curve_point_is_a_key_but_not_a_public_key() {
        let mut bytes = [0u8; 32];
        bytes[0] = 2;
        assert!(AuthorKey::from_bytes(bytes).public_key().is_none());
        let identity = crate::identity::Identity::generate();
        let author = identity.author_key();
        assert_eq!(author.public_key(), Some(identity.public()));
    }
}
