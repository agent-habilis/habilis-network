//! The key of the author of a message.

use iroh_base::PublicKey;

use crate::identity;
use std::fmt;
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
/// let _ = AuthorKey::from([0u8; 32]) == [0u8; 32];
/// ```
///
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AuthorKey([u8; 32]);

impl From<[u8; 32]> for AuthorKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AuthorKey {
    /// The raw bytes, borrowed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The raw bytes, owned.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Read the 64-character lowercase hex form, the only one the wire carries. `None` for any
    /// other length, for an uppercase digit, and for a non-hex character.
    #[must_use]
    pub fn decode_hex(hex: &str) -> Option<Self> {
        identity::decode_lower_hex_32(hex).map(Self)
    }

    /// The 64 ASCII bytes of the lowercase hex form, on the stack: what the signed bytes carry
    /// and what the dedup key hashes, written for every inbound message without an allocation.
    #[must_use]
    pub fn hex(&self) -> [u8; 64] {
        identity::encode_lower_hex_32(&self.0)
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

    /// Make an author key from its 32 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

// Hex, so a log line and an assertion failure stay readable.
impl fmt::Debug for AuthorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthorKey({self})")
    }
}

impl fmt::Display for AuthorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        identity::write_hex(f, &self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorKey;

    use crate::identity;
    const HEX: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

    #[test]
    fn it_round_trips_through_its_hex_text() {
        let _guard = ::habilis_network_test_tracing::init();
        let key = AuthorKey::decode_hex(HEX).expect("a lowercase 64-char string");
        assert_eq!(key.to_string(), HEX, "the author key displays its hex text");
        assert_eq!(
            key.as_bytes()[0],
            0xea,
            "the first byte of the author key is 0xea"
        );
        assert_eq!(
            key.to_bytes()[31],
            0x2c,
            "the last byte of the wire key is 0x2c"
        );
        assert_eq!(
            format!("{key:?}"),
            format!("AuthorKey({HEX})"),
            "the author key debug prints its hex text"
        );
    }

    #[test]
    fn it_rejects_what_the_wire_rejects() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            AuthorKey::decode_hex("").is_none(),
            "an empty hex string is refused as an author key"
        );
        assert!(AuthorKey::decode_hex(&HEX[..62]).is_none(), "short");
        assert!(AuthorKey::decode_hex(&format!("{HEX}00")).is_none(), "long");
        assert!(
            AuthorKey::decode_hex(&HEX.to_uppercase()).is_none(),
            "uppercase"
        );
        assert!(AuthorKey::decode_hex(&"zz".repeat(32)).is_none(), "not hex");
        assert!(
            AuthorKey::decode_hex(&"é".repeat(32)).is_none(),
            "multibyte"
        );
    }

    #[test]
    fn hex_is_the_display_text_as_bytes() {
        let _guard = ::habilis_network_test_tracing::init();
        let key =
            AuthorKey::decode_hex(HEX).expect("the fixture hex is a valid author key encoding");
        assert_eq!(
            key.hex().as_slice(),
            HEX.as_bytes(),
            "the hex bytes are the display text"
        );
        assert_eq!(
            key.hex().as_slice(),
            key.to_string().as_bytes(),
            "the hex bytes match the display text"
        );
    }

    #[test]
    fn matches_hex_agrees_with_display() {
        let _guard = ::habilis_network_test_tracing::init();
        let key =
            AuthorKey::decode_hex(HEX).expect("the fixture hex is a valid author key encoding");
        assert!(key.matches_hex(HEX), "matches_hex accepts the display text");
        assert!(
            !key.matches_hex(&HEX.to_uppercase()),
            "matches_hex refuses upper-case text"
        );
        assert!(
            !key.matches_hex(&HEX[..62]),
            "matches_hex refuses a short text"
        );
        assert!(
            !key.matches_hex(&format!("{}00", &HEX[..62])),
            "matches_hex refuses a text with a changed last byte"
        );
        assert!(!key.matches_hex(""), "matches_hex refuses an empty text");
    }

    #[test]
    fn it_orders_by_its_bytes() {
        let _guard = ::habilis_network_test_tracing::init();
        let low = AuthorKey::from([1; 32]);
        let high = AuthorKey::from([2; 32]);
        assert!(low < high, "author keys order by their bytes");
    }

    #[test]
    fn a_string_that_is_not_a_curve_point_is_a_key_but_not_a_public_key() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut bytes = [0u8; 32];
        bytes[0] = 2;
        assert!(
            AuthorKey::from(bytes).public_key().is_none(),
            "a non-curve string is an author key but not a public key"
        );
        let identity = identity::Identity::generate();
        let author = identity.author_key();
        assert_eq!(
            author.public_key(),
            Some(identity.public()),
            "the public key of the identity is its author key"
        );
    }
}
