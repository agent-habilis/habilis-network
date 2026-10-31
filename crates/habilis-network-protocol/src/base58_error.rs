//! `Base58Check`: the encoding every bare identifier and ticket in this
//! workspace shares — a mesh id, an invite ticket, a blob ticket.
//!
//! Payload, then a 4-byte SHA-256d checksum over it, then Base58. Decoding
//! reverses that and rejects a payload whose checksum does not match, which is
//! what turns a mistyped id into an error instead of a wrong lookup.
//!
//! This lives in one module because it is a **wire contract**. It used to be
//! copy-pasted into `mesh`, `invite::ticket` and the engine's `blob::ticket`;
//! three copies of a checksum rule can drift, and a drifted copy is not a
//! compile error — it is a ticket minted by one path that no longer decodes on
//! another.

use std::fmt;

use sha2::Sha256;

use std::error;
/// The double-SHA-256 checksum, truncated to its first 4 bytes.
/// Why a `Base58Check` text does not decode. `what` names the text, for example
/// `mesh identifier`.
///
/// # Examples
///
/// A character outside the Base58 alphabet fails before the checksum is read.
///
/// ```
/// use habilis_network_protocol::base58check::{Base58Error, decode};
///
/// let error = decode("0OIl", "invite ticket").unwrap_err();
/// assert!(matches!(error, Base58Error::Alphabet(_)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum Base58Error {
    /// The text is not Base58.
    Alphabet(String),
    /// The text is too short to carry a checksum.
    Short(String),
    /// The checksum does not match the payload.
    Checksum(String),
}

impl fmt::Display for Base58Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alphabet(what) => write!(formatter, "invalid Base58 in {what}"),
            Self::Short(what) => write!(formatter, "{what} too short"),
            Self::Checksum(what) => write!(formatter, "invalid {what} checksum"),
        }
    }
}

impl error::Error for Base58Error {}

fn checksum(bytes: &[u8]) -> [u8; 4] {
    use sha2::Digest;
    let first = Sha256::digest(bytes);
    let second = Sha256::digest(first);
    let mut out = [0u8; 4];
    out.copy_from_slice(&second[..4]);
    out
}

/// Encode `payload` with its checksum appended.
///
/// # Examples
///
/// The text is the payload and a 4-byte checksum, in Base58.
///
/// ```
/// use habilis_network_protocol::base58check::encode;
///
/// let text = encode(b"mesh");
/// assert!(!text.is_empty());
/// ```
#[must_use]
pub fn encode(payload: &[u8]) -> String {
    let mut with_checksum = payload.to_vec();
    with_checksum.extend_from_slice(&checksum(payload));
    bs58::encode(with_checksum).into_string()
}

/// Decode `encoded` and verify its checksum, returning the payload alone.
///
/// `what` names the thing being decoded ("mesh identifier", "invite ticket")
/// so the three callers' error messages stay as specific as when each owned
/// its own copy.
///
/// # Errors
/// # Errors
/// [`Base58Error::Alphabet`] when `encoded` is not Base58, [`Base58Error::Short`]
/// when it is too short to carry a checksum, or [`Base58Error::Checksum`] when the
/// checksum does not match the payload.
///
/// # Examples
///
/// A text with a changed character fails its checksum, so a mistyped id is an error.
///
/// ```
/// use habilis_network_protocol::base58check::{decode, encode};
///
/// let text = encode(b"mesh");
/// assert_eq!(decode(&text, "mesh identifier").unwrap(), b"mesh");
///
/// let mut damaged = text.clone();
/// damaged.pop();
/// assert!(decode(&damaged, "mesh identifier").is_err());
/// ```
pub fn decode(encoded: &str, what: &str) -> Result<Vec<u8>, Base58Error> {
    let Ok(decoded) = bs58::decode(encoded).into_vec() else {
        return Err(Base58Error::Alphabet(what.to_owned()));
    };
    if decoded.len() < 4 {
        return Err(Base58Error::Short(what.to_owned()));
    }
    let (payload, received) = decoded.split_at(decoded.len() - 4);
    if received != checksum(payload) {
        return Err(Base58Error::Checksum(what.to_owned()));
    }
    Ok(payload.to_vec())
}

/// Read `N` bytes from `bytes` at `pos`, advancing it. `None` if short.
///
/// The cursor half of the same wire vocabulary: every ticket body here is a
/// sequence of fixed-width fields read in order.
///
/// # Examples
///
/// Each call reads the next fixed-width field and moves the cursor past it.
///
/// ```
/// use habilis_network_protocol::base58check::take_array;
///
/// let bytes = [1, 2, 3, 4, 5];
/// let mut position = 0;
/// let first: Option<[u8; 2]> = take_array(&bytes, &mut position);
/// assert_eq!(first, Some([1, 2]));
/// assert_eq!(position, 2);
/// ```
pub fn take_array<const N: usize>(bytes: &[u8], position: &mut usize) -> Option<[u8; N]> {
    let slice = bytes.get(*position..position.checked_add(N)?)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    *position += N;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, take_array};

    #[test]
    fn round_trips_a_payload() {
        let _guard = ::habilis_network_test_tracing::init();
        let payload = b"the quick brown fox";
        let encoded = encode(payload);
        assert_eq!(
            decode(&encoded, "test value")
                .expect("the encoded value was just produced by encode, so it decodes"),
            payload,
            "a payload round trips through base58"
        );
    }

    #[test]
    fn round_trips_an_empty_payload() {
        let _guard = ::habilis_network_test_tracing::init();
        let encoded = encode(b"");
        let empty: Vec<u8> = Vec::new();
        assert_eq!(
            decode(&encoded, "test value")
                .expect("the encoded value was just produced by encode, so it decodes"),
            empty,
            "an empty payload round trips through base58"
        );
    }

    #[test]
    fn rejects_a_flipped_payload_byte() {
        let _guard = ::habilis_network_test_tracing::init();
        let encoded = encode(b"the quick brown fox");
        // Swap one character for another valid Base58 one, so the failure is the
        // checksum rather than the alphabet.
        let mut chars: Vec<char> = encoded.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();

        let error = decode(&tampered, "test value")
            .expect_err("the tampered text has a character outside the Base58 alphabet, so decoding is refused")
            .to_string();
        assert!(
            error.contains("checksum") || error.contains("too short"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_non_base58() {
        let _guard = ::habilis_network_test_tracing::init();
        // `0`, `O`, `I` and `l` are the four characters Base58 omits.
        let error = decode("0OIl", "test value")
            .expect_err("the literal has the characters 0, O, I and l, which Base58 refuses")
            .to_string();
        assert!(
            error.contains("invalid Base58"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_a_string_too_short_to_hold_a_checksum() {
        let _guard = ::habilis_network_test_tracing::init();
        // "2" decodes to a single byte, fewer than the 4 a checksum needs.
        let error = decode("2", "test value")
            .expect_err("the literal is a single character that is not a whole Base58 value, so decoding is refused")
            .to_string();
        assert!(error.contains("too short"), "unexpected error: {error}");
    }

    #[test]
    fn the_error_names_what_failed() {
        let _guard = ::habilis_network_test_tracing::init();
        let error = decode("0OIl", "invite ticket")
            .expect_err("the literal has the characters 0, O, I and l, which Base58 refuses")
            .to_string();
        assert!(error.contains("invite ticket"), "unexpected error: {error}");
    }

    #[test]
    fn take_array_walks_a_cursor() {
        let _guard = ::habilis_network_test_tracing::init();
        let bytes = [1u8, 2, 3, 4, 5];
        let mut position = 0;
        let first: Option<[u8; 2]> = take_array(&bytes, &mut position);
        assert_eq!(
            first,
            Some([1, 2]),
            "take_array returns the first two bytes and moves the cursor"
        );
        assert_eq!(position, 2, "the cursor is at two after the first take");
        let second: Option<[u8; 3]> = take_array(&bytes, &mut position);
        assert_eq!(
            second,
            Some([3, 4, 5]),
            "take_array returns the next three bytes"
        );
        assert_eq!(position, 5, "the cursor is at five after the second take");
        let past_end: Option<[u8; 1]> = take_array(&bytes, &mut position);
        assert_eq!(past_end, None, "a take past the end returns none");
    }

    #[test]
    fn take_array_does_not_overflow_on_a_huge_cursor() {
        let _guard = ::habilis_network_test_tracing::init();
        let bytes = [1u8, 2, 3];
        let mut position = usize::MAX;
        let taken: Option<[u8; 4]> = take_array(&bytes, &mut position);
        assert_eq!(taken, None, "a huge cursor does not overflow the take");
    }
}
