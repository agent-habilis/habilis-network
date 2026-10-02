//! Base58Check: the encoding every bare identifier and ticket in this
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

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

/// The double-SHA-256 checksum, truncated to its first 4 bytes.
fn checksum(bytes: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(bytes);
    let second = Sha256::digest(first);
    let mut out = [0u8; 4];
    out.copy_from_slice(&second[..4]);
    out
}

/// Encode `payload` with its checksum appended.
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
/// `encoded` is not Base58, is too short to carry a checksum, or its checksum
/// does not match the payload.
pub fn decode(encoded: &str, what: &str) -> Result<Vec<u8>> {
    let Ok(decoded) = bs58::decode(encoded).into_vec() else {
        bail!("invalid Base58 in {what}");
    };
    if decoded.len() < 4 {
        bail!("{what} too short");
    }
    let (payload, received) = decoded.split_at(decoded.len() - 4);
    if received != checksum(payload) {
        bail!("invalid {what} checksum");
    }
    Ok(payload.to_vec())
}

/// Read `N` bytes from `bytes` at `pos`, advancing it. `None` if short.
///
/// The cursor half of the same wire vocabulary: every ticket body here is a
/// sequence of fixed-width fields read in order.
pub fn take_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> Option<[u8; N]> {
    let slice = bytes.get(*pos..pos.checked_add(N)?)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    *pos += N;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, take_array};

    #[test]
    fn round_trips_a_payload() {
        let payload = b"the quick brown fox";
        let encoded = encode(payload);
        assert_eq!(decode(&encoded, "test value").unwrap(), payload);
    }

    #[test]
    fn round_trips_an_empty_payload() {
        let encoded = encode(b"");
        assert_eq!(decode(&encoded, "test value").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn rejects_a_flipped_payload_byte() {
        let encoded = encode(b"the quick brown fox");
        // Swap one character for another valid Base58 one, so the failure is the
        // checksum rather than the alphabet.
        let mut chars: Vec<char> = encoded.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();

        let error = decode(&tampered, "test value").unwrap_err().to_string();
        assert!(
            error.contains("checksum") || error.contains("too short"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_non_base58() {
        // `0`, `O`, `I` and `l` are the four characters Base58 omits.
        let error = decode("0OIl", "test value").unwrap_err().to_string();
        assert!(
            error.contains("invalid Base58"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_a_string_too_short_to_hold_a_checksum() {
        // "2" decodes to a single byte, fewer than the 4 a checksum needs.
        let error = decode("2", "test value").unwrap_err().to_string();
        assert!(error.contains("too short"), "unexpected error: {error}");
    }

    #[test]
    fn the_error_names_what_failed() {
        let error = decode("0OIl", "invite ticket").unwrap_err().to_string();
        assert!(error.contains("invite ticket"), "unexpected error: {error}");
    }

    #[test]
    fn take_array_walks_a_cursor() {
        let bytes = [1u8, 2, 3, 4, 5];
        let mut pos = 0;
        assert_eq!(take_array::<2>(&bytes, &mut pos), Some([1, 2]));
        assert_eq!(pos, 2);
        assert_eq!(take_array::<3>(&bytes, &mut pos), Some([3, 4, 5]));
        assert_eq!(pos, 5);
        assert_eq!(take_array::<1>(&bytes, &mut pos), None);
    }

    #[test]
    fn take_array_does_not_overflow_on_a_huge_cursor() {
        let bytes = [1u8, 2, 3];
        let mut pos = usize::MAX;
        assert_eq!(take_array::<4>(&bytes, &mut pos), None);
    }
}
