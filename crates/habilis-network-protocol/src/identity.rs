//! Per-peer **identity**: the Ed25519 keypair that authenticates
//! every message this member authors.
//!
//! Distinct from the two other keys in the system: the transport
//! `EndpointId` (authenticates the *connection*) and the seed-derived
//! rendezvous key (shared by every member — see [`super::crypto`]). This
//! is the first **per-author** credential, and the root of
//! `docs/history-integrity.md`.
//!
//! The public key is the durable identity; the [`crate::Nickname`] is a display
//! label bound to it trust-on-first-use by the receiver.
//!
//! The key is currently **in-process / ephemeral** — minted once per
//! `create`/`join` and held in memory for the process lifetime. A process
//! restart therefore mints a *new* key, so under the same nickname it is
//! seen as a new identity (peers that pinned the old key flag it). Stable
//! cross-restart identity (on-disk persistence) is a documented follow-up;
//! see `docs/history-integrity.md`.

use std::fmt;

use anyhow::Result;
use iroh_base::{PublicKey, SecretKey, Signature};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::{AuthorKey, DedupKey, SymmetricKey};

/// A per-peer signing identity — just the secret key. The nickname
/// it speaks under is carried by the message `author` field and bound to
/// this key trust-on-first-use by receivers, so it is not stored here.
#[derive(Debug)]
pub struct Identity {
    secret: SecretKey,
}

impl Identity {
    /// Mint a fresh random identity. `SecretKey::from_bytes` is infallible
    /// — any 32 bytes is a valid Ed25519 secret.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Identity {
            secret: SecretKey::from_bytes(&bytes),
        }
    }

    #[must_use]
    pub fn public(&self) -> PublicKey {
        self.secret.public()
    }

    /// The public key as the author key of a message: what [`Message::sign`] puts in the
    /// message, and what a peer reads back from `Message::author_key`.
    ///
    /// [`Message::sign`]: crate::Message::sign
    #[must_use]
    pub fn author_key(&self) -> AuthorKey {
        AuthorKey::from_bytes(*self.public().as_bytes())
    }

    /// Sign `bytes` (the message's canonical bytes) with our secret.
    #[must_use]
    pub(crate) fn sign(&self, bytes: &[u8]) -> Signature {
        self.secret.sign(bytes)
    }

    /// Our static X25519 secret for sealing/unsealing directed frames, derived
    /// deterministically from the Ed25519 identity seed under a distinct label —
    /// so the signing key and the encryption key never coincide (no key reuse).
    #[must_use]
    pub fn seal_secret(&self) -> x25519_dalek::StaticSecret {
        // Two bare arrays on the stack are not wiped, and we do not control either: the one that
        // iroh's `to_bytes()` returns, and the one that `StaticSecret::from` takes by value below.
        // Between them the bytes sit in a buffer that wipes itself on drop.
        let identity_seed =
            SymmetricKey::from_zeroizing(zeroize::Zeroizing::new(self.secret.to_bytes()));
        x25519_dalek::StaticSecret::from(*identity_seed.derive(SEAL_ENC_LABEL).as_bytes())
    }

    /// The X25519 public key peers seal to us with — published in our card.
    #[must_use]
    pub fn seal_public(&self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(&self.seal_secret())
    }
}

/// KDF label deriving the X25519 encryption key from the Ed25519 identity seed —
/// distinct from every other `derive_secret` label so the keys stay independent.
const SEAL_ENC_LABEL: &[u8] = b"habilis-mesh/x25519-enc/v1";

/// Verify `signature` over `bytes` against `pubkey`. A malformed or
/// non-matching signature returns `false` (never panics).
#[must_use]
pub(crate) fn verify(pubkey: &PublicKey, bytes: &[u8], signature: &Signature) -> bool {
    pubkey.verify(bytes, signature).is_ok()
}

/// A 16-byte dedup / anti-entropy key binding an author's public key to a
/// message id: `SHA-256(pubkey ‖ id)[..16]`. Dedup and the digest key on
/// this, not the bare id, so a peer that signs its own message under a
/// **victim's** id produces a different key — it can no longer suppress the
/// victim's genuine message (they hash apart) or hide it from anti-entropy.
/// 16 bytes keeps the digest wire format unchanged; binding the pubkey (not
/// the content) preserves the fresh-id re-announce path (a new id ⇒ a new
/// key ⇒ not falsely deduped).
#[must_use]
pub(crate) fn dedup_key16(author: Option<&AuthorKey>, id_bytes: &[u8; 16]) -> DedupKey {
    let mut hasher = Sha256::new();
    // The hex text of the key, as the signed bytes carry it; nothing for an unsigned message.
    if let Some(author) = author {
        hasher.update(author.hex());
    }
    hasher.update(id_bytes);
    let digest = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    DedupKey::from_bytes(key)
}

// ── wire encoding ──────────────────────────────────────────────────────
//
// Public keys (32 bytes) and signatures (64 bytes) travel as lowercase
// hex strings in the JSON envelope, so the `--output json` wire stays
// inspectable and does not depend on iroh's serde representation.

#[must_use]
pub fn encode_pubkey(pubkey: &PublicKey) -> String {
    to_hex(pubkey.as_bytes())
}

/// Parse a hex Ed25519 signature (64 bytes) from the wire.
pub(crate) fn decode_sig(hex: &str) -> Result<Signature> {
    let bytes: [u8; 64] = from_hex(hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    Ok(Signature::from_bytes(&bytes))
}

/// Lowercase hex of `bytes`, the spelling the wire uses for keys and signatures.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    to_hex(bytes)
}

/// Write `bytes` into `formatter` as lowercase hex, so that a `Display` for a byte-array newtype is
/// one call.
///
/// # Errors
/// The formatter fails.
pub fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// The 32 bytes of a 64-character lowercase hex string, the one spelling the wire carries for a
/// key or a hash. `None` for any other length, an uppercase digit, or a non-hex character.
pub(crate) fn decode_lower_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let mut bytes = [0u8; 32];
    for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(bytes)
}

/// The 64 ASCII bytes of the lowercase hex of `bytes`, on the stack.
pub(crate) fn encode_lower_hex_32(bytes: &[u8; 32]) -> [u8; 64] {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = [0u8; 64];
    for (pair, byte) in text.chunks_exact_mut(2).zip(bytes) {
        pair[0] = DIGITS[usize::from(byte >> 4)];
        pair[1] = DIGITS[usize::from(byte & 0x0f)];
    }
    text
}

/// The bytes of a hex string, either case; `None` for odd length or a non-hex
/// digit.
#[must_use]
pub fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    from_hex(hex).ok()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble < 16"));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("nibble < 16"));
    }
    out
}

fn from_hex(hex: &str) -> Result<Vec<u8>> {
    // Operate on raw bytes, not `&str` slices: an attacker-controlled
    // `pubkey`/`sig` is arbitrary UTF-8, and byte-indexing a `&str`
    // (`&hex[i..i+2]`) panics if `i` lands inside a multibyte char. Decoding
    // each ASCII nibble from bytes is panic-free — any non-hex byte (including
    // a continuation byte) is a graceful `Err`.
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        anyhow::bail!("hex string has odd length");
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

/// Decode one lowercase/uppercase ASCII hex digit byte to its 0..=15 value.
fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => anyhow::bail!("invalid hex digit"),
    }
}

#[cfg(test)]
mod tests {
    use super::{Identity, decode_sig, dedup_key16, encode_hex, encode_pubkey, verify};
    use crate::AuthorKey;

    #[test]
    fn sign_verify_round_trip() {
        let identity = Identity::generate();
        let bytes = b"canonical message bytes";
        let sig = identity.sign(bytes);
        assert!(verify(&identity.public(), bytes, &sig));
    }

    #[test]
    fn tampered_bytes_fail_verification() {
        let identity = Identity::generate();
        let sig = identity.sign(b"original");
        assert!(!verify(&identity.public(), b"tampered", &sig));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signer = Identity::generate();
        let other = Identity::generate();
        let bytes = b"hello";
        let sig = signer.sign(bytes);
        assert!(!verify(&other.public(), bytes, &sig));
    }

    #[test]
    fn pubkey_hex_round_trip() {
        let identity = Identity::generate();
        let hex = encode_pubkey(&identity.public());
        assert_eq!(hex.len(), 64);
        let key = AuthorKey::from_hex(&hex).unwrap();
        assert_eq!(key.public_key(), Some(identity.public()));
    }

    #[test]
    fn sig_hex_round_trip() {
        let identity = Identity::generate();
        let sig = identity.sign(b"x");
        let hex = encode_hex(&sig.to_bytes());
        assert_eq!(hex.len(), 128);
        assert!(verify(&identity.public(), b"x", &decode_sig(&hex).unwrap()));
    }

    /// Golden: the key is `SHA-256(pubkey text ‖ id bytes)[..16]`. The unsigned form hashes an
    /// empty pubkey text. The values were captured at the base commit.
    #[test]
    fn dedup_key16_is_pinned_for_a_fixed_pubkey_and_id() {
        let pubkey = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
        let mut id = [0u8; 16];
        id[15] = 1;
        assert_eq!(
            encode_hex(dedup_key16(AuthorKey::from_hex(pubkey).as_ref(), &id).as_bytes()),
            "c7ba26a2ed0d21f0e8913dd8b4456086"
        );
        assert_eq!(
            encode_hex(dedup_key16(None, &id).as_bytes()),
            "7c3ccd10bb7ec37b46d37926ae627426"
        );
    }

    /// The seal key is the same key as before the secret went through a wiped key: the
    /// derivation of the plain bytes under the same label.
    #[test]
    fn the_seal_secret_is_the_derivation_of_the_identity_seed() {
        let identity = Identity::generate();
        let by_hand = x25519_dalek::StaticSecret::from(*crate::crypto::derive_secret(
            &identity.secret.to_bytes(),
            super::SEAL_ENC_LABEL,
        ));
        assert_eq!(identity.seal_secret().to_bytes(), by_hand.to_bytes());
        assert_eq!(
            identity.seal_public(),
            x25519_dalek::PublicKey::from(&by_hand)
        );
    }

    #[test]
    fn write_hex_writes_the_same_text_as_encode_hex() {
        struct Hex<'a>(&'a [u8]);
        impl std::fmt::Display for Hex<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                super::write_hex(f, self.0)
            }
        }
        let bytes = [0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(Hex(&bytes).to_string(), "000fa5ff");
        assert_eq!(Hex(&bytes).to_string(), encode_hex(&bytes));
    }

    #[test]
    fn decode_rejects_bad_hex() {
        assert!(AuthorKey::from_hex("zz").is_none());
        assert!(AuthorKey::from_hex("abc").is_none()); // odd length
        assert!(decode_sig("00").is_err()); // wrong length
    }

    #[test]
    fn decode_rejects_non_ascii_hex_without_panicking() {
        // Regression: an inbound `pubkey`/`sig` is arbitrary UTF-8. A
        // multibyte char of even *byte* length (here `aéa` = 0x61 C3 A9 0x61,
        // 4 bytes) positioned so a 2-byte slice splits it used to panic on a
        // non-char-boundary slice — a one-message remote DoS reachable from
        // `verify_signature`. It must now decode byte-wise and return `Err`.
        assert!(AuthorKey::from_hex("aéa").is_none());
        assert!(decode_sig("aéa").is_err());
        // Pure multibyte input of even byte length, too.
        assert!(AuthorKey::from_hex("€€").is_none()); // 6 bytes, all continuation/non-hex
    }
}
