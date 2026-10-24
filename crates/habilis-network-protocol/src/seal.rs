//! End-to-end sealing of a directed frame body: a NaCl-sealed-box-style
//! construction so only the addressed recipient can read it. A relay still
//! forwards the frame and verifies its Ed25519 signature (which covers the
//! ciphertext), but cannot open it.
//!
//! Construction: a fresh **ephemeral** X25519 keypair per frame → ECDH with the
//! recipient's static X25519 public key → the shared secret is run through the
//! in-tree `derive_secret` KDF (SHA-256, domain-separated) into a 32-byte AEAD
//! key → ChaCha20-Poly1305. The ephemeral public key travels in the envelope, so
//! the recipient (holding the static secret) can re-derive the shared secret;
//! nobody else can. The ephemeral key gives forward secrecy; **sender
//! authenticity comes from the frame's Ed25519 signature**, not the box.
//!
//! The envelope is a small JSON object with Base58 fields, so it is a valid
//! [`MessageBody`] (UTF-8, no control characters).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::MessageBody;
use super::crypto::{SymmetricKey, derive_secret};

/// KDF label separating the seal key from every other seed-derived secret, and
/// the AEAD associated data (bound into the tag).
const SEAL_LABEL: &[u8] = b"habilis-mesh/seal/v1";

/// AEAD associated data (construction tag) for the symmetric channel seal. The
/// key is already domain-separated by the caller (a `derive_secret` channel
/// label), so this only pins the construction version.
const SYM_AAD: &[u8] = b"habilis-mesh/sym/v1";

/// Envelope construction tag — bumped only on a breaking crypto change.
const ENVELOPE_VERSION: &str = "x25519-chacha20poly1305/1";

/// A sealed payload: the ephemeral X25519 public key, the AEAD nonce, and the
/// ciphertext (with the 16-byte Poly1305 tag appended by the AEAD).
struct Sealed {
    epk: [u8; 32],
    nonce: [u8; 12],
    ct: Vec<u8>,
}

/// The on-wire JSON form of a [`Sealed`] — Base58 fields keep it MessageBody-safe.
#[derive(Serialize, Deserialize)]
struct Envelope {
    #[serde(rename = "v")]
    version: String,
    epk: String,
    #[serde(rename = "n")]
    nonce: String,
    ct: String,
}

/// Why a seal does not open, or a sealed body does not decode.
#[derive(Debug)]
#[non_exhaustive]
pub enum SealError {
    /// The seal does not open, or a fixed check failed. The text says which.
    Failed(&'static str),
    /// The envelope names a version this build does not read.
    UnsupportedVersion(String),
    /// A value does not have the shape the seal needs.
    Invalid(String),
    /// A field does not decode.
    Source {
        /// The step that failed, for example `bad nonce`.
        step: &'static str,
        /// The error of the decoder.
        source: Box<dyn Error + Send + Sync>,
    },
}

impl SealError {
    fn source<E>(step: &'static str) -> impl FnOnce(E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        move |source| Self::Source {
            step,
            source: source.into(),
        }
    }
}

impl fmt::Display for SealError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(text) => formatter.write_str(text),
            Self::Invalid(text) => formatter.write_str(text),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported seal envelope version: {version}")
            }
            Self::Source { step, .. } => formatter.write_str(step),
        }
    }
}

impl Error for SealError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source { source, .. } => Some(source.as_ref()),
            Self::Failed(_) | Self::UnsupportedVersion(_) | Self::Invalid(_) => None,
        }
    }
}

/// Seal `plaintext` to `recipient_pub`. Infallible in practice — the only
/// fallible step is AEAD encryption, which cannot fail for a well-formed
/// key/nonce.
fn seal(recipient_pub: &PublicKey, plaintext: &[u8]) -> Sealed {
    let mut eph_bytes = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *eph_bytes);
    let ephemeral = StaticSecret::from(*eph_bytes);
    let epk = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(recipient_pub);

    let key = derive_secret(shared.as_bytes(), SEAL_LABEL);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: SEAL_LABEL,
            },
        )
        .expect("ChaCha20-Poly1305 encryption cannot fail for a valid key/nonce");
    Sealed {
        epk: *epk.as_bytes(),
        nonce,
        ct,
    }
}

/// Open a [`Sealed`] with our static X25519 secret.
///
/// # Errors
/// The AEAD fails to authenticate — a wrong recipient key or a tampered
/// ciphertext/nonce.
fn unseal(our_secret: &StaticSecret, sealed: &Sealed) -> Result<Vec<u8>, SealError> {
    let shared = our_secret.diffie_hellman(&PublicKey::from(sealed.epk));
    let key = derive_secret(shared.as_bytes(), SEAL_LABEL);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
    cipher
        .decrypt(
            Nonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ct,
                aad: SEAL_LABEL,
            },
        )
        .map_err(|_| SealError::Failed("unseal failed: wrong recipient key or tampered ciphertext"))
}

/// Seal `plaintext` (a serialized application payload) to `recipient_pub`, returning the
/// envelope as a [`MessageBody`] ready to drop into a directed frame.
///
/// # Errors
/// The envelope (pure ASCII JSON) somehow fails `MessageBody` validation.
///
/// # Panics
/// If `Envelope` fails to serialize. Its fields are `String`s and a version
/// tag, so serialization cannot fail short of an allocator failure.
pub fn seal_to_body(recipient_pub: &PublicKey, plaintext: &str) -> Result<MessageBody, SealError> {
    let sealed = seal(recipient_pub, plaintext.as_bytes());
    let envelope = Envelope {
        version: ENVELOPE_VERSION.to_string(),
        epk: bs58::encode(sealed.epk).into_string(),
        nonce: bs58::encode(sealed.nonce).into_string(),
        ct: bs58::encode(sealed.ct).into_string(),
    };
    let json = serde_json::to_string(&envelope).expect("Envelope always serializes");
    MessageBody::new(json).map_err(|error| SealError::Invalid(error.to_string()))
}

/// Open a sealed directed `body` with our static X25519 secret, recovering the
/// plaintext application payload string.
///
/// # Errors
/// The body is not a sealed envelope, has an unknown version, carries malformed
/// Base58, or fails to decrypt/authenticate.
pub fn unseal_from_body(
    our_secret: &StaticSecret,
    body: &MessageBody,
) -> Result<String, SealError> {
    let envelope: Envelope = serde_json::from_str(body.as_str())
        .map_err(SealError::source("body is not a sealed envelope"))?;
    if envelope.version != ENVELOPE_VERSION {
        return Err(SealError::UnsupportedVersion(envelope.version));
    }
    let epk = decode_array::<32>(&envelope.epk).map_err(SealError::source("bad ephemeral key"))?;
    let nonce = decode_array::<12>(&envelope.nonce).map_err(SealError::source("bad nonce"))?;
    let ct = bs58::decode(&envelope.ct)
        .into_vec()
        .map_err(SealError::source("bad ciphertext"))?;
    let plaintext = unseal(our_secret, &Sealed { epk, nonce, ct })?;
    String::from_utf8(plaintext).map_err(SealError::source("decrypted payload is not valid UTF-8"))
}

fn decode_array<const N: usize>(encoded: &str) -> Result<[u8; N], SealError> {
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(SealError::source("invalid Base58"))?;
    bytes
        .try_into()
        .map_err(|_| SealError::Invalid(format!("expected {N} bytes")))
}

/// Symmetrically seal `plaintext` under a pre-shared `key` (a
/// mesh-password-derived channel key). Layout: `nonce(12) ‖ ct+tag`. Unlike
/// [`seal_to_body`] there is no ECDH — every holder of `key` can open it, which
/// is exactly the shared-channel (state/meta) model: membership already gated
/// the password, and this keeps the payload unreadable to a relay or a captured
/// frame.
#[must_use]
/// # Panics
/// Never in practice: ChaCha20-Poly1305 encryption cannot fail for a valid
/// key/nonce pair, and both are constructed here.
pub fn seal_symmetric(key: &SymmetricKey, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: SYM_AAD,
            },
        )
        .expect("ChaCha20-Poly1305 encryption cannot fail for a valid key/nonce");
    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Open a [`seal_symmetric`] blob with the same `key`.
///
/// # Errors
/// The blob is too short to carry a nonce, or the AEAD fails to authenticate (a
/// wrong key or tampered bytes).
pub fn open_symmetric(key: &SymmetricKey, blob: &[u8]) -> Result<Vec<u8>, SealError> {
    if blob.len() < 12 {
        return Err(SealError::Failed("symmetric blob too short for a nonce"));
    }
    let (nonce, ct) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: SYM_AAD,
            },
        )
        .map_err(|_| SealError::Failed("symmetric open failed: wrong key or tampered ciphertext"))
}

#[cfg(test)]
mod tests {
    use super::{open_symmetric, seal_symmetric, seal_to_body, unseal_from_body};
    use crate::crypto::SymmetricKey;
    use habilis_network_test_tracing::test;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn key(byte: u8) -> SymmetricKey {
        SymmetricKey::from_bytes([byte; 32])
    }

    #[test]
    fn symmetric_round_trips() {
        let key = key(7);
        for plaintext in [b"".as_slice(), b"hello state doc", &[0u8; 5000]] {
            let blob = seal_symmetric(&key, plaintext);
            assert_ne!(
                blob.as_slice(),
                plaintext,
                "ciphertext is not the plaintext"
            );
            assert_eq!(open_symmetric(&key, &blob).unwrap(), plaintext);
        }
    }

    #[test]
    fn symmetric_wrong_key_or_tamper_fails() {
        let blob = seal_symmetric(&key(1), b"the shared state");
        assert!(
            open_symmetric(&key(2), &blob).is_err(),
            "a wrong key must not open the blob"
        );
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(
            open_symmetric(&key(1), &tampered).is_err(),
            "a flipped byte must fail the AEAD tag"
        );
        assert!(
            open_symmetric(&key(1), &[0u8; 4]).is_err(),
            "a blob too short for a nonce must fail cleanly"
        );
    }

    fn keypair(byte: u8) -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::from([byte; 32]);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    #[test]
    fn round_trips_to_the_recipient() {
        let (secret, public) = keypair(1);
        let plaintext = r#"{"kind":"status-update","taskId":"7f3e"}"#;
        let body = seal_to_body(&public, plaintext).unwrap();
        assert_eq!(unseal_from_body(&secret, &body).unwrap(), plaintext);
    }

    /// Golden: an envelope captured at the base commit opens to its plaintext. The nonce and the
    /// ephemeral key are random on seal, so this pins the open path and the envelope shape, and
    /// there is no golden for the seal path.
    #[test]
    fn a_fixed_envelope_opens_to_its_plaintext() {
        let (secret, _public) = keypair(1);
        let body = crate::MessageBody::new(
            concat!(
                r#"{"v":"x25519-chacha20poly1305/1","#,
                r#""epk":"EuHtd9yCn95edmJqLKFeyXeoPw9nPzp1HTwdJEWEw9YL","#,
                r#""n":"AtaLN3mCmEyUj5ur","#,
                r#""ct":"79cUk28wvxuqaGBndLf5927gRbiTXuUAaSgPKp2Sho86SQcf1iSKCvXJnj9gvLrpDjSoUarapYeiR"}"#,
            )
            .to_owned(),
        )
        .unwrap();
        assert_eq!(
            unseal_from_body(&secret, &body).unwrap(),
            r#"{"kind":"status-update","taskId":"7f3e"}"#
        );
    }

    #[test]
    fn a_wrong_recipient_cannot_open_it() {
        let (_recipient, recipient_pub) = keypair(1);
        let (eavesdropper, _) = keypair(2);
        let body = seal_to_body(&recipient_pub, "secret").unwrap();
        assert!(
            unseal_from_body(&eavesdropper, &body).is_err(),
            "a non-recipient must not be able to open the envelope"
        );
    }

    #[test]
    fn a_tampered_ciphertext_fails() {
        let (secret, public) = keypair(3);
        let body = seal_to_body(&public, "the quick brown fox").unwrap();
        // Flip the last Base58 char of the `ct` field.
        let mut json: serde_json::Value = serde_json::from_str(body.as_str()).unwrap();
        let ct = json["ct"].as_str().unwrap().to_owned();
        let mut chars: Vec<char> = ct.chars().collect();
        let last = chars.last_mut().unwrap();
        *last = if *last == '1' { '2' } else { '1' };
        json["ct"] = serde_json::Value::String(chars.into_iter().collect());
        let tampered = crate::MessageBody::new(json.to_string()).unwrap();
        assert!(
            unseal_from_body(&secret, &tampered).is_err(),
            "a tampered ciphertext must fail the AEAD tag"
        );
    }

    #[test]
    fn seals_empty_and_large_payloads() {
        let (secret, public) = keypair(4);
        for plaintext in ["", &"x".repeat(40_000)] {
            let body = seal_to_body(&public, plaintext).unwrap();
            assert_eq!(unseal_from_body(&secret, &body).unwrap(), plaintext);
        }
    }

    #[test]
    fn a_plaintext_body_does_not_open_as_sealed() {
        let (secret, _) = keypair(5);
        let body = crate::MessageBody::new(r#"{"kind":"message"}"#.to_owned()).unwrap();
        assert!(
            unseal_from_body(&secret, &body).is_err(),
            "an un-sealed body must not be mistaken for an envelope"
        );
    }
}
