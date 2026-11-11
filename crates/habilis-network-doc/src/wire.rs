//! The sealed channel body: the encrypted form of a `state` or `meta` slice body.
//!
//! A sealed body is the tagged envelope `{"k":"enc","d":"<base58>"}`. Its `d` is the Base58 of
//! `seal_symmetric(channel_key, plaintext)`, so a relay or a captured frame sees only opaque bytes.
//! A passwordless mesh passes a plain body through; a passworded mesh refuses one.

use serde::{Deserialize, Serialize};

use habilis_network_protocol::SymmetricKey;

use crate::DocError;
use habilis_network_protocol::messages::MessageBody;

use habilis_network_protocol::seal_error;

/// The tagged envelope of a sealed channel body.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
enum SealedBody {
    /// An encrypted channel body (password-protected mesh only): `d` is Base58
    /// of `seal_symmetric(channel_key, plaintext)`.
    Enc {
        #[serde(rename = "d")]
        data: String,
    },
}

/// Seal a plain body under `key`, and wrap the Base58 of the sealed bytes in the `enc` envelope.
///
/// # Errors
/// The envelope does not encode, or the sealed body exceeds the size limit.
///
/// # Examples
///
/// A sealed body does not open without its key.
///
/// ```
/// use habilis_network_doc::wire::{decrypt_body, encrypt_body};
/// use habilis_network_protocol::MessageBody;
/// use habilis_network_protocol::SymmetricKey;
///
/// let key = SymmetricKey::from([9u8; 32]);
/// let plain = MessageBody::try_new("hello").expect("a body");
/// let sealed = encrypt_body(&plain, &key).expect("a sealed body");
/// assert_eq!(decrypt_body(sealed.as_str(), Some(&key)).as_deref(), Some("hello"));
/// ```
pub fn encrypt_body(plain: &MessageBody, key: &SymmetricKey) -> Result<MessageBody, DocError> {
    let blob = seal_error::seal_symmetric(key, plain.as_str().as_bytes());
    let json = serde_json::to_string(&SealedBody::Enc {
        data: bs58::encode(blob).into_string(),
    })
    .map_err(DocError::encode)?;
    Ok(MessageBody::try_new(&json)?)
}

/// The escaped length of the sealed body that [`encrypt_body`] makes for a plain body of `plain_len`
/// bytes, at the longest Base58 text that the blob can take.
///
/// A seal draws a fresh nonce, and the Base58 text of one blob can be a byte or two shorter or longer
/// than the text of the next blob of the same length. A caller that checks a size needs one number,
/// so it takes this bound.
pub(crate) fn sealed_body_len_bound(plain_len: usize) -> usize {
    // The blob is the 12-byte nonce, the ciphertext, and the 16-byte tag. Base58 takes at most
    // 1.3657 characters per byte, and 138 percent is the bound used here.
    const NONCE_AND_TAG: usize = 12 + 16;
    let blob_len = plain_len + NONCE_AND_TAG;
    let longest_text = "1".repeat(blob_len * 138 / 100 + 1);
    let body = serde_json::to_string(&SealedBody::Enc { data: longest_text }).unwrap_or_default();
    serde_json::to_string(&body).map_or(usize::MAX, |escaped| escaped.len())
}

/// Recover the plaintext body string. With a `key` (passworded mesh) the body
/// **must** be a sealed `enc` envelope: it is opened, and any other body is
/// rejected (`None`) so cleartext can never slip past the encryption guarantee.
/// Without a key (passwordless) a body is returned unchanged. `None` also when
/// an `enc` body can't be opened (wrong key / malformed) — the caller treats a
/// `None` as an opaque no-op.
///
/// # Examples
///
/// An encrypted body does not open without its key.
///
/// ```
/// use habilis_network_doc::wire::{decrypt_body, encrypt_body};
/// use habilis_network_protocol::MessageBody;
/// use habilis_network_protocol::SymmetricKey;
///
/// let key = SymmetricKey::from([9u8; 32]);
/// let plain = MessageBody::try_new("hello").expect("a body");
/// let sealed = encrypt_body(&plain, &key).expect("a sealed body");
/// assert!(decrypt_body(sealed.as_str(), None).is_none());
/// ```
#[must_use]
pub fn decrypt_body(body: &str, key: Option<&SymmetricKey>) -> Option<String> {
    let op: Result<SealedBody, _> = serde_json::from_str(body);
    match op {
        Ok(SealedBody::Enc { data }) => {
            let key = key?;
            let blob = bs58::decode(&data).into_vec().ok()?;
            let plain = seal_error::open_symmetric(key, &blob).ok()?;
            String::from_utf8(plain).ok()
        }
        // A body that is not sealed: passthrough on a passwordless mesh (no key), but
        // rejected on a passworded one — encryption is enforced, not optional.
        _ => match key {
            Some(_) => None,
            None => Some(body.to_owned()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{decrypt_body, encrypt_body};
    use habilis_network_protocol::{MessageBody, SymmetricKey};

    fn key(byte: u8) -> SymmetricKey {
        SymmetricKey::from([byte; 32])
    }

    /// A plain slice body, as the store writes it.
    fn plain_body() -> MessageBody {
        MessageBody::try_new(r#"{"version":1,"value":{"board":"x"}}"#).expect("a slice body")
    }

    #[test]
    fn enc_body_round_trips_and_hides_the_value() {
        let _guard = ::habilis_network_test_tracing::init();
        let key = key(3);
        let plain = plain_body();
        let enc = encrypt_body(&plain, &key).expect("encrypt");
        assert_ne!(
            enc.as_str(),
            plain.as_str(),
            "wire body is not the plaintext"
        );
        assert!(
            !enc.as_str().contains("board"),
            "the value must not leak into the ciphertext body"
        );
        let recovered = decrypt_body(enc.as_str(), Some(&key)).expect("decrypt");
        assert_eq!(
            recovered,
            plain.as_str(),
            "an enc body round trips to the recovered plaintext"
        );
    }

    #[test]
    fn enc_body_needs_the_right_key() {
        let _guard = ::habilis_network_test_tracing::init();
        let enc =
            encrypt_body(&plain_body(), &key(1)).expect("the body encrypts under a fresh key");
        assert!(
            decrypt_body(enc.as_str(), Some(&key(2))).is_none(),
            "wrong key"
        );
        assert!(decrypt_body(enc.as_str(), None).is_none(), "no key");
    }

    #[test]
    fn decrypt_enforces_encryption_only_when_keyed() {
        let _guard = ::habilis_network_test_tracing::init();
        let plain = plain_body();
        // Passwordless (no key): a body that is not sealed is returned verbatim.
        assert_eq!(
            decrypt_body(plain.as_str(), None).as_deref(),
            Some(plain.as_str()),
            "decrypt enforces encryption only when keyed"
        );
        // Passworded (key set): a body that is not sealed is rejected — cleartext can't
        // slip past the encryption guarantee.
        assert!(
            decrypt_body(plain.as_str(), Some(&key(7))).is_none(),
            "a plain body is refused when keyed"
        );
    }
}
