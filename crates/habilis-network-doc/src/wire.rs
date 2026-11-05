//! The `state`/`meta` channel wire body: the tagged envelope that carries one
//! automerge change (or, from an old binary, a legacy RFC 7386 merge the
//! automerge engine treats as a no-op). The convergent document itself — merge,
//! authorization, and reconciliation — lives in the parent module.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;

use habilis_network_protocol::SymmetricKey;

use crate::DocError;
use habilis_network_protocol::messages::MessageBody;

use habilis_network_protocol::seal_error;
/// What the root frame of a state seed says about the chain that it starts: how many frames the
/// chain has, the root included, and the hash of the last change (hex). A node adopts a seed only
/// when it holds a chain that matches this mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SeedMark {
    /// The number of frames of the chain, the root included.
    #[serde(rename = "n")]
    pub frames: u32,
    /// The hash of the last change of the chain, in hex.
    #[serde(rename = "l")]
    pub last: String,
}

impl SeedMark {
    /// A mark for a chain of `frames` frames whose last change has the hash `last`, in hex.
    #[must_use]
    pub fn new(frames: u32, last: String) -> Self {
        Self { frames, last }
    }
}

/// A change body, read back: the change bytes, the epoch, and the seed mark of a seed root.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParsedChange {
    /// The automerge change bytes.
    pub bytes: Vec<u8>,
    /// The epoch of the change, 0 when the body has none.
    pub epoch: u64,
    /// The mark of a seed root, `None` for any other change.
    pub seed: Option<SeedMark>,
}

/// The tagged `State`/`Meta` message body.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
enum StateOp<'merge> {
    /// The live wire form: one automerge change, Base58-encoded so the body stays
    /// `MessageBody`-safe (wire key `c`), plus an optional `m` carrying the
    /// RFC 7386 merge the author applied — the human-readable delta the
    /// `state`/`meta` output event surfaces (the change bytes themselves are
    /// opaque). Omitted for internal writes that are never surfaced (the card
    /// publish), so those stay lean.
    Change {
        #[serde(rename = "c")]
        data: String,
        #[serde(rename = "m", default, skip_serializing_if = "Option::is_none")]
        merge: Option<Cow<'merge, Value>>,
        /// The epoch of the history this change belongs to (wire key `e`). Left out at 0, so a
        /// body of epoch 0 is the body from before epochs.
        #[serde(rename = "e", default, skip_serializing_if = "Option::is_none")]
        epoch: Option<u64>,
        /// The mark of a state seed root (wire key `s`). Left out of every other body.
        #[serde(rename = "s", default, skip_serializing_if = "Option::is_none")]
        seed: Option<SeedMark>,
    },
    /// The pre-automerge RFC 7386 merge shape. Retained only so a body still
    /// composes for the adversarial harness; the automerge engine ignores it (a
    /// no-op), which is the forward-compat behavior an old binary now hits.
    Merge { merge: Value },
    /// An encrypted channel body (password-protected mesh only): `d` is Base58
    /// of `seal_symmetric(channel_key, plaintext)`, where `plaintext` is the
    /// UTF-8 bytes of a plaintext `change` body — so neither the automerge
    /// change nor the human-readable `m` delta is exposed on the wire. A relay
    /// or a captured frame (no key) sees only opaque bytes; every mesh member
    /// holds the key and decrypts. See [`encrypt_body`]/[`decrypt_body`].
    Enc {
        #[serde(rename = "d")]
        data: String,
    },
}

/// Compose a legacy RFC 7386 merge body. Only the adversarial harness and tests
/// emit this now (the live path uses [`change_body`]); a receiver treats it as a
/// no-op.
///
/// # Errors
/// Serialization failure or a body exceeding the size limit.
///
/// # Examples
///
/// A merge body is not a change, so it carries no change bytes.
///
/// ```
/// use habilis_network_doc::wire::{merge_body, parse_change_body};
///
/// let body = merge_body(serde_json::json!({"title": "hi"})).expect("a merge body");
/// assert!(parse_change_body(body.as_str()).is_none());
/// ```
#[cfg(any(test, feature = "adversarial"))]
pub fn merge_body(merge: Value) -> Result<MessageBody, DocError> {
    let json = serde_json::to_string(&StateOp::Merge { merge }).map_err(DocError::encode)?;
    Ok(MessageBody::try_new(&json)?)
}

/// Wrap one automerge change's raw bytes as a channel-event body. `merge` is the
/// RFC 7386 delta the author applied, carried for the output event's
/// human-readable `merge` field; pass `None` for an internal write that is never
/// surfaced (keeps the body lean — no delta duplicated alongside the change).
///
/// # Errors
/// Serialization failure or a body exceeding the size limit.
///
/// # Examples
///
/// A change body carries its change bytes, and they read back unchanged.
///
/// ```
/// use habilis_network_doc::wire::{change_body, parse_change_body};
///
/// let body = change_body(&[1, 2], None).expect("a change body");
/// assert_eq!(parse_change_body(body.as_str()), Some(vec![1, 2]));
/// ```
pub fn change_body(change: &[u8], merge: Option<&Value>) -> Result<MessageBody, DocError> {
    change_body_at(change, merge, 0)
}

/// [`change_body`] for a change of `epoch`. Epoch 0 adds nothing to the body, so its bytes are
/// those of a body from before the epoch existed.
///
/// # Errors
/// Serialization failure or a body exceeding the size limit.
pub fn change_body_at(
    change: &[u8],
    merge: Option<&Value>,
    epoch: u64,
) -> Result<MessageBody, DocError> {
    change_body_seed(change, merge, epoch, None)
}

/// [`change_body_at`] for the root of a state seed, which carries the `seed` mark of its chain.
///
/// # Errors
/// Serialization failure or a body exceeding the size limit.
pub fn change_body_seed(
    change: &[u8],
    merge: Option<&Value>,
    epoch: u64,
    seed: Option<&SeedMark>,
) -> Result<MessageBody, DocError> {
    let tagged: Option<u64> = (epoch != 0).then_some(epoch);
    let mark: Option<SeedMark> = seed.cloned();
    let json = serde_json::to_string(&StateOp::Change {
        data: bs58::encode(change).into_string(),
        merge: merge.map(Cow::Borrowed),
        epoch: tagged,
        seed: mark,
    })
    .map_err(DocError::encode)?;
    Ok(MessageBody::try_new(&json)?)
}

/// Decode a channel-event body back to raw automerge change bytes. `None` for a
/// non-`change` body (a legacy `merge`, an `enc` envelope, or anything that
/// doesn't parse) — such a body is a no-op on the automerge doc. Call
/// [`decrypt_body`] first for a passworded mesh's `enc` bodies.
///
/// # Examples
///
/// A change body reads back to the change bytes it carries.
///
/// ```
/// use habilis_network_doc::wire::{change_body, parse_change_body};
///
/// let body = change_body(&[1, 2], None).expect("a change body");
/// assert_eq!(parse_change_body(body.as_str()), Some(vec![1, 2]));
/// ```
#[must_use]
pub fn parse_change_body(body: &str) -> Option<Vec<u8>> {
    parse_change(body).map(|(bytes, _)| bytes)
}

/// [`parse_change_body`] with the epoch of the change. A body with no epoch reads as epoch 0.
#[must_use]
pub fn parse_change(body: &str) -> Option<(Vec<u8>, u64)> {
    parse_change_full(body).map(|parsed| (parsed.bytes, parsed.epoch))
}

/// [`parse_change`] with the seed mark of a seed root.
#[must_use]
pub fn parse_change_full(body: &str) -> Option<ParsedChange> {
    let op: StateOp<'_> = serde_json::from_str(body).ok()?;
    match op {
        StateOp::Change {
            data, epoch, seed, ..
        } => Some(ParsedChange {
            bytes: bs58::decode(&data).into_vec().ok()?,
            epoch: epoch.unwrap_or(0),
            seed,
        }),
        StateOp::Merge { .. } | StateOp::Enc { .. } => None,
    }
}

/// Encrypt a plaintext body under `key`, producing an `enc` envelope. Seals the
/// whole plaintext body — used for the `state`/`meta` change bodies (both the
/// automerge change and the `m` delta) and for broadcast chat (broadcast chat) bodies.
///
/// # Errors
/// Serialization or `MessageBody` validation of the envelope fails.
///
/// # Examples
///
/// An encrypted body opens with its key, and only with its key.
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
    let json = serde_json::to_string(&StateOp::Enc {
        data: bs58::encode(blob).into_string(),
    })
    .map_err(DocError::encode)?;
    Ok(MessageBody::try_new(&json)?)
}

/// Recover the plaintext body string. With a `key` (passworded mesh) the body
/// **must** be a sealed `enc` envelope: it is opened, and any non-`enc` body is
/// rejected (`None`) so cleartext can never slip past the encryption guarantee.
/// Without a key (passwordless) a body is returned unchanged. `None` also when
/// an `enc` body can't be opened (wrong key / malformed) — the caller treats a
/// `None` as an opaque no-op (state/meta) or a drop (chat).
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
    let op: Result<StateOp<'_>, _> = serde_json::from_str(body);
    match op {
        Ok(StateOp::Enc { data }) => {
            let key = key?;
            let blob = bs58::decode(&data).into_vec().ok()?;
            let plain = seal_error::open_symmetric(key, &blob).ok()?;
            String::from_utf8(plain).ok()
        }
        // A non-`enc` body: passthrough on a passwordless mesh (no key), but
        // rejected on a passworded one — encryption is enforced, not optional.
        _ => match key {
            Some(_) => None,
            None => Some(body.to_owned()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SeedMark, change_body, change_body_at, change_body_seed, decrypt_body, encrypt_body,
        merge_body, parse_change, parse_change_body, parse_change_full,
    };
    use habilis_network_protocol::SymmetricKey;

    fn key(byte: u8) -> SymmetricKey {
        SymmetricKey::from([byte; 32])
    }

    #[test]
    fn a_seed_mark_reads_back_and_a_body_without_one_is_unchanged() {
        let _guard = ::habilis_network_test_tracing::init();
        let mark = SeedMark {
            frames: 565,
            last: "ab".repeat(32),
        };
        let body = change_body_seed(&[1, 2], None, 4, Some(&mark)).expect("a seed root body");
        let parsed = parse_change_full(body.as_str()).expect("it parses");
        assert_eq!(parsed.bytes, vec![1, 2], "the change bytes read back");
        assert_eq!(parsed.epoch, 4, "the epoch reads back");
        assert_eq!(parsed.seed, Some(mark), "the mark reads back");
        let plain = change_body_at(&[1, 2], None, 4).expect("a body");
        assert_eq!(
            parse_change_full(plain.as_str()).expect("it parses").seed,
            None,
            "a body without a mark reads with none"
        );
        assert!(
            !plain.as_str().contains("\"s\""),
            "a body without a mark adds nothing to the wire"
        );
    }

    #[test]
    fn an_epoch_above_zero_reads_back_and_epoch_zero_adds_nothing_to_the_body() {
        let _guard = ::habilis_network_test_tracing::init();
        let before_epochs = r#"{"k":"change","c":"Ldp"}"#;
        let epoch_zero = change_body(&[1, 2, 3], None).expect("a body");
        assert_eq!(
            epoch_zero.as_str(),
            before_epochs,
            "epoch 0 is the old body"
        );
        let epoch_seven = change_body_at(&[1, 2, 3], None, 7).expect("a body");
        assert_eq!(
            parse_change(epoch_seven.as_str()),
            Some((vec![1, 2, 3], 7)),
            "an epoch above 0 reads back"
        );
        assert_eq!(
            parse_change(before_epochs),
            Some((vec![1, 2, 3], 0)),
            "a body with no epoch is epoch 0"
        );
        assert_eq!(
            parse_change_body(epoch_seven.as_str()),
            Some(vec![1, 2, 3]),
            "the epoch does not change the change bytes"
        );
    }

    #[test]
    fn enc_body_round_trips_and_hides_the_delta() {
        let _guard = ::habilis_network_test_tracing::init();
        let key = key(3);
        let plain =
            change_body(&[1, 2, 3, 4], Some(&serde_json::json!({"board": "x"}))).expect("compose");
        let enc = encrypt_body(&plain, &key).expect("encrypt");
        assert_ne!(
            enc.as_str(),
            plain.as_str(),
            "wire body is not the plaintext"
        );
        assert!(
            !enc.as_str().contains("board"),
            "the merge delta must not leak into the ciphertext body"
        );
        // decrypt_body recovers the exact plaintext body, which then parses.
        let recovered = decrypt_body(enc.as_str(), Some(&key)).expect("decrypt");
        assert_eq!(
            recovered,
            plain.as_str(),
            "an enc body round trips to the recovered plaintext"
        );
        assert_eq!(
            parse_change_body(&recovered),
            Some(vec![1u8, 2, 3, 4]),
            "an enc body parses back to the plain change"
        );
    }

    #[test]
    fn enc_body_needs_the_right_key() {
        let _guard = ::habilis_network_test_tracing::init();
        let enc = encrypt_body(
            &change_body(&[9, 9], None).expect("a two-byte change is a valid body"),
            &key(1),
        )
        .expect("the body encrypts under a fresh key");
        assert!(
            decrypt_body(enc.as_str(), Some(&key(2))).is_none(),
            "wrong key"
        );
        assert!(decrypt_body(enc.as_str(), None).is_none(), "no key");
        // An `enc` body is not itself a change (must be decrypted first).
        assert_eq!(
            parse_change_body(enc.as_str()),
            None,
            "an enc body needs the right key"
        );
    }

    #[test]
    fn decrypt_enforces_encryption_only_when_keyed() {
        let _guard = ::habilis_network_test_tracing::init();
        let plain = change_body(&[5], None).expect("compose");
        // Passwordless (no key): a non-`enc` body is returned verbatim.
        assert_eq!(
            decrypt_body(plain.as_str(), None).as_deref(),
            Some(plain.as_str()),
            "decrypt enforces encryption only when keyed"
        );
        // Passworded (key set): a non-`enc` body is rejected — cleartext can't
        // slip past the encryption guarantee.
        assert!(
            decrypt_body(plain.as_str(), Some(&key(7))).is_none(),
            "a plain body is refused when keyed"
        );
    }

    #[test]
    fn change_body_round_trips() {
        let _guard = ::habilis_network_test_tracing::init();
        let change = vec![1u8, 2, 3, 250, 0, 42];
        // The optional `m` delta does not affect change decoding either way.
        let with_merge =
            change_body(&change, Some(&serde_json::json!({"k": "v"}))).expect("compose");
        assert_eq!(
            parse_change_body(with_merge.as_str()),
            Some(change.clone()),
            "a change body round trips with a merge"
        );
        let lean = change_body(&change, None).expect("compose");
        assert_eq!(
            parse_change_body(lean.as_str()),
            Some(change),
            "a lean change body round trips"
        );
    }

    #[test]
    fn legacy_merge_body_is_a_no_op_change() {
        let _guard = ::habilis_network_test_tracing::init();
        // A legacy `merge` body (or any non-`change` body) decodes to no change,
        // so the automerge engine ignores it — forward-compat with old binaries.
        let body = merge_body(serde_json::json!({"turn": "a"})).expect("compose");
        assert_eq!(
            parse_change_body(body.as_str()),
            None,
            "a legacy merge body is a no-op change"
        );
        assert_eq!(
            parse_change_body("not json"),
            None,
            "a non-json body is not a change"
        );
    }
}
