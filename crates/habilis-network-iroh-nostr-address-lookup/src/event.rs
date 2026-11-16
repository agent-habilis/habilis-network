//! NIP-01 events: the id, the BIP-340 signature, and the ephemeral kind a tag
//! maps to.

use std::fmt;

use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::event_error::EventError;
use crate::lane::{LANE_KIND_SPAN, Lane};

/// The tag name every event and filter uses. Trystero uses the same one.
pub const TAG: &str = "x";

/// The ephemeral kind for a 32-byte tag on a lane. The kinds of a lane are spread roughly evenly
/// over its range, as Trystero does over the whole one, so one busy tag does not share a kind
/// with every other one on a relay that indexes by kind.
#[must_use]
pub fn kind_for(lane: Lane, tag: &[u8; 32]) -> u32 {
    lane.kind_start() + u32::from(u16::from_be_bytes([tag[0], tag[1]])) % LANE_KIND_SPAN
}

/// A signing key for one session. It proves nothing about who we are: it only
/// satisfies the relay, which rejects unsigned events.
#[derive(Clone)]
pub struct Keys {
    signing: SigningKey,
    pubkey: String,
}

impl fmt::Debug for Keys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Keys")
            .field("pubkey", &self.pubkey)
            .finish_non_exhaustive()
    }
}

impl Keys {
    /// The keys of the secret `bytes`.
    ///
    /// # Errors
    /// [`EventError::InvalidSecretKey`] when `bytes` is zero or not below the curve order.
    pub fn try_new(bytes: &[u8; 32]) -> Result<Self, EventError> {
        let signing =
            SigningKey::from_bytes(&(*bytes).into()).map_err(|_| EventError::InvalidSecretKey)?;
        let pubkey = hex::encode(signing.verifying_key().to_bytes());
        Ok(Self { signing, pubkey })
    }

    /// A fresh key from the workspace `rand`. Not `SigningKey::random`, which
    /// k256 0.14 deprecates and which takes a `rand_core` 0.10 RNG, while the
    /// workspace `rand` is 0.9.
    #[must_use]
    pub fn generate() -> Self {
        loop {
            // A random 32-byte string is a valid scalar with probability
            // 1 - 2^-128; the loop is for the proof, not for practice.
            if let Ok(keys) = Self::try_new(&rand::random()) {
                return keys;
            }
        }
    }

    /// The x-only public key, lowercase hex.
    #[must_use]
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }
}

/// A signed NIP-01 event, in its wire shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Event {
    /// The SHA-256 of the serialized event, as lowercase hex.
    pub id: String,
    /// The public key of the author, as lowercase hex.
    pub pubkey: String,
    /// The creation time, in seconds since the Unix epoch.
    pub created_at: u64,
    /// The NIP-01 event kind.
    pub kind: u32,
    /// The tags of the event, each a list of strings.
    pub tags: Vec<Vec<String>>,
    /// The content of the event.
    pub content: String,
    /// The Schnorr signature over the id, as lowercase hex. `sig` on the wire.
    #[serde(rename = "sig")]
    pub signature: String,
}

impl Event {
    /// Build and sign an event on `lane` carrying `content` under one `x` tag.
    ///
    /// # Panics
    /// Never in practice: BIP-340 signing fails only on a zero nonce, which
    /// the auxiliary randomness rules out.
    #[must_use]
    pub fn sign(lane: Lane, keys: &Keys, created_at: u64, tag: &[u8; 32], content: String) -> Self {
        let kind = kind_for(lane, tag);
        let tags = vec![vec![TAG.to_owned(), hex::encode(tag)]];
        let id = compute_id(keys.pubkey(), created_at, kind, &tags, &content);
        let signature = keys
            .signing
            .sign_raw(&id, &rand::random())
            .expect("BIP-340 signing of a 32-byte digest cannot fail");
        Self {
            id: hex::encode(id),
            pubkey: keys.pubkey().to_owned(),
            created_at,
            kind,
            tags,
            content,
            signature: hex::encode(signature.to_bytes()),
        }
    }

    /// An event that names `pubkey` as its author, with a valid id and a
    /// signature that is not one: what anyone can forge, since the receiver
    /// checks only the id.
    #[cfg(test)]
    pub(crate) fn forged_as(
        pubkey: &str,
        created_at: u64,
        tag: &[u8; 32],
        content: String,
    ) -> Self {
        let kind = kind_for(Lane::Signal, tag);
        let tags = vec![vec![TAG.to_owned(), hex::encode(tag)]];
        let id = compute_id(pubkey, created_at, kind, &tags, &content);
        Self {
            id: hex::encode(id),
            pubkey: pubkey.to_owned(),
            created_at,
            kind,
            tags,
            content,
            signature: "00".repeat(64),
        }
    }

    /// Check only that the id is the hash of the fields. A receiver that
    /// authenticates the content some other way uses this: it stops a relay's
    /// copy that kept the id and changed the content, and it costs one hash
    /// where [`verify`](Self::verify) also checks a Schnorr signature.
    ///
    /// # Errors
    /// [`EventError::IdMismatch`] when the id does not match the fields.
    pub fn verify_id(&self) -> Result<(), EventError> {
        self.checked_id().map(|_| ())
    }

    /// The id the fields hash to, if it is the id the event names.
    fn checked_id(&self) -> Result<[u8; 32], EventError> {
        let id = compute_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        if hex::encode(id) != self.id {
            return Err(EventError::IdMismatch);
        }
        Ok(id)
    }

    /// Check the id and the signature, as a relay does before it forwards.
    ///
    /// # Errors
    /// The id does not match the fields, a field does not decode, or the
    /// signature does not verify.
    pub fn verify(&self) -> Result<(), EventError> {
        let id = self.checked_id()?;
        let pubkey = hex::decode(&self.pubkey).map_err(|_| EventError::Malformed {
            step: "pubkey is not hex",
        })?;
        let key = VerifyingKey::try_from(pubkey.as_slice()).map_err(|_| EventError::Malformed {
            step: "pubkey is not an x-only key",
        })?;
        let signature_bytes = hex::decode(&self.signature).map_err(|_| EventError::Malformed {
            step: "signature is not hex",
        })?;
        let signature =
            Signature::try_from(signature_bytes.as_slice()).map_err(|_| EventError::Malformed {
                step: "signature is not 64 bytes",
            })?;
        key.verify_raw(&id, &signature)
            .map_err(|_| EventError::BadSignature)?;
        Ok(())
    }

    /// The value of the first `x` tag, if any.
    #[must_use]
    pub fn tag(&self) -> Option<&str> {
        let named = |candidate: &&Vec<String>| candidate.first().map(String::as_str) == Some(TAG);
        let found: &Vec<String> = self.tags.iter().find(named)?;
        found.get(1).map(String::as_str)
    }
}

/// `sha256` of the NIP-01 serialization `[0,pubkey,created_at,kind,tags,content]`.
fn compute_id(
    pubkey: &str,
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    Sha256::digest(serialize(pubkey, created_at, kind, tags, content).as_bytes()).into()
}

fn serialize(
    pubkey: &str,
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> String {
    // serde_json writes no whitespace and escapes exactly what NIP-01 asks for.
    serde_json::json!([0, pubkey, created_at, kind, tags, content]).to_string()
}

#[cfg(test)]
mod tests {
    use super::{Event, Keys, kind_for, serialize};
    use crate::lane::{DATA_KIND_START, LANE_KIND_SPAN, Lane, SIGNAL_KIND_START};

    /// BIP-340 test vector 0 (github.com/bitcoin/bips, bip-0340/test-vectors.csv).
    #[test]
    fn bip340_vector_zero() {
        let mut secret = [0u8; 32];
        secret[31] = 3;
        let keys = Keys::try_new(&secret).expect("a valid secret key");
        assert_eq!(
            keys.pubkey(),
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            "the public key of secret 3"
        );
        let signature = keys
            .signing
            .sign_raw(&[0u8; 32], &[0u8; 32])
            .expect("a signature");
        assert_eq!(
            hex::encode(signature.to_bytes()),
            "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215\
             25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
            "the signature of test vector 0"
        );
    }

    /// The NIP-01 serialization: no whitespace, fields in this order, content
    /// JSON-escaped.
    #[test]
    fn nip01_serialization_is_the_compact_array() {
        let tags = vec![vec!["x".to_owned(), "ab".to_owned()]];
        assert_eq!(
            serialize("pk", 1_700_000_000, 20_001, &tags, "hi \"there\"\n"),
            r#"[0,"pk",1700000000,20001,[["x","ab"]],"hi \"there\"\n"]"#,
            "the compact NIP-01 array"
        );
    }

    #[test]
    fn a_signed_event_verifies_and_a_tampered_one_does_not() {
        let keys = Keys::generate();
        let event = Event::sign(
            Lane::Signal,
            &keys,
            1_700_000_000,
            &[9u8; 32],
            "hello".to_owned(),
        );
        event.verify().expect("a valid event");
        assert_eq!(
            event.tag(),
            Some(hex::encode([9u8; 32]).as_str()),
            "the event carries its tag"
        );

        let mut tampered = event.clone();
        tampered.content = "bye".to_owned();
        assert!(
            tampered.verify().is_err(),
            "content change must break the id"
        );

        let mut forged = event;
        forged.pubkey = Keys::generate().pubkey().to_owned();
        assert!(forged.verify().is_err(), "another key must not verify");
    }

    /// The receiver authenticates the content by the seal and the endpoint
    /// signature inside it, so the check it runs on receipt is the id alone: a
    /// valid id with a bad Schnorr signature passes, a changed content does not.
    #[test]
    fn verify_id_accepts_a_bad_signature_and_refuses_a_changed_content() {
        let keys = Keys::generate();
        let event = Event::sign(
            Lane::Signal,
            &keys,
            1_700_000_000,
            &[9u8; 32],
            "hello".to_owned(),
        );

        let mut bad_signature = event.clone();
        bad_signature.signature = "00".repeat(64);
        bad_signature
            .verify_id()
            .expect("the id still matches the fields");
        assert!(
            bad_signature.verify().is_err(),
            "a relay still refuses the bad signature"
        );

        let mut changed = event;
        changed.content = "bye".to_owned();
        assert!(
            changed.verify_id().is_err(),
            "a copy with the id kept and the content changed is refused"
        );
    }

    #[test]
    fn an_event_is_signed_on_the_kind_of_its_lane() {
        let keys = Keys::generate();
        for lane in [Lane::Signal, Lane::Data] {
            let event = Event::sign(lane, &keys, 1_700_000_000, &[9u8; 32], "x".to_owned());
            assert_eq!(event.kind, kind_for(lane, &[9u8; 32]), "{lane:?}");
            event.verify().expect("a valid event");
        }
    }

    #[test]
    fn kinds_are_ephemeral_and_deterministic() {
        for lane in [Lane::Signal, Lane::Data] {
            let start = lane.kind_start();
            for tag in [
                [0u8; 32],
                [0xff; 32],
                [
                    0x27, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0,
                ],
            ] {
                let kind = kind_for(lane, &tag);
                assert!(
                    (start..start + LANE_KIND_SPAN).contains(&kind),
                    "{lane:?}: {kind}"
                );
                assert_eq!(
                    kind,
                    kind_for(lane, &tag),
                    "the same tag gives the same kind"
                );
            }
        }
    }

    /// The kinds are goldens: the relay server pins the same ranges.
    #[test]
    fn each_lane_has_its_kind_range() {
        assert_eq!(
            kind_for(Lane::Signal, &[0u8; 32]),
            20_000,
            "tag zero is the base kind of signalling"
        );
        assert_eq!(
            kind_for(Lane::Data, &[0u8; 32]),
            25_000,
            "tag zero is the base kind of data"
        );
        // 0xffff = 65535 -> 65535 % 5000 = 535.
        assert_eq!(
            kind_for(Lane::Signal, &[0xff; 32]),
            20_535,
            "the largest prefix wraps inside signalling"
        );
        assert_eq!(
            kind_for(Lane::Data, &[0xff; 32]),
            25_535,
            "the largest prefix wraps inside data"
        );
    }

    /// The relay server pins `DATA_KIND_START` too: a change here is a change there.
    #[test]
    fn the_data_lane_starts_at_25000() {
        assert_eq!(DATA_KIND_START, 25_000, "the first data kind");
        assert_eq!(SIGNAL_KIND_START, 20_000, "the first signalling kind");
        assert_eq!(
            SIGNAL_KIND_START + LANE_KIND_SPAN,
            DATA_KIND_START,
            "signalling ends where data starts"
        );
        assert_eq!(
            DATA_KIND_START + LANE_KIND_SPAN,
            30_000,
            "data ends at the end of the ephemeral range"
        );
    }
}
