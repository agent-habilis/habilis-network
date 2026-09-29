//! NIP-01 events: the id, the BIP-340 signature, and the ephemeral kind a tag
//! maps to.

use anyhow::{Context as _, Result, bail};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The tag name every event and filter uses. Trystero uses the same one.
pub const TAG: &str = "x";

/// Ephemeral kinds are 20000..30000: relays forward them and store nothing.
const EPHEMERAL_BASE: u32 = 20_000;
const EPHEMERAL_SPAN: u32 = 10_000;

/// The ephemeral kind for a 32-byte tag. Spreading tags roughly evenly over the range, as
/// Trystero does, keeps one busy tag from sharing a kind with every other one
/// on a relay that indexes by kind.
#[must_use]
pub fn kind_for(tag: &[u8; 32]) -> u32 {
    EPHEMERAL_BASE + u32::from(u16::from_be_bytes([tag[0], tag[1]])) % EPHEMERAL_SPAN
}

/// A signing key for one session. It proves nothing about who we are: it only
/// satisfies the relay, which rejects unsigned events.
#[derive(Clone)]
pub struct Keys {
    signing: SigningKey,
    pubkey: String,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Keys")
            .field("pubkey", &self.pubkey)
            .finish_non_exhaustive()
    }
}

impl Keys {
    /// # Errors
    /// `bytes` is zero or not below the curve order.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let signing = SigningKey::from_bytes(bytes).context("invalid secp256k1 secret key")?;
        let pubkey = hex::encode(signing.verifying_key().to_bytes());
        Ok(Self { signing, pubkey })
    }

    /// A fresh key from the workspace `rand`. Not `SigningKey::random`, which
    /// wants `rand_core` 0.6 and would drag a second `getrandom` onto wasm.
    #[must_use]
    pub fn generate() -> Self {
        loop {
            // A random 32-byte string is a valid scalar with probability
            // 1 - 2^-128; the loop is for the proof, not for practice.
            if let Ok(keys) = Self::from_bytes(&rand::random()) {
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
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl Event {
    /// Build and sign an event carrying `content` under one `x` tag.
    ///
    /// # Panics
    /// Never in practice: BIP-340 signing fails only on a zero nonce, which
    /// the auxiliary randomness rules out.
    #[must_use]
    pub fn sign(keys: &Keys, created_at: u64, tag: &[u8; 32], content: String) -> Self {
        let kind = kind_for(tag);
        let tags = vec![vec![TAG.to_owned(), hex::encode(tag)]];
        let id = compute_id(keys.pubkey(), created_at, kind, &tags, &content);
        let sig = keys
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
            sig: hex::encode(sig.to_bytes()),
        }
    }

    /// Check the id and the signature, as a relay does before it forwards.
    ///
    /// # Errors
    /// The id does not match the fields, or the signature does not verify.
    pub fn verify(&self) -> Result<()> {
        let id = compute_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        if hex::encode(id) != self.id {
            bail!("event id does not match its fields");
        }
        let pubkey = hex::decode(&self.pubkey).context("pubkey is not hex")?;
        let key = VerifyingKey::from_bytes(&pubkey).context("pubkey is not an x-only key")?;
        let sig = hex::decode(&self.sig).context("sig is not hex")?;
        let sig = Signature::try_from(sig.as_slice()).context("sig is not 64 bytes")?;
        key.verify_raw(&id, &sig).context("bad signature")?;
        Ok(())
    }

    /// The value of the first `x` tag, if any.
    #[must_use]
    pub fn tag(&self) -> Option<&str> {
        self.tags
            .iter()
            .find(|tag| tag.first().map(String::as_str) == Some(TAG))
            .and_then(|tag| tag.get(1))
            .map(String::as_str)
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
    use super::*;

    /// BIP-340 test vector 0 (github.com/bitcoin/bips, bip-0340/test-vectors.csv).
    #[test]
    fn bip340_vector_zero() {
        let mut secret = [0u8; 32];
        secret[31] = 3;
        let keys = Keys::from_bytes(&secret).unwrap();
        assert_eq!(
            keys.pubkey(),
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        );
        let sig = keys.signing.sign_raw(&[0u8; 32], &[0u8; 32]).unwrap();
        assert_eq!(
            hex::encode(sig.to_bytes()),
            "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215\
             25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
        );
    }

    /// The NIP-01 serialization: no whitespace, fields in this order, content
    /// JSON-escaped.
    #[test]
    fn nip01_serialization_is_the_compact_array() {
        let tags = vec![vec!["x".to_owned(), "ab".to_owned()]];
        assert_eq!(
            serialize("pk", 1_700_000_000, 20_001, &tags, "hi \"there\"\n"),
            r#"[0,"pk",1700000000,20001,[["x","ab"]],"hi \"there\"\n"]"#
        );
    }

    #[test]
    fn a_signed_event_verifies_and_a_tampered_one_does_not() {
        let keys = Keys::generate();
        let event = Event::sign(&keys, 1_700_000_000, &[9u8; 32], "hello".to_owned());
        event.verify().unwrap();
        assert_eq!(event.tag(), Some(hex::encode([9u8; 32]).as_str()));

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

    #[test]
    fn kinds_are_ephemeral_and_deterministic() {
        for tag in [
            [0u8; 32],
            [0xff; 32],
            [
                0x27, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
        ] {
            let kind = kind_for(&tag);
            assert!((20_000..30_000).contains(&kind), "{kind}");
            assert_eq!(kind, kind_for(&tag));
        }
        assert_eq!(kind_for(&[0u8; 32]), 20_000);
        // 0xffff = 65535 → 65535 % 10000 = 5535.
        assert_eq!(kind_for(&[0xff; 32]), 25_535);
    }
}
