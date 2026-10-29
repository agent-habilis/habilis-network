//! The wire form of a message as it is read: every field a string or a plain value.

use habilis_network_util::unix_secs::UnixSecs;
use serde::Deserialize;

use super::{Message, MessageBody, MessageId, MessageKind, Shard, Signer, default_ext};
use crate::mesh::MeshId;
use crate::nickname_error::Nickname;
use crate::{AuthorKey, ContentHash, identity};

use serde::de::Error;
/// A [`Message`] as the wire has it, read: every field a string or a plain value, so that one
/// place ([`Message::try_from`]) decides what a well-formed message is.
#[derive(Deserialize)]
pub(super) struct WireIn {
    #[serde(rename = "v")]
    pub(super) version: String,
    id: MessageId,
    #[serde(flatten)]
    kind: MessageKind,
    mesh: MeshId,
    author: Nickname,
    #[serde(rename = "ts")]
    timestamp: i64,
    body: MessageBody,
    #[serde(default)]
    pub(super) pubkey: String,
    #[serde(default)]
    #[serde(rename = "sig")]
    pub(super) signature: String,
    #[serde(default)]
    pub(super) seq: Option<u64>,
    #[serde(rename = "prev", default)]
    pub(super) previous: Option<String>,
    #[serde(default)]
    pub(super) parents: Vec<String>,
    #[serde(default)]
    pub(super) shard: Option<Shard>,
    #[serde(default = "default_ext")]
    pub(super) ext: serde_json::Value,
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<Decoder: serde::Deserializer<'de>>(
        deserializer: Decoder,
    ) -> Result<Self, Decoder::Error> {
        let wire = WireIn::deserialize(deserializer)?;
        Message::try_from(wire).map_err(Error::custom)
    }
}

impl TryFrom<WireIn> for Message {
    type Error = &'static str;

    /// Shape-check the history-integrity fields at the boundary, so a crafted
    /// value never reaches signature verification or the fork/DAG indexes
    /// (which key on `prev`/`parents` as content hashes). An empty `pubkey` and an empty `sig`
    /// is the canonical unsigned form — the receive path drops anything that
    /// then fails verification; a *present* key/sig/hash must be well-formed
    /// lowercase hex of the right length (Ed25519 pubkey 32B, signature 64B,
    /// SHA-256 hash 32B). A key with no signature, and a signature with no key, are errors:
    /// no sender emits either, and a message cannot hold one.
    fn try_from(wire: WireIn) -> Result<Self, Self::Error> {
        let key: Option<AuthorKey> = (!wire.pubkey.is_empty())
            .then(|| AuthorKey::decode_hex(&wire.pubkey).ok_or("malformed pubkey"))
            .transpose()?;
        if !wire.signature.is_empty() && !is_lower_hex(&wire.signature, 64) {
            return Err("malformed signature");
        }
        let previous: Option<ContentHash> = wire
            .previous
            .as_deref()
            .map(|hash| ContentHash::decode_hex(hash).ok_or("malformed prev hash"))
            .transpose()?;
        let parents: Result<Vec<ContentHash>, &str> = wire
            .parents
            .iter()
            .map(|hash| ContentHash::decode_hex(hash).ok_or("malformed parent hash"))
            .collect();
        let parents = parents?;
        let signer = match (key, wire.signature.is_empty()) {
            (None, true) => None,
            (Some(_), true) => return Err("pubkey without a signature"),
            (None, false) => return Err("signature without a pubkey"),
            (Some(key), false) => {
                let signature =
                    identity::decode_sig(&wire.signature).map_err(|_| "malformed signature")?;
                Some(Signer::new(key, signature))
            }
        };
        Ok(Message {
            version: wire.version,
            id: wire.id,
            kind: wire.kind,
            mesh: wire.mesh,
            author: wire.author,
            timestamp: UnixSecs::from(wire.timestamp),
            body: wire.body,
            signer,
            seq: wire.seq,
            previous,
            parents,
            shard: wire.shard,
            ext: wire.ext,
        })
    }
}

/// Is `value` exactly `bytes * 2` lowercase-hex characters — the canonical
/// wire form of a fixed-width binary field (pubkey / signature / hash)?
fn is_lower_hex(value: &str, bytes: usize) -> bool {
    let lower: bool = value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    value.len() == bytes * 2 && lower
}
