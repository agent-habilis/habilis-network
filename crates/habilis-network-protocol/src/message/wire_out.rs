//! The wire form of a message as it is written: the JSON the sender puts on the wire.

use serde::Serialize;
use std::fmt;

use crate::mesh::MeshId;
use crate::identity;
use crate::nickname::Nickname;
use crate::ContentHash;
use super::{Message, MessageBody, MessageId, MessageKind, Shard};






/// A [`Message`] as the wire has it, written. The field order is the order of the JSON text.
#[derive(Serialize)]
pub(super) struct WireOut<'message> {
    #[serde(rename = "v")]
    version: &'message str,
    id: &'message MessageId,
    #[serde(flatten)]
    kind: &'message MessageKind,
    mesh: &'message MeshId,
    author: &'message Nickname,
    #[serde(rename = "ts")]
    timestamp: i64,
    body: &'message MessageBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey: Option<HexOut<'message>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "sig")]
    signature: Option<HexOut<'message>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev: &'message Option<ContentHash>,
    #[serde(skip_serializing_if = "<[ContentHash]>::is_empty")]
    parents: &'message [ContentHash],
    #[serde(skip_serializing_if = "Option::is_none")]
    shard: &'message Option<Shard>,
    ext: &'message serde_json::Value,
}

/// Bytes written as lowercase hex, straight into the serializer.
pub(super) struct HexOut<'bytes>(pub(super) &'bytes [u8]);

impl Serialize for HexOut<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        struct Hex<'bytes>(&'bytes [u8]);
        impl fmt::Display for Hex<'_> {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                identity::write_hex(formatter, self.0)
            }
        }
        serializer.collect_str(&Hex(self.0))
    }
}

/// The wire form of a message. The serde impl lives on this private wrapper, not on [`Message`], so a
/// message that a caller holds through a `Deref` (an [`Authored`] view) has no public `Serialize`.
pub(super) struct Wire<'message>(pub(super) &'message Message);

impl Serialize for Wire<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let message = self.0;
        let signer = message.signer.as_ref();
        let sig_bytes = signer.map(|signed| signed.signature.to_bytes());
        WireOut {
            version: &message.version,
            id: &message.id,
            kind: &message.kind,
            mesh: &message.mesh,
            author: &message.author,
            timestamp: message.timestamp.as_secs(),
            body: &message.body,
            pubkey: signer.map(|signed| HexOut(signed.key.as_bytes())),
            signature: sig_bytes.as_ref().map(|bytes| HexOut(bytes)),
            seq: message.seq,
            prev: &message.prev,
            parents: &message.parents,
            shard: &message.shard,
            ext: &message.ext,
        }
        .serialize(serializer)
    }
}

