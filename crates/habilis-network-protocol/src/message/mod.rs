//! The `Message` envelope + its value types.
//!
//! - [`MessageBody`] (`body`) and [`MessageId`] (`id`) — the
//!   validated newtypes the envelope carries.
//! - [`Message`] (`message`) — the JSON wire envelope, its
//!   [`MessageKind`] / [`PresenceSubtype`] tags, the constructors, and
//!   (de)serialization.

#[cfg(any(test, feature = "test-fixtures"))]
use iroh_base::Signature;

#[cfg(any(test, feature = "test-fixtures"))]
use super::AuthorKey;
#[cfg(any(test, feature = "test-fixtures"))]
#[cfg(test)]
use super::identity;
#[cfg(any(test, feature = "test-fixtures"))]
#[cfg(any(test, feature = "test-fixtures"))]
use super::mesh::MeshId;
#[cfg(any(test, feature = "test-fixtures"))]
use habilis_network_util::clock::UnixSecs;

#[cfg(any(test, feature = "test-fixtures"))]
mod chain_ctx;
#[cfg(any(test, feature = "test-fixtures"))]
pub use chain_ctx::ChainCtx;
#[cfg(any(test, feature = "test-fixtures"))]
mod build_msg_params;
#[cfg(any(test, feature = "test-fixtures"))]
pub use build_msg_params::BuildMsgParams;
#[expect(
    clippy::module_inception,
    reason = "the file is named for its type, Message, as O9 asks"
)]
mod message;
pub use message::Message;
mod message_kind;
pub use message_kind::MessageKind;
mod channel;
#[cfg(test)]
use super::nickname::Nickname;
pub use channel::Channel;
mod app_tag;
pub use app_tag::AppTag;
mod corr_id;
pub use corr_id::CorrId;
mod sole_addressee;
pub use sole_addressee::sole_addressee;
#[cfg(any(test, feature = "test-fixtures"))]
mod build_msg_bytes;
#[cfg(any(test, feature = "test-fixtures"))]
pub use build_msg_bytes::build_msg_bytes;
mod resend;
pub use resend::RESEND_TRAILER_LEN;
use resend::{split_resend_trailer, wire_with_resend_nonce};
mod presence_subtype;
pub use presence_subtype::PresenceSubtype;
mod app_frame_params;
pub use app_frame_params::AppFrameParams;
mod wire_in;
use wire_in::WireIn;
mod wire_out;
use wire_out::Wire;
mod signer;
pub use signer::Signer;
mod body_error;

use body_error as body;
mod error;
mod id_error;
use id_error as id;
mod shard;
mod verified;
mod wire_frame;
use wire_frame as wire;

pub use verified::{Authored, Proof, Verified};
pub use wire::WireFrame;

pub use body::{BodyError, MessageBody};
pub use error::{AppTagError, CorrIdError, MessageError};
pub use id::{IdError, MessageId};
pub use shard::{Shard, ShardGroup, shard_fits_log};

/// Maximum serialized message size — a network-wide wire contract kept
/// under iroh-gossip's payload budget so a message we accept always fits
/// one gossip message (see `habilis_network_util::consts::MAX_MESSAGE_SIZE` for why). Lives
/// in the shared crate; the compile-time assertion below guards the
/// relationship against the live gossip constant.
pub(crate) use habilis_network_util::consts::MAX_MESSAGE_SIZE;

// The compile-time tripwire that guards `MAX_MESSAGE_SIZE` against
// iroh-gossip's `DEFAULT_MAX_MESSAGE_SIZE` lives in `habilis-network`
// (`gossip/mod.rs`): this crate is deliberately off iroh-gossip, so it cannot
// name the constant it checks against.

/// Protocol version embedded in every message, `12.0` for the engine's
/// de-branding. The crypto byte-domains are mixed into signature and
/// key-derivation transcripts, so any rebrand changes the bytes an older build
/// derives and its signature verification fails *silently*. The exact-match gate
/// in `parse` exists to turn that into a loud rejection rather than a frame that
/// folds to a no-op and diverges. Rebrand the domains, bump this.
///
/// As of `12.0` the domains carry the **engine's** name, not the product's
/// (`habilis-mesh/…`): the unicast and blob ALPNs, the seal/sym/x25519/invite
/// seeds, the message signing domain, the directory base seed, and the
/// shared-document genesis actor. A consumer's own bridge ALPN stays branded
/// because it belongs to the application, not to this engine.
///
/// The identity wire key stays **`mesh`**, and so does the internal vocabulary.
/// The user-facing noun for a session is **gossip**, but that is a CLI/docs/MCP
/// surface word and never reaches the wire.
///
/// **`12.0` is the first version bump that breaks real interop.** `11.0` shipped
/// (v0.7.4, on the Homebrew tap), so an `11.0` peer and a `12.0` peer cannot form
/// a mesh at all — not merely fail on one frame kind. That is the designed
/// behavior of the `parse` gate: a loud rejection beats silent divergence. Every
/// bump below it predates any release, so no peer ever ran them, and they are
/// *format* history rather than interop history:
///
/// `12.0` also split the shipped consumer's chat tag in two, one per
/// addressing: a broadcast tag every member receives, and a directed tag
/// carried to a single addressee. That is an application-side change — the
/// `App` envelope has been tag-opaque since `8.0` — and it is recorded here
/// only because it lands inside the same interop break rather than needing one
/// of its own.
///
/// - `11.0` — a product rebrand (the product's name was in the byte-domains).
/// - `10.0` / `9.0` — the agent-mesh → agent-square and swarm → mesh renames.
///   `9.0` also moved the identity wire key to `"mesh"` and the JSON-RPC
///   namespace to `mesh:*`.
/// - `8.0` — the payload-generic `App` envelope (opaque `tag`, addressee `to`,
///   generic `corr`), multipart bodies up to
///   [`habilis_network_util::consts::MAX_SHARD_TOTAL`] (`64 MiB`), and password-mesh
///   `{"k":"enc",…}` content encryption.
/// - `7.0` — the automerge `state`/`meta` channels: Base58 change bodies,
///   heads-based digests.
/// - `6.0` — directed sealing.
/// - `5.0` — the application's v1.0 / `ProtoJSON` payload migration.
/// - `4.0` — the native application-payload port.
/// - `3.0` — the application-payload migration.
/// - `2.0` — RFC 6902 → RFC 7386 shared state.
pub(crate) const VERSION: &str = "12.0";

pub(super) fn default_ext() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

pub(super) fn empty_body() -> MessageBody {
    MessageBody::try_new("").expect("empty string is always a valid MessageBody")
}

#[cfg(any(test, feature = "test-fixtures"))]
impl Message {
    /// This message claiming `key` as its author, with a signature that does not verify: for a
    /// test that needs a message with an author key and never checks the signature.
    #[must_use]
    pub fn with_unverified_key(mut self, key: AuthorKey) -> Self {
        self.signer = Some(Signer::new(key, Signature::from_bytes(&[0u8; 64])));
        self
    }

    /// A fixed test message of `kind` with `body`, from `alice-bot` on mesh `test`.
    #[must_use]
    pub fn fixture(kind: MessageKind, body: &str) -> Self {
        Message {
            version: VERSION.to_string(),
            id: "00000000-0000-0000-0000-000000000001".into(),
            kind,
            mesh: MeshId::from("test"),
            author: "alice-bot".into(),
            timestamp: UnixSecs::from_secs(1_700_000_000),
            body: body.into(),
            signer: None,
            seq: None,
            prev: None,
            parents: Vec::new(),
            shard: None,
            ext: serde_json::json!({}),
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
