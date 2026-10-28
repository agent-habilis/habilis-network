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
use super::identity::Identity;
#[cfg(any(test, feature = "test-fixtures"))]
use super::mesh::MeshId;
#[cfg(any(test, feature = "test-fixtures"))]
use habilis_network_util::clock::UnixSecs;

use serde::Deserialize;

use super::nickname::Nickname;
use crate::newtype::string_newtype;

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
pub use channel::Channel;
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

/// The single addressee of a directed frame — the routing mirror of
/// `gossip::recv::addressed_to_us`. `Some(nick)` for a frame that targets
/// exactly one peer (`Pong`, an application's directed push legs, its RPC
/// request/response); `None` for a broadcast or infrastructure kind. The
/// `habilis-network`'s transport layer send router uses this to decide point-to-point vs gossip.
///
/// Deliberately **separate** from `addressed_to_us`: that answers a *surfacing*
/// question and treats `Pong` as broadcast-visible, whereas routing wants the
/// `Pong`'s addressee too. Merging them would change the surface/relay filter.
#[must_use]
pub fn sole_addressee(kind: &MessageKind) -> Option<&Nickname> {
    match kind {
        MessageKind::Pong { to, .. } => Some(to),
        MessageKind::App { to, .. } => to.as_ref(),
        MessageKind::Presence { .. }
        | MessageKind::PeerInfo
        | MessageKind::Digest
        | MessageKind::Ping
        | MessageKind::State
        | MessageKind::StateDigest
        | MessageKind::Meta
        | MessageKind::MetaDigest
        | MessageKind::LinkState => None,
    }
}

string_newtype!(
/// An opaque application-payload tag — the wire discriminant for a
/// [`MessageKind::App`] frame (serialized in the `tag` field). The engine never
/// interprets it; the consuming application owns the taxonomy (e.g. an application
/// layer's `app_msg` / `app_status` / `app_req` tags) and dispatches on it.
/// Validated as a short non-empty ASCII slug so a crafted value can't smuggle
/// structure into the routing layer.
    AppTag,
    error = &'static str,
    deserialize,
);

impl AppTag {
    fn validate(raw: &str) -> bool {
        !raw.is_empty()
            && raw.len() <= 32
            && raw
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    }

    /// There is no `From<&str>`: a bad literal would panic, so every caller handles the error.
    ///
    /// ```compile_fail
    /// use habilis_network_protocol::AppTag;
    /// let _ = AppTag::from("app_msg");
    /// ```
    ///
    /// ```
    /// use habilis_network_protocol::AppTag;
    /// assert!(AppTag::try_new("app_msg").is_ok());
    /// ```
    ///
    /// # Errors
    /// # Errors
    /// A [`AppTagError::Invalid`] when the tag is empty, longer than 32 bytes, or not
    /// an ASCII slug.
    pub fn try_new(raw: impl Into<String>) -> Result<Self, AppTagError> {
        let raw: String = raw.into();
        if !Self::validate(&raw) {
            return Err(AppTagError::Invalid);
        }
        Ok(Self(raw))
    }
}

string_newtype!(
/// An opaque request/response correlation id carried on a directed
/// [`MessageKind::App`] frame (the `corr` field). Matched by the engine's
/// pending-call registry to pair a reply with its outstanding call; the app
/// mints and interprets its value (the application layer uses a UUID). Kept generic so
/// the engine correlates without knowing the payload model.
    CorrId,
    error = CorrIdError,
);

impl CorrId {
    fn validate(raw: &str) -> bool {
        !raw.is_empty() && raw.len() <= 64
    }

    /// There is no `From<&str>`: a bad literal would panic, so every caller handles the error.
    ///
    /// ```compile_fail
    /// use habilis_network_protocol::CorrId;
    /// let _ = CorrId::from("aaaa");
    /// ```
    ///
    /// ```
    /// use habilis_network_protocol::CorrId;
    /// assert!(CorrId::try_new("aaaa").is_ok());
    /// ```
    ///
    /// # Errors
    /// # Errors
    /// A [`CorrIdError::Invalid`] when the correlation id is empty or longer than 64
    /// bytes.
    pub fn try_new(raw: impl Into<String>) -> Result<Self, CorrIdError> {
        let raw: String = raw.into();
        if !Self::validate(&raw) {
            return Err(CorrIdError::Invalid);
        }
        Ok(Self(raw))
    }
}

impl<'de> Deserialize<'de> for CorrId {
    fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
    where
        Decoder: serde::Deserializer<'de>,
    {
        // The engine stays payload-agnostic (the app enforces its own UUID
        // contract), but a length bound caps DoS at the wire boundary: the app
        // mints a 36-char UUID, so anything empty or wildly larger is a crafted
        // frame, not a correlation id. Mirrors [`AppTag`]'s bounded deserialize.
        let raw = String::deserialize(deserializer)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

pub(super) fn default_ext() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

pub(super) fn empty_body() -> MessageBody {
    MessageBody::try_new("").expect("empty string is always a valid MessageBody")
}

/// Build the serialized wire bytes for an outbound user message
/// (open or directed reply), returning the bytes alongside the
/// canonical [`Message`] so callers can echo it without re-parsing.
/// The single message-construction point shared by the IPC `msg`
/// command, the library API send path, and interactive stdin.
///
/// # Errors
/// A [`MessageError`] from the message encoding: an oversized payload or a JSON failure.
#[cfg(any(test, feature = "test-fixtures"))]
/// # Errors
/// Serialization fails, or the message exceeds `MAX_MESSAGE_SIZE`.
pub fn build_msg_bytes(
    params: BuildMsgParams<'_>,
    identity: &Identity,
) -> Result<(WireFrame, Verified), MessageError> {
    let msg = Message::new_app(
        params.mesh,
        params.author,
        AppFrameParams {
            tag: params.tag,
            to: None,
            corr: None,
            body: params.body,
        },
    )
    .with_chain(params.chain.seq, params.chain.prev)
    .with_parents(params.chain.parents)
    .sign(identity);
    let raw = msg.serialize()?;
    Ok((raw, msg))
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

/// The byte that starts the trailer of a resend. JSON text holds no raw 0x1E: control bytes are
/// escaped inside a string and are not whitespace outside one.
const RESEND_TRAILER_MARK: u8 = 0x1E;
/// The length of the nonce of a resend, in bytes.
const RESEND_NONCE_LEN: usize = 8;
/// The bytes a resend adds to a frame: the mark and the nonce. It stays inside the 256 bytes of
/// headroom under the gossip limit that `MAX_MESSAGE_SIZE` leaves.
pub const RESEND_TRAILER_LEN: usize = 1 + RESEND_NONCE_LEN;

/// `frame` (the bytes of `Message::serialize`) with the trailer of a resend: a mark and a
/// nonce. The gossip layer names a message by the hash of its payload and drops a payload it has
/// seen for 90 s, so a resend of the same bytes cannot repair a message that the gossip layer
/// delivered and the app did not read. The nonce gives each resend a new name. It sits outside
/// the signature, so the receiver checks the frame as it checks any other, and a reader that
/// does not know the trailer fails to parse the payload (closed, not silently).
#[must_use]
pub(crate) fn wire_with_resend_nonce(frame: &[u8], nonce: u64) -> Vec<u8> {
    let mut wire = Vec::with_capacity(frame.len() + RESEND_TRAILER_LEN);
    wire.extend_from_slice(frame);
    wire.push(RESEND_TRAILER_MARK);
    wire.extend_from_slice(&nonce.to_be_bytes());
    wire
}

/// Split `data` into the frame and the nonce of a resend, if it ends in the trailer.
fn split_resend_trailer(data: &[u8]) -> (&[u8], Option<u64>) {
    let Some(mark_at) = data.len().checked_sub(RESEND_TRAILER_LEN) else {
        return (data, None);
    };
    if data[mark_at] != RESEND_TRAILER_MARK {
        return (data, None);
    }
    let mut nonce = [0u8; RESEND_NONCE_LEN];
    nonce.copy_from_slice(&data[mark_at + 1..]);
    (&data[..mark_at], Some(u64::from_be_bytes(nonce)))
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
