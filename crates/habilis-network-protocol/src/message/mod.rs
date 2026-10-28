//! The `Message` envelope + its value types.
//!
//! - [`MessageBody`] (`body`) and [`MessageId`] (`id`) — the
//!   validated newtypes the envelope carries.
//! - [`Message`] (this file) — the JSON wire envelope, its
//!   [`MessageKind`] / [`PresenceSubtype`] tags, the constructors, and
//!   (de)serialization.

use std::fmt;

#[cfg(any(test, feature = "test-fixtures"))]
use iroh_base::Signature;

use serde::{Deserialize, Serialize};

use habilis_network_util::clock::UnixSecs;

use super::identity::{self, Identity};
use super::mesh::MeshId;
use super::nickname::Nickname;
use super::{AuthorKey, ContentHash, DedupKey};
use crate::newtype::string_newtype;

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

/// Message kind — the frame's routing discriminator. The engine owns the
/// infrastructure kinds (presence, peer-info, digests, ping/pong, channel
/// events, link-state); all application payloads ride the single generic
/// [`App`](MessageKind::App) variant, distinguished by its opaque `tag`.
/// - `App`: an application payload — the body is a whole serialized app object
///   (e.g. a broadcast chat message, a task leg, a directed JSON-RPC envelope),
///   opaque to this layer and dispatched on `tag`.
/// - `Presence`: agent lifecycle (joined/left), empty body.
/// - `PeerInfo`: infrastructure — carries endpoint address for mesh formation. Not user-visible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
#[non_exhaustive]
pub enum MessageKind {
    /// An application payload. `tag` is the wire discriminant the app dispatches
    /// on (the engine treats it opaquely); `to` is the directed addressee
    /// (`None` for a broadcast); `corr` correlates a request with its reply for
    /// the pending-call registry (`None` for fire-and-forget). Everything else
    /// the payload needs (task id, method, params) rides inside `body`.
    App {
        /// The application tag, which routes the frame to its app handler.
        tag: AppTag,
        /// The recipient, when the message is directed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to: Option<Nickname>,
        /// The correlation id of a request or reply.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        corr: Option<CorrId>,
    },
    /// A presence change of a member.
    Presence {
        /// What changed.
        subtype: PresenceSubtype,
    },
    /// The identity of a peer.
    PeerInfo,
    /// Anti-entropy digest. Body is a JSON array of recent message ids
    /// the sender holds; a receiver re-broadcasts any of *its* logged
    /// messages absent from that list, so a peer that missed them
    /// (partition / sleep / late join) recovers. Plumbing like
    /// `PeerInfo`: never logged or surfaced via `poll`/`fetch`.
    Digest,
    /// Liveness probe broadcast by a node running an RTT round. Every
    /// receiver auto-responds with a `Pong` addressed back to the
    /// pinger. Plumbing like `PeerInfo`/`Digest`: never logged or surfaced
    /// via `poll`/`fetch` — only the originator's `ping_report` event surfaces.
    Ping,
    /// Response to a `Ping`, addressed to the original pinger (`to`). `probe` is
    /// the id of the `Ping` it answers: a round sends more than one probe, and the
    /// pinger reads the RTT from the probe that the pong names, and drops a pong
    /// that names none of its own. Same plumbing treatment as `Ping`.
    Pong {
        /// The member that sent the probe.
        to: Nickname,
        /// The probe that this pong answers.
        probe: MessageId,
    },
    /// A durable `state`-channel event: one Base58 automerge change
    /// (`{"k":"change",…}`) applied to the channel's `MeshDoc`
    /// CRDT. Carried on the gossip topic like everything else; the signed frame
    /// is retained as the doc's re-serve store. Signed like any message; never
    /// entered into the chat message-log, never surfaced via poll/fetch.
    State,
    /// Anti-entropy digest for the **state** channel — the dedicated counterpart
    /// to [`Digest`](MessageKind::Digest). Body is the doc's automerge heads; a
    /// receiver computes the changes the sender lacks (`changes_since`) and
    /// re-broadcasts their frames, so a cold/late joiner (advertising an empty or
    /// genesis-only frontier) pulls the whole history over successive rounds.
    /// Separate from `Digest` for its own resend budget. Plumbing like `Digest`.
    StateDigest,
    /// A durable event on the **meta** channel — a second shared-state channel,
    /// identical machinery to [`State`](MessageKind::State) but with the
    /// foreign-card forgery gate enabled (a `meta` card carries a peer's
    /// cryptographic identity). The split is application convention (`meta` for
    /// mesh metadata, `state` for the task).
    Meta,
    /// Anti-entropy digest for the **meta** channel — the meta-channel counterpart
    /// to [`StateDigest`](MessageKind::StateDigest).
    MetaDigest,
    /// A multihop-routing **link-state** advertisement: the author's own measured
    /// links + underlay address (`body` is a serialized
    /// `habilis_network_iroh_multihop_transport::LinkVector`). Broadcast
    /// plumbing like `Digest`/`Ping` — never logged, never surfaced, never
    /// chain/DAG-folded; every node folds the freshest vector per origin into its
    /// routing graph. Ephemeral (a fresh vector supersedes the old by `seq`), so
    /// it rides gossip rather than a durable channel log.
    #[serde(rename = "linkstate")]
    LinkState,
}

impl fmt::Display for MessageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageKind::App { tag, .. } => write!(f, "{tag}"),
            MessageKind::Presence { .. } => write!(f, "presence"),
            MessageKind::PeerInfo => write!(f, "peerinfo"),
            MessageKind::Digest => write!(f, "digest"),
            MessageKind::Ping => write!(f, "ping"),
            MessageKind::Pong { .. } => write!(f, "pong"),
            MessageKind::State => write!(f, "state"),
            MessageKind::StateDigest => write!(f, "state_digest"),
            MessageKind::Meta => write!(f, "meta"),
            MessageKind::MetaDigest => write!(f, "meta_digest"),
            MessageKind::LinkState => write!(f, "linkstate"),
        }
    }
}

impl MessageKind {
    /// The app-payload tag if this is an [`App`](MessageKind::App) frame, else
    /// `None`. The one accessor app code uses to dispatch on payload type
    /// without destructuring, now that the app-frame kinds share one variant.
    #[must_use]
    pub fn app_tag(&self) -> Option<&AppTag> {
        match self {
            MessageKind::App { tag, .. } => Some(tag),
            MessageKind::Presence { .. }
            | MessageKind::PeerInfo
            | MessageKind::Digest
            | MessageKind::Ping
            | MessageKind::Pong { .. }
            | MessageKind::State
            | MessageKind::StateDigest
            | MessageKind::Meta
            | MessageKind::MetaDigest
            | MessageKind::LinkState => None,
        }
    }

    /// `true` iff this is an [`App`](MessageKind::App) frame with tag `tag`.
    #[must_use]
    pub fn is_app(&self, tag: &str) -> bool {
        self.app_tag().is_some_and(|value| value.as_str() == tag)
    }

    /// A broadcast [`App`](MessageKind::App) kind (no addressee, no correlation)
    /// with tag `tag` — the test/fixture ergonomic for what used to be a bare
    /// unit variant per app tag.
    ///
    /// # Panics
    /// `tag` is not a valid [`AppTag`]. A fixture names a fixed literal.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn app_broadcast(tag: &str) -> Self {
        MessageKind::App {
            tag: AppTag::try_new(tag).expect("a valid app tag"),
            to: None,
            corr: None,
        }
    }

    /// A directed [`App`](MessageKind::App) kind addressed to `to`, tag `tag`,
    /// with an optional correlation id — the test ergonomic for the former
    /// directed app variants.
    ///
    /// # Panics
    /// `tag` is not a valid [`AppTag`]. A fixture names a fixed literal.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn app_to(tag: &str, to: Nickname, corr: Option<CorrId>) -> Self {
        MessageKind::App {
            tag: AppTag::try_new(tag).expect("a valid app tag"),
            to: Some(to),
            corr,
        }
    }
}

pub(super) fn default_ext() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

fn empty_body() -> MessageBody {
    MessageBody::try_new("").expect("empty string is always a valid MessageBody")
}

/// A protocol frame — serialized as JSON on the wire. The transport
/// envelope beneath the app layer: for an app frame (e.g. chat, `app_msg`),
/// `body` carries a whole serialized app payload opaque to this layer;
/// plumbing kinds (presence, digests, ping/pong, state/meta) carry their own
/// opaque bodies.
///
/// Wire format (compact JSON, one line):
/// ```json
/// {"v":"12.0","id":"<uuid>","type":"app","tag":"app_msg","mesh":"...","author":"word-word","ts":1234567890,"body":"{\"messageId\":\"<uuid>\",\"role\":\"ROLE_USER\",...}","ext":{}}
/// ```
///
/// `to` (the addressee nickname) is inlined into the JSON for a directed app frame.
/// `ext`: free-form object for experimental/future fields; parsers MUST ignore unknown keys inside it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Message {
    /// The protocol version of the message.
    pub version: String,
    /// The id of the message.
    pub id: MessageId,
    /// What the message carries.
    pub kind: MessageKind,
    /// The mesh that the message belongs to.
    pub mesh: MeshId,
    /// The member that signed the message.
    pub author: Nickname,
    /// Unix timestamp (seconds, UTC).
    pub timestamp: UnixSecs,
    /// The body of the message (sealed for a directed frame on a passworded mesh).
    pub body: MessageBody,
    /// Author's Ed25519 public key and the detached signature over the message's
    /// [canonical bytes](Message::canonical_bytes), always together: a message has both or
    /// neither. `None` is the unsigned message: its key and signature are skipped on the wire,
    /// which is also the **canonical pre-signing form** that [`Message::canonical_bytes`] hashes
    /// (the signature cannot cover itself). Real outbound traffic is always signed on the
    /// broadcast path, and the receive path drops anything that fails verification. See
    /// `docs/history-integrity.md`.
    pub signer: Option<Signer>,
    /// Per-author hash-linked log (Phase 2), set on `Msg` only: `seq` is
    /// this author's monotonic counter and `prev` the content hash of their
    /// previous `Msg` (`None` at `seq 0`). Both are signed. Plumbing /
    /// presence kinds leave them `None`. The message's own content hash is
    /// computed locally (`content_hash_hex`), never transmitted. See
    /// `docs/history-integrity.md`.
    pub seq: Option<u64>,
    /// The hash of the previous message of the author.
    pub prev: Option<ContentHash>,
    /// Cross-author DAG (Phase 3), `Msg` only: content hashes of the DAG
    /// tips this author had seen when authoring — the causal links. Signed.
    /// Empty for the very first message / messages with no observed
    /// predecessor. See `docs/history-integrity.md`.
    pub parents: Vec<ContentHash>,
    /// Shard header: present only on a message that is one slice of a body
    /// too large for a single message (see [`Shard`]). `None` on an ordinary
    /// message, so its wire form is unchanged. Signed like every other field.
    pub shard: Option<Shard>,
    /// Extension escape hatch. Add experimental fields here; stable fields get promoted to top-level.
    pub ext: serde_json::Value,
}

impl Message {
    fn new(mesh: &MeshId, author: &Nickname, kind: MessageKind, body: MessageBody) -> Self {
        Message {
            version: VERSION.to_string(),
            id: MessageId::random(),
            kind,
            mesh: mesh.clone(),
            author: author.clone(),
            timestamp: UnixSecs::now(),
            body,
            signer: None,
            seq: None,
            prev: None,
            parents: Vec::new(),
            shard: None,
            ext: default_ext(),
        }
    }

    /// A frame of an explicit `kind` — the generic constructor the task
    /// send path uses to build the application's directed frames through
    /// one shard-splitting flow.
    #[must_use]
    pub fn new_frame(
        mesh: &MeshId,
        author: &Nickname,
        kind: MessageKind,
        body: MessageBody,
    ) -> Self {
        Self::new(mesh, author, kind, body)
    }

    /// An application-payload frame: `tag` is the app's wire discriminant, `to`
    /// the directed addressee (`None` for a broadcast), `corr` the optional
    /// request/response correlation id, and `body` the opaque payload. The
    /// engine routes on `to`/`corr` and never inspects `body`.
    ///
    /// Reused as-is by `habilis_network::ops::send_app`, whose `App` frame shape is
    /// identical.
    #[must_use]
    pub fn new_app(mesh: &MeshId, author: &Nickname, params: AppFrameParams) -> Self {
        let AppFrameParams {
            tag,
            to,
            corr,
            body,
        } = params;
        Self::new(mesh, author, MessageKind::App { tag, to, corr }, body)
    }

    /// A presence message for `author` joining `mesh`. It has no body.
    #[must_use]
    pub fn new_joined(mesh: &MeshId, author: &Nickname) -> Self {
        // Presence carries no body; peer metadata (model/harness/host) is application
        // data an agent writes into the `meta` channel, not a presence payload.
        Self::new(
            mesh,
            author,
            MessageKind::Presence {
                subtype: PresenceSubtype::Joined,
            },
            empty_body(),
        )
    }

    /// A presence message for `author` leaving `mesh`. It has no body.
    #[must_use]
    pub fn new_left(mesh: &MeshId, author: &Nickname) -> Self {
        Self::new(
            mesh,
            author,
            MessageKind::Presence {
                subtype: PresenceSubtype::Left,
            },
            empty_body(),
        )
    }

    /// A presence message that `author` is alive on `mesh`. It has no body.
    #[must_use]
    pub fn new_alive(mesh: &MeshId, author: &Nickname) -> Self {
        Self::new(
            mesh,
            author,
            MessageKind::Presence {
                subtype: PresenceSubtype::Alive,
            },
            empty_body(),
        )
    }

    /// A liveness probe (broadcast). Receivers auto-respond with a
    /// `Pong` addressed back to `author`.
    #[must_use]
    pub fn new_ping(mesh: &MeshId, author: &Nickname) -> Self {
        Self::new(mesh, author, MessageKind::Ping, empty_body())
    }

    /// A `Pong` response addressed to the original pinger (`to`), naming the `Ping` (`probe`) that
    /// it answers.
    #[must_use]
    pub fn new_pong(mesh: &MeshId, author: &Nickname, to: Nickname, probe: &MessageId) -> Self {
        let probe = probe.clone();
        Self::new(mesh, author, MessageKind::Pong { to, probe }, empty_body())
    }

    /// Create a `PeerInfo` message. The body carries endpoint address data
    /// as a JSON string for mesh peer lookup.
    #[must_use]
    pub fn new_peer_info(mesh: &MeshId, author: &Nickname, addr_data: MessageBody) -> Self {
        Self::new(mesh, author, MessageKind::PeerInfo, addr_data)
    }

    /// An anti-entropy digest carrying `ids_json` (a JSON array of the
    /// recent message ids we hold) in the body.
    #[must_use]
    pub fn new_digest(mesh: &MeshId, author: &Nickname, ids_json: MessageBody) -> Self {
        Self::new(mesh, author, MessageKind::Digest, ids_json)
    }

    /// A multihop link-state advertisement; `vector_json` is a serialized
    /// `habilis_network_iroh_multihop_transport::LinkVector`.
    ///
    /// Portable: it only builds a `Message`, so a browser that mints vectors builds
    /// the advertisement as a native node does.
    #[must_use]
    pub fn new_link_state(mesh: &MeshId, author: &Nickname, vector_json: MessageBody) -> Self {
        Self::new(mesh, author, MessageKind::LinkState, vector_json)
    }

    /// A durable state event whose opaque payload is `body`. Routed to the
    /// un-pruned `daemon::state_log`, not the chat message-log. Harness
    /// constructor; production uses [`new_channel_event`](Self::new_channel_event).
    #[cfg(any(test, feature = "adversarial"))]
    #[must_use]
    pub fn new_state(mesh: &MeshId, author: &Nickname, body: MessageBody) -> Self {
        Self::new(mesh, author, MessageKind::State, body)
    }

    /// A durable event on the given channel (`state` / `meta`).
    #[must_use]
    pub fn new_channel_event(
        mesh: &MeshId,
        author: &Nickname,
        body: MessageBody,
        channel: Channel,
    ) -> Self {
        Self::new(mesh, author, channel.event_kind(), body)
    }

    /// An anti-entropy digest for the given channel.
    #[must_use]
    pub fn new_channel_digest(
        mesh: &MeshId,
        author: &Nickname,
        body: MessageBody,
        channel: Channel,
    ) -> Self {
        Self::new(mesh, author, channel.digest_kind(), body)
    }

    /// A state anti-entropy digest whose `body` is the windowed digest the
    /// sender advertises (a `DigestBody` of `WireWindow`s over the `State`
    /// events it holds — the unbounded analogue of the chat digest). Test-only;
    /// production uses [`new_channel_digest`](Self::new_channel_digest).
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn new_state_digest(mesh: &MeshId, author: &Nickname, body: MessageBody) -> Self {
        Self::new(mesh, author, MessageKind::StateDigest, body)
    }

    /// Serialize to compact JSON bytes for the gossip wire. Outside this crate only a [`Verified`]
    /// serializes, through [`Verified::serialize`]: an unverified or an authored view has no wire form.
    /// # Errors
    /// # Errors
    /// A [`MessageError::Source`] when the JSON does not encode, or
    /// [`MessageError::Oversize`] when the bytes pass `MAX_MESSAGE_SIZE`.
    pub(crate) fn serialize(&self) -> Result<Vec<u8>, MessageError> {
        let bytes = serde_json::to_vec(&Wire(self))
            .map_err(MessageError::with_step("failed to serialize message"))?;
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(MessageError::Oversize { bytes: bytes.len() });
        }
        Ok(bytes)
    }

    /// Parse a message from JSON bytes.
    /// # Errors
    /// # Errors
    /// A [`MessageError::TooLarge`] past `MAX_MESSAGE_SIZE`, a [`MessageError::Source`]
    /// when the JSON does not parse, [`MessageError::UnsupportedVersion`] for another
    /// protocol version, or [`MessageError::Invalid`] for a field the protocol does not allow.
    pub fn parse(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(MessageError::TooLarge);
        }
        let wire: WireIn = serde_json::from_slice(data)
            .map_err(MessageError::with_step("failed to parse message JSON"))?;
        if wire.version != VERSION {
            return Err(MessageError::UnsupportedVersion(wire.version));
        }
        Message::try_from(wire).map_err(MessageError::Invalid)
    }

    /// Parse a gossip payload that may end in the trailer of a resend (see
    /// [`WireFrame::with_resend_nonce`](wire::WireFrame::with_resend_nonce)). Returns the message and the nonce, if any. The trailer is
    /// outside the signature: it changes the gossip message id and nothing else.
    ///
    /// # Errors
    /// # Errors
    /// A [`MessageError`] as for [`Message::parse`].
    pub fn parse_wire(data: &[u8]) -> Result<(Self, Option<u64>), MessageError> {
        let (frame, nonce) = split_resend_trailer(data);
        Ok((Self::parse(frame)?, nonce))
    }

    /// Deterministic, domain-separated, length-prefixed encoding of every
    /// signed field (i.e. all of them **except** `sig`, including
    /// `pubkey` so the key is bound to the message). This — not the JSON —
    /// is what gets signed and hashed, so signature verification does not
    /// depend on JSON formatting. `kind` and `ext` are folded in via their
    /// (deterministic, sorted-key) `serde_json` encodings.
    #[must_use]
    /// # Panics
    /// If a field exceeds `u32::MAX` bytes; the wire cap makes that unreachable.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_with_key(self.author_key().as_ref())
    }

    /// [`Self::canonical_bytes`] as if the author key were `key`. The signature is not in
    /// the signed bytes, so a message under signing has the key and not yet the signature.
    fn canonical_with_key(&self, key: Option<&AuthorKey>) -> Vec<u8> {
        const DOMAIN: &[u8] = b"habilis-mesh/msg";
        let mut buf = Vec::new();
        let mut field = |bytes: &[u8]| {
            buf.extend_from_slice(
                &u32::try_from(bytes.len())
                    .expect("a message field fits in u32")
                    .to_le_bytes(),
            );
            buf.extend_from_slice(bytes);
        };
        field(DOMAIN);
        field(self.version.as_bytes());
        field(self.id.as_str().as_bytes());
        field(&serde_json::to_vec(&self.kind).unwrap_or_default());
        field(self.mesh.as_str().as_bytes());
        field(self.author.as_str().as_bytes());
        field(&self.timestamp.to_le_bytes());
        field(self.body.as_str().as_bytes());
        // The hex text of the key, not its 32 bytes: the text is what every signature covers.
        match key {
            Some(key) => field(&key.hex()),
            None => field(&[]),
        }
        // `seq`/`prev` are signed too. `None` encodes as a zero-length field
        // (distinct from `Some(0)`, which is 8 bytes), so a plumbing message
        // and a `seq 0` message never collide.
        match self.seq {
            Some(value) => field(&value.to_le_bytes()),
            None => field(&[]),
        }
        match &self.prev {
            Some(value) => field(&value.hex()),
            None => field(&[]),
        }
        // Parents (DAG causal links) are signed too. Serialized as their
        // deterministic JSON array; empty for no-parent messages.
        field(&serde_json::to_vec(&self.parents).unwrap_or_default());
        // The shard header is signed so a shard can't be re-grouped or
        // re-indexed by a relay. `None` (ordinary message) folds as `null`.
        field(&serde_json::to_vec(&self.shard).unwrap_or_default());
        field(&serde_json::to_vec(&self.ext).unwrap_or_default());
        buf
    }

    /// This message's content hash (SHA-256 of [`Message::canonical_bytes`]) — the id used by
    /// another author's `prev` backlink and by fork detection, and the key of the DAG.
    /// Recomputed locally on receive; never trusted off the wire.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::of(&self.canonical_bytes())
    }

    /// The key that signed this message, or `None` for an unsigned message. Outside this module
    /// a message that is not known to be signed has no proven key: a [`Verified`] or an
    /// [`Authored`] gives it through `key()`, with no `Option`.
    #[must_use]
    pub(crate) fn author_key(&self) -> Option<AuthorKey> {
        self.signer.map(|signed| signed.key)
    }

    /// The 16-byte dedup / anti-entropy key (`SHA-256(pubkey ‖ id)[..16]`).
    /// Dedup, the message/state logs, and the digest all key on this rather
    /// than the sender-chosen id, so a forged message reusing a victim's id
    /// cannot suppress the genuine one. See `identity::dedup_key16`.
    #[must_use]
    pub fn dedup_key(&self) -> DedupKey {
        identity::dedup_key16(self.author_key().as_ref(), &self.id.as_uuid_bytes())
    }

    /// Stamp the per-author log fields before signing (`Msg` only). `seq`
    /// is the author's monotonic counter, `prev` the hash of their previous
    /// `Msg` (`None` at `seq 0`). Consuming-builder so it composes with
    /// [`sign`](Self::sign): `Message::new_app(..).with_chain(..).sign(..)`.
    #[must_use]
    pub fn with_chain(mut self, seq: u64, prev: Option<ContentHash>) -> Self {
        self.seq = Some(seq);
        self.prev = prev;
        self
    }

    /// Stamp the cross-author DAG `parents` (content hashes of the tips
    /// seen when authoring) before signing. Consuming-builder, composes
    /// with [`with_chain`](Self::with_chain) and [`sign`](Self::sign).
    #[must_use]
    pub fn with_parents(mut self, parents: impl IntoIterator<Item = ContentHash>) -> Self {
        self.parents = parents.into_iter().collect();
        self
    }

    /// Stamp the [`Shard`] header (which slice of a split body this
    /// message carries) before signing. `None` leaves it an ordinary message.
    #[must_use]
    pub fn with_shard(mut self, shard: Option<Shard>) -> Self {
        self.shard = shard;
        self
    }

    /// Replace the minted random id before signing. The chat path pins the
    /// frame id to the payload's own logical id so every consumer-visible id
    /// (dedup, poll cursor, echo) *is* the payload's own id; receive validates the two
    /// agree.
    #[must_use]
    pub fn with_id(mut self, id: MessageId) -> Self {
        self.id = id;
        self
    }

    /// The serialized wire size **without** the `MAX_MESSAGE_SIZE` gate, for
    /// deciding how to split a body. `serialize` is the gated counterpart.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        serde_json::to_vec(&Wire(self)).map_or(usize::MAX, |bytes| bytes.len())
    }

    /// Sign this message with `identity` and return it as a [`Verified`], the proof that its
    /// signature covers these exact bytes. The key is part of the signed bytes, so they are
    /// computed with the key and before the signature exists; consuming-builder style so it composes
    /// in the construction expression (`Message::new_app(..).sign(&id)`).
    #[must_use]
    pub fn sign(mut self, identity: &Identity) -> Verified {
        let key = identity.author_key();
        let signature = identity.sign(&self.canonical_with_key(Some(&key)));
        self.signer = Some(Signer::new(key, signature));
        Verified::new(self, key)
    }

    /// Check the signature of an untrusted message over its canonical bytes. `Ok` is the proof. `Err`
    /// gives the message back unchanged, because it is unsigned or its signature does not verify.
    ///
    /// # Errors
    ///
    /// Returns the message itself when [`verify_signature_with`](Self::verify_signature_with) fails.
    #[expect(
        clippy::result_large_err,
        reason = "the error is the message itself, handed back unchanged for the caller to drop or keep"
    )]
    pub fn verify(self) -> Result<Verified, Message> {
        self.verify_canonical().map(|(verified, _)| verified)
    }

    /// [`verify`](Self::verify), and also the canonical bytes that were checked, so the receive path
    /// serializes each inbound frame once. The bytes are computed here from this message, never taken
    /// from the caller, so they are always the bytes the signature covers.
    ///
    /// # Errors
    ///
    /// Returns the message itself when its signature does not verify.
    ///
    /// Outside the crate the canonical bytes cannot be supplied by the caller: `verify_with` is
    /// crate-private, so an edited clone cannot be checked against another message's bytes.
    ///
    /// ```compile_fail,E0624
    /// use habilis_network_protocol::message::Message;
    ///
    /// const SIGNED: &str = r#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","pubkey":"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","sig":"eeea2aca75b3ef10bd592fe6a835e147def33b203c0bfcf26253edb7b7d06a450e383d6fdd3fb0ef153969d16df0e6d4b97f1a7ca434106378d8f772814ad50e","seq":3,"prev":"1111111111111111111111111111111111111111111111111111111111111111","parents":["2222222222222222222222222222222222222222222222222222222222222222"],"ext":{}}"#;
    ///
    /// let message = Message::parse(SIGNED.as_bytes()).unwrap();
    /// let canonical = message.canonical_bytes();
    /// let _ = message.verify_with(&canonical);
    /// ```
    #[expect(
        clippy::result_large_err,
        reason = "the error is the message itself, handed back unchanged for the caller to drop or keep"
    )]
    pub fn verify_canonical(self) -> Result<(Verified, Vec<u8>), Message> {
        let canonical = self.canonical_bytes();
        match self.verify_with(&canonical) {
            Ok(verified) => Ok((verified, canonical)),
            Err(message) => Err(message),
        }
    }

    /// The check behind [`verify_canonical`](Self::verify_canonical), against canonical bytes that
    /// the caller computed. Crate-private: outside the crate the bytes must come from the message.
    #[expect(
        clippy::result_large_err,
        reason = "the error is the message itself, handed back unchanged for the caller to drop or keep"
    )]
    pub(crate) fn verify_with(self, canonical: &[u8]) -> Result<Verified, Message> {
        let Some(signed) = self.signer else {
            return Err(self);
        };
        if !self.verify_signature_with(canonical) {
            return Err(self);
        }
        Ok(Verified::new(self, signed.key()))
    }

    /// Verify the detached signature against the embedded key over the
    /// canonical bytes. `false` if the message is unsigned, the key is not a
    /// point of the curve, or the signature does not match — never panics.
    /// (Whether the key is the *expected* identity for this `author` is the
    /// receiver's TOFU check, separate from this cryptographic check.)
    /// Convenience wrapper that computes the canonical bytes itself. The hot
    /// receive path uses [`verify_signature_with`](Self::verify_signature_with)
    /// to share one `canonical_bytes()` with the content hash; this form is
    /// only the ergonomic one used by tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn verify_signature(&self) -> bool {
        self.verify_signature_with(&self.canonical_bytes())
    }

    /// Like `verify_signature` but against
    /// **precomputed** canonical bytes. The hot receive path computes
    /// `canonical_bytes()` once and reuses it for both this check and the
    /// content hash, instead of re-serializing the message twice per `Msg`.
    /// `canonical` MUST be `self.canonical_bytes()` for the result to be
    /// meaningful.
    #[must_use]
    pub fn verify_signature_with(&self, canonical: &[u8]) -> bool {
        let Some(signed) = &self.signer else {
            return false;
        };
        let Some(public) = signed.key.public_key() else {
            return false;
        };
        identity::verify(&public, canonical, &signed.signature)
    }
}

/// Build the serialized wire bytes for an outbound user message
/// (open or directed reply), returning the bytes alongside the
/// canonical [`Message`] so callers can echo it without re-parsing.
/// The single message-construction point shared by the IPC `msg`
/// command, the library API send path, and interactive stdin.
///
/// # Errors
/// A [`MessageError`] from the message encoding: an oversized payload or a JSON failure.
/// The per-author log + DAG position to stamp on an outbound `Msg`: the
/// chain `seq`/`prev` (Phase 2) and the DAG `parents` (Phase 3). Bundled so
/// [`build_msg_bytes`] stays within the argument budget. Test-only now that the
/// send path (`gossip::broadcast`) stamps the chain inline to interleave it with
/// the multipart split.
#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ChainCtx {
    /// The position of the message in its author's chain.
    pub seq: u64,
    /// The hash of the message before this one.
    pub prev: Option<ContentHash>,
    /// The hashes of the other messages that this one follows.
    pub parents: Vec<ContentHash>,
}

#[cfg(any(test, feature = "test-fixtures"))]
impl ChainCtx {
    /// The genesis position (seq 0, no predecessor, no parents).
    #[must_use]
    pub fn genesis() -> Self {
        ChainCtx {
            seq: 0,
            prev: None,
            parents: Vec::new(),
        }
    }
}

/// The inputs of a test message: the mesh, the author, the body, the chain and the app tag.
#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BuildMsgParams<'mesh> {
    /// The mesh of the message.
    pub mesh: &'mesh MeshId,
    /// The member that signs the message.
    pub author: &'mesh Nickname,
    /// The body to sign.
    pub body: MessageBody,
    /// Where the message sits in its author's chain.
    pub chain: ChainCtx,
    /// The app tag to stamp. A parameter, not a constant: this fixture is used
    /// across crates, and hardcoding one consumer's tag made it build a frame
    /// that consumer would then fail to recognise.
    pub tag: AppTag,
}

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
