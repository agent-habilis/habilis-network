//! The `Message` envelope + its value types.
//!
//! - [`MessageBody`] ([`body`]) and [`MessageId`] ([`id`]) — the
//!   validated newtypes the envelope carries.
//! - [`Message`] (this file) — the JSON wire envelope, its
//!   [`MessageKind`] / [`PresenceSubtype`] tags, the constructors, and
//!   (de)serialization.

use std::fmt;

use anyhow::{Context, Result, bail};
#[cfg(any(test, feature = "test-fixtures"))]
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use habilis_network_util::clock;

use super::identity::{self, Identity};
use super::mesh::MeshId;
use super::nickname::Nickname;
use crate::newtype::string_newtype;

mod body;
mod id;
mod shard;

pub use body::{BodyError, MessageBody};
pub use id::{IdError, MessageId};
pub use shard::shard_fits_log;
pub use shard::{Shard, ShardGroup};

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

/// Presence subtype.
/// `Joined`/`Left` are user-visible; `Alive` is a silent keepalive used
/// by the heartbeat-based peer tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceSubtype {
    Joined,
    Left,
    Alive,
}

impl fmt::Display for PresenceSubtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PresenceSubtype::Joined => write!(f, "joined"),
            PresenceSubtype::Left => write!(f, "left"),
            PresenceSubtype::Alive => write!(f, "alive"),
        }
    }
}

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
        MessageKind::Pong { to } => Some(to),
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

    /// # Errors
    /// The tag is empty, longer than 32 bytes, or not an ASCII slug.
    pub fn new(raw: impl Into<String>) -> Result<Self, &'static str> {
        let raw = raw.into();
        if !Self::validate(&raw) {
            return Err("invalid app tag");
        }
        Ok(Self(raw))
    }
}

impl From<&str> for AppTag {
    fn from(raw: &str) -> Self {
        Self::new(raw).expect("invalid app tag")
    }
}

string_newtype!(
/// An opaque request/response correlation id carried on a directed
/// [`MessageKind::App`] frame (the `corr` field). Matched by the engine's
/// pending-call registry to pair a reply with its outstanding call; the app
/// mints and interprets its value (the application layer uses a UUID). Kept generic so
/// the engine correlates without knowing the payload model.
    CorrId,
    error = &'static str,
);

impl CorrId {
    fn validate(raw: &str) -> bool {
        !raw.is_empty() && raw.len() <= 64
    }

    /// # Errors
    /// The correlation id is empty or longer than 64 bytes.
    pub fn new(raw: impl Into<String>) -> Result<Self, &'static str> {
        let raw = raw.into();
        if !Self::validate(&raw) {
            return Err("invalid correlation id");
        }
        Ok(Self(raw))
    }
}

impl<'de> Deserialize<'de> for CorrId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // The engine stays payload-agnostic (the app enforces its own UUID
        // contract), but a length bound caps DoS at the wire boundary: the app
        // mints a 36-char UUID, so anything empty or wildly larger is a crafted
        // frame, not a correlation id. Mirrors [`AppTag`]'s bounded deserialize.
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

impl From<&str> for CorrId {
    fn from(raw: &str) -> Self {
        Self::new(raw).expect("invalid correlation id")
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
pub enum MessageKind {
    /// An application payload. `tag` is the wire discriminant the app dispatches
    /// on (the engine treats it opaquely); `to` is the directed addressee
    /// (`None` for a broadcast); `corr` correlates a request with its reply for
    /// the pending-call registry (`None` for fire-and-forget). Everything else
    /// the payload needs (task id, method, params) rides inside `body`.
    App {
        tag: AppTag,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to: Option<Nickname>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        corr: Option<CorrId>,
    },
    Presence {
        subtype: PresenceSubtype,
    },
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
    /// Response to a `Ping`, addressed to the original pinger (`to`).
    /// The pinger records its local arrival time to compute RTT. Same
    /// plumbing treatment as `Ping`.
    Pong {
        to: Nickname,
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

/// Which shared-state channel an event/digest belongs to. The two channels share
/// all machinery; this selects the wire kind, the log, and the surfaced name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    State,
    Meta,
}

impl Channel {
    pub(crate) fn event_kind(self) -> MessageKind {
        match self {
            Channel::State => MessageKind::State,
            Channel::Meta => MessageKind::Meta,
        }
    }

    pub(crate) fn digest_kind(self) -> MessageKind {
        match self {
            Channel::State => MessageKind::StateDigest,
            Channel::Meta => MessageKind::MetaDigest,
        }
    }

    /// The event name surfaced on the `--output json` stream (`state` / `meta`).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Channel::State => "state",
            Channel::Meta => "meta",
        }
    }
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
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn app_broadcast(tag: &str) -> Self {
        MessageKind::App {
            tag: AppTag::from(tag),
            to: None,
            corr: None,
        }
    }

    /// A directed [`App`](MessageKind::App) kind addressed to `to`, tag `tag`,
    /// with an optional correlation id — the test ergonomic for the former
    /// directed app variants.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn app_to(tag: &str, to: Nickname, corr: Option<CorrId>) -> Self {
        MessageKind::App {
            tag: AppTag::from(tag),
            to: Some(to),
            corr,
        }
    }
}

fn default_ext() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

fn empty_body() -> MessageBody {
    MessageBody::new("").expect("empty string is always a valid MessageBody")
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "v")]
    pub version: String,
    pub id: MessageId,
    #[serde(flatten)]
    pub kind: MessageKind,
    pub mesh: MeshId,
    pub author: Nickname,
    /// Unix timestamp (seconds, UTC).
    #[serde(rename = "ts")]
    pub timestamp: i64,
    pub body: MessageBody,
    /// Author's Ed25519 public key (lowercase hex), and the detached
    /// signature over the message's [canonical bytes](Message::canonical_bytes).
    /// Empty on an unsigned message: the empty fields are skipped, which is
    /// also the **canonical pre-signing form** that [`Message::canonical_bytes`] hashes
    /// (the signature cannot cover itself). Real outbound traffic is always
    /// signed on the broadcast path, and the receive path drops anything that
    /// fails verification. See `docs/history-integrity.md`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pubkey: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig: String,
    /// Per-author hash-linked log (Phase 2), set on `Msg` only: `seq` is
    /// this author's monotonic counter and `prev` the content hash of their
    /// previous `Msg` (`None` at `seq 0`). Both are signed. Plumbing /
    /// presence kinds leave them `None`. The message's own content hash is
    /// computed locally (`content_hash_hex`), never transmitted. See
    /// `docs/history-integrity.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    /// Cross-author DAG (Phase 3), `Msg` only: content hashes of the DAG
    /// tips this author had seen when authoring — the causal links. Signed.
    /// Empty for the very first message / messages with no observed
    /// predecessor. See `docs/history-integrity.md`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<String>,
    /// Shard header: present only on a message that is one slice of a body
    /// too large for a single message (see [`Shard`]). `None` on an ordinary
    /// message, so its wire form is unchanged. Signed like every other field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard: Option<Shard>,
    /// Extension escape hatch. Add experimental fields here; stable fields get promoted to top-level.
    #[serde(default = "default_ext")]
    pub ext: serde_json::Value,
}

/// Is `value` exactly `bytes * 2` lowercase-hex characters — the canonical
/// wire form of a fixed-width binary field (pubkey / signature / hash)?
fn is_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Parameters for [`Message::new_app`] (and `habilis_network::ops::send_app`, which
/// shares the same `App` frame shape).
#[derive(Debug)]
pub struct AppFrameParams {
    pub tag: AppTag,
    pub to: Option<Nickname>,
    pub corr: Option<CorrId>,
    pub body: MessageBody,
}

impl Message {
    fn new(mesh: &MeshId, author: &Nickname, kind: MessageKind, body: MessageBody) -> Self {
        Message {
            version: VERSION.to_string(),
            id: MessageId::random(),
            kind,
            mesh: mesh.clone(),
            author: author.clone(),
            timestamp: clock::unix_secs(),
            body,
            pubkey: String::new(),
            sig: String::new(),
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

    /// A `Pong` response addressed to the original pinger (`to`).
    #[must_use]
    pub fn new_pong(mesh: &MeshId, author: &Nickname, to: Nickname) -> Self {
        Self::new(mesh, author, MessageKind::Pong { to }, empty_body())
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
    /// `host`-only with the transport that mints the vectors. The *kind* stays
    /// portable — a browser still receives and ignores a peer's advertisement.
    #[cfg(feature = "host")]
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

    /// Serialize to compact JSON bytes for the gossip wire.
    /// # Errors
    /// Serialization of a field fails.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).context("failed to serialize message")?;
        if bytes.len() > MAX_MESSAGE_SIZE {
            bail!(
                "message too large: {} bytes (max {})",
                bytes.len(),
                MAX_MESSAGE_SIZE
            );
        }
        Ok(bytes)
    }

    /// Parse a message from JSON bytes.
    /// # Errors
    /// The bytes are malformed or truncated.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() > MAX_MESSAGE_SIZE {
            bail!("message too large");
        }
        let msg: Message = serde_json::from_slice(data).context("failed to parse message JSON")?;
        if msg.version != VERSION {
            bail!("unsupported protocol version: {}", msg.version);
        }
        // Shape-check the history-integrity fields at the boundary, so a crafted
        // value never reaches signature verification or the fork/DAG indexes
        // (which key on `prev`/`parents` as content hashes). Empty `pubkey`/`sig`
        // is the canonical unsigned form — the receive path drops anything that
        // then fails verification; a *present* key/sig/hash must be well-formed
        // lowercase hex of the right length (Ed25519 pubkey 32B, signature 64B,
        // SHA-256 hash 32B).
        if !msg.pubkey.is_empty() && !is_lower_hex(&msg.pubkey, 32) {
            bail!("malformed pubkey");
        }
        if !msg.sig.is_empty() && !is_lower_hex(&msg.sig, 64) {
            bail!("malformed signature");
        }
        if let Some(prev) = &msg.prev
            && !is_lower_hex(prev, 32)
        {
            bail!("malformed prev hash");
        }
        if msg.parents.iter().any(|hash| !is_lower_hex(hash, 32)) {
            bail!("malformed parent hash");
        }
        Ok(msg)
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
        field(self.pubkey.as_bytes());
        // `seq`/`prev` are signed too. `None` encodes as a zero-length field
        // (distinct from `Some(0)`, which is 8 bytes), so a plumbing message
        // and a `seq 0` message never collide.
        match self.seq {
            Some(value) => field(&value.to_le_bytes()),
            None => field(&[]),
        }
        match &self.prev {
            Some(value) => field(value.as_bytes()),
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

    /// This message's content hash (SHA-256 of [`Message::canonical_bytes`], hex) —
    /// the id used by another author's `prev` backlink and by fork
    /// detection. Recomputed locally on receive; never trusted off the wire.
    #[must_use]
    pub fn content_hash_hex(&self) -> String {
        identity::content_hash_hex(&self.canonical_bytes())
    }

    /// The 16-byte dedup / anti-entropy key (`SHA-256(pubkey ‖ id)[..16]`).
    /// Dedup, the message/state logs, and the digest all key on this rather
    /// than the sender-chosen id, so a forged message reusing a victim's id
    /// cannot suppress the genuine one. See [`identity::dedup_key16`].
    #[must_use]
    pub fn dedup_key(&self) -> [u8; 16] {
        identity::dedup_key16(&self.pubkey, &self.id.as_uuid_bytes())
    }

    /// Stamp the per-author log fields before signing (`Msg` only). `seq`
    /// is the author's monotonic counter, `prev` the hash of their previous
    /// `Msg` (`None` at `seq 0`). Consuming-builder so it composes with
    /// [`signed`](Self::signed): `Message::new_app(..).with_chain(..).signed(..)`.
    #[must_use]
    pub fn with_chain(mut self, seq: u64, prev: Option<String>) -> Self {
        self.seq = Some(seq);
        self.prev = prev;
        self
    }

    /// Stamp the cross-author DAG `parents` (content hashes of the tips
    /// seen when authoring) before signing. Consuming-builder, composes
    /// with [`with_chain`](Self::with_chain) and [`signed`](Self::signed).
    #[must_use]
    pub fn with_parents(mut self, parents: Vec<String>) -> Self {
        self.parents = parents;
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
        serde_json::to_vec(self).map_or(usize::MAX, |bytes| bytes.len())
    }

    /// Sign this message with `identity`, filling `pubkey` then `sig`.
    /// `pubkey` is set before the canonical bytes are computed so the key
    /// is part of what is signed; consuming-builder style so it composes in
    /// the construction expression (`Message::new_app(..).signed(&id)`).
    #[must_use]
    pub fn signed(mut self, identity: &Identity) -> Self {
        self.pubkey = identity::encode_pubkey(&identity.public());
        self.sig = identity::encode_sig(&identity.sign(&self.canonical_bytes()));
        self
    }

    /// Verify the detached signature against the embedded `pubkey` over the
    /// canonical bytes. `false` if either field is absent/malformed or the
    /// signature does not match — never panics. (Whether `pubkey` is the
    /// *expected* identity for this `author` is the receiver's TOFU check,
    /// separate from this cryptographic check.)
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
        if self.pubkey.is_empty() || self.sig.is_empty() {
            return false;
        }
        let (Ok(pubkey), Ok(sig)) = (
            identity::decode_pubkey(&self.pubkey),
            identity::decode_sig(&self.sig),
        ) else {
            return false;
        };
        identity::verify(&pubkey, canonical, &sig)
    }
}

/// Build the serialized wire bytes for an outbound user message
/// (open or directed reply), returning the bytes alongside the
/// canonical [`Message`] so callers can echo it without re-parsing.
/// The single message-construction point shared by the IPC `msg`
/// command, the library API send path, and interactive stdin.
///
/// # Errors
/// Propagates [`Message::serialize`] failure (oversized payload).
/// The per-author log + DAG position to stamp on an outbound `Msg`: the
/// chain `seq`/`prev` (Phase 2) and the DAG `parents` (Phase 3). Bundled so
/// [`build_msg_bytes`] stays within the argument budget. Test-only now that the
/// send path (`gossip::broadcast`) stamps the chain inline to interleave it with
/// the multipart split.
#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Debug)]
pub struct ChainCtx {
    pub seq: u64,
    pub prev: Option<String>,
    pub parents: Vec<String>,
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

#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Debug)]
pub struct BuildMsgParams<'a> {
    pub mesh: &'a MeshId,
    pub author: &'a Nickname,
    pub body: MessageBody,
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
) -> Result<(Bytes, Message)> {
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
    .signed(identity);
    let raw = msg.serialize()?;
    Ok((Bytes::from(raw), msg))
}

#[cfg(any(test, feature = "test-fixtures"))]
impl Message {
    #[must_use]
    pub fn fixture(kind: MessageKind, body: &str) -> Self {
        Message {
            version: VERSION.to_string(),
            id: "00000000-0000-0000-0000-000000000001".into(),
            kind,
            mesh: MeshId::from("test"),
            author: "alice-bot".into(),
            timestamp: 1_700_000_000,
            body: body.into(),
            pubkey: String::new(),
            sig: String::new(),
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
