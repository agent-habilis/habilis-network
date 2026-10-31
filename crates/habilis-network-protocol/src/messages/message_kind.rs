//! The routing discriminator of a message: the kind of frame it carries.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{AppTag, CorrId, MessageId, PresenceSubtype};
use crate::nickname_error::Nickname;

/// Message kind — the frame's routing discriminator. The engine owns the
/// infrastructure kinds (presence, peer-info, digests, ping/pong, channel
/// events, link-state); all application payloads ride the single generic
/// [`App`](MessageKind::App) variant, distinguished by its opaque `tag`.
/// - `App`: an application payload — the body is a whole serialized app object
///   (e.g. a broadcast chat message, a task leg, a directed JSON-RPC envelope),
///   opaque to this layer and dispatched on `tag`.
/// - `Presence`: agent lifecycle (joined/left), empty body.
/// - `PeerInfo`: infrastructure — carries endpoint address for mesh formation. Not user-visible.
///
/// # Examples
///
/// A frame that is not an application frame has no app tag.
///
/// ```
/// use habilis_network_protocol::messages::MessageKind;
///
/// assert!(MessageKind::State.app_tag().is_none());
/// assert!(!MessageKind::Meta.is_app("chat"));
/// ```
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
