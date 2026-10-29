use crate::protocol::mesh::MeshName;
use crate::protocol::message::Authored;
use crate::protocol::{AuthorKey, Channel, MeshId, Nickname};

#[cfg(test)]
use std::sync::atomic;
#[cfg(test)]
use std::sync::atomic::Ordering;
/// A generic surfacing the engine emits — the chat-agnostic subset of the app's
/// `OutputEvent`. The app's [`NodeSink`] impl maps each variant onto the
/// existing `Output` method, so the rendered stdout / `--output json` / library API
/// forms stay byte-identical.
///
/// # Examples
///
/// A node event says what happened, such as an info line.
///
/// ```
/// use habilis_network::embed::NodeEvent;
///
/// let event = NodeEvent::Info("started".to_owned());
/// assert!(matches!(event, NodeEvent::Info(_)));
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NodeEvent {
    /// The daemon can serve. Mesh identity only — a consumer that wants to
    /// announce startup diagnostics of its own (a stale install, a localhost
    /// port it bound) splices them in on receipt; the engine has no notion of
    /// either and used to carry them purely to hand them back.
    Ready {
        /// The mesh id.
        mesh: MeshId,
        /// The mesh name.
        name: MeshName,
        /// The nickname of this member.
        nickname: Nickname,
    },
    /// An informational line.
    Info(String),
    /// An error line.
    Error(String),
    /// The author forked its chain.
    Fork {
        /// The nickname of the member.
        nickname: Nickname,
        /// The public key of the member, in hex.
        pubkey: String,
        /// The sequence number of the message.
        seq: u64,
    },
    /// A member went quiet.
    PeerTimeout {
        /// The nickname of the member.
        nickname: Nickname,
        /// Seconds since the member was last heard from.
        last_seen_secs_ago: u64,
    },
    /// A member came back.
    PeerReturn {
        /// The nickname of the member.
        nickname: Nickname,
    },
    /// A peer's arrival, departure, or announcement. `msg` is the proof of the presence
    /// frame, and for a `synthetic` presence it is the proof this node minted (its own
    /// signature, the peer's nickname). `peer` is the key of the peer the presence is
    /// about: the signer of the frame that triggered it. It is never read from `msg`, so
    /// a synthetic presence cannot name the peer by a key it does not hold.
    Presence {
        /// The proof of the presence frame. For a synthetic presence, the proof that this node minted.
        message: Box<Authored>,
        /// The key of the peer that the presence is about: the signer of the frame that triggered it.
        peer: AuthorKey,
        /// `true` when this node minted the presence for a peer's arrival, `false` when
        /// it is the peer's own frame.
        synthetic: bool,
    },
    /// The result of a ping round.
    PingReport {
        /// Each responder and its round-trip time in milliseconds, sorted by
        /// nickname. A pair rather than a named struct: the only consumer maps
        /// it straight onto its own public ping type, so a struct here was one
        /// field-for-field conversion in each direction and nothing else.
        peers: Vec<(Nickname, u64)>,
        /// How many peers the node knows.
        known: usize,
    },
    /// The shared state changed.
    StateChanged {
        /// The channel of the write.
        channel: Channel,
        /// The signed message that carried the write. It is our own when `is_self`.
        event: Box<Authored>,
        /// The shared document after the write.
        document: serde_json::Value,
        /// Whether the write is this member's own.
        is_self: bool,
    },
}

/// The sink the engine emits generic [`NodeEvent`]s through. The app implements
/// it (backed by its `Output` renderer); the engine holds only a `&dyn NodeSink`
/// / `Arc<dyn NodeSink>` and never names the concrete sink.
///
/// # Examples
///
/// A sink receives each node event as it happens.
///
/// ```
/// use habilis_network::embed::{NodeEvent, NodeSink};
///
/// struct Printer;
///
/// impl NodeSink for Printer {
///     fn emit(&self, event: NodeEvent) {
///         let _ = event;
///     }
/// }
///
/// Printer.emit(NodeEvent::Info("started".to_owned()));
/// ```
pub trait NodeSink: Send + Sync {
    /// Send an event to the consumer.
    fn emit(&self, event: NodeEvent);
}

// a shared sink is a sink: the loop and the setup hold the same Arc
impl<T: NodeSink + ?Sized> NodeSink for std::sync::Arc<T> {
    fn emit(&self, event: NodeEvent) {
        (**self).emit(event);
    }
}

/// A sink that drops every [`NodeEvent`]. The no-op emitter for an embedder that
/// renders nothing from the engine's transport/membership surfacings (e.g. a
/// bytes-piping consumer that only reacts to its own `App` frames), and for
/// tests that need a sink handle without asserting on it.
///
/// # Examples
///
/// A silent sink accepts events and drops them.
///
/// ```
/// use habilis_network::embed::{NodeEvent, NodeSink, SilentSink};
///
/// SilentSink::default().emit(NodeEvent::Info("quiet".to_owned()));
/// ```
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SilentSink;

impl NodeSink for SilentSink {
    fn emit(&self, _event: NodeEvent) {}
}

/// A test sink that counts emitted [`NodeEvent`]s without inspecting them —
/// enough to assert an engine surfacing fired (and how many times) without
/// pulling the app's `Output` into an engine test.
#[cfg(test)]
pub(crate) struct CountingSink(atomic::AtomicUsize);

#[cfg(test)]
impl CountingSink {
    pub(crate) fn new() -> Self {
        Self(atomic::AtomicUsize::new(0))
    }

    pub(crate) fn count(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
impl NodeSink for CountingSink {
    fn emit(&self, _event: NodeEvent) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
