//! The gossip topic identifier, as bytes.
//!
//! iroh-gossip has its own `TopicId`, and this crate used to return it
//! directly. That single type was the only thing tying the wire vocabulary to
//! iroh-gossip — and through it to iroh, tokio and QUIC — for what is really
//! just 32 bytes out of a hash. Keeping a byte-shaped identifier here is what
//! lets `habilis-network-protocol` build with neither.
//!
//! `habilis-network` converts at the gossip boundary (`daemon::setup`),
//! which is the only place that needs the iroh-gossip type.

/// A gossip topic: the 32 bytes derived from a mesh's seed, name and config by
/// [`crypto::derive_topic_id`](crate::crypto::derive_topic_id).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TopicId([u8; 32]);

impl TopicId {
    /// Wrap 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, borrowed.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The raw bytes, owned — what the conversion to iroh-gossip's `TopicId`
    /// consumes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

// Hex, matching how iroh-gossip's `TopicId` renders. A derived `Debug` would
// print a 32-element byte array instead, which is unreadable in a log line and
// would silently churn the pinned golden in `mesh::mesh_tests`.
impl std::fmt::Debug for TopicId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TopicId({self})")
    }
}

impl std::fmt::Display for TopicId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<[u8; 32]> for TopicId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<TopicId> for [u8; 32] {
    fn from(topic: TopicId) -> Self {
        topic.0
    }
}
