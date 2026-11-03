use iroh::EndpointId;

use crate::util::clock::Instant;
use crate::util::tuning::UNICAST_DIGESTS;

/// The chat digest that this node sent to one peer at its last tick, and how the answer is going.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChatAsk {
    pub(crate) peer: EndpointId,
    /// The size of the chat log when the digest went out.
    pub(crate) log_len: usize,
    pub(crate) at: Instant,
    /// How many times the digest was repeated after a full answer.
    pub(crate) retries: u32,
}

/// The state of the unicast form of the digests (see `UNICAST_DIGESTS`).
#[derive(Debug, Clone)]
pub(crate) struct UnicastDigests {
    /// Whether the unicast form is on. The const sets it, so a test can set it either way.
    pub(crate) enabled: bool,
    /// The endpoint of the connection that carried the frame that `ingest` is handling now, or
    /// `None` for a frame that came by gossip. A digest that arrives by unicast is answered to it.
    pub(crate) arrived_from: Option<EndpointId>,
    pub(crate) chat_ask: Option<ChatAsk>,
}

impl Default for UnicastDigests {
    fn default() -> Self {
        Self {
            enabled: UNICAST_DIGESTS,
            arrived_from: None,
            chat_ask: None,
        }
    }
}
