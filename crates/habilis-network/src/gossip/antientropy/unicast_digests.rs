use iroh::EndpointId;

use crate::util::clock::Instant;

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

/// The state of the unicast form of the digests. A node sends its chat and state digests by unicast
/// to one random linked peer. The peer that holds more answers the asker only, on a unicast stream,
/// with the frames as they were signed (no new nonce, no re-broadcast). A digest that arrives
/// broadcast (an older peer) is answered by unicast too. Where no unicast path can start, the digest
/// and the answer go on gossip.
#[derive(Debug, Clone, Default)]
pub(crate) struct UnicastDigests {
    /// The endpoint of the connection that carried the frame that `ingest` is handling now, or
    /// `None` for a frame that came by gossip. A digest that arrives by unicast is answered to it.
    pub(crate) arrived_from: Option<EndpointId>,
    pub(crate) chat_ask: Option<ChatAsk>,
}
