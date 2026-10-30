//! The redial counter: how often a peer is dialled again soon after a close.

use super::track::Track;

/// The three tracks of a node: every live QUIC connection (the gossip links too), the pooled
/// unicast connections that a send used, and the `WebRTC` sessions.
#[derive(Debug, Default, Clone)]
pub(crate) struct Redials {
    pub(crate) quic: Track,
    pub(crate) pool: Track,
    pub(crate) session: Track,
}
