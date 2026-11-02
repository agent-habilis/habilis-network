//! The per-author chain position that a test message stamps on itself.

use crate::ContentHash;

/// The per-author log + DAG position to stamp on an outbound `Msg`: the
/// chain `seq`/`prev` (Phase 2) and the DAG `parents` (Phase 3). Bundled so
/// [`super::build_msg_bytes()`] stays within the argument budget. Test-only now that the
/// send path (`gossip::broadcast`) stamps the chain inline to interleave it with
/// the multipart split.
///
/// # Examples
///
/// The first message of an author has sequence 0 and no earlier message.
///
/// ```
/// use habilis_network_protocol::messages::ChainCtx;
///
/// let chain = ChainCtx::genesis();
/// assert_eq!(chain.seq, 0);
/// assert!(chain.previous.is_none());
/// ```
#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ChainCtx {
    /// The position of the message in its author's chain.
    pub seq: u64,
    /// The hash of the message before this one.
    pub previous: Option<ContentHash>,
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
            previous: None,
            parents: Vec::new(),
        }
    }
}
