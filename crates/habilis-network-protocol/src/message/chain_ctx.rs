//! The per-author chain position that a test message stamps on itself.

use crate::ContentHash;

/// The per-author log + DAG position to stamp on an outbound `Msg`: the
/// chain `seq`/`prev` (Phase 2) and the DAG `parents` (Phase 3). Bundled so
/// [`super::build_msg_bytes`] stays within the argument budget. Test-only now that the
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
