//! What a signal says.

use serde::{Deserialize, Serialize};

/// What a signal says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum SignalKind {
    /// "I am here": on the room tag to everyone, or on a member's self tag to
    /// wake it.
    Hello,
    /// A `WebRTC` offer, to the answering member's self tag.
    Offer,
    /// The answer to the offer whose nonce is in `re`.
    Answer,
    /// The answerer is at its session cap; `re` names the refused offer.
    Refuse,
}
