//! One slot of the admission table.

use iroh::endpoint::WeakConnectionHandle;

use super::Round;

/// Everything held under one peer.
#[derive(Debug)]
pub(crate) struct Slot {
    /// The signalling round that holds the negotiation slot.
    pub(crate) round: Option<Round>,
    /// Every QUIC connection to the peer, whatever its protocol or path.
    pub(crate) conns: Vec<WeakConnectionHandle>,
    /// Which round holds the slot: a guard releases the slot only if its round still does.
    pub(crate) epoch: u64,
    /// The round that holds the slot is an offer of this node, not an answer.
    pub(crate) outgoing: bool,
}

impl Slot {
    pub(crate) fn new() -> Self {
        Self {
            round: None,
            conns: Vec::new(),
            epoch: 0,
            outgoing: false,
        }
    }
}
