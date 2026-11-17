//! What the table does with the Nostr name of a peer.

/// What the table does with the Nostr name of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NostrName {
    /// Frames to the peer may go.
    Allow,
    /// Frames to the peer are stopped by name: a usable path serves the pair.
    Stop,
    /// The table says nothing about the peer: a pair with no connection and no want. A peer that
    /// dials first must get its replies, so no refusal by name stays.
    Forget,
}
