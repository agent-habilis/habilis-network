//! What the frame loop asks the event loop to send.

use habilis_network::protocol::AuthorKey;

/// What the frame loop asks the event loop to send.
///
/// Pushed through `Node::sender()`; drained by
/// [`handle_session`](super::RollbackDriver), which is where `&mut EventLoopState`
/// finally exists.
#[derive(Debug)]
#[non_exhaustive]
pub enum Outbound {
    /// A rollback packet for one peer, addressed by public key.
    Rollback {
        /// The recipient's public key.
        to: AuthorKey,
        /// Pre-serialized packet.
        payload: String,
    },
    /// A lobby packet for everyone currently in the mesh roster.
    Lobby {
        /// Pre-serialized packet.
        payload: String,
    },
}
