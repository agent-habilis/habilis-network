//! What a session reports to the application.

use crate::frame::Frame;

/// Something the application should know about.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[non_exhaustive]
pub enum Event<Peer> {
    /// A peer finished its handshake.
    Synchronized {
        /// Who.
        addr: Peer,
    },
    /// Every peer has synchronized; the match starts now.
    Running,
    /// A peer went silent past the timeout.
    Disconnected {
        /// Who.
        addr: Peer,
    },
    /// A peer's checksum disagrees with ours: the two are no longer
    /// simulating the same game. Unrecoverable — see
    /// [`RollbackError::Desync`](crate::RollbackError::Desync).
    Desync {
        /// The frame that disagreed.
        frame: Frame,
        /// Our checksum.
        local: u128,
        /// Theirs.
        remote: u128,
    },
}
