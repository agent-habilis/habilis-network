//! The error of an IPC call that finds no running daemon.

use crate::protocol::Nickname;
use std::{error, fmt};
/// Nothing is listening on `nickname`'s control socket. Typed rather than a
/// finished sentence: the remedy is "start one with …", which names a command,
/// and only the consumer knows what its commands are called. It appends that
/// half after matching on this.
///
/// # Examples
///
/// The reason that no daemon answered, carried by the error. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::ipc::NoDaemon;
///
/// # fn demo(daemon: NoDaemon) {
/// let _ = daemon;
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NoDaemon {
    /// The nickname of the member.
    pub nickname: Nickname,
}

impl fmt::Display for NoDaemon {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "No active gossip server running for nickname '{}'.",
            self.nickname
        )
    }
}

impl error::Error for NoDaemon {}
