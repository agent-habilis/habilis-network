//! The error of an IPC call that finds no running daemon.

use crate::protocol::Nickname;
/// Nothing is listening on `nickname`'s control socket. Typed rather than a
/// finished sentence: the remedy is "start one with …", which names a command,
/// and only the consumer knows what its commands are called. It appends that
/// half after matching on this.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NoDaemon {
    /// The nickname of the member.
    pub nickname: Nickname,
}

impl std::fmt::Display for NoDaemon {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "No active gossip server running for nickname '{}'.",
            self.nickname
        )
    }
}

impl std::error::Error for NoDaemon {}
