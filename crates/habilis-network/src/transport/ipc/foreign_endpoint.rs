//! The error of a client whose endpoint belongs to another account.

use std::{error, fmt};

use super::ipc_name::IpcName;
use crate::protocol::Nickname;

/// The endpoint that a client reached is owned by another account: on Windows
/// the owner of the pipe is not the current user, or its owner cannot be read.
/// A squat, not an absent daemon, so the remedy "start one" does not fit it. The
/// client sends nothing to such an endpoint.
///
/// # Examples
///
/// The error names the nickname that the client asked for, when it had one. The
/// doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::ipc::ForeignEndpoint;
///
/// # fn demo(error: &ForeignEndpoint) -> bool {
/// error.nickname.is_some()
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForeignEndpoint {
    /// The nickname that the client asked for; `None` for
    /// [`send_to_endpoint`](super::send_to_endpoint), which addresses the
    /// endpoint by name.
    pub nickname: Option<Nickname>,
    /// The endpoint that was reached.
    pub name: IpcName,
}

impl fmt::Display for ForeignEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.nickname {
            Some(nickname) => write!(
                formatter,
                "The IPC endpoint for '{nickname}' is held by another user; refusing to talk to it."
            ),
            None => write!(
                formatter,
                "The IPC endpoint {} is held by another user; refusing to talk to it.",
                self.name
            ),
        }
    }
}

impl error::Error for ForeignEndpoint {}
