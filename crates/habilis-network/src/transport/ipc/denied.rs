//! The error of an IPC call that the operating system refuses.

use std::{error, fmt};
/// The operating system denied the connect to the daemon socket. A daemon
/// can be alive behind it: a sandbox that blocks the socket gives this error,
/// and no daemon is not the cause. Typed rather than a finished sentence, like
/// [`NoDaemon`](super::NoDaemon): the remedy names a command, and only the
/// consumer knows what its commands are called.
///
/// # Examples
///
/// The socket that the operating system denied, carried by the error. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::ipc::Denied;
///
/// # fn demo(denied: Denied) -> String {
/// denied.socket
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Denied {
    /// The path of the socket that the operating system denied.
    pub socket: String,
}

impl fmt::Display for Denied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "The operating system denied access to the daemon socket '{}'.",
            self.socket
        )
    }
}

impl error::Error for Denied {}
