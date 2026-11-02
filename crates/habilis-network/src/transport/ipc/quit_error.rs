//! Why the IPC quit did not stop a daemon.

use std::{error, fmt};

/// Why [`quit`](super::quit) did not stop a daemon.
///
/// # Examples
///
/// On Unix the IPC quit does not exist. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::ipc::QuitError;
///
/// # fn demo(error: &QuitError) -> bool {
/// matches!(error, QuitError::Unsupported)
/// # }
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum QuitError {
    /// The IPC quit exists only on Windows. On Unix a daemon stops on
    /// `SIGTERM`, which [`terminate`](super::terminate) sends.
    Unsupported,
    /// The quit was not heard: no marker, nothing accepts on the endpoint, an
    /// endpoint of another account, a failed exchange, or no answer.
    Unreached(anyhow::Error),
    /// The daemon answered that it cannot parse the quit: it is of a version
    /// from before the command. Holds the answer. An app error that starts
    /// with the same text (`parse error`) reads the same.
    OldDaemon(String),
    /// The daemon heard the quit and refused it, for example because the mesh
    /// is not its own, or answered with something that is no JSON. Holds the
    /// answer.
    Refused(String),
}

impl fmt::Display for QuitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => {
                formatter.write_str("the IPC quit is Windows only; on Unix send SIGTERM")
            }
            Self::Unreached(error) => write!(formatter, "the quit was not heard: {error}"),
            Self::OldDaemon(reply) => write!(
                formatter,
                "the daemon does not know the quit command: {reply}"
            ),
            Self::Refused(reply) => write!(formatter, "the daemon refused the quit: {reply}"),
        }
    }
}

impl error::Error for QuitError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Unreached(error) => Some(error.as_ref()),
            Self::Unsupported | Self::OldDaemon(_) | Self::Refused(_) => None,
        }
    }
}
