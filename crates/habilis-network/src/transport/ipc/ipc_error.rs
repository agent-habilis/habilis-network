//! The error of an IPC round trip.

use super::no_daemon::NoDaemon;

use std::{error, fmt};
/// Why a command could not reach its daemon.
///
/// [`IpcError::NoDaemon`] is the one a caller acts on (no live daemon to ask).
/// [`IpcError::Internal`] holds the causes no caller acts on: a bad socket name, a
/// round trip that fails, or a response that is too large.
///
/// # Examples
///
/// A control call that finds no daemon returns this error. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::ipc::{IpcError, NoDaemon};
///
/// # fn demo(error: &IpcError) -> bool {
/// matches!(error, IpcError::NoDaemon(_))
/// # }
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum IpcError {
    /// No daemon is listening on the socket.
    NoDaemon(NoDaemon),
    /// A cause no caller acts on. It keeps its text and its chain.
    Internal(Box<dyn error::Error + Send + Sync>),
}

impl IpcError {
    /// Wraps a cause no caller acts on, keeping its text and its chain.
    pub(crate) fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDaemon(error) => fmt::Display::fmt(error, f),
            Self::Internal(error) => fmt::Display::fmt(error.as_ref(), f),
        }
    }
}

impl error::Error for IpcError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(error) => error.source(),
            Self::NoDaemon(_) => None,
        }
    }
}
