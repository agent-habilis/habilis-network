//! The error of an IPC round trip.

use super::no_daemon::NoDaemon;

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
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

impl IpcError {
    /// Wraps a cause no caller acts on, keeping its text and its chain.
    pub(crate) fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDaemon(error) => std::fmt::Display::fmt(error, f),
            Self::Internal(error) => std::fmt::Display::fmt(error.as_ref(), f),
        }
    }
}

impl std::error::Error for IpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(error) => error.source(),
            Self::NoDaemon(_) => None,
        }
    }
}
