//! Why a text is no IPC name of this OS.

use std::{error, fmt};

/// Why [`IpcName::new`](super::IpcName::new) refused a text.
///
/// # Examples
///
/// An empty text is no name.
///
/// ```
/// use habilis_network::runtime::ipc::{IpcName, IpcNameError};
///
/// assert!(matches!(IpcName::new(String::new()), Err(IpcNameError::Empty)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum IpcNameError {
    /// The text is empty.
    Empty,
    /// The text is longer than the bound, in bytes.
    TooLong(usize),
    /// The text holds a line break.
    LineBreak,
    /// The text is not an endpoint of this OS: an absolute path on Unix, a local
    /// pipe on Windows. Holds the text.
    NotAnEndpoint(String),
}

impl fmt::Display for IpcNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("an IPC name is empty"),
            Self::TooLong(bound) => write!(formatter, "an IPC name is longer than {bound} bytes"),
            Self::LineBreak => formatter.write_str("an IPC name holds a line break"),
            #[cfg(unix)]
            Self::NotAnEndpoint(raw) => {
                write!(
                    formatter,
                    "the IPC name {raw:?} is not an absolute socket path"
                )
            }
            #[cfg(not(unix))]
            Self::NotAnEndpoint(raw) => {
                write!(formatter, "the IPC name {raw:?} is not a local named pipe")
            }
        }
    }
}

impl error::Error for IpcNameError {}
