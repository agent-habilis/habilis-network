//! The error of a chunk store: a backend that fails, a value that is not
//! well formed, or a lock that a panic poisoned.

use std::error::Error;
use std::fmt;

/// The source of a failed step. A backend's own error goes in whole.
type BoxedError = Box<dyn Error + Send + Sync>;

/// Why a chunk store call failed.
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum ChunkError {
    /// A value or a row is not what the call needs: a bad hex text, a row of
    /// the wrong length, a row that is not stored, or bytes that do not address
    /// the hash they claim.
    Malformed(String),
    /// A lock was poisoned by a panic in another thread.
    Poisoned(&'static str),
    /// The backend could not do the step.
    Store {
        /// The step that failed, for example `reading a chunk`.
        step: String,
        /// The error of the backend.
        source: BoxedError,
    },
}

impl fmt::Display for ChunkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(message) => formatter.write_str(message),
            Self::Poisoned(what) => write!(
                formatter,
                "the {what} lock was poisoned by a panic in another thread"
            ),
            Self::Store { step, .. } => formatter.write_str(step),
        }
    }
}

impl Error for ChunkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store { source, .. } => Some(source.as_ref()),
            Self::Malformed(_) | Self::Poisoned(_) => None,
        }
    }
}
