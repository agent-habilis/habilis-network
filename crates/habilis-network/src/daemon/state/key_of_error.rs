//! Why a nickname names no single key.

use std::error::Error;
use std::fmt;

/// Why [`EventLoopState::key_of`](super::EventLoopState::key_of) names no key.
///
/// # Examples
///
/// A nickname that no live key uses is unknown.
///
/// ```
/// use habilis_network::embed::KeyOfError;
///
/// assert_ne!(KeyOfError::Unknown, KeyOfError::Ambiguous);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum KeyOfError {
    /// No live key uses the nickname.
    Unknown,
    /// Two or more live keys use the nickname. A nickname is a label, so the engine never picks
    /// one of them.
    Ambiguous,
}

impl fmt::Display for KeyOfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("no live peer uses this nickname"),
            Self::Ambiguous => f.write_str("two or more live peers use this nickname"),
        }
    }
}

impl Error for KeyOfError {}
