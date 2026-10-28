//! Why a correlation id is refused.

use std::error::Error;
use std::fmt;

/// Why a correlation id is refused: empty or longer than 64 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum CorrIdError {
    /// The text is not a valid correlation id.
    Invalid,
}

impl fmt::Display for CorrIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid correlation id")
    }
}

impl Error for CorrIdError {}
