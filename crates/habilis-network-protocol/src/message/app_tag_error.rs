//! Why an app tag is refused.

use std::error::Error;
use std::fmt;

/// Why an app tag is refused: empty, longer than 32 bytes, or not an ASCII slug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum AppTagError {
    /// The text is not a valid app tag.
    Invalid,
}

impl fmt::Display for AppTagError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid app tag")
    }
}

impl Error for AppTagError {}
