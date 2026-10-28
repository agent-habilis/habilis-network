//! The errors of the message wire: a message that does not parse or encode,
//! and the tags and correlation ids a message carries.

use std::error::Error;
use std::fmt;

use super::MAX_MESSAGE_SIZE;

/// The source of a failed step. A parser's own error goes in whole.
type BoxedError = Box<dyn Error + Send + Sync>;

/// Why a message does not parse or encode.
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum MessageError {
    /// The bytes are larger than a message may be.
    TooLarge,
    /// The message encodes to more bytes than a message may be.
    Oversize {
        /// The size the message encodes to.
        bytes: usize,
    },
    /// The message names a protocol version this build does not read.
    UnsupportedVersion(String),
    /// A field does not hold a value the protocol allows.
    Invalid(&'static str),
    /// The JSON does not encode or decode.
    Source {
        /// The step that failed, for example `failed to parse message JSON`.
        step: &'static str,
        /// The error of the JSON layer.
        source: BoxedError,
    },
}

impl MessageError {
    /// Wraps a JSON error. The step is a fixed text, so the message reads the
    /// same as the context it replaces.
    pub(crate) fn with_step<E>(step: &'static str) -> impl FnOnce(E) -> Self
    where
        E: Into<BoxedError>,
    {
        move |source| Self::Source {
            step,
            source: source.into(),
        }
    }
}

impl fmt::Display for MessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => formatter.write_str("message too large"),
            Self::Oversize { bytes } => write!(
                formatter,
                "message too large: {bytes} bytes (max {MAX_MESSAGE_SIZE})"
            ),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported protocol version: {version}")
            }
            Self::Invalid(reason) => formatter.write_str(reason),
            Self::Source { step, .. } => formatter.write_str(step),
        }
    }
}

impl Error for MessageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source { source, .. } => Some(source.as_ref()),
            Self::TooLarge
            | Self::Oversize { .. }
            | Self::UnsupportedVersion(_)
            | Self::Invalid(_) => None,
        }
    }
}

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
