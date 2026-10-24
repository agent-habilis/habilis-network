//! The error of a mesh config: the lookups, the transports and the identifier
//! that carries them.

use std::error::Error;
use std::fmt;

/// The source of a failed step. A parser's own error goes in whole.
type BoxedError = Box<dyn Error + Send + Sync>;

/// Why a mesh config is refused, or a mesh identifier does not decode.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConfigError {
    /// A config that is well formed but refused: a combination of lookups and
    /// transports that cannot form a mesh, or a value over a wire limit.
    Invalid(String),
    /// The bytes end before a field they must carry.
    Truncated(&'static str),
    /// A field does not parse.
    Source {
        /// The step that failed, for example `invalid mesh name UTF-8`.
        step: &'static str,
        /// The error of the parser.
        source: BoxedError,
    },
}

impl ConfigError {
    /// Wraps a parser's error. The step is a fixed text, so the message reads
    /// the same as the context it replaces.
    pub(crate) fn source<E>(step: &'static str) -> impl FnOnce(E) -> Self
    where
        E: Into<BoxedError>,
    {
        move |source| Self::Source {
            step,
            source: source.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Truncated(what) | Self::Source { step: what, .. } => formatter.write_str(what),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source { source, .. } => Some(source.as_ref()),
            Self::Invalid(_) | Self::Truncated(_) => None,
        }
    }
}
