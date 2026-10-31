//! The error of a stream hash token, which does not decode.

use std::error::Error;
use std::fmt;

/// The source of a failed step. A lower layer's error goes in whole.
type BoxedError = Box<dyn Error + Send + Sync>;
/// Why a stream hash token does not decode.
///
/// # Examples
///
/// A text that is not a stream hash returns this error.
///
/// ```
/// use habilis_network_stream::{HashError, StreamHash};
///
/// let error: HashError = StreamHash::decode("not a hash").unwrap_err();
/// assert!(!format!("{error:?}").is_empty());
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum HashError {
    /// The token is not a stream hash of this kind.
    WrongKind,
    /// The hash has a version this build does not know.
    UnknownVersion(u8),
    /// The hash sets flags this build does not know.
    UnknownFlags(u8),
    /// The payload ends before one of its fields.
    Truncated(&'static str),
    /// A field of the hash does not decode.
    Field {
        /// The step that failed, for example `decode the address`.
        step: &'static str,
        /// The error of the layer that decodes the field.
        source: BoxedError,
    },
}

impl HashError {
    pub(crate) fn field<E: Into<BoxedError>>(step: &'static str) -> impl FnOnce(E) -> Self {
        move |source| Self::Field {
            step,
            source: source.into(),
        }
    }
}

impl fmt::Display for HashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongKind => formatter.write_str("not a stream hash: wrong ticket kind"),
            Self::UnknownVersion(version) => {
                write!(formatter, "unsupported stream hash version: {version}")
            }
            Self::UnknownFlags(flags) => write!(
                formatter,
                "unsupported stream hash flags {flags:#04x}: upgrade to a newer build"
            ),
            Self::Truncated(what) => formatter.write_str(what),
            Self::Field { step, .. } => formatter.write_str(step),
        }
    }
}

impl Error for HashError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Field { source, .. } => Some(source.as_ref()),
            Self::WrongKind
            | Self::UnknownVersion(_)
            | Self::UnknownFlags(_)
            | Self::Truncated(_) => None,
        }
    }
}
