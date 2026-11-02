//! The error of an invite ticket: minting it, decoding it, and redeeming it.

use std::error::Error;
use std::fmt;

use crate::base58check::Base58Error;

/// The source of a failed step. A decoder's own error goes in whole.
type BoxedError = Box<dyn Error + Send + Sync>;

/// Why an invite ticket cannot be minted, decoded or redeemed.
///
/// # Examples
///
/// A token that is not `Base58Check` returns this error.
///
/// ```
/// use habilis_network_protocol::invite::{InviteError, InviteTicket};
///
/// let error = InviteTicket::decode("0OIl").unwrap_err();
/// assert!(matches!(error, InviteError::Base58(_)));
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum InviteError {
    /// The token is not a `Base58Check` text.
    Base58(Base58Error),
    /// The ticket names a version this build does not read.
    UnsupportedVersion(String),
    /// The ticket is refused for a reason the text names.
    Refused(&'static str),
    /// The ticket ends before a field it must carry.
    Truncated(&'static str),
    /// A field does not decode.
    Source {
        /// The step that failed, for example `invalid mesh hash utf-8`.
        step: &'static str,
        /// The error of the decoder.
        source: BoxedError,
    },
}

impl InviteError {
    /// Wraps a decoder's error. The step is a fixed text, so the message reads
    /// the same as the context it replaces.
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

impl fmt::Display for InviteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base58(error) => fmt::Display::fmt(error, formatter),
            Self::UnsupportedVersion(message) => formatter.write_str(message),
            Self::Refused(message) | Self::Truncated(message) => formatter.write_str(message),
            Self::Source { step, .. } => formatter.write_str(step),
        }
    }
}

impl Error for InviteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Base58(error) => error.source(),
            Self::Source { source, .. } => Some(source.as_ref()),
            Self::UnsupportedVersion(_) | Self::Refused(_) | Self::Truncated(_) => None,
        }
    }
}
