use std::error::Error;
use std::fmt;

/// Why a blob cannot be fetched, offered, or decoded.
///
/// [`BlobError::PasswordRequired`], [`BlobError::PasswordNotNeeded`] and
/// [`BlobError::HandshakeStalled`] are the causes a frontend acts on: it prompts for the
/// password, it drops the flag, or it closes its endpoint and builds a new one.
/// [`BlobError::Internal`] holds the other causes, which no caller acts on.
///
/// # Examples
///
/// A blob that is protected by a password returns this error without one.
///
/// ```
/// use habilis_network::ops::blob::BlobError;
///
/// assert!(matches!(BlobError::PasswordRequired, BlobError::PasswordRequired));
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum BlobError {
    /// The ticket is password-protected, and no password was given.
    PasswordRequired,
    /// The ticket has no password, and one was given.
    PasswordNotNeeded,
    /// The producer never completed the handshake, on each of the attempts, each longer than the
    /// last. A fetch over an endpoint of the caller (`fetch_with_endpoint`) returns this. A retry
    /// from the same endpoint can stall again: close it and build a new one.
    HandshakeStalled,
    /// A cause no caller acts on. It keeps its text and its chain.
    Internal(Box<dyn Error + Send + Sync>),
}

impl BlobError {
    /// Wraps a cause no caller acts on, keeping its text and its chain.
    pub(crate) fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl fmt::Display for BlobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordRequired => {
                formatter.write_str("this blob ticket is password-protected — pass --password")
            }
            Self::PasswordNotNeeded => {
                formatter.write_str("this blob ticket has no password — drop --password")
            }
            Self::HandshakeStalled => formatter.write_str(
                "the blob producer did not complete the handshake — build a new endpoint and try again",
            ),
            Self::Internal(error) => fmt::Display::fmt(error.as_ref(), formatter),
        }
    }
}

impl Error for BlobError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Internal(error) => error.source(),
            Self::PasswordRequired | Self::PasswordNotNeeded | Self::HandshakeStalled => None,
        }
    }
}
