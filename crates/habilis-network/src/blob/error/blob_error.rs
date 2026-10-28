use std::error::Error;
use std::fmt;

/// Why a blob cannot be fetched, offered, or decoded.
///
/// [`BlobError::PasswordRequired`] and [`BlobError::PasswordNotNeeded`] are the causes a
/// frontend acts on: it prompts for the password, or it drops the flag.
/// [`BlobError::Internal`] holds the other causes, which no caller acts on.
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum BlobError {
    /// The ticket is password-protected, and no password was given.
    PasswordRequired,
    /// The ticket has no password, and one was given.
    PasswordNotNeeded,
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
            Self::Internal(error) => fmt::Display::fmt(error.as_ref(), formatter),
        }
    }
}

impl Error for BlobError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Internal(error) => error.source(),
            Self::PasswordRequired | Self::PasswordNotNeeded => None,
        }
    }
}
