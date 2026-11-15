//! The error of sealing a channel body for the wire.

use std::fmt;

use habilis_network_protocol::messages::BodyError;

use std::error;
/// Why a channel body could not be sealed or wrapped for the wire.
///
/// # Examples
///
/// A body that the envelope cannot hold returns the body error.
///
/// ```
/// use habilis_network_doc::DocError;
///
/// let body = habilis_network_protocol::MessageBody::try_new("bell\u{7}");
/// assert!(body.is_err(), "a control character is refused");
/// let error = DocError::from(body.expect_err("a control character"));
/// assert!(matches!(error, DocError::Body(_)));
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum DocError {
    /// The body failed `MessageBody` validation.
    Body(BodyError),
    /// The envelope did not encode.
    Encode(Box<dyn error::Error + Send + Sync + 'static>),
}

impl DocError {
    /// Wrap a failure of the envelope encoding.
    pub(crate) fn encode(error: impl Into<Box<dyn error::Error + Send + Sync + 'static>>) -> Self {
        Self::Encode(error.into())
    }

    /// Make a doc error from a body error.
    pub fn from_body_error(error: BodyError) -> Self {
        Self::Body(error)
    }
}

impl fmt::Display for DocError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Body(_) => "the body is not a valid message body",
            Self::Encode(_) => "the body could not be encoded",
        })
    }
}

impl error::Error for DocError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Body(error) => Some(error),
            Self::Encode(error) => Some(&**error),
        }
    }
}

impl From<BodyError> for DocError {
    fn from(error: BodyError) -> Self {
        Self::from_body_error(error)
    }
}
