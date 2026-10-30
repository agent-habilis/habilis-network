//! The error of building or wrapping a shared-state change for the wire.

use std::fmt;

use habilis_network_protocol::messages::BodyError;

use std::error;
/// Why a shared-state change could not be built or wrapped for the wire.
///
/// # Examples
///
/// A document body that is not a JSON object returns this error.
///
/// ```
/// use habilis_network_doc::DocError;
///
/// let error = DocError::NotAnObject;
/// assert!(matches!(error, DocError::NotAnObject));
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum DocError {
    /// The merge is not a JSON object: the automerge document root is a map.
    NotAnObject,
    /// The body failed `MessageBody` validation.
    Body(BodyError),
    /// Automerge refused the change, or the envelope did not encode.
    Encode(Box<dyn error::Error + Send + Sync + 'static>),
}

impl DocError {
    /// Wrap a failure of automerge or of the envelope encoding.
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
            Self::NotAnObject => {
                "merge must be a JSON object (the automerge document root is a map)"
            }
            Self::Body(_) => "the change body is not a valid message body",
            Self::Encode(_) => "the change could not be encoded",
        })
    }
}

impl error::Error for DocError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::NotAnObject => None,
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
