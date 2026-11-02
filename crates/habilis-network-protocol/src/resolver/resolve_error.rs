//! Why a join target does not resolve to a locked mesh.

use std::error::Error;
use std::fmt;

/// Why a join target does not resolve to a locked mesh.
///
/// # Examples
///
/// A mesh id that does not decode returns this error with the reason.
///
/// ```
/// use habilis_network_protocol::resolver::ResolveError;
///
/// let error = ResolveError::InvalidId("not a mesh id".to_owned());
/// assert!(!error.to_string().is_empty());
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
#[must_use]
pub enum ResolveError {
    /// The mesh id does not decode. The text names why.
    InvalidId(String),
    /// An invite reached `resolve`, which takes only a mesh id. The join redeems
    /// an invite in `JoinParams::resolve`.
    InviteTarget,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId(reason) => write!(formatter, "invalid mesh id: {reason}"),
            Self::InviteTarget => {
                formatter.write_str("internal: an invite target must be redeemed via JoinParams")
            }
        }
    }
}

impl Error for ResolveError {}
