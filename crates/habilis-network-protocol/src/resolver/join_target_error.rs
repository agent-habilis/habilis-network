//! Why a string is not a join target.

use std::error::Error;
use std::fmt;

use crate::meshes::MeshIdError;

/// Why a string is not a join target. A *classification*, not a rendered
/// remedy: the engine has no commands to point at, so a consumer matches the
/// variant and appends its own "use … instead" hint. [`Unrecognized`] carries
/// the trimmed input for exactly that.
///
/// [`Unrecognized`]: JoinTargetError::Unrecognized
///
/// # Examples
///
/// A rejected join target returns an error that says why.
///
/// ```
/// use habilis_network_protocol::JoinTarget;
///
/// let error = "not a mesh id".parse::<JoinTarget>().unwrap_err();
/// assert!(!error.to_string().is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum JoinTargetError {
    /// Looked like a mesh id (base58) but failed checksum/payload validation.
    MalformedMeshId(MeshIdError),
    /// Not a token at all — wrong length or outside the Base58 charset.
    /// Carries the trimmed input to echo back.
    Unrecognized(String),
}

impl fmt::Display for JoinTargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JoinTargetError::MalformedMeshId(error) => error.fmt(formatter),
            JoinTargetError::Unrecognized(input) => write!(
                formatter,
                "`{input}` is not a mesh id or invite (expected a base58 mesh id or invite ticket)"
            ),
        }
    }
}

impl Error for JoinTargetError {}
