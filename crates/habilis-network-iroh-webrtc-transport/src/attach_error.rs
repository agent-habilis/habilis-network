//! The error a transport returns when it refuses to attach a session.

use iroh::EndpointId;

use std::{error, fmt};
/// Why an attach was refused.
///
/// # Examples
///
/// A peer that already has a session returns this error.
///
/// ```
/// use habilis_network_iroh_webrtc_transport::AttachError;
/// use iroh_base::SecretKey;
///
/// let id = SecretKey::from_bytes(&[1u8; 32]).public();
/// let error = AttachError::AlreadyAttached(id);
/// assert!(matches!(error, AttachError::AlreadyAttached(_)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum AttachError {
    /// Someone already holds this peer's slot: a live session, or another
    /// negotiation partway through attaching one.
    ///
    /// Not necessarily a fault. The mount lane and the mesh lane share one
    /// registry, so either can reach a peer first; the loser should use the
    /// winner's session rather than treat this as a failure.
    ///
    /// The handles passed to `attach` have already been closed.
    AlreadyAttached(EndpointId),
    /// The session driver ended while the attach was still recording it, so
    /// nothing is attached. Only the native backend returns this.
    Retired(EndpointId),
}

impl fmt::Display for AttachError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyAttached(remote) => {
                write!(formatter, "a WebRTC session for {remote} already exists")
            }
            Self::Retired(remote) => {
                write!(
                    formatter,
                    "the WebRTC session for {remote} ended while attaching"
                )
            }
        }
    }
}

impl error::Error for AttachError {}
