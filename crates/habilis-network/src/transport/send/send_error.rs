//! Why a send failed.

use crate::daemon::event_loop::EventLoopError;
use iroh::EndpointId;

use std::{error, fmt};
/// Why a frame could not be sent.
///
/// [`SendError::Held`] is the one a caller parks rather than fails on (`send_app`), so it
/// is a variant and not a downcast. [`SendError::Internal`] holds the causes no caller acts on.
///
/// # Examples
///
/// A send that finds the node stopped returns this error.
///
/// ```
/// use habilis_network::runtime::SendError;
///
/// let error = SendError::Stopped;
/// assert!(matches!(error, SendError::Stopped));
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum SendError {
    /// The frame waits for a direct path: its peer's only path is the relay, which is lookup
    /// only on this mesh.
    Held {
        /// The endpoint the frame is held for.
        eid: EndpointId,
    },
    /// The addressee has no known path: a route that waits on `PeerInfo`, or the rendezvous.
    Undeliverable(String),
    /// The message is larger than one frame carries.
    Oversize(String),
    /// The addressee is not a valid nickname.
    InvalidAddressee(String),
    /// The mesh event loop has stopped, so nothing can carry the message.
    Stopped,
    /// The event loop of the node ended with an error, so a leave failed.
    EventLoop(EventLoopError),
    /// A cause no caller acts on. It keeps its text and its chain.
    Internal(Box<dyn error::Error + Send + Sync>),
}

impl SendError {
    /// Wraps a cause no caller acts on, keeping its text and its chain.
    pub(crate) fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Held { eid } => write!(
                f,
                "directed message held: {eid}'s only path is the relay, which is lookup only on this mesh"
            ),
            Self::Undeliverable(message)
            | Self::Oversize(message)
            | Self::InvalidAddressee(message) => f.write_str(message),
            Self::Stopped => f.write_str("mesh event loop has stopped"),
            Self::EventLoop(_) => f.write_str("the mesh event loop failed"),
            Self::Internal(error) => fmt::Display::fmt(error.as_ref(), f),
        }
    }
}

impl error::Error for SendError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::EventLoop(error) => Some(error),
            Self::Internal(error) => error.source(),
            Self::Held { .. }
            | Self::Undeliverable(_)
            | Self::Oversize(_)
            | Self::InvalidAddressee(_)
            | Self::Stopped => None,
        }
    }
}
