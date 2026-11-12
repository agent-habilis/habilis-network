//! Why a send failed.

use crate::daemon::event_loop::EventLoopError;
use iroh::EndpointId;

use std::{error, fmt};
/// Why a frame could not be sent.
///
/// [`SendError::Held`] is a refusal that the caller can retry later, so it is a variant and not a
/// downcast. [`SendError::Internal`] holds the causes no caller acts on.
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
    /// The send is refused: a probe found that the only path of its peer is the relay, which is
    /// lookup only on this mesh. The caller can retry the send later, when a direct path is proven.
    Held {
        /// The endpoint the frame is held for.
        eid: EndpointId,
    },
    /// The addressee has no known path: a route that waits on `PeerInfo`, or the rendezvous.
    Undeliverable(String),
    /// The message is larger than one frame carries.
    Oversize(String),
    /// A send to one key of a frame that another key signed. A node sends only the frames it
    /// signed, so it is not a unicast relay for any frame it has seen.
    ForeignFrame,
    /// A send to one key of a frame that is directed to another key. Its body is sealed to that
    /// key, and the first key cannot open it.
    OtherAddressee,
    /// The addressee is not a valid nickname.
    InvalidAddressee(String),
    /// The mesh event loop has stopped, so nothing can carry the message.
    Stopped,
    /// The event loop of the node ended with an error, so a leave failed.
    EventLoop(EventLoopError),
    /// The shared state refused a write of this node, with the typed reason. A write past the rate
    /// limit is not retried: the caller sends it again later. A value too large for a frame is refused.
    State(habilis_network_doc::SliceError),
    /// A cause no caller acts on. It keeps its text and its chain. `{}` prints only the outer
    /// text; `{:#}` prints the chain.
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
                "directed message to {eid} refused: a probe found only the relay, and the relay is lookup only on this mesh; retry the send later"
            ),
            Self::Undeliverable(message)
            | Self::Oversize(message)
            | Self::InvalidAddressee(message) => f.write_str(message),
            Self::ForeignFrame => f.write_str(
                "send to one key refused: a node sends to one key only a frame that it signed",
            ),
            Self::OtherAddressee => {
                f.write_str("send to one key refused: the frame is directed to another key")
            }
            Self::Stopped => f.write_str("mesh event loop has stopped"),
            Self::EventLoop(_) => f.write_str("the mesh event loop failed"),
            Self::State(error) => fmt::Display::fmt(error, f),
            Self::Internal(error) => {
                write!(f, "{error}")?;
                if f.alternate() {
                    let mut cause = error.source();
                    while let Some(inner) = cause {
                        write!(f, ": {inner}")?;
                        cause = inner.source();
                    }
                }
                Ok(())
            }
        }
    }
}

impl error::Error for SendError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::EventLoop(error) => Some(error),
            Self::State(error) => Some(error),
            Self::Internal(error) => error.source(),
            Self::Held { .. }
            | Self::Undeliverable(_)
            | Self::Oversize(_)
            | Self::InvalidAddressee(_)
            | Self::ForeignFrame
            | Self::OtherAddressee
            | Self::Stopped => None,
        }
    }
}
