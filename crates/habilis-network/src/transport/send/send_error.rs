//! Why a send failed.

use crate::daemon::event_loop::EventLoopError;
use iroh::EndpointId;

use habilis_network_doc::DocError;
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
    /// The shared state refused a write of this node: it has not synced yet, it is full, or the
    /// write nests too deep or holds a value that no frame of a seed could carry.
    State(StateRefusal),
    /// A cause no caller acts on. It keeps its text and its chain.
    Internal(Box<dyn error::Error + Send + Sync>),
}

impl SendError {
    /// Wraps a cause no caller acts on, keeping its text and its chain.
    pub(crate) fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error.into())
    }

    /// The error of a write that the document of a channel refused: a refusal of the shared state
    /// is a [`SendError::State`] that an app can show and act on, any other cause is internal.
    pub(crate) fn of_doc(error: DocError) -> Self {
        match StateRefusal::of(&error) {
            Some(refusal) => Self::State(refusal),
            None => Self::Internal(error.into()),
        }
    }
}

/// Why the shared state refused a write of this node, with the words that an app shows.
///
/// # Examples
///
/// A node that has not synced yet tells the app to try again.
///
/// ```
/// use habilis_network::runtime::StateRefusal;
///
/// let text = StateRefusal::NotSynced.to_string();
/// assert!(text.contains("retry"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateRefusal {
    /// The node has not heard of another write yet, so its clock could put a write below its own
    /// earlier ones. It ends within 30 seconds of the start of the node, or at the first answer to
    /// its digest.
    NotSynced,
    /// The state is full: the write would take its next seed, or its frames, over a line.
    Full {
        /// The size that the write would reach.
        used: usize,
        /// The line that it would pass.
        limit: usize,
        /// What the two numbers count: `bytes` or `operations`.
        what: &'static str,
    },
    /// The write adds a value nested deeper than the state allows.
    TooDeep {
        /// The keys on the way to the deepest value that the write adds.
        depth: usize,
        /// The deepest nesting that a write may add.
        limit: usize,
    },
    /// A value of the write, with its keys, is larger than a frame of a seed can carry.
    TooLarge {
        /// The bytes of the value and its keys.
        bytes: usize,
    },
}

impl StateRefusal {
    /// The refusal that a document error stands for, if it is one.
    fn of(error: &DocError) -> Option<Self> {
        match error {
            DocError::ClockNotReady => Some(Self::NotSynced),
            DocError::StateFull { used, limit, what } => Some(Self::Full {
                used: *used,
                limit: *limit,
                what,
            }),
            DocError::StateTooDeep { depth, limit } => Some(Self::TooDeep {
                depth: *depth,
                limit: *limit,
            }),
            DocError::TooLarge { bytes } => Some(Self::TooLarge { bytes: *bytes }),
            // Any other error of a document (it is `non_exhaustive`) is no refusal of the state.
            DocError::NotAnObject
            | DocError::Body(_)
            | DocError::Encode(_)
            | DocError::SeedTooLong { .. }
            | DocError::CandidateHeld
            | _ => None,
        }
    }
}

impl fmt::Display for StateRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSynced => {
                f.write_str("the shared state has not synced yet; retry in a few seconds")
            }
            Self::Full { used, limit, what } => write!(
                f,
                "the shared state is full: {used} of {limit} {what}; a write that adds a value is refused, also with the same value; delete keys with a null merge to free space, or wait for the next cut"
            ),
            Self::TooDeep { depth, limit } => write!(
                f,
                "the value is nested {depth} levels deep and the shared state allows {limit}"
            ),
            Self::TooLarge { bytes } => write!(
                f,
                "a value of the write is too large for the shared state: {bytes} bytes with its keys; a value and its keys must fit one frame"
            ),
        }
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
            Self::State(refusal) => fmt::Display::fmt(refusal, f),
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
            | Self::State(_)
            | Self::Stopped => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_doc::DocError;

    use super::{SendError, StateRefusal};

    #[test]
    fn a_refusal_of_the_shared_state_is_a_state_error_with_the_words_of_an_app() {
        let cases = [
            (
                DocError::ClockNotReady,
                "has not synced yet; retry in a few seconds",
            ),
            (
                DocError::StateFull {
                    used: 9,
                    limit: 8,
                    what: "bytes",
                },
                "delete keys with a null merge",
            ),
            (
                DocError::StateTooDeep {
                    depth: 13,
                    limit: 12,
                },
                "nested 13 levels deep",
            ),
            (
                DocError::TooLarge { bytes: 4_000 },
                "too large for the shared state",
            ),
        ];
        for (error, words) in cases {
            let sent = SendError::of_doc(error);
            assert!(
                matches!(sent, SendError::State(_)),
                "a refusal of the state is a State error: {sent:?}"
            );
            assert!(
                sent.to_string().contains(words),
                "the text of the error says `{words}`: {sent}"
            );
        }
    }

    #[test]
    fn any_other_error_of_a_document_stays_internal() {
        let sent = SendError::of_doc(DocError::NotAnObject);
        assert!(
            matches!(sent, SendError::Internal(_)),
            "a merge that is no object is no refusal of the state"
        );
        assert_eq!(
            StateRefusal::NotSynced,
            StateRefusal::NotSynced,
            "a refusal is equal to itself"
        );
    }
}
