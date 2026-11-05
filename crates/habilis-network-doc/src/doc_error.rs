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
    /// One value is larger than the budget of a frame and cannot be cut.
    TooLarge {
        /// The bytes of the value as JSON.
        bytes: usize,
    },
    /// The seed would have more frames than a node accepts.
    SeedTooLong {
        /// The number of frames that the seed would have.
        frames: usize,
    },
    /// The document holds a candidate seed. It adopts the candidate after the wait and cuts no
    /// epoch of its own: a cut from a view that the candidate replaces loses the values of others.
    CandidateHeld,
    /// A state document that has not heard of any other write yet. Its clock is 0, so a change
    /// that it wrote now would get a time below the writes that its node made before a restart,
    /// and would lose to them. The caller holds the write until a frame with a time arrives or
    /// it calls `finish_sync`.
    ClockNotReady,
    /// The state document is full: a write that adds a value would take the next seed, or the
    /// frames that the document holds, over a line of its limits. A write that only deletes passes
    /// until the memory line. The caller deletes keys to free space, or waits for the next cut.
    StateFull {
        /// The size that the write would reach.
        used: usize,
        /// The line that it would pass.
        limit: usize,
        /// What the two numbers count: `bytes` or `operations`.
        what: &'static str,
    },
    /// The merge adds a value nested deeper than the state document allows.
    StateTooDeep {
        /// The keys on the way to the deepest value that the merge adds, counting its own.
        depth: usize,
        /// The deepest nesting that a write may add.
        limit: usize,
    },
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
        if let Self::StateFull { used, limit, what } = self {
            return write!(
                formatter,
                "the shared state is full: {used} of {limit} {what}; a write that adds a value is refused, also with the same value; delete keys with a null merge to free space, or wait for the next cut"
            );
        }
        if let Self::StateTooDeep { depth, limit } = self {
            return write!(
                formatter,
                "the value is nested {depth} levels deep and the shared state allows {limit}"
            );
        }
        formatter.write_str(match self {
            Self::NotAnObject => {
                "merge must be a JSON object (the automerge document root is a map)"
            }
            Self::Body(_) => "the change body is not a valid message body",
            Self::Encode(_) => "the change could not be encoded",
            Self::TooLarge { .. } => "one value is larger than a frame and cannot be cut",
            Self::SeedTooLong { .. } => "the seed would have more frames than a node accepts",
            Self::CandidateHeld => "the document holds a candidate seed and cuts no epoch",
            Self::ClockNotReady => "the clock of the document has not heard of another write yet",
            Self::StateFull { .. } | Self::StateTooDeep { .. } => unreachable!("written above"),
        })
    }
}

impl error::Error for DocError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::NotAnObject
            | Self::TooLarge { .. }
            | Self::SeedTooLong { .. }
            | Self::CandidateHeld
            | Self::ClockNotReady
            | Self::StateFull { .. }
            | Self::StateTooDeep { .. } => None,
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
