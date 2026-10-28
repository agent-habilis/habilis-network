//! The errors of a stream call: the node, its producers and its readers.

use std::error::Error;
use std::fmt;

use crate::read::Refused;

/// The source of a failed step. A lower layer's error goes in whole.
type BoxedError = Box<dyn Error + Send + Sync>;
/// Why a stream call failed.
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum StreamError {
    /// The options name a transport that a stream does not use.
    Options(&'static str),
    /// The stream node does not start.
    Bind {
        /// The step that failed, for example `parse the relay list`.
        step: &'static str,
        /// The error of the layer that failed.
        source: BoxedError,
    },
    /// The producer refused the hash, or ended the stream early.
    Refused(Refused),
    /// The consumer cannot reach the producer.
    Open {
        /// The step that failed, for example `connect to the producer`.
        step: &'static str,
        /// The error of the layer that failed.
        source: BoxedError,
    },
    /// The stream node closed before a consumer arrived.
    NodeClosed,
    /// The stream is closed.
    Closed,
    /// The consumer went away while the producer wrote or closed.
    ConsumerGone(BoxedError),
    /// The link to the producer was lost while the consumer read.
    Lost(BoxedError),
}

impl StreamError {
    pub(crate) fn bind<E: Into<BoxedError>>(step: &'static str) -> impl FnOnce(E) -> Self {
        move |source| Self::Bind {
            step,
            source: source.into(),
        }
    }

    pub(crate) fn open<E: Into<BoxedError>>(step: &'static str) -> impl FnOnce(E) -> Self {
        move |source| Self::Open {
            step,
            source: source.into(),
        }
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Options(message) => formatter.write_str(message),
            Self::Bind { step, .. } | Self::Open { step, .. } => formatter.write_str(step),
            Self::Refused(refused) => fmt::Display::fmt(refused, formatter),
            Self::NodeClosed => {
                formatter.write_str("the stream node closed before a consumer arrived")
            }
            Self::Closed => formatter.write_str("the stream is closed"),
            Self::ConsumerGone(_) => formatter.write_str("the consumer went away"),
            Self::Lost(_) => formatter.write_str("the stream was lost"),
        }
    }
}

impl Error for StreamError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bind { source, .. }
            | Self::Open { source, .. }
            | Self::ConsumerGone(source)
            | Self::Lost(source) => Some(source.as_ref()),
            Self::Refused(_) | Self::Options(_) | Self::NodeClosed | Self::Closed => None,
        }
    }
}
