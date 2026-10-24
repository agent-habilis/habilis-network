//! The errors of the stream API: a stream hash token, and the node, its
//! producers and its readers.

use std::error::Error;
use std::fmt;

use crate::read::Refused;

/// The source of a failed step. A lower layer's error goes in whole.
type BoxedError = Box<dyn Error + Send + Sync>;

/// Why a stream hash token does not decode.
#[derive(Debug)]
#[non_exhaustive]
pub enum HashError {
    /// The token is not a stream hash of this kind.
    WrongKind,
    /// The hash has a version this build does not know.
    UnknownVersion(u8),
    /// The hash sets flags this build does not know.
    UnknownFlags(u8),
    /// The payload ends before one of its fields.
    Truncated(&'static str),
    /// A field of the hash does not decode.
    Field {
        /// The step that failed, for example `decode the address`.
        step: &'static str,
        /// The error of the layer that decodes the field.
        source: BoxedError,
    },
}

impl HashError {
    pub(crate) fn field<E: Into<BoxedError>>(step: &'static str) -> impl FnOnce(E) -> Self {
        move |source| Self::Field {
            step,
            source: source.into(),
        }
    }
}

impl fmt::Display for HashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongKind => formatter.write_str("not a stream hash: wrong ticket kind"),
            Self::UnknownVersion(version) => {
                write!(formatter, "unsupported stream hash version: {version}")
            }
            Self::UnknownFlags(flags) => write!(
                formatter,
                "unsupported stream hash flags {flags:#04x}: upgrade to a newer build"
            ),
            Self::Truncated(what) => formatter.write_str(what),
            Self::Field { step, .. } => formatter.write_str(step),
        }
    }
}

impl Error for HashError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Field { source, .. } => Some(source.as_ref()),
            Self::WrongKind
            | Self::UnknownVersion(_)
            | Self::UnknownFlags(_)
            | Self::Truncated(_) => None,
        }
    }
}

/// Why a stream call failed.
#[derive(Debug)]
#[non_exhaustive]
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
