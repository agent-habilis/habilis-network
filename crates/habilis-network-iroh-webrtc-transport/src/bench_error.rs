//! The error of the benchmark harness: a bind, a stream or a reply that fails, or a reply that is
//! not the bytes that were sent.

use std::fmt;

use iroh::endpoint;
use std::{error, num};
/// Why a benchmark step failed.
///
/// # Examples
///
/// A benchmark whose echo does not match its payload returns this error. The `bench_error` module is private, so the doc test compiles it but does not run it.
///
/// ```
/// use habilis_network_iroh_webrtc_transport::BenchError;
///
/// let error = BenchError::EchoMismatch;
/// assert!(matches!(error, BenchError::EchoMismatch));
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum BenchError {
    /// The endpoint could not bind.
    Bind(endpoint::BindError),
    /// The connection failed before a stream opened.
    Connection(endpoint::ConnectionError),
    /// A write to the stream failed.
    Write(endpoint::WriteError),
    /// The stream was closed before the request was finished.
    Closed(endpoint::ClosedStream),
    /// The reply could not be read.
    Read(endpoint::ReadToEndError),
    /// A size does not fit the wire header.
    Size(num::TryFromIntError),
    /// The transfer asks for more bytes than the harness allows.
    TooLarge {
        /// The bytes asked for.
        bulk: usize,
    },
    /// The reply has a different number of bytes from the one asked for.
    ShortReply {
        /// The bytes the reply should hold.
        wanted: usize,
        /// The bytes the reply held.
        got: usize,
    },
    /// The reply bytes are not the payload that the server sends.
    ReplyMismatch,
    /// The echo is not the probe that was sent.
    EchoMismatch,
}

impl fmt::Display for BenchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(error) => write!(formatter, "the endpoint could not bind: {error}"),
            Self::Connection(error) => write!(formatter, "the connection failed: {error}"),
            Self::Write(error) => write!(formatter, "a write to the stream failed: {error}"),
            Self::Closed(error) => write!(formatter, "the stream was closed: {error}"),
            Self::Read(error) => write!(formatter, "the reply could not be read: {error}"),
            Self::Size(error) => write!(formatter, "a size does not fit the header: {error}"),
            Self::TooLarge { bulk } => {
                write!(formatter, "{bulk} bytes is past the transfer ceiling")
            }
            Self::ShortReply { wanted, got } => {
                write!(formatter, "short reply: wanted {wanted} bytes, got {got}")
            }
            Self::ReplyMismatch => write!(formatter, "reply body did not match"),
            Self::EchoMismatch => write!(formatter, "the echo is not the probe"),
        }
    }
}

impl error::Error for BenchError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Bind(error) => Some(error),
            Self::Connection(error) => Some(error),
            Self::Write(error) => Some(error),
            Self::Closed(error) => Some(error),
            Self::Read(error) => Some(error),
            Self::Size(error) => Some(error),
            Self::TooLarge { .. }
            | Self::ShortReply { .. }
            | Self::ReplyMismatch
            | Self::EchoMismatch => None,
        }
    }
}

impl From<endpoint::BindError> for BenchError {
    fn from(error: endpoint::BindError) -> Self {
        Self::from_bind_error(error)
    }
}

impl BenchError {
    /// Make a bench error from a bind error.
    #[must_use]
    pub fn from_bind_error(error: endpoint::BindError) -> Self {
        Self::Bind(error)
    }

    /// Make a bench error from a connection error.
    #[must_use]
    pub fn from_connection_error(error: endpoint::ConnectionError) -> Self {
        Self::Connection(error)
    }

    /// Make a bench error from a write error.
    #[must_use]
    pub fn from_write_error(error: endpoint::WriteError) -> Self {
        Self::Write(error)
    }

    /// Make a bench error from a closed stream.
    #[must_use]
    pub fn from_closed_stream(error: endpoint::ClosedStream) -> Self {
        Self::Closed(error)
    }

    /// Make a bench error from a read-to-end error.
    #[must_use]
    pub fn from_read_to_end_error(error: endpoint::ReadToEndError) -> Self {
        Self::Read(error)
    }

    /// Make a bench error from an integer conversion error.
    #[must_use]
    pub fn from_try_from_int_error(error: num::TryFromIntError) -> Self {
        Self::Size(error)
    }
}

impl From<endpoint::ConnectionError> for BenchError {
    fn from(error: endpoint::ConnectionError) -> Self {
        Self::from_connection_error(error)
    }
}

impl From<endpoint::WriteError> for BenchError {
    fn from(error: endpoint::WriteError) -> Self {
        Self::from_write_error(error)
    }
}

impl From<endpoint::ClosedStream> for BenchError {
    fn from(error: endpoint::ClosedStream) -> Self {
        Self::from_closed_stream(error)
    }
}

impl From<endpoint::ReadToEndError> for BenchError {
    fn from(error: endpoint::ReadToEndError) -> Self {
        Self::from_read_to_end_error(error)
    }
}

impl From<num::TryFromIntError> for BenchError {
    fn from(error: num::TryFromIntError) -> Self {
        Self::from_try_from_int_error(error)
    }
}
