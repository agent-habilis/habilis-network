//! The error of the benchmark harness: a bind, a stream or a reply that fails, or a reply that is
//! not the bytes that were sent.

use std::fmt;

/// Why a benchmark step failed.
///
/// # Examples
///
/// A benchmark whose echo does not match its payload returns this error. The `bench_error` module is private, so this is not compiled.
///
/// ```ignore
/// use habilis_network_iroh_webrtc_transport::bench::BenchError;
///
/// let error = BenchError::EchoMismatch;
/// assert!(matches!(error, BenchError::EchoMismatch));
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum BenchError {
    /// The endpoint could not bind.
    Bind(iroh::endpoint::BindError),
    /// The connection failed before a stream opened.
    Connection(iroh::endpoint::ConnectionError),
    /// A write to the stream failed.
    Write(iroh::endpoint::WriteError),
    /// The stream was closed before the request was finished.
    Closed(iroh::endpoint::ClosedStream),
    /// The reply could not be read.
    Read(iroh::endpoint::ReadToEndError),
    /// A size does not fit the wire header.
    Size(std::num::TryFromIntError),
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

impl std::error::Error for BenchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
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

impl From<iroh::endpoint::BindError> for BenchError {
    fn from(error: iroh::endpoint::BindError) -> Self {
        Self::Bind(error)
    }
}

impl From<iroh::endpoint::ConnectionError> for BenchError {
    fn from(error: iroh::endpoint::ConnectionError) -> Self {
        Self::Connection(error)
    }
}

impl From<iroh::endpoint::WriteError> for BenchError {
    fn from(error: iroh::endpoint::WriteError) -> Self {
        Self::Write(error)
    }
}

impl From<iroh::endpoint::ClosedStream> for BenchError {
    fn from(error: iroh::endpoint::ClosedStream) -> Self {
        Self::Closed(error)
    }
}

impl From<iroh::endpoint::ReadToEndError> for BenchError {
    fn from(error: iroh::endpoint::ReadToEndError) -> Self {
        Self::Read(error)
    }
}

impl From<std::num::TryFromIntError> for BenchError {
    fn from(error: std::num::TryFromIntError) -> Self {
        Self::Size(error)
    }
}
