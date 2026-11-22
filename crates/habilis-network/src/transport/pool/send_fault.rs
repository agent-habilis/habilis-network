//! Why a unicast send ended with no acknowledgement.

use std::{error, fmt};

use super::timeouts::{SEND_TIMED_OUT, SEND_TIMEOUT};

/// The cause of a send that the peer did not acknowledge. Only the first one is a fault of the
/// connection, so only it earns the eviction of the connection and one more send.
#[derive(Debug)]
pub(crate) enum SendFault {
    /// The connection ended, or its stream failed, before the peer acknowledged. The peer can take
    /// the frame on a new connection.
    ConnectionLost(String),
    /// The peer is there and said no: it reset the acknowledgement side of the stream, or it sent
    /// bytes where the end of the stream is the acknowledgement.
    NotTaken,
    /// The deadline of the send ended. The text says which step was waiting.
    TimedOut(&'static str),
}

impl fmt::Display for SendFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionLost(why) => write!(formatter, "unicast stream failed: {why}"),
            Self::NotTaken => formatter.write_str("the peer did not take the frame"),
            Self::TimedOut(step) => {
                write!(formatter, "{SEND_TIMED_OUT} after {SEND_TIMEOUT:?}: {step}")
            }
        }
    }
}

impl error::Error for SendFault {}
