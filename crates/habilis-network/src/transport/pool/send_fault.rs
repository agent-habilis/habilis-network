//! Why a unicast send did not end with the end of the peer.

use std::{error, fmt};

use super::timeouts::{SEND_TIMED_OUT, SEND_TIMEOUT};

/// The cause of a send that the peer did not acknowledge. The phase is the phase of the SENDER: the
/// commit is its finish of the stream. A fault before it is certain: the peer never takes the frame.
/// A fault after it is not: the peer can have taken the frame, and the sender did not hear it.
#[derive(Debug)]
pub(crate) enum SendFault {
    /// The peer said no before it held the frame: its inbox is full, or the frame is too long. The
    /// peer is there, so no second send follows.
    NotTaken,
    /// The connection ended, or its stream failed, before the commit.
    LostBeforeCommit(String),
    /// The deadline of the send ended before the commit. The text says which step was waiting.
    TimedOutBeforeCommit(&'static str),
    /// The connection ended, or its stream failed, after the commit.
    LostAfterCommit(String),
    /// The deadline of the send ended after the commit, before the peer ended its side.
    TimedOutAfterCommit,
}

impl SendFault {
    /// Whether the sender had committed the frame when it failed.
    pub(crate) fn committed(&self) -> bool {
        matches!(self, Self::LostAfterCommit(_) | Self::TimedOutAfterCommit)
    }

    /// Whether the connection is the cause, the only cause that a second send on a new connection
    /// can mend.
    pub(crate) fn connection_lost(&self) -> bool {
        matches!(self, Self::LostBeforeCommit(_) | Self::LostAfterCommit(_))
    }
}

impl fmt::Display for SendFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotTaken => formatter.write_str("the peer did not take the frame"),
            Self::LostBeforeCommit(why) => {
                write!(formatter, "unicast stream failed before the commit: {why}")
            }
            Self::TimedOutBeforeCommit(step) => {
                write!(formatter, "{SEND_TIMED_OUT} after {SEND_TIMEOUT:?}: {step}")
            }
            Self::LostAfterCommit(why) => {
                write!(formatter, "unicast stream failed after the commit: {why}")
            }
            Self::TimedOutAfterCommit => write!(
                formatter,
                "{SEND_TIMED_OUT} after {SEND_TIMEOUT:?}: the peer did not end the frame"
            ),
        }
    }
}

impl error::Error for SendFault {}
