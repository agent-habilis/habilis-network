//! What a producer's refusal looks like to the consumer.

use std::fmt;

use habilis_network::iroh::endpoint::{Connection, ConnectionError};

use crate::code;
/// Why a producer would not, or no longer will, give this consumer its stream.
/// Reached as [`crate::error::StreamError::Refused`], so a caller can tell a refusal from a
/// lost link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refused {
    /// No open stream has this hash: never created, closed, or abandoned
    /// before this consumer was admitted.
    Unknown,
    /// Another consumer already holds the stream.
    Taken,
    /// The only path is the relay, and the stream's policy keeps the relay for
    /// finding peers only.
    RelayRefused,
    /// The producer dropped the stream before closing it, after this consumer
    /// was admitted (while it read, or during the hand-off).
    Abandoned,
    /// The producer is at its direct-peer cap. Try again later.
    AtCap,
}

impl fmt::Display for Refused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "no open stream has this hash",
            Self::Taken => "another consumer already holds this stream",
            Self::RelayRefused => "the only path is the relay, and this stream refuses it",
            Self::Abandoned => "the producer abandoned the stream",
            Self::AtCap => "the producer is at its direct-peer cap",
        })
    }
}

impl std::error::Error for Refused {}

/// The refusal behind a connection the producer closed, if it closed it with
/// one of the stream's codes.
pub(crate) fn refusal(conn: &Connection) -> Option<Refused> {
    let Some(ConnectionError::ApplicationClosed(close)) = conn.close_reason() else {
        return None;
    };
    match u32::try_from(close.error_code.into_inner()).ok()? {
        code::UNKNOWN => Some(Refused::Unknown),
        code::TAKEN => Some(Refused::Taken),
        code::RELAY_REFUSED => Some(Refused::RelayRefused),
        code::ABANDONED => Some(Refused::Abandoned),
        _ => None,
    }
}
