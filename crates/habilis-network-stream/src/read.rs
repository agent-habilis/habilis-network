//! The consumer's side: the [`Reader`], and what a refusal looks like.

use std::fmt;

use anyhow::Result;
use bytes::Bytes;
use habilis_network::iroh::endpoint::{Connection, ConnectionError, RecvStream};

use crate::code;

/// The largest chunk one `read` hands back.
const CHUNK: usize = 64 * 1024;

/// Why a producer would not, or no longer will, give this consumer its stream.
/// Reached through `anyhow::Error::downcast_ref`, so a caller can tell a refusal
/// from a lost link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl fmt::Display for Refused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "no open stream has this hash",
            Self::Taken => "another consumer already holds this stream",
            Self::RelayRefused => "the only path is the relay, and this stream refuses it",
            Self::Abandoned => "the producer abandoned the stream",
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

/// One stream's reading end.
#[derive(Debug)]
pub struct Reader {
    conn: Connection,
    recv: RecvStream,
}

impl Reader {
    pub(crate) fn new(conn: Connection, recv: RecvStream) -> Self {
        Self { conn, recv }
    }

    /// The next bytes, in order; `None` once the producer closed the stream.
    ///
    /// # Errors
    /// A [`Refused`] when the producer refused or abandoned the stream, or the
    /// link's own error when it was lost.
    pub async fn read(&mut self) -> Result<Option<Bytes>> {
        match self.recv.read_chunk(CHUNK).await {
            Ok(chunk) => {
                if chunk.is_none() {
                    self.conn.close(code::DONE.into(), b"done");
                }
                Ok(chunk)
            }
            Err(error) => Err(match refusal(&self.conn) {
                Some(refused) => refused.into(),
                None => anyhow::anyhow!("the stream was lost: {error}"),
            }),
        }
    }
}
