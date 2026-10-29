//! The consumer's side: one stream's reading end.

use bytes::Bytes;
use habilis_network::iroh::endpoint::{Connection, RecvStream};

use super::refused;

use crate::code;
use crate::error::StreamError;

/// The largest chunk one `read` hands back.
const CHUNK: usize = 64 * 1024;

/// One stream's reading end.
#[derive(Debug)]
pub struct Reader {
    connection: Connection,
    recv: RecvStream,
}

impl Reader {
    pub(crate) fn new(connection: Connection, recv: RecvStream) -> Self {
        Self { connection, recv }
    }

    /// The next bytes, in order; `None` once the producer closed the stream.
    ///
    /// # Errors
    /// # Errors
    /// [`crate::error::StreamError::Refused`] when the producer refused or abandoned the stream,
    /// or [`StreamError::Lost`] when the link was lost.
    pub async fn read(&mut self) -> Result<Option<Bytes>, StreamError> {
        match self.recv.read_chunk(CHUNK).await {
            Ok(chunk) => {
                if chunk.is_none() {
                    self.connection.close(code::DONE.into(), b"done");
                }
                Ok(chunk)
            }
            Err(error) => Err(match refused::refusal(&self.connection) {
                Some(refused) => StreamError::Refused(refused),
                None => StreamError::Lost(error.into()),
            }),
        }
    }
}
