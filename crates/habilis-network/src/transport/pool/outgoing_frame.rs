//! The sender's half of one frame, before it commits.

use iroh::endpoint::{ReadExactError, RecvStream, SendStream, WriteError};

use super::committed::Committed;
use super::send_fault::SendFault;
use super::uncommitted_stream::UncommittedStream;
use crate::transport::unicast_acceptor::HELD;

/// One frame on its stream, written and not yet committed. The commit is the finish of the stream:
/// the peer hands the frame to its loop only after it. A stream that is dropped finishes by itself,
/// so the stream is held by [`UncommittedStream`], which resets it when it goes away uncommitted,
/// and [`Self::commit`] is the only way to the finish. A fault on any path out of the send before
/// the commit then is a frame that the peer drops.
#[derive(Debug)]
pub(super) struct OutgoingFrame {
    stream: UncommittedStream,
    held: RecvStream,
}

impl OutgoingFrame {
    pub(super) fn new(stream: SendStream, held: RecvStream) -> Self {
        Self {
            stream: UncommittedStream::new(stream),
            held,
        }
    }

    /// Write the length of the frame, and the frame. A frame that the length cannot name is refused
    /// before the first byte.
    pub(super) async fn write(&mut self, bytes: &[u8]) -> Result<(), SendFault> {
        let Ok(length) = u32::try_from(bytes.len()) else {
            return Err(SendFault::LostBeforeCommit(
                "the frame is longer than its length can name".to_owned(),
            ));
        };
        self.stream
            .write(&length.to_be_bytes(), bytes)
            .await
            .map_err(|error: WriteError| SendFault::LostBeforeCommit(error.to_string()))
    }

    /// Wait for the byte with which the peer says that it holds the frame, and a place in its inbox
    /// for it.
    pub(super) async fn held(&mut self) -> Result<(), ReadExactError> {
        let mut byte = [0u8; 1];
        self.held.read_exact(&mut byte).await?;
        if byte[0] == HELD {
            Ok(())
        } else {
            Err(ReadExactError::FinishedEarly(0))
        }
    }

    /// Commit the frame: finish the stream. From here a fault is not certain.
    pub(super) fn commit(self) -> Result<Committed, SendFault> {
        let Self { stream, held } = self;
        stream.commit()?;
        Ok(Committed::new(held))
    }
}
