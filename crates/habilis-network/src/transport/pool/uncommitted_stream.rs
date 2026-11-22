//! The send stream of a frame that is not committed.

use iroh::endpoint::{SendStream, WriteError};

use super::send_fault::SendFault;
use crate::transport::unicast_acceptor::UNCOMMITTED;

/// The send stream of one frame, until the commit. A stream that is dropped finishes by itself, and
/// the finish is the commit, so this type resets the stream when it goes away uncommitted.
/// [`Self::commit`] is the only finish.
#[derive(Debug)]
#[must_use = "a dropped stream is reset: the peer takes no frame"]
pub(super) struct UncommittedStream {
    stream: Option<SendStream>,
}

impl UncommittedStream {
    pub(super) fn new(stream: SendStream) -> Self {
        Self {
            stream: Some(stream),
        }
    }

    /// Write the two parts of a frame in order.
    pub(super) async fn write(&mut self, first: &[u8], second: &[u8]) -> Result<(), WriteError> {
        let Some(stream) = self.stream.as_mut() else {
            return Err(WriteError::ClosedStream);
        };
        stream.write_all(first).await?;
        stream.write_all(second).await
    }

    /// Finish the stream: the commit.
    pub(super) fn commit(mut self) -> Result<(), SendFault> {
        let Some(mut stream) = self.stream.take() else {
            return Err(SendFault::LostBeforeCommit(
                "the frame has no stream".to_owned(),
            ));
        };
        stream
            .finish()
            .map_err(|error| SendFault::LostBeforeCommit(error.to_string()))
    }
}

impl Drop for UncommittedStream {
    fn drop(&mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.reset(UNCOMMITTED.into());
        }
    }
}
