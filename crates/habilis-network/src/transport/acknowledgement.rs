//! The side of the receiver of one frame.

use iroh::endpoint::{SendStream, WriteError};

use super::unicast_acceptor::{DROPPED, HELD, NOT_TAKEN};

/// The side of the receiver of one frame: `HELD` after it holds the frame, and the end of the
/// stream after it handed the frame to its loop. A stream that is dropped finishes by itself, and
/// the finish is the acknowledgement. So this type resets the stream when it goes away without
/// [`Self::deliver`]: a task that was cancelled, or that returned early, never tells the sender
/// that the frame was delivered.
#[derive(Debug)]
#[must_use = "a dropped acknowledgement resets the stream: the sender reads no end"]
pub(super) struct Acknowledgement {
    stream: Option<SendStream>,
}

impl Acknowledgement {
    pub(super) fn new(stream: SendStream) -> Self {
        Self {
            stream: Some(stream),
        }
    }

    /// Say that the frame is held, and that a place in the inbox is kept for it.
    pub(super) async fn hold(&mut self) -> Result<(), WriteError> {
        let Some(stream) = self.stream.as_mut() else {
            return Err(WriteError::ClosedStream);
        };
        stream.write_all(&[HELD]).await
    }

    /// Say no before the frame is held: the inbox is full, or the frame is too long.
    pub(super) fn refuse(&mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.reset(NOT_TAKEN.into());
        }
    }

    /// End the side of the receiver: the loop took the frame.
    pub(super) fn deliver(mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.finish();
        }
    }
}

impl Drop for Acknowledgement {
    fn drop(&mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.reset(DROPPED.into());
        }
    }
}
