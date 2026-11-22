//! A frame that the sender committed, and the end that it waits for.

use iroh::endpoint::{ReadToEndError, RecvStream};

/// A frame whose stream the sender finished. The peer ends its side of the stream after it handed
/// the frame to its loop, so the end is the acknowledgement. Only [`OutgoingFrame::commit`] makes one.
///
/// [`OutgoingFrame::commit`]: super::outgoing_frame::OutgoingFrame::commit
#[derive(Debug)]
pub(super) struct Committed {
    held: RecvStream,
}

impl Committed {
    pub(super) fn new(held: RecvStream) -> Self {
        Self { held }
    }

    /// Wait for the end of the side of the peer. Bytes where the end should be are no end.
    pub(super) async fn delivered(&mut self) -> Result<(), ReadToEndError> {
        self.held.read_to_end(0).await.map(|_| ())
    }

    /// Stop reading: the sender gave up on the end.
    pub(super) fn stop(&mut self) {
        let _ = self.held.stop(0u32.into());
    }
}
