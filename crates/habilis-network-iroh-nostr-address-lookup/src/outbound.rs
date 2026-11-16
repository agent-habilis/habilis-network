//! The sending half of a socket. Signalling writes straight to the socket. Data goes through a
//! queue and a pacer, and a task of its own does the write: a relay that stops reading holds up
//! that task, and nothing else, so the socket keeps reading.

use std::future;

use anyhow::{Result, anyhow};
use n0_future::task;
use n0_future::time::{Instant, sleep_until};
use tokio::sync::mpsc;

#[cfg(target_arch = "wasm32")]
use crate::data_queue;
use crate::data_queue::{DataQueue, Frame, Outgoing};
use crate::lane::Lane;
use crate::ws;

/// When a socket may send the data in its queue: the state of the relay decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pace {
    /// Now, at the rate of the pacer.
    Open,
    /// Not before the instant: the relay limited us until then.
    After(Instant),
    /// Not until the state of the relay changes.
    Held,
}

pub(crate) enum Outbound {
    /// Every frame is written when it is sent.
    Direct(ws::Sender),
    /// Data frames wait in a queue for the pacer.
    Paced(Paced),
}

pub(crate) struct Paced {
    queue: DataQueue,
    writer: mpsc::Sender<Frame>,
}

/// What the loop of a socket waits for to send its next frame. It owns what it needs, so it
/// borrows nothing from the socket while the loop selects.
pub(crate) struct Wake {
    at: Option<Instant>,
    writer: Option<mpsc::Sender<Frame>>,
}

impl Wake {
    /// Wait until a frame is due and the writer has room for it. `Err` when the writer is gone:
    /// the socket is dead. Never ready for a socket with no queue.
    pub(crate) async fn permit(self) -> Result<mpsc::OwnedPermit<Frame>> {
        let Some(writer) = self.writer else {
            return future::pending().await;
        };
        if let Some(at) = self.at {
            sleep_until(at).await;
            writer
                .reserve_owned()
                .await
                .map_err(|_| anyhow!("the writer of the socket is gone"))
        } else {
            writer.closed().await;
            Err(anyhow!("the writer of the socket is gone"))
        }
    }
}

impl Outbound {
    pub(crate) fn new(lane: Lane, sender: ws::Sender) -> Self {
        match lane {
            Lane::Signal => Self::Direct(sender),
            Lane::Data => Self::Paced(Paced {
                queue: DataQueue::new(Instant::now()),
                writer: spawn_writer(sender),
            }),
        }
    }

    /// Send a frame that is not payload: a REQ or a CLOSE.
    pub(crate) async fn send(&mut self, text: String) -> Result<()> {
        match self {
            Self::Direct(sender) => sender.send(text).await,
            Self::Paced(paced) => {
                paced.queue.push_control(text);
                Ok(())
            }
        }
    }

    /// Send an event that the caller signed.
    pub(crate) async fn publish(&mut self, frame: String) -> Result<()> {
        match self {
            Self::Direct(sender) => sender.send(frame).await,
            Self::Paced(paced) => {
                paced.queue.push_frame(Instant::now(), frame);
                Ok(())
            }
        }
    }

    /// Queue a datagram. A socket with no queue carries none.
    pub(crate) fn datagram(&mut self, outgoing: Outgoing) {
        if let Self::Paced(paced) = self {
            paced.queue.push_datagram(Instant::now(), outgoing);
        }
    }

    /// What the loop waits for next. A socket that is `Held` waits for nothing: the loop wakes
    /// on a frame from the relay, and asks again.
    pub(crate) fn wake(&mut self, pace: Pace) -> Wake {
        let now = Instant::now();
        match self {
            Self::Direct(_) => Wake {
                at: None,
                writer: None,
            },
            Self::Paced(paced) => match pace {
                Pace::Held => Wake {
                    at: None,
                    writer: None,
                },
                Pace::Open => Wake {
                    at: paced.queue.next_wake(now),
                    writer: Some(mpsc::Sender::clone(&paced.writer)),
                },
                Pace::After(not_before) => Wake {
                    at: paced.queue.next_wake(now).map(|at| at.max(not_before)),
                    writer: Some(mpsc::Sender::clone(&paced.writer)),
                },
            },
        }
    }

    /// The writer has room: hand it the next frame that is due, if one is. `true` if it did.
    pub(crate) fn pump(&mut self, permit: mpsc::OwnedPermit<Frame>) -> bool {
        let Self::Paced(paced) = self else {
            return false;
        };
        let now = Instant::now();
        paced.queue.flush_due(now);
        let Some(frame) = paced.queue.pop_ready(now) else {
            return false;
        };
        permit.send(frame);
        true
    }

    /// Frames dropped for want of room, as a socket with no queue counts them: none.
    pub(crate) fn dropped(&self) -> u64 {
        match self {
            Self::Direct(_) => 0,
            Self::Paced(paced) => paced.queue.dropped(),
        }
    }

    pub(crate) async fn close(self) {
        match self {
            Self::Direct(sender) => sender.close().await,
            // The writer closes the socket when the last handle to it goes.
            Self::Paced(paced) => drop(paced),
        }
    }
}

/// A task that owns the sending half and writes what it is given, one frame at a time. Its
/// channel holds one frame, so the pacer hands it the next frame only when it is free.
fn spawn_writer(mut sender: ws::Sender) -> mpsc::Sender<Frame> {
    let (frames, mut incoming): (mpsc::Sender<Frame>, mpsc::Receiver<Frame>) = mpsc::channel(1);
    task::spawn(async move {
        while let Some(frame) = incoming.recv().await {
            let text = match frame {
                Frame::Control(text) => text,
                Frame::Data(text) => {
                    #[cfg(target_arch = "wasm32")]
                    if data_queue::over_buffer_bound(sender.buffered()) {
                        tracing::debug!(target: "habilis_network::lookup", "browser socket is behind; a data frame is dropped");
                        continue;
                    }
                    text
                }
            };
            if sender.send(text).await.is_err() {
                return;
            }
        }
        sender.close().await;
    });
    frames
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use n0_future::time::{Instant, timeout};
    use tokio::sync::mpsc;

    use super::{Outbound, Pace, Paced};
    use crate::data_queue::{DataQueue, Frame, Outgoing};
    use crate::event::Keys;

    // One key signs every datagram a test queues, as one pool does.
    fn outgoing(keys: &Arc<Keys>, bytes: Vec<u8>) -> Outgoing {
        Outgoing {
            keys: Arc::clone(keys),
            tag: [1u8; 32],
            from: [2u8; 32],
            bytes,
        }
    }

    /// A relay that stops reading holds up the writer, and only the writer: queueing a datagram
    /// still returns at once, the pacer waits for the writer instead of spinning, and the queue
    /// drops its oldest frames, so nothing grows.
    #[tokio::test]
    async fn a_stalled_writer_blocks_nothing_and_the_queue_stays_bounded() {
        let (writer, mut stalled): (mpsc::Sender<Frame>, mpsc::Receiver<Frame>) = mpsc::channel(1);
        let mut outbound = Outbound::Paced(Paced {
            queue: DataQueue::new(Instant::now()),
            writer,
        });
        // The key of a test pool, shared by the datagrams it queues.
        let keys = Arc::new(Keys::generate());

        outbound.datagram(outgoing(&keys, b"first".to_vec()));
        let permit: mpsc::OwnedPermit<Frame> =
            timeout(Duration::from_secs(1), outbound.wake(Pace::Open).permit())
                .await
                .expect("a frame is due and the writer has room")
                .expect("the writer is alive");
        outbound.pump(permit);

        // The writer now holds one frame and reads no more.
        for index in 0..1_000u32 {
            outbound.datagram(outgoing(&keys, index.to_be_bytes().repeat(300)));
            let wake = outbound.wake(Pace::Open);
            assert!(
                timeout(Duration::from_millis(1), wake.permit())
                    .await
                    .is_err(),
                "the pacer waits for a writer with no room"
            );
        }
        assert!(
            outbound.dropped() > 0,
            "the queue dropped its oldest frames"
        );
        assert!(
            stalled.try_recv().is_ok(),
            "the first frame is the writer's"
        );
    }
}
