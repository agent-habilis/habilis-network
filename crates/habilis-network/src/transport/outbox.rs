//! The queue between the event loop and what it has to send, so that the loop
//! never waits on a peer.
//!
//! A digest answer is up to `ANTIENTROPY_MAX_RESEND` messages. Broadcasting them
//! from inside the loop made the loop wait on the command queue of the gossip
//! actor for as long as that queue stayed full (232 s in one 48-node run): the
//! node sent no heartbeat and read nothing meanwhile, and its peers pruned it.
//! The loop now puts each resend in a bounded queue and goes on. One task sends
//! from the queue.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use iroh::EndpointId;
use tokio::sync::mpsc;

use super::pool::{UnicastPool, WarmSend};
use super::sender::MeshSender;

/// One message that is ready to go, with the plane its addressing chose.
#[derive(Debug)]
pub(crate) enum Resend {
    Broadcast(Bytes),
    Unicast(EndpointId, Bytes),
}

/// The loop's end of the queue. A full queue refuses the resend: it is dropped
/// and counted, and the next digest asks for it again.
#[derive(Debug)]
pub(crate) struct ResendOutbox {
    queue: mpsc::Sender<Resend>,
    dropped: Arc<AtomicU64>,
}

impl ResendOutbox {
    pub(crate) fn new(capacity: usize) -> (Self, mpsc::Receiver<Resend>) {
        let (queue, receiver) = mpsc::channel(capacity);
        let outbox = Self {
            queue,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        (outbox, receiver)
    }

    /// Queue `resend` without waiting. `false` when the queue is full.
    pub(crate) fn offer(&self, resend: Resend) -> bool {
        let queued = self.queue.try_send(resend).is_ok();
        if !queued {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        queued
    }

    /// How many resends wait to be sent.
    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.queue.max_capacity() - self.queue.capacity()
    }

    /// How many resends were refused, in total.
    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Send what the outbox holds, in order, until the loop drops its end.
///
/// A cold unicast peer is dialed in the background, so one slow dial does not
/// hold the resends behind it.
pub(crate) async fn drain(
    mut receiver: mpsc::Receiver<Resend>,
    sender: MeshSender,
    pool: UnicastPool,
) {
    while let Some(resend) = receiver.recv().await {
        match resend {
            Resend::Broadcast(bytes) => {
                if let Err(error) = sender.broadcast(bytes).await {
                    tracing::debug!(target: "habilis_network::gossip", %error, "anti-entropy resend failed");
                }
            }
            Resend::Unicast(peer, bytes) => match pool.send_if_warm(peer, bytes.clone()).await {
                WarmSend::Sent | WarmSend::Refused => {}
                WarmSend::Cold => {
                    pool.dial_and_send_in_background(peer, bytes).await;
                }
            },
        }
    }
}
