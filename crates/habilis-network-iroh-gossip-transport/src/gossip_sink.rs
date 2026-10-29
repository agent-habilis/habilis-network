//! A sink over a real gossip topic.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use iroh_gossip::api::GossipSender;
use tokio::sync::mpsc;

use crate::FrameSink;

use n0_future::task;
/// Frames waiting for the topic's sender. A full queue refuses the frame: QUIC
/// treats that as loss.
const QUEUE: usize = 256;

/// Hands frames to the topic's sender from a task of its own, because the
/// sender's `broadcast` is async and a sink must not block.
///
/// The task ends when the topic is closed or when the sink is dropped. When it
/// ends it clears the alive flag, and the handle then treats the path as not valid
/// and counts a datagram as `dropped_no_sink`.
///
/// # Examples
///
/// It sends frames on a live gossip sender, which a caller gets from a running gossip node, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_gossip_transport::{FrameSink, GossipSink, iroh_gossip::api::GossipSender};
///
/// # fn demo(sender: GossipSender) -> bool {
/// GossipSink::spawn(sender).is_alive()
/// # }
/// ```
#[derive(Debug)]
pub struct GossipSink {
    queue: mpsc::Sender<Bytes>,
    // the sink's task and the handle both read the liveness flag
    alive: Arc<AtomicBool>,
}

impl GossipSink {
    /// Start the task that sends on `sender`.
    #[must_use]
    pub fn spawn(sender: GossipSender) -> Self {
        let (queue, mut frames) = mpsc::channel::<Bytes>(QUEUE);
        // the sink's task and the handle both read the liveness flag
        let alive = Arc::new(AtomicBool::new(true));
        let task_alive = Arc::clone(&alive);
        task::spawn(async move {
            while let Some(frame) = frames.recv().await {
                if sender.broadcast(frame).await.is_err() {
                    break;
                }
            }
            task_alive.store(false, Ordering::SeqCst);
        });
        Self { queue, alive }
    }
}

impl FrameSink for GossipSink {
    fn try_send(&self, frame: Bytes) -> bool {
        self.queue.try_send(frame).is_ok()
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}
