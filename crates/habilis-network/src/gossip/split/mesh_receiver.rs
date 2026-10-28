use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{mpsc, oneshot};

use super::topic_item::TopicItem;

/// The queue of the mesh messages, from the splitter to the event loop. It is bounded by the
/// capacity of the topic subscription: a hostile member must not be able to grow it without
/// limit. When it is full the newest message is dropped and counted, and anti-entropy repairs it
/// (the topic itself does the same when it lags).
type DataRx = mpsc::Receiver<TopicItem>;

/// The queue of the control events (a neighbor up or down, a lag, an error): their volume is
/// bounded by the topology, and none may be dropped.
type ControlRx = mpsc::UnboundedReceiver<TopicItem>;

/// The mesh events that the splitter forwards, with the same `next()` as the topic receiver.
#[derive(Debug)]
pub(crate) struct MeshReceiver<S> {
    pub(super) data: DataRx,
    pub(super) control: Option<ControlRx>,
    pub(super) dead: Option<oneshot::Receiver<S>>,
    /// The most mesh messages that the data queue held at once.
    pub(super) high_water: Arc<AtomicUsize>,
}

impl<S> MeshReceiver<S> {
    /// The next mesh event, or `None` when the topic ended and the queued messages are read.
    /// The control events come first, so a control event can overtake a mesh message that was
    /// queued before it: nobody relies on the order across the two queues. The end of the topic
    /// comes after the data queued before it.
    pub(crate) async fn next(&mut self) -> Option<TopicItem> {
        loop {
            let Some(control) = self.control.as_mut() else {
                return self.data.recv().await;
            };
            tokio::select! {
                biased;
                item = control.recv() => match item {
                    Some(item) => return Some(item),
                    None => self.control = None,
                },
                item = self.data.recv() => return item,
            }
        }
    }

    /// The most mesh messages that the data queue held at once.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the tests and the load run of the split")
    )]
    pub(crate) fn high_water(&self) -> usize {
        self.high_water.load(Ordering::Relaxed)
    }

    /// The reading of [`Self::high_water`] for a task that outlives the receiver.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the tests and the load run of the split")
    )]
    pub(crate) fn high_water_gauge(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.high_water)
    }

    /// The topic receiver of a subscription that ended, for the drain of what it buffered. It does
    /// not wait: the task hands the receiver back before it closes the queues, so a loop that has
    /// read the end of the topic finds it here. A subscription that has not ended yields none.
    pub(crate) fn into_dead(mut self) -> Option<S> {
        self.dead.take()?.try_recv().ok()
    }
}
