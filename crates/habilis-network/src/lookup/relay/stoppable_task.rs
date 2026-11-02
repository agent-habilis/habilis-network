use std::future::Future;

use n0_future::task::JoinHandle;
use tokio::sync::watch;

use crate::util::tuning::RENDEZVOUS_CLOSE;

use n0_future::{task, time};
/// A task that walks the relay ladder, held so its owner can stop it and wait
/// for it on the way out. It is never aborted: the walk probes each rung on an
/// endpoint of its own, and an abort mid-walk drops that endpoint open.
/// Dropped without [`Self::stop_and_wait`], the task still stops and closes
/// its endpoint on its own, as long as the runtime lives.
#[derive(Debug)]
pub(crate) struct StoppableTask {
    task: JoinHandle<()>,
    /// Dropped to tell the task to stop.
    stop: watch::Sender<()>,
}

impl StoppableTask {
    /// Spawn `run`, which must return promptly once its receiver reports the
    /// sender gone (see `select_bootstrap_rung`).
    pub(crate) fn spawn<Fut>(run: impl FnOnce(watch::Receiver<()>) -> Fut) -> Self
    where
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (stop, stopped) = watch::channel(());
        Self {
            task: task::spawn(run(stopped)),
            stop,
        }
    }

    /// Stop the task and wait for it, bounded by `RENDEZVOUS_CLOSE` like
    /// the other closes on the way out.
    pub(crate) async fn stop_and_wait(self) {
        let Self { task, stop } = self;
        drop(stop);
        if time::timeout(RENDEZVOUS_CLOSE, task).await.is_err() {
            tracing::debug!(target: "habilis_network::lookup", "relay ladder walk did not stop in time; abandoning it");
        }
    }
}
