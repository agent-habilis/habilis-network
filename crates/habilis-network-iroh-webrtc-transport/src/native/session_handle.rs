//! The send side of one session, and the guard that stops its driver.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Aborts the session driver task when the handle leaves the registry, so
/// a `detach` (or dropping the whole transport) reliably stops the str0m
/// loop instead of detaching it.
///
/// Not at once: dropping the handle also closes the driver's outbound queue,
/// and the driver answers that by closing the data channel, which is how the
/// far side learns of the detach. [`CLOSE_GRACE`] lets that close go out; a
/// driver still running after it is aborted.
struct AbortOnDrop(JoinHandle<()>);

const CLOSE_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        let abort = self.0.abort_handle();
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    tokio::time::sleep(CLOSE_GRACE).await;
                    abort.abort();
                });
            }
            Err(_) => abort.abort(),
        }
    }
}

pub(crate) struct SessionHandle {
    pub(crate) out_tx: mpsc::Sender<Bytes>,
    // the session drop counter, shared with the registry
    pub(crate) dropped_tx: Arc<AtomicU64>,
    /// Aborts the driver when the registry drops this handle.
    _task: AbortOnDrop,
}

impl SessionHandle {
    pub(crate) fn new(
        out_tx: mpsc::Sender<Bytes>,
        // the session drop counter, shared with the registry
        dropped_tx: Arc<AtomicU64>,
        task: JoinHandle<()>,
    ) -> Self {
        Self {
            out_tx,
            dropped_tx,
            _task: AbortOnDrop(task),
        }
    }
}
