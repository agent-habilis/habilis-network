use iroh::Endpoint;
use tokio::runtime::Handle;

/// An endpoint that closes itself when the fetch future is dropped before it closes the
/// endpoint. `Endpoint::close` is async, so the drop spawns it. Without this a cancelled fetch
/// leaks the endpoint: the task that follows its home relay holds a clone for the life of the
/// process.
#[must_use = "the endpoint closes when this is dropped"]
pub(super) struct CloseOnDrop {
    pub(super) endpoint: Endpoint,
    // The runtime of the fetch. A drop on a plain thread has no runtime of its own.
    runtime: Handle,
    closed: bool,
}

impl CloseOnDrop {
    pub(super) fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            runtime: Handle::current(),
            closed: false,
        }
    }

    pub(super) async fn close(mut self) {
        self.endpoint.close().await;
        self.closed = true;
    }
}

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        if !self.closed {
            let endpoint = self.endpoint.clone();
            self.runtime.spawn(async move { endpoint.close().await });
        }
    }
}
