use crate::daemon::config::EndpointOwner;

/// What the loop closes as it ends: the router with its endpoint, and the multi-hop
/// underlay, when the engine bound them. An injected endpoint is the caller's and stays
/// open, though the router is still held to the end so its accept loop outlives the loop.
pub(in crate::daemon) struct OwnedEndpoints {
    pub(in crate::daemon) router: iroh::protocol::Router,
    pub(in crate::daemon) owner: EndpointOwner,
    #[cfg(feature = "multihop")]
    pub(in crate::daemon) multihop: Option<habilis_network_iroh_multihop_transport::MultihopHandle>,
}

impl OwnedEndpoints {
    /// Dropping an endpoint that was never closed makes iroh log an ERROR and abort its
    /// connections. `Router::shutdown` closes the router and its endpoint; the two
    /// closes run together, as each can wait on peers that are already gone.
    pub(in crate::daemon) async fn close(self) {
        if self.owner != EndpointOwner::Engine {
            return;
        }
        tokio::join!(
            async {
                // It fails only when a protocol handler panicked, which the task has
                // already reported; the loop is ending either way.
                if let Err(error) = self.router.shutdown().await {
                    tracing::debug!(%error, "the router failed while it shut down");
                }
            },
            async {
                #[cfg(feature = "multihop")]
                if let Some(handle) = self.multihop.as_ref() {
                    handle.close().await;
                }
            },
        );
    }
}
