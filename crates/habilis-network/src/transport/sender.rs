use std::sync::{Arc, RwLock};

use bytes::Bytes;
use iroh::EndpointId;
use iroh_gossip::api::{ApiError, GossipSender};

/// The mesh's outbound broadcast plane: a thin wrapper over the gossip sender
/// that survives a topic resubscribe (`gossip::heal`) via [`MeshSender::replace_gossip`],
/// so the ~ten existing `.broadcast()` call sites hold a stable handle across
/// the swap.
///
/// A clone shares the handle, so the task that sends the digest answers (see
/// [`ResendOutbox`](super::ResendOutbox)) follows a resubscribe too.
#[derive(Debug, Clone)]
pub struct MeshSender {
    gossip: Arc<RwLock<GossipSender>>,
}

impl MeshSender {
    pub(crate) fn new(gossip: GossipSender) -> Self {
        Self {
            gossip: Arc::new(RwLock::new(gossip)),
        }
    }

    /// The current gossip handle. Cloned out of the lock, so no lock is held
    /// across the `await` of a send.
    fn current(&self) -> GossipSender {
        self.gossip.read().expect("gossip sender lock").clone()
    }

    /// Broadcast over gossip. Same signature as [`GossipSender::broadcast`], so
    /// call sites are unchanged.
    /// # Errors
    /// The gossip topic has been closed, or the send buffer is full.
    pub async fn broadcast(&self, message: Bytes) -> Result<(), ApiError> {
        self.current().broadcast(message).await
    }

    pub(crate) async fn join_peers(&self, peers: Vec<EndpointId>) -> Result<(), ApiError> {
        self.current().join_peers(peers).await
    }

    /// Ask `peers` for a link with low priority: a peer with a full view refuses
    /// and keeps its neighbors, where a [`Self::join_peers`] evicts one.
    pub(crate) async fn neighbor_peers(&self, peers: Vec<EndpointId>) -> Result<(), ApiError> {
        self.current().neighbor_peers(peers).await
    }

    /// Leave `peers` on purpose: gossip tells each that we are not coming back,
    /// so it does not dial us to refill its view, and closes the link itself.
    pub(crate) async fn leave_peers(&self, peers: Vec<EndpointId>) -> Result<(), ApiError> {
        self.current().leave_peers(peers).await
    }

    /// Swap the inner gossip sender after a topic resubscribe (`gossip::heal`).
    pub(crate) fn replace_gossip(&mut self, gossip: GossipSender) {
        *self.gossip.write().expect("gossip sender lock") = gossip;
    }
}
