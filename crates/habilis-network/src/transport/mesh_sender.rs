use std::sync::{Arc, RwLock};

use iroh::EndpointId;
use iroh_gossip::api::{ApiError, GossipSender};

use crate::daemon::state::note_wire_out;
use crate::protocol::messages::WireFrame;

/// The mesh's outbound broadcast plane: a thin wrapper over the gossip sender
/// that survives a topic resubscribe (`gossip::heal`) via `MeshSender::replace_gossip`,
/// so the ~ten existing `.broadcast()` call sites hold a stable handle across
/// the swap.
///
/// A clone shares the handle, so the task that sends the digest answers (see
/// `ResendOutbox`) follows a resubscribe too.
///
/// # Examples
///
/// A mesh sender broadcasts wire frames to the mesh. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::ops::MeshSender;
/// use habilis_network::protocol::messages::WireFrame;
///
/// # async fn demo(sender: &MeshSender, frame: WireFrame) {
/// let _ = sender.broadcast(frame).await;
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct MeshSender {
    // the sender is shared by the mesh handles, which swap the gossip under it
    gossip: Arc<RwLock<GossipSender>>,
}

impl MeshSender {
    pub(crate) fn new(gossip: GossipSender) -> Self {
        Self {
            // the sender is shared by the mesh handles, which swap the gossip under it
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
    pub async fn broadcast(&self, message: WireFrame) -> Result<(), ApiError> {
        let bytes = message.into_bytes();
        let sent = self.current().broadcast(bytes.clone()).await;
        if sent.is_ok() {
            note_wire_out(&bytes);
        }
        sent
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

#[cfg(test)]
mod tests {
    use iroh::endpoint::presets;
    use iroh_gossip::net::Gossip;
    use iroh_gossip::proto;

    use super::MeshSender;
    use crate::daemon::state::{app_frame_with_tag, sent_tag_bytes};
    use crate::protocol::messages::WireFrame;

    /// A broadcast is counted in the sent bytes, once, under the kind and the tag of the frame. The
    /// tag is the test's own, and the send repeats until it shows, because the tests that end an
    /// interval run beside this one and can take the count first.
    #[test]
    fn a_broadcast_is_counted_in_the_sent_bytes() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let endpoint = iroh::Endpoint::builder(presets::Minimal)
                .bind()
                .await
                .expect("bind a local endpoint");
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let topic = gossip
                .subscribe(proto::TopicId::from_bytes([6u8; 32]), vec![])
                .await
                .expect("subscribe to a peerless topic");
            let (gossip_sender, _receiver) = topic.split();
            let sender = MeshSender::new(gossip_sender);
            let bytes = app_frame_with_tag("broadcast_count_probe");
            let mut counted = 0;
            for _ in 0..50 {
                let frame = WireFrame::fixture_raw(bytes::Bytes::from(bytes.clone()));
                sender
                    .broadcast(frame)
                    .await
                    .expect("a peerless broadcast is accepted");
                counted = sent_tag_bytes("broadcast_count_probe");
                if counted >= bytes.len() as u64 {
                    break;
                }
            }
            assert!(
                counted >= bytes.len() as u64,
                "{counted} bytes counted for a frame of {}",
                bytes.len()
            );
            endpoint.close().await;
        });
    }
}
