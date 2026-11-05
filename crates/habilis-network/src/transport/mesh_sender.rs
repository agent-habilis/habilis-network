#[cfg(test)]
use std::sync::Mutex;
use std::sync::{Arc, RwLock};

use iroh::EndpointId;
use iroh_gossip::api::{ApiError, GossipSender};

use crate::daemon::state::WireOutTally;
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
    /// Where the sent frames are counted: the tally of the loop that owns this sender. A sender
    /// that no loop owns counts into a tally that nobody reads.
    tally: WireOutTally,
    /// The bytes of every broadcast frame, in order, so a test can count what a node puts on the
    /// wire.
    #[cfg(test)]
    tap: Arc<Mutex<Vec<Vec<u8>>>>, // shared with every clone of the sender, so a test counts them all
}

impl MeshSender {
    pub(crate) fn new(gossip: GossipSender) -> Self {
        Self {
            // the sender is shared by the mesh handles, which swap the gossip under it
            gossip: Arc::new(RwLock::new(gossip)),
            tally: WireOutTally::default(),
            #[cfg(test)]
            tap: Arc::default(),
        }
    }

    /// Count the frames of this sender into `tally`, the tally of the loop that owns it.
    #[must_use]
    pub(crate) fn counting(mut self, tally: WireOutTally) -> Self {
        self.tally = tally;
        self
    }

    /// The frames broadcast so far, as they went on the wire.
    #[cfg(test)]
    pub(crate) fn broadcast_frames(&self) -> Vec<Vec<u8>> {
        self.tap.lock().expect("the tap lock").clone()
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
        #[cfg(test)]
        let recorded = bytes.to_vec();
        let sent = self.current().broadcast(bytes.clone()).await;
        if sent.is_ok() {
            self.tally.note(&bytes);
            // The tap holds only the frames that were sent, or a test counts bytes that never left.
            #[cfg(test)]
            if let Ok(mut tap) = self.tap.lock() {
                tap.push(recorded);
            }
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
    use crate::daemon::state::{WireOutTally, app_frame_with_tag};
    use crate::protocol::messages::WireFrame;

    /// A broadcast is counted in the tally of its own sender, once, under the tag of the frame, and
    /// not in the tally of another loop.
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
            let ours = WireOutTally::default();
            let other = WireOutTally::default();
            let sender = MeshSender::new(gossip_sender).counting(ours.clone());
            let bytes = app_frame_with_tag("broadcast_count_probe");
            let frame = WireFrame::fixture_raw(bytes::Bytes::from(bytes.clone()));
            sender
                .broadcast(frame)
                .await
                .expect("a peerless broadcast is accepted");
            let counted = ours.tag_bytes("broadcast_count_probe");
            assert_eq!(counted, bytes.len() as u64, "the one frame, once");
            assert_eq!(
                other.tag_bytes("broadcast_count_probe"),
                0,
                "the tally of another loop does not take the bytes"
            );
            endpoint.close().await;
        });
    }
}
