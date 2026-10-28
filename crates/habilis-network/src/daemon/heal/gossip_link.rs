use iroh_gossip::api::GossipReceiver;

use crate::gossip::split::MeshReceiver;
use crate::transport::MeshSender;

/// The live gossip link a resubscribe mutates: the sender/receiver pair
/// swapped in on success, and the consecutive-failure counter it resets or
/// increments.
pub(in crate::daemon) struct GossipLink<'link> {
    pub(in crate::daemon) sender: &'link mut MeshSender,
    pub(in crate::daemon) receiver: &'link mut MeshReceiver<GossipReceiver>,
    pub(in crate::daemon) attempts: &'link mut u32,
}
