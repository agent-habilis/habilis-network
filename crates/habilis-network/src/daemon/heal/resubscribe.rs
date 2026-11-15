use iroh_gossip::api::{GossipReceiver, GossipSender};

use crate::gossip::split::MeshReceiver;

/// Outcome of one resubscribe attempt (the heal arm drives one per
/// tick while the gossip stream is down).
pub(in crate::daemon) enum Resubscribe {
    Restored(GossipSender, MeshReceiver<GossipReceiver>),
    Pending,
    Fatal,
}
