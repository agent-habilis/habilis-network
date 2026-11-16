//! Where a frame goes: the data lane of the Nostr relay client.

use bytes::Bytes;
use habilis_network_iroh_gossip_transport::{FrameSink, frame};
use habilis_network_iroh_nostr_address_lookup::DataPool;
use habilis_network_protocol::nostr::NostrKeys;

/// Sends each frame to the tag of its destination. The pool drops what the socket cannot
/// carry, and QUIC sends it again, so the sink always accepts a frame it can read.
#[derive(Debug)]
pub(crate) struct DataSink {
    pool: DataPool,
    keys: NostrKeys,
}

impl DataSink {
    pub(crate) fn new(pool: DataPool, keys: NostrKeys) -> Self {
        Self { pool, keys }
    }
}

impl FrameSink for DataSink {
    fn try_send(&self, frame: Bytes) -> bool {
        let Ok(decoded) = frame::decode(&frame) else {
            return false;
        };
        let tag = self.keys.self_tag(&decoded.dst);
        self.pool.send(&tag, frame.to_vec());
        true
    }
}
