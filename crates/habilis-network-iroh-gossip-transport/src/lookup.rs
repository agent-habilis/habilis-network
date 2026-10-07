//! Resolving an endpoint id to its gossip address, for the first dial.

use std::sync::Arc;

use std::sync::atomic::Ordering;

use iroh::address_lookup::{AddressLookup, Error, Item};
use iroh::endpoint_info::{EndpointData, EndpointInfo};
use iroh::{EndpointId, TransportAddr};
use n0_future::boxed::BoxStream;
use n0_future::stream;

use crate::gossip_addr;
use crate::transport::Shared;

/// Provenance tag that iroh attaches to the items this lookup produces.
const PROVENANCE: &str = "iroh-gossip-transport";

/// The gossip address names a node and not a place, so every member has one. The
/// lookup answers a dial of a peer once, and only while a sink is attached: a path
/// that cannot carry a packet is not offered. Which pairs *keep* the path is the
/// engine's rule (`GossipHandle::allow`), not this lookup's.
#[derive(Debug)]
pub(crate) struct GossipLookup {
    pub(crate) shared: Arc<Shared>,
}

impl AddressLookup for GossipLookup {
    fn publish(&self, _data: &EndpointData) {}

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        if endpoint_id == self.shared.app_id || !self.shared.attached.load(Ordering::SeqCst) {
            return None;
        }
        let info = EndpointInfo::from_parts(
            endpoint_id,
            EndpointData::from_iter([TransportAddr::Custom(gossip_addr(endpoint_id))]),
        );
        Some(Box::pin(stream::once(Ok(Item::new(
            info, PROVENANCE, None,
        )))))
    }
}

#[cfg(test)]
mod tests {
    use iroh::{SecretKey, TransportAddr};
    use n0_future::StreamExt;

    use crate::memory::MemoryHub;
    use crate::{GossipHandle, gossip_addr};

    fn id(seed: u8) -> iroh::EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    async fn answer(handle: &GossipHandle, peer: iroh::EndpointId) -> Option<Vec<TransportAddr>> {
        use iroh::address_lookup::AddressLookup;
        let mut stream = handle.address_lookup().resolve(peer)?;
        let item = stream.next().await?.expect("an item");
        Some(item.endpoint_info().data.addrs().cloned().collect())
    }

    /// The first dial of a peer gets the gossip address, once a sink is attached.
    #[tokio::test]
    async fn the_lookup_answers_a_peer_with_its_gossip_address_once_attached() {
        let handle = GossipHandle::new(id(1));
        assert_eq!(answer(&handle, id(2)).await, None, "before attach");

        MemoryHub::new().join(&handle);

        assert_eq!(
            answer(&handle, id(2)).await,
            Some(vec![TransportAddr::Custom(gossip_addr(id(2)))])
        );
    }

    #[tokio::test]
    async fn the_lookup_does_not_answer_for_the_node_itself() {
        let handle = GossipHandle::new(id(1));
        MemoryHub::new().join(&handle);

        assert_eq!(answer(&handle, id(1)).await, None);
    }
}
