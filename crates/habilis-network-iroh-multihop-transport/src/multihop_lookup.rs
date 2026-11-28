//! The address lookup that answers iroh with the multihop address of a destination.
//!
//! The answer is the address of the destination and nothing more: it holds no route, so a link that leaves the
//! graph can never make it stale. Whether a cell can leave this node toward the destination is decided for each
//! cell by the next hop of the node, and the lookup answers only while a next hop exists now.

use std::sync::Arc;

use iroh::address_lookup::{AddressLookup, Error, Item};
use iroh::endpoint_info::{EndpointData, EndpointInfo};
use iroh::{EndpointId, TransportAddr};
use n0_future::boxed::BoxStream;
use n0_future::stream;

use crate::app_id::AppId;
use crate::destination::Destination;
use crate::next_hop::NextHop;
use crate::underlay::Forwarder;

/// The provenance that the lookup gives to the items that it answers.
const PROVENANCE: &str = "iroh-multihop";

/// Answers the address of a destination when this node has a next hop toward it.
#[derive(Debug, Clone)]
pub(crate) struct MultihopLookup {
    // shared with the handle that forwards for it
    forwarder: Arc<Forwarder>,
    self_id: AppId,
}

impl MultihopLookup {
    pub(crate) fn new(
        self_id: AppId,
        // shared with the handle that forwards for it
        forwarder: Arc<Forwarder>,
    ) -> Self {
        Self { forwarder, self_id }
    }
}

impl AddressLookup for MultihopLookup {
    fn publish(&self, _data: &EndpointData) {}

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        let dst = AppId::new(endpoint_id);
        let next = self.forwarder.next_hop(dst, None);
        let found = matches!(next, NextHop::Forward(_));
        tracing::debug!(target: "habilis_lookup", me = %self.self_id.fmt_short(), remote = %endpoint_id.fmt_short(), found, "multihop lookup");
        if !found {
            return None;
        }
        let address = TransportAddr::Custom(Destination::new(dst).encode());
        let info = EndpointInfo::from_parts(endpoint_id, EndpointData::from_iter([address]));
        Some(Box::pin(stream::once(Ok(Item::new(
            info, PROVENANCE, None,
        )))))
    }
}
