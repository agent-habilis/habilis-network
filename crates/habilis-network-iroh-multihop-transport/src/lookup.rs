//! Resolving an endpoint id to a multihop [`CustomAddr`](iroh_base::CustomAddr).
//!
//! This is the initiator-side authority: given the local [`Topology`], compute
//! the best source route to a target and hand iroh the route packed into a
//! custom transport address. iroh then forms an end-to-end QUIC connection whose
//! packets ride that route. Because the route is self-contained, no hop needs a
//! separate lookup — the destination even derives its reply route from the cell.

use std::sync::{Arc, RwLock};

use iroh::EndpointId;
use iroh::TransportAddr;
use iroh::address_lookup::{AddressLookup, Error, Item};
use iroh::endpoint_info::{EndpointData, EndpointInfo};
use n0_future::stream::{self, Boxed};

use crate::topology::Topology;

/// Provenance tag iroh attaches to items this lookup produces.
const PROVENANCE: &str = "iroh-multihop";

#[derive(Debug)]
pub(crate) struct MultihopLookup {
    self_id: EndpointId,
    topology: Arc<RwLock<Topology>>,
}

impl MultihopLookup {
    pub(crate) fn new(self_id: EndpointId, topology: Arc<RwLock<Topology>>) -> Self {
        Self { self_id, topology }
    }
}

impl AddressLookup for MultihopLookup {
    fn publish(&self, _data: &EndpointData) {}

    fn resolve(&self, endpoint_id: EndpointId) -> Option<Boxed<Result<Item, Error>>> {
        // One route: the pool's alternates are for the send path's own failover,
        // not iroh's path set, and nothing here reads past the first.
        //
        // Asking for `max_paths` and then taking `[0]` cost a Dijkstra per
        // discarded alternate on every dial. `max_paths` stays on the handle
        // for the failover consumer that will want it; until one exists, the
        // resolver pays for exactly what it uses.
        let route = self
            .topology
            .read()
            .expect("topology lock poisoned")
            .route_to(self.self_id, endpoint_id, 1)
            .into_iter()
            .next()?;
        let info = EndpointInfo::from_parts(
            endpoint_id,
            EndpointData::from_iter([TransportAddr::Custom(route.encode())]),
        );
        Some(Box::pin(stream::once(Ok(Item::new(
            info, PROVENANCE, None,
        )))))
    }
}
