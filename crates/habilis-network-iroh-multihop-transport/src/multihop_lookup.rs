//! Resolving an endpoint id to a multihop [`CustomAddr`](iroh_base::CustomAddr).
//!
//! This is the initiator-side authority: given the local [`Topology`], compute
//! the best source route to a target and hand iroh the route packed into a
//! custom transport address. iroh then forms an end-to-end QUIC connection whose
//! packets ride that route. Because the route is self-contained, no hop needs a
//! separate lookup — the destination even derives its reply route from the cell.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use iroh::address_lookup::{AddressLookup, Error, Item};
use iroh::endpoint_info::{EndpointData, EndpointInfo};
use iroh::{EndpointId, TransportAddr};
use n0_future::boxed::BoxStream;
use n0_future::stream;

use crate::app_id::AppId;
use crate::graph::Leg;
use crate::route::Route;
use crate::topology::Topology;
use crate::underlay::Forwarder;

/// Provenance tag iroh attaches to items this lookup produces.
const PROVENANCE: &str = "iroh-multihop";

/// The address is ONE fixed route, computed when the lookup answers. It is not
/// kept up to date: the sender decodes the route from the destination address on
/// every packet and never reads the topology again. When a hop of the route leaves
/// or stops forwarding, its cells are dropped at that hop, QUIC sees no
/// acknowledgements and abandons the path at its idle timeout, and the pair falls
/// to the next rung. A new route comes only from a new lookup, which iroh runs
/// when something dials the remote and no non-relay path is selected, and which
/// answers only if the topology has a route at that moment.
#[derive(Debug)]
pub(crate) struct MultihopLookup {
    chooser: RouteChooser,
}

impl MultihopLookup {
    pub(crate) fn new(chooser: RouteChooser) -> Self {
        Self { chooser }
    }
}

/// A route that [`RouteChooser::choose`] picked.
#[derive(Debug)]
pub(crate) struct Chosen {
    pub(crate) route: Route,
    /// Whether the shortest route was left for another, because the gate refuses
    /// its first hop.
    pub(crate) skipped: bool,
}

/// The one place that picks the route to a destination, for the lookup that iroh
/// asks and for the dial that carries the route itself.
///
/// It takes the shortest route, unless the gate refuses its first hop now. Then
/// it takes the shortest one that starts elsewhere, and when there is none, the
/// shortest again. The link vector that other nodes see drops a hop only after
/// the stuck deadline; our own choice of a first hop reads the live gate.
#[derive(Debug, Clone)]
pub(crate) struct RouteChooser {
    self_id: AppId,
    topology: Arc<RwLock<Topology>>,
    forwarder: Arc<Forwarder>,
}

impl RouteChooser {
    pub(crate) fn new(
        self_id: AppId,
        topology: Arc<RwLock<Topology>>,
        forwarder: Arc<Forwarder>,
    ) -> Self {
        Self {
            self_id,
            topology,
            forwarder,
        }
    }

    pub(crate) fn choose(&self, dst: AppId) -> Option<Chosen> {
        let refused: HashSet<AppId> = self.forwarder.refusing_hops().into_iter().collect();
        let topology = self.topology.read().expect("topology lock poisoned");
        let leg = Leg {
            src: self.self_id,
            dst,
        };
        let shortest = topology.route_to(leg, 1).next();
        let first_hop = shortest.as_ref().and_then(|route| route.hops().first());
        let first_is_refused: bool = first_hop.is_some_and(|hop| refused.contains(&hop.app_id));
        if first_is_refused
            && let Some(route) = topology.route_to_avoiding_first_hops(leg, &refused)
        {
            return Some(Chosen {
                route,
                skipped: true,
            });
        }
        shortest.map(|route| Chosen {
            route,
            skipped: false,
        })
    }
}

impl AddressLookup for MultihopLookup {
    fn publish(&self, _data: &EndpointData) {}

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        // One route, chosen as `route_addr` chooses it: the shortest, unless the gate
        // refuses its first hop.
        let chosen = self.chooser.choose(AppId::new(endpoint_id));
        let first_hop_skipped = chosen.as_ref().is_some_and(|chosen| chosen.skipped);
        let hops = chosen
            .as_ref()
            .map_or_else(String::new, |chosen| chosen.route.describe());
        tracing::debug!(target: "habilis_lookup", me = %self.chooser.self_id.fmt_short(), remote = %endpoint_id.fmt_short(), found = chosen.is_some(), first_hop_skipped = first_hop_skipped, hops = %hops, "multihop lookup");
        let route = chosen?.route;
        let info = EndpointInfo::from_parts(
            endpoint_id,
            EndpointData::from_iter([TransportAddr::Custom(route.encode())]),
        );
        Some(Box::pin(stream::once(Ok(Item::new(
            info, PROVENANCE, None,
        )))))
    }
}
