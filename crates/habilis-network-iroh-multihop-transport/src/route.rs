//! The route carried inside a multihop [`CustomAddr`].
//!
//! A multihop address is not a location — it is a **source route**: the ordered
//! hops from the sender to the destination, each named by two ids: the
//! application endpoint and its underlay endpoint. iroh treats the whole encoded
//! route as an opaque path locator; we pack/unpack it here.
//!
//! A hop carries no address. iroh maps an address to a path by its bytes, so an
//! address in the route would make one route two paths as soon as the two ends
//! hold different versions of it (a relay switch, a new IP). A forwarder looks up
//! the address of its next hop in its own topology, from the vector that the hop
//! signed.
//!
//! Reachability-first: the route is *reversible*. A terminal derives the return
//! route from the forward route plus the sender's own hop, so a reply needs no
//! fresh lookup (see [`Route::reverse_from`]). This assumes the underlay links
//! are usable in both directions, which the bidirectional link-state graph
//! already models.

use iroh_base::CustomAddr;
use serde::{Deserialize, Deserializer, Serialize};

use crate::MULTIHOP_TRANSPORT_ID;
use crate::app_id::{AppId, UnderlayId};

/// Longest route this transport will build or relay. Routes come from Dijkstra
/// over the link-state graph and multihop is a last-resort path, so real ones
/// are short; the ceiling exists to bound what a *hostile* route can cost. It is
/// the amplification limit: a cell can be forwarded at most this many times.
pub(crate) const MAX_ROUTE_HOPS: usize = 8;

/// One hop in a source route: which node it is (its [`AppId`])
/// and which multihop **underlay** endpoint carries its cells. Two ids, 64 bytes,
/// and no address: see the module note.
///
/// # Examples
///
/// The routing code builds a hop, and a caller outside the crate cannot build one, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_multihop_transport::RouteHop;
///
/// # fn demo(hop: RouteHop) {
/// drop(hop);
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub struct RouteHop {
    pub(crate) app_id: AppId,
    pub(crate) underlay_id: UnderlayId,
}

/// A source route: the ordered hops **after** the sender, ending at the
/// destination.
///
/// Constructing one validates it, and `new` is the only way in —
/// including from the wire, since [`Deserialize`] goes through it. So every
/// `Route` in the program is non-empty, at most `MAX_ROUTE_HOPS` long, and
/// visits each node once. That last property is what stops a relay being used as
/// an amplifier: a route cannot revisit a hop, so no node forwards a given cell
/// more than once.
///
/// # Examples
///
/// The topology builds a route from a Leg, which a caller outside the crate cannot build, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_multihop_transport::Route;
///
/// # fn demo(route: &Route) -> Route {
/// route.clone()
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Route(Vec<RouteHop>);

impl Route {
    /// The hops as short ids for a log line: the application id of each, then the id
    /// of its underlay, which differ because the underlay has a key of its own.
    pub(crate) fn describe(&self) -> String {
        let describe_hop =
            |hop: &RouteHop| format!("{}/{}", hop.app_id.fmt_short(), hop.underlay_id.fmt_short());
        let hops: Vec<String> = self.0.iter().map(describe_hop).collect();
        hops.join(">")
    }

    pub(crate) fn singleton(hop: RouteHop) -> Self {
        Self(vec![hop])
    }

    pub(crate) fn try_new(hops: Vec<RouteHop>) -> Option<Self> {
        if hops.is_empty() || hops.len() > MAX_ROUTE_HOPS {
            return None;
        }
        if repeats_a_hop(&hops) {
            return None;
        }
        Some(Self(hops))
    }

    pub(crate) fn hops(&self) -> &[RouteHop] {
        &self.0
    }

    /// The hop at `pos`, or `None` if `pos` is past the end.
    pub(crate) fn hop_at(&self, position: usize) -> Option<&RouteHop> {
        self.0.get(position)
    }

    /// Encode into the opaque `data` of a multihop [`CustomAddr`]. postcard is
    /// deterministic, so the same route always yields byte-identical addresses —
    /// which iroh relies on to dedupe a peer's path.
    pub(crate) fn encode(&self) -> CustomAddr {
        let bytes = postcard::to_allocvec(self).expect("route serializes");
        CustomAddr::from_parts(MULTIHOP_TRANSPORT_ID, &bytes)
    }

    /// Decode a multihop [`CustomAddr`] back into a route. Returns `None` for a
    /// wrong transport id or malformed bytes. The `underlay_id` of a decoded hop is an
    /// id to resolve, not an address: the forwarder looks up the address in its topology.
    pub(crate) fn decode(address: &CustomAddr) -> Option<Self> {
        if address.id() != MULTIHOP_TRANSPORT_ID {
            return None;
        }
        postcard::from_bytes(address.data()).ok()
    }

    /// The return route a terminal should hand back as its remote address, given
    /// the forward route it received and the original `source` hop.
    ///
    /// Forward `S → [R1, R2, B]` (source `S`) reverses to `B → [R2, R1, S]`:
    /// drop the destination (`B`, which is us), reverse the interior, then append
    /// the source. Applying this again at `S` reproduces the original forward
    /// route. A hop holds ids and no address, so the bytes of the route are the
    /// same at both ends, whatever address either end holds for a hop: iroh sees
    /// one path locator for the pair, not one per spelling.
    ///
    /// The caller must have established that `forward` ends at this node —
    /// [`Forwarder::handle_cell`](crate::underlay::Forwarder::handle_cell) does,
    /// which is what makes the `skip(1)` true rather than merely hoped for.
    /// `None` when the result is not a legal route: `source` already appears in
    /// `forward`, so reversing would mint a cyclic return path.
    pub(crate) fn reverse_from(forward: &[RouteHop], source: RouteHop) -> Option<Self> {
        let trimmed = forward.iter().rev().skip(1); // drop the destination (ourselves)
        let mut hops: Vec<RouteHop> = trimmed.copied().collect();
        hops.push(source);
        Self::try_new(hops)
    }
}

/// Whether any two hops name the same node. Both identities are checked, and
/// separately: a repeated `underlay_id` is a bounce because that is the key the
/// forwarder dials on, and a repeated `app_id` is a bounce at the layer above.
/// Comparing them pairwise rather than pooling them keeps a node whose two
/// endpoints share a key from rejecting its own routes.
///
/// Quadratic over at most [`MAX_ROUTE_HOPS`] entries, which beats allocating.
fn repeats_a_hop(hops: &[RouteHop]) -> bool {
    hops.iter().enumerate().any(|(index, hop)| {
        hops[..index]
            .iter()
            .any(|earlier| earlier.underlay_id == hop.underlay_id || earlier.app_id == hop.app_id)
    })
}

impl<'de> Deserialize<'de> for Route {
    fn deserialize<DeserializerT>(deserializer: DeserializerT) -> Result<Self, DeserializerT::Error>
    where
        DeserializerT: Deserializer<'de>,
    {
        let hops = Vec::<RouteHop>::deserialize(deserializer)?;
        Self::try_new(hops).ok_or_else(|| serde::de::Error::custom("empty multihop route"))
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_ROUTE_HOPS, Route, RouteHop};
    use crate::app_id::{AppId, UnderlayId};
    use iroh::{EndpointId, SecretKey};
    use std::fmt::Write as _;

    fn hop(seed: u8) -> RouteHop {
        let id: EndpointId = SecretKey::from_bytes(&[seed; 32]).public();
        RouteHop {
            app_id: AppId::new(id),
            underlay_id: UnderlayId::new(id),
        }
    }

    #[test]
    fn encode_decode_roundtrips() {
        let _guard = ::habilis_network_test_tracing::init();
        let route = Route::try_new(vec![hop(1), hop(2), hop(3)]).unwrap();
        let address = route.encode();
        assert_eq!(
            Route::decode(&address).expect("decodes"),
            route,
            "an encoded route decodes back to the same route"
        );
    }

    /// The route is a wire value: iroh dedupes a peer's path on these bytes, and a second
    /// build must read what this one writes.
    #[test]
    fn a_route_encodes_to_fixed_bytes() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = |seed: u8| -> EndpointId { SecretKey::from_bytes(&[seed; 32]).public() };
        let route = Route::try_new(vec![
            RouteHop {
                app_id: AppId::new(id(1)),
                underlay_id: UnderlayId::new(id(2)),
            },
            RouteHop {
                app_id: AppId::new(id(3)),
                underlay_id: UnderlayId::new(id(4)),
            },
        ])
        .unwrap();
        let mut data = String::new();
        for byte in route.encode().data() {
            write!(data, "{byte:02x}").unwrap();
        }
        assert_eq!(
            data,
            concat!(
                "028a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
                "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394ed",
                "4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1ca93",
                "ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c"
            ),
            "a route encodes to fixed bytes"
        );
    }

    #[test]
    fn wrong_transport_id_does_not_decode() {
        let _guard = ::habilis_network_test_tracing::init();
        let route = Route::try_new(vec![hop(1)]).unwrap();
        let address = route.encode();
        let foreign = iroh_base::CustomAddr::from_parts(0x99, address.data());
        assert!(
            Route::decode(&foreign).is_none(),
            "a route with a foreign transport id does not decode"
        );
    }

    #[test]
    fn empty_route_does_not_decode() {
        let _guard = ::habilis_network_test_tracing::init();
        let bytes = postcard::to_allocvec(&Vec::<RouteHop>::new()).unwrap();
        let address = iroh_base::CustomAddr::from_parts(crate::MULTIHOP_TRANSPORT_ID, &bytes);
        assert!(
            Route::decode(&address).is_none(),
            "an empty route does not decode"
        );
    }

    #[test]
    fn reverse_is_an_involution_across_the_two_ends() {
        let _guard = ::habilis_network_test_tracing::init();
        // Source S=hop(9); forward route to B: [R1, R2, B].
        let (source, r1, r2, dest) = (hop(9), hop(1), hop(2), hop(3));
        let forward = vec![r1, r2, dest];

        // At B, the return route is [R2, R1, S].
        let ret = Route::reverse_from(&forward, source).expect("reverses");
        assert_eq!(
            ret.0,
            vec![r2, r1, source],
            "the reversed route lists the hops back to the source"
        );

        // Reversing again at S (source now B) reproduces the forward route.
        let back = Route::reverse_from(&ret.0, dest).expect("reverses");
        assert_eq!(back.0, forward, "reversing twice returns the forward route");
    }

    #[test]
    fn a_route_past_the_hop_ceiling_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        // ~4000 hops fit in one cell, which is what turns a relay into a
        // 1000x amplifier; the ceiling is the cap on that.
        let hops: Vec<RouteHop> = (0..=MAX_ROUTE_HOPS)
            .map(|seed| hop(u8::try_from(seed).expect("seed fits")))
            .collect();
        assert!(
            Route::try_new(hops).is_none(),
            "a route past the hop ceiling is refused"
        );
    }

    #[test]
    fn a_route_at_the_hop_ceiling_is_accepted() {
        let _guard = ::habilis_network_test_tracing::init();
        let hops: Vec<RouteHop> = (0..MAX_ROUTE_HOPS)
            .map(|seed| hop(u8::try_from(seed).expect("seed fits")))
            .collect();
        assert!(
            Route::try_new(hops).is_some(),
            "a route at the hop ceiling is accepted"
        );
    }

    #[test]
    fn a_route_that_revisits_a_hop_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        // The [X, Y, X, Y, …] ping-pong: every entry is a real node, so an
        // "am I named here?" check passes at every bounce. Acyclicity is what
        // actually stops it.
        assert!(
            Route::try_new(vec![hop(1), hop(2), hop(1)]).is_none(),
            "a route that revisits a hop is refused"
        );
    }

    #[test]
    fn a_route_past_the_hop_ceiling_does_not_decode() {
        let _guard = ::habilis_network_test_tracing::init();
        let hops: Vec<RouteHop> = (0..=MAX_ROUTE_HOPS)
            .map(|seed| hop(u8::try_from(seed).expect("seed fits")))
            .collect();
        let bytes = postcard::to_allocvec(&hops).unwrap();
        let address = iroh_base::CustomAddr::from_parts(crate::MULTIHOP_TRANSPORT_ID, &bytes);
        assert!(
            Route::decode(&address).is_none(),
            "a route past the hop ceiling does not decode"
        );
    }

    #[test]
    fn a_cyclic_route_does_not_decode() {
        let _guard = ::habilis_network_test_tracing::init();
        let hops = vec![hop(1), hop(2), hop(1)];
        let bytes = postcard::to_allocvec(&hops).unwrap();
        let address = iroh_base::CustomAddr::from_parts(crate::MULTIHOP_TRANSPORT_ID, &bytes);
        assert!(
            Route::decode(&address).is_none(),
            "a cyclic route does not decode"
        );
    }

    #[test]
    fn reverse_refuses_a_source_already_in_the_path() {
        let _guard = ::habilis_network_test_tracing::init();
        // A cell claiming a source that is also one of its hops would reverse
        // into a cyclic return route — including a source claiming to be us.
        let forward = vec![hop(1), hop(2), hop(3)];
        assert!(
            Route::reverse_from(&forward, hop(1)).is_none(),
            "reverse refuses a source already in the path"
        );
    }
}
