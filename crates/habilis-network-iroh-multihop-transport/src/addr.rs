//! The route carried inside a multihop [`CustomAddr`].
//!
//! A multihop address is not a location — it is a **source route**: the ordered
//! hops from the sender to the destination, each carrying the underlay
//! [`EndpointAddr`] needed to dial it. iroh treats the whole encoded route as an
//! opaque path locator; we pack/unpack it here.
//!
//! Reachability-first: the route is *reversible*. A terminal derives the return
//! route from the forward route plus the sender's own hop, so a reply needs no
//! fresh lookup (see [`Route::reverse_from`]). This assumes the underlay links
//! are usable in both directions, which the bidirectional link-state graph
//! already models.

use iroh::{EndpointAddr, EndpointId};
use iroh_base::CustomAddr;
use serde::{Deserialize, Deserializer, Serialize};

use crate::MULTIHOP_TRANSPORT_ID;

/// Longest route this transport will build or relay. Routes come from Dijkstra
/// over the link-state graph and multihop is a last-resort path, so real ones
/// are short; the ceiling exists to bound what a *hostile* route can cost. It is
/// the amplification limit: a cell can be forwarded at most this many times.
pub(crate) const MAX_ROUTE_HOPS: usize = 8;

/// One hop in a source route: which node it is (its app-layer [`EndpointId`])
/// and how to dial its multihop **underlay** endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteHop {
    pub(crate) app_id: EndpointId,
    pub(crate) underlay: EndpointAddr,
}

/// A source route: the ordered hops **after** the sender, ending at the
/// destination.
///
/// Constructing one validates it, and [`new`](Self::new) is the only way in —
/// including from the wire, since [`Deserialize`] goes through it. So every
/// `Route` in the program is non-empty, at most [`MAX_ROUTE_HOPS`] long, and
/// visits each node once. That last property is what stops a relay being used as
/// an amplifier: a route cannot revisit a hop, so no node forwards a given cell
/// more than once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Route(Vec<RouteHop>);

impl Route {
    pub(crate) fn singleton(hop: RouteHop) -> Self {
        Self(vec![hop])
    }

    pub(crate) fn new(hops: Vec<RouteHop>) -> Option<Self> {
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
    pub(crate) fn hop_at(&self, pos: usize) -> Option<&RouteHop> {
        self.0.get(pos)
    }

    /// Encode into the opaque `data` of a multihop [`CustomAddr`]. postcard is
    /// deterministic, so the same route always yields byte-identical addresses —
    /// which iroh relies on to dedupe a peer's path.
    pub(crate) fn encode(&self) -> CustomAddr {
        let bytes = postcard::to_allocvec(self).expect("route serializes");
        CustomAddr::from_parts(MULTIHOP_TRANSPORT_ID, &bytes)
    }

    /// Decode a multihop [`CustomAddr`] back into a route. Returns `None` for a
    /// wrong transport id or malformed bytes.
    pub(crate) fn decode(addr: &CustomAddr) -> Option<Self> {
        if addr.id() != MULTIHOP_TRANSPORT_ID {
            return None;
        }
        postcard::from_bytes(addr.data()).ok()
    }

    /// The return route a terminal should hand back as its remote address, given
    /// the forward route it received and the original `source` hop.
    ///
    /// Forward `S → [R1, R2, B]` (source `S`) reverses to `B → [R2, R1, S]`:
    /// drop the destination (`B`, which is us), reverse the interior, then append
    /// the source. Applying this again at `S` reproduces the original forward
    /// route, so the two ends agree on one stable path locator each.
    ///
    /// The caller must have established that `forward` ends at this node —
    /// [`Forwarder::handle_cell`](crate::underlay::Forwarder::handle_cell) does,
    /// which is what makes the `skip(1)` true rather than merely hoped for.
    /// `None` when the result is not a legal route: `source` already appears in
    /// `forward`, so reversing would mint a cyclic return path.
    pub(crate) fn reverse_from(forward: &[RouteHop], source: RouteHop) -> Option<Self> {
        let mut hops: Vec<RouteHop> = forward
            .iter()
            .rev()
            .skip(1) // drop the destination (ourselves)
            .cloned()
            .collect();
        hops.push(source);
        Self::new(hops)
    }
}

/// Whether any two hops name the same node. Both identities are checked, and
/// separately: a repeated `underlay.id` is a bounce because that is the key the
/// forwarder dials on, and a repeated `app_id` is a bounce at the layer above.
/// Comparing them pairwise rather than pooling them keeps a node whose two
/// endpoints share a key from rejecting its own routes.
///
/// Quadratic over at most [`MAX_ROUTE_HOPS`] entries, which beats allocating.
fn repeats_a_hop(hops: &[RouteHop]) -> bool {
    hops.iter().enumerate().any(|(index, hop)| {
        hops[..index]
            .iter()
            .any(|earlier| earlier.underlay.id == hop.underlay.id || earlier.app_id == hop.app_id)
    })
}

impl<'de> Deserialize<'de> for Route {
    fn deserialize<DeserializerT>(deserializer: DeserializerT) -> Result<Self, DeserializerT::Error>
    where
        DeserializerT: Deserializer<'de>,
    {
        let hops = Vec::<RouteHop>::deserialize(deserializer)?;
        Self::new(hops).ok_or_else(|| serde::de::Error::custom("empty multihop route"))
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_ROUTE_HOPS, Route, RouteHop};
    use iroh::{EndpointAddr, EndpointId, SecretKey};

    fn hop(seed: u8) -> RouteHop {
        let id: EndpointId = SecretKey::from_bytes(&[seed; 32]).public();
        RouteHop {
            app_id: id,
            underlay: EndpointAddr::new(id),
        }
    }

    #[test]
    fn encode_decode_roundtrips() {
        let route = Route::new(vec![hop(1), hop(2), hop(3)]).unwrap();
        let addr = route.encode();
        assert_eq!(Route::decode(&addr).expect("decodes"), route);
    }

    #[test]
    fn wrong_transport_id_does_not_decode() {
        let route = Route::new(vec![hop(1)]).unwrap();
        let addr = route.encode();
        let foreign = iroh_base::CustomAddr::from_parts(0x99, addr.data());
        assert!(Route::decode(&foreign).is_none());
    }

    #[test]
    fn empty_route_does_not_decode() {
        let bytes = postcard::to_allocvec(&Vec::<RouteHop>::new()).unwrap();
        let addr = iroh_base::CustomAddr::from_parts(crate::MULTIHOP_TRANSPORT_ID, &bytes);
        assert!(Route::decode(&addr).is_none());
    }

    #[test]
    fn reverse_is_an_involution_across_the_two_ends() {
        // Source S=hop(9); forward route to B: [R1, R2, B].
        let (source, r1, r2, dest) = (hop(9), hop(1), hop(2), hop(3));
        let forward = vec![r1.clone(), r2.clone(), dest.clone()];

        // At B, the return route is [R2, R1, S].
        let ret = Route::reverse_from(&forward, source.clone()).expect("reverses");
        assert_eq!(ret.0, vec![r2, r1, source]);

        // Reversing again at S (source now B) reproduces the forward route.
        let back = Route::reverse_from(&ret.0, dest).expect("reverses");
        assert_eq!(back.0, forward);
    }

    #[test]
    fn a_route_past_the_hop_ceiling_is_refused() {
        // ~4000 hops fit in one cell, which is what turns a relay into a
        // 1000x amplifier; the ceiling is the cap on that.
        let hops: Vec<RouteHop> = (0..=MAX_ROUTE_HOPS)
            .map(|seed| hop(u8::try_from(seed).expect("seed fits")))
            .collect();
        assert!(Route::new(hops).is_none());
    }

    #[test]
    fn a_route_at_the_hop_ceiling_is_accepted() {
        let hops: Vec<RouteHop> = (0..MAX_ROUTE_HOPS)
            .map(|seed| hop(u8::try_from(seed).expect("seed fits")))
            .collect();
        assert!(Route::new(hops).is_some());
    }

    #[test]
    fn a_route_that_revisits_a_hop_is_refused() {
        // The [X, Y, X, Y, …] ping-pong: every entry is a real node, so an
        // "am I named here?" check passes at every bounce. Acyclicity is what
        // actually stops it.
        assert!(Route::new(vec![hop(1), hop(2), hop(1)]).is_none());
    }

    #[test]
    fn a_route_past_the_hop_ceiling_does_not_decode() {
        let hops: Vec<RouteHop> = (0..=MAX_ROUTE_HOPS)
            .map(|seed| hop(u8::try_from(seed).expect("seed fits")))
            .collect();
        let bytes = postcard::to_allocvec(&hops).unwrap();
        let addr = iroh_base::CustomAddr::from_parts(crate::MULTIHOP_TRANSPORT_ID, &bytes);
        assert!(Route::decode(&addr).is_none());
    }

    #[test]
    fn a_cyclic_route_does_not_decode() {
        let hops = vec![hop(1), hop(2), hop(1)];
        let bytes = postcard::to_allocvec(&hops).unwrap();
        let addr = iroh_base::CustomAddr::from_parts(crate::MULTIHOP_TRANSPORT_ID, &bytes);
        assert!(Route::decode(&addr).is_none());
    }

    #[test]
    fn reverse_refuses_a_source_already_in_the_path() {
        // A cell claiming a source that is also one of its hops would reverse
        // into a cyclic return route — including a source claiming to be us.
        let forward = vec![hop(1), hop(2), hop(3)];
        assert!(Route::reverse_from(&forward, hop(1)).is_none());
    }
}
