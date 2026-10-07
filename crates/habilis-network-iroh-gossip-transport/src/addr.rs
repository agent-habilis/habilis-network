//! The address of a node on the gossip transport: its endpoint id.

use iroh::EndpointId;
use iroh_base::CustomAddr;

use crate::GOSSIP_TRANSPORT_ID;

/// The gossip address of `endpoint`: the transport id and the 32 bytes of its id.
/// It names a node and not a place, so it is valid for every member of the mesh.
#[must_use]
pub fn gossip_addr(endpoint: EndpointId) -> CustomAddr {
    CustomAddr::from_parts(GOSSIP_TRANSPORT_ID, endpoint.as_bytes())
}

/// The endpoint id in a gossip address, or `None` for another transport's address
/// or for bytes that are not an endpoint id.
#[must_use]
pub fn parse_gossip_addr(addr: &CustomAddr) -> Option<EndpointId> {
    if addr.id() != GOSSIP_TRANSPORT_ID {
        return None;
    }
    let raw: [u8; 32] = addr.data().try_into().ok()?;
    EndpointId::from_bytes(&raw).ok()
}
