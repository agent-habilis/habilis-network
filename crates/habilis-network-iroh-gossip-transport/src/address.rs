//! The address of a node on the gossip transport: its endpoint id.

use iroh::EndpointId;
use iroh_base::CustomAddr;

use crate::GOSSIP_TRANSPORT_ID;

/// The gossip address of `endpoint`: the transport id and the 32 bytes of its id.
/// It names a node and not a place, so it is valid for every member of the mesh.
///
/// # Examples
///
/// A gossip address keeps the endpoint id it was made from.
///
/// ```
/// use habilis_network_iroh_gossip_transport::{gossip_addr, parse_gossip_addr};
/// use iroh::SecretKey;
///
/// let id = SecretKey::from_bytes(&[1u8; 32]).public();
/// assert_eq!(parse_gossip_addr(&gossip_addr(id)), Some(id));
/// ```
#[must_use]
pub fn gossip_addr(endpoint: EndpointId) -> CustomAddr {
    CustomAddr::from_parts(GOSSIP_TRANSPORT_ID, endpoint.as_bytes())
}

/// The endpoint id in a gossip address, or `None` for another transport's address
/// or for bytes that are not an endpoint id.
///
/// # Examples
///
/// The endpoint id of a gossip address reads back from it.
///
/// ```
/// use habilis_network_iroh_gossip_transport::{gossip_addr, parse_gossip_addr};
/// use iroh::SecretKey;
///
/// let id = SecretKey::from_bytes(&[1u8; 32]).public();
/// let address = gossip_addr(id);
/// assert_eq!(parse_gossip_addr(&address), Some(id));
/// ```
#[must_use]
pub fn parse_gossip_addr(address: &CustomAddr) -> Option<EndpointId> {
    if address.id() != GOSSIP_TRANSPORT_ID {
        return None;
    }
    let raw: [u8; 32] = address.data().try_into().ok()?;
    EndpointId::from_bytes(&raw).ok()
}
