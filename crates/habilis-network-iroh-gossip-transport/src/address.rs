//! The address of a node on the gossip transport: its endpoint id.

use iroh::EndpointId;
use iroh_base::CustomAddr;

use crate::GOSSIP_TRANSPORT_ID;

/// The address of `endpoint` on the custom transport `transport_id`: the id and the
/// 32 bytes of the endpoint id. The core of the transport takes the id as a
/// parameter, so that the gossip transport and another frame transport share it.
///
/// # Examples
///
/// An address keeps the endpoint id it was made from, and only for its own transport.
///
/// ```
/// use habilis_network_iroh_gossip_transport::{parse_transport_addr, transport_addr};
/// use iroh::SecretKey;
///
/// let id = SecretKey::from_bytes(&[1u8; 32]).public();
/// let address = transport_addr(0x1234, id);
/// assert_eq!(parse_transport_addr(0x1234, &address), Some(id));
/// assert_eq!(parse_transport_addr(0x4321, &address), None);
/// ```
#[must_use]
pub fn transport_addr(transport_id: u64, endpoint: EndpointId) -> CustomAddr {
    CustomAddr::from_parts(transport_id, endpoint.as_bytes())
}

/// The endpoint id in an address of the transport `transport_id`, or `None` for the
/// address of another transport or for bytes that are not an endpoint id.
///
/// # Examples
///
/// See [`transport_addr`].
///
/// ```
/// use habilis_network_iroh_gossip_transport::{parse_transport_addr, transport_addr};
/// use iroh::SecretKey;
///
/// let id = SecretKey::from_bytes(&[2u8; 32]).public();
/// assert_eq!(parse_transport_addr(7, &transport_addr(7, id)), Some(id));
/// ```
#[must_use]
pub fn parse_transport_addr(transport_id: u64, address: &CustomAddr) -> Option<EndpointId> {
    if address.id() != transport_id {
        return None;
    }
    let raw: [u8; 32] = address.data().try_into().ok()?;
    EndpointId::from_bytes(&raw).ok()
}

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
    transport_addr(GOSSIP_TRANSPORT_ID, endpoint)
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
    parse_transport_addr(GOSSIP_TRANSPORT_ID, address)
}
