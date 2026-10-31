use std::io;

use iroh_base::{CustomAddr, EndpointId};

/// ASCII `WRTC`. Chosen like Tor's `0x544F52` ("TOR"); not yet registered
/// in iroh's `TRANSPORTS.md` id table.
pub const WEBRTC_TRANSPORT_ID: u64 = 0x5752_5443;

/// The `WebRTC` custom address of `endpoint`: transport id + the 32-byte
/// Ed25519 endpoint id. Deriving the address from the identity (the
/// Tor-transport convention) means both sides already know each other's
/// address once a session is negotiated — nothing extra to exchange.
///
/// # Examples
///
/// A webrtc address keeps the endpoint id it was made from.
///
/// ```
/// use habilis_network_iroh_webrtc_transport::{custom_addr, parse_custom_addr};
/// use iroh_base::SecretKey;
///
/// let id = SecretKey::from_bytes(&[1u8; 32]).public();
/// assert_eq!(parse_custom_addr(&custom_addr(id)).expect("a webrtc address"), id);
/// ```
#[must_use]
pub fn custom_addr(endpoint: EndpointId) -> CustomAddr {
    CustomAddr::from_parts(WEBRTC_TRANSPORT_ID, endpoint.as_bytes())
}

/// Recover the endpoint id from a `WebRTC` [`CustomAddr`].
///
/// # Errors
/// The address carries another transport's id, or its payload is not a
/// 32-byte endpoint id.
///
/// # Examples
///
/// The endpoint id of a webrtc address reads back from it.
///
/// ```
/// use habilis_network_iroh_webrtc_transport::{custom_addr, parse_custom_addr};
/// use iroh_base::SecretKey;
///
/// let id = SecretKey::from_bytes(&[1u8; 32]).public();
/// let address = custom_addr(id);
/// assert_eq!(parse_custom_addr(&address).expect("a webrtc address"), id);
/// ```
pub fn parse_custom_addr(address: &CustomAddr) -> io::Result<EndpointId> {
    if address.id() != WEBRTC_TRANSPORT_ID {
        return Err(io::Error::other("unexpected transport id"));
    }
    let bytes: [u8; 32] = address
        .data()
        .try_into()
        .map_err(|_| io::Error::other("unexpected endpoint id length"))?;
    EndpointId::from_bytes(&bytes).map_err(io::Error::other)
}
