//! `PeerInfo` address wire codec.
//!
//! A `PeerInfo` message body carries the author's iroh `EndpointAddr`
//! as JSON so peers can dial each other directly. This is mesh-
//! formation plumbing, distinct from the mesh-id codec
//! (`protocol::mesh`) — kept in its own module so the two never get
//! conflated.

use std::net::SocketAddr;

use std::error::Error;
use std::fmt;

use iroh_base::{EndpointAddr, EndpointId, RelayUrl};

/// Serialize an `EndpointAddr` to a JSON value for `PeerInfo` messages.
///
/// # Examples
///
/// The JSON that this writes reads back to the same endpoint id.
///
/// ```
/// use habilis_network_protocol::iroh_base::{EndpointAddr, SecretKey};
/// use habilis_network_protocol::peer_addr_error::{endpoint_addr_from_json, endpoint_addr_to_json};
///
/// let id = SecretKey::from_bytes(&[5u8; 32]).public();
/// let json = endpoint_addr_to_json(&EndpointAddr::new(id));
/// let (back, _) = endpoint_addr_from_json(&json).expect("the JSON round trips");
/// assert_eq!(back, id);
/// ```
pub fn endpoint_addr_to_json(address: &EndpointAddr) -> serde_json::Value {
    let ips: Vec<String> = address.ip_addrs().map(ToString::to_string).collect();
    let relay: Option<String> = address.relay_urls().next().map(ToString::to_string);
    serde_json::json!({
        "id": address.id.to_string(),
        "ips": ips,
        "relay": relay,
    })
}

/// Why a JSON value does not decode to an endpoint address.
///
/// # Examples
///
/// JSON with no endpoint id returns this error.
///
/// ```
/// use habilis_network_protocol::peer_addr_error::{PeerAddrError, endpoint_addr_from_json};
///
/// let error = endpoint_addr_from_json(&serde_json::json!({})).unwrap_err();
/// assert!(matches!(error, PeerAddrError::Missing(_)));
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum PeerAddrError {
    /// The JSON has no endpoint id.
    Missing(&'static str),
    /// The endpoint id does not parse.
    Source {
        /// The step that failed.
        step: &'static str,
        /// The error of the id parser.
        source: Box<dyn Error + Send + Sync>,
    },
}

impl fmt::Display for PeerAddrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(message) => formatter.write_str(message),
            Self::Source { step, .. } => formatter.write_str(step),
        }
    }
}

impl Error for PeerAddrError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source { source, .. } => Some(source.as_ref()),
            Self::Missing(_) => None,
        }
    }
}

/// Deserialize an `EndpointAddr` from a JSON value produced by `endpoint_addr_to_json`.
/// # Errors
/// # Errors
/// [`PeerAddrError::Missing`] when the JSON has no endpoint id, or
/// [`PeerAddrError::Source`] when the id does not parse.
///
/// # Examples
///
/// ```
/// use habilis_network_protocol::peer_addr_error::endpoint_addr_from_json;
///
/// let result = endpoint_addr_from_json(&serde_json::json!({}));
/// assert!(result.is_err());
/// ```
pub fn endpoint_addr_from_json(
    json: &serde_json::Value,
) -> Result<(EndpointId, EndpointAddr), PeerAddrError> {
    let id_str = json["id"]
        .as_str()
        .ok_or(PeerAddrError::Missing("missing id"))?;
    let endpoint_id: EndpointId = id_str.parse().map_err(|error| PeerAddrError::Source {
        step: "invalid EndpointId",
        source: Box::new(error),
    })?;
    let mut address = EndpointAddr::new(endpoint_id);
    if let Some(ips) = json["ips"].as_array() {
        for ip in ips {
            let socket: Option<SocketAddr> = ip.as_str().and_then(|text| text.parse().ok());
            if let Some(socket) = socket {
                address = address.with_ip_addr(socket);
            }
        }
    }
    let url: Option<RelayUrl> = json["relay"].as_str().and_then(|relay| relay.parse().ok());
    if let Some(url) = url {
        address = address.with_relay_url(url);
    }
    Ok((endpoint_id, address))
}
