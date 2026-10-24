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
pub fn endpoint_addr_to_json(addr: &EndpointAddr) -> serde_json::Value {
    let ips: Vec<String> = addr.ip_addrs().map(ToString::to_string).collect();
    let relay: Option<String> = addr.relay_urls().next().map(ToString::to_string);
    serde_json::json!({
        "id": addr.id.to_string(),
        "ips": ips,
        "relay": relay,
    })
}

/// Why a JSON value does not decode to an endpoint address.
#[derive(Debug)]
#[non_exhaustive]
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
/// The JSON is missing the endpoint id, or a field fails to parse.
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
    let mut addr = EndpointAddr::new(endpoint_id);
    if let Some(ips) = json["ips"].as_array() {
        for ip in ips {
            if let Some(text) = ip.as_str()
                && let Ok(socket) = text.parse::<SocketAddr>()
            {
                addr = addr.with_ip_addr(socket);
            }
        }
    }
    if let Some(relay) = json["relay"].as_str()
        && let Ok(url) = relay.parse::<RelayUrl>()
    {
        addr = addr.with_relay_url(url);
    }
    Ok((endpoint_id, addr))
}
