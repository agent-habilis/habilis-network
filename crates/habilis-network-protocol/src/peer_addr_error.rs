//! `PeerInfo` address wire codec.
//!
//! A `PeerInfo` message body carries the author's iroh `EndpointAddr`
//! as JSON so peers can dial each other directly. This is mesh-
//! formation plumbing, distinct from the mesh-id codec
//! (`protocol::meshes`) — kept in its own module so the two never get
//! conflated.

use std::net::SocketAddr;

use std::error::Error;
use std::fmt;

use iroh_base::{EndpointAddr, EndpointId, RelayUrl, SecretKey, Signature};

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

/// Signed with the lane flag, so no other message signed by an endpoint key
/// can be passed off as one. The signature carries no freshness: that is safe
/// while endpoint keys are minted per process and a node's flag never changes
/// within one, so a replay can only repeat what is true. A key that outlives a
/// process and changes its transports would need a timestamp here.
const LANE_DOMAIN: &[u8] = b"habilis-network/peer-lane/1";

fn lane_message(scope: &[u8], id: &EndpointId, needs_lane: bool) -> Vec<u8> {
    let mut message = Vec::with_capacity(LANE_DOMAIN.len() + scope.len() + 33);
    message.extend_from_slice(LANE_DOMAIN);
    message.extend_from_slice(scope);
    message.extend_from_slice(id.as_bytes());
    message.push(u8::from(needs_lane));
    message
}

/// A `PeerInfo` body: the author's address plus whether it needs a data
/// channel (`webrtc`). The flag is said out loud because an address cannot
/// always say it: a node with no IP and no relay advertises an empty address,
/// which reads as "not known yet" rather than "browser".
///
/// The flag is signed by the endpoint key it describes, over `scope` (the
/// mesh id). The gossip signature only binds the body to a nickname, so
/// without this any member could say another member needs a data channel and
/// fill that member's session slots.
///
/// # Panics
/// If `secret` is not the key of `address`: a caller bug.
#[must_use]
pub fn peer_info_to_json(
    address: &EndpointAddr,
    // true when the node has no IP transport and needs a data channel
    needs_lane: bool,
    secret: &SecretKey,
    scope: &[u8],
) -> serde_json::Value {
    assert_eq!(
        secret.public(),
        address.id,
        "a lane flag is signed by its endpoint"
    );
    let signature = secret.sign(&lane_message(scope, &address.id, needs_lane));
    let mut json = endpoint_addr_to_json(address);
    json["webrtc"] = serde_json::Value::Bool(needs_lane);
    json["lane_sig"] = serde_json::Value::String(bs58::encode(signature.to_bytes()).into_string());
    json
}

/// The lane flag of a `PeerInfo` body, if the endpoint it names signed it
/// for `scope`. `None` for a missing or forged flag: the caller leaves what it
/// knew unchanged.
#[must_use]
pub fn peer_info_needs_lane(json: &serde_json::Value, scope: &[u8]) -> Option<bool> {
    let needs_lane = json["webrtc"].as_bool()?;
    let id: EndpointId = json["id"].as_str()?.parse().ok()?;
    let encoded = json["lane_sig"].as_str()?;
    let bytes = bs58::decode(encoded).into_vec().ok()?;
    let signature: [u8; 64] = bytes.try_into().ok()?;
    id.verify(
        &lane_message(scope, &id, needs_lane),
        &Signature::from_bytes(&signature),
    )
    .ok()?;
    Some(needs_lane)
}

#[cfg(test)]
mod lane_tests {
    use iroh_base::{EndpointAddr, SecretKey};

    use super::{
        endpoint_addr_from_json, endpoint_addr_to_json, peer_info_needs_lane, peer_info_to_json,
    };

    const MESH: &[u8] = b"mesh-a";

    #[test]
    fn a_signed_lane_flag_reads_back_beside_an_empty_address() {
        let bob = SecretKey::from_bytes(&[3u8; 32]);
        let empty = EndpointAddr::new(bob.public());
        let json = peer_info_to_json(&empty, true, &bob, MESH);
        assert_eq!(
            peer_info_needs_lane(&json, MESH),
            Some(true),
            "the flag reads back as signed"
        );
        let (id, parsed) = endpoint_addr_from_json(&json).expect("the body decodes");
        assert_eq!(id, bob.public(), "the body still names the endpoint");
        assert!(parsed.is_empty(), "the address stays empty");
        let has_ip = peer_info_to_json(&empty, false, &bob, MESH);
        assert_eq!(
            peer_info_needs_lane(&has_ip, MESH),
            Some(false),
            "a false flag reads back as false, not as missing"
        );
    }

    /// The attack the signature closes: a member names another member's
    /// endpoint and claims it needs a data channel (or that it does not).
    #[test]
    fn a_lane_flag_not_signed_by_its_endpoint_is_ignored() {
        let bob = SecretKey::from_bytes(&[3u8; 32]);
        let mallory = SecretKey::from_bytes(&[4u8; 32]);
        let bobs = EndpointAddr::new(bob.public());
        for claim in [true, false] {
            // Mallory signs a flag for her own endpoint, then swaps in Bob's id.
            let mut forged =
                peer_info_to_json(&EndpointAddr::new(mallory.public()), claim, &mallory, MESH);
            forged["id"] = serde_json::Value::String(bob.public().to_string());
            assert_eq!(peer_info_needs_lane(&forged, MESH), None, "claim {claim}");
        }
        // A flag with no signature at all.
        let mut bare = endpoint_addr_to_json(&bobs);
        bare["webrtc"] = serde_json::Value::Bool(true);
        assert_eq!(
            peer_info_needs_lane(&bare, MESH),
            None,
            "a flag with no signature is ignored"
        );
        // Bob's own flag, replayed into another mesh.
        let real = peer_info_to_json(&bobs, true, &bob, MESH);
        assert_eq!(
            peer_info_needs_lane(&real, b"mesh-b"),
            None,
            "a flag signed for one mesh is ignored in another"
        );
    }
}
