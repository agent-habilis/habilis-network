//! `PeerInfo` address wire codec.
//!
//! A `PeerInfo` message body carries the author's iroh `EndpointAddr`
//! as JSON so peers can dial each other directly. This is mesh-
//! formation plumbing, distinct from the mesh-id codec
//! (`protocol::mesh`) — kept in its own module so the two never get
//! conflated.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use iroh_base::{EndpointAddr, EndpointId, RelayUrl, SecretKey, Signature};

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
/// If `secret` is not the key of `addr`: a caller bug.
#[must_use]
pub fn peer_info_to_json(
    addr: &EndpointAddr,
    needs_lane: bool,
    secret: &SecretKey,
    scope: &[u8],
) -> serde_json::Value {
    assert_eq!(
        secret.public(),
        addr.id,
        "a lane flag is signed by its endpoint"
    );
    let signature = secret.sign(&lane_message(scope, &addr.id, needs_lane));
    let mut json = endpoint_addr_to_json(addr);
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
    let signature: [u8; 64] = bs58::decode(json["lane_sig"].as_str()?)
        .into_vec()
        .ok()?
        .try_into()
        .ok()?;
    id.verify(
        &lane_message(scope, &id, needs_lane),
        &Signature::from_bytes(&signature),
    )
    .ok()?;
    Some(needs_lane)
}

/// Deserialize an `EndpointAddr` from a JSON value produced by `endpoint_addr_to_json`.
/// # Errors
/// The JSON is missing the endpoint id, or a field fails to parse.
pub fn endpoint_addr_from_json(json: &serde_json::Value) -> Result<(EndpointId, EndpointAddr)> {
    let id_str = json["id"].as_str().context("missing id")?;
    let endpoint_id: EndpointId = id_str.parse().context("invalid EndpointId")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    const MESH: &[u8] = b"mesh-a";

    #[test]
    fn a_signed_lane_flag_reads_back_beside_an_empty_address() {
        let bob = SecretKey::from_bytes(&[3u8; 32]);
        let empty = EndpointAddr::new(bob.public());
        let json = peer_info_to_json(&empty, true, &bob, MESH);
        assert_eq!(peer_info_needs_lane(&json, MESH), Some(true));
        let (id, parsed) = endpoint_addr_from_json(&json).unwrap();
        assert_eq!(id, bob.public());
        assert!(parsed.is_empty());
        let has_ip = peer_info_to_json(&empty, false, &bob, MESH);
        assert_eq!(peer_info_needs_lane(&has_ip, MESH), Some(false));
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
        assert_eq!(peer_info_needs_lane(&bare, MESH), None);
        // Bob's own flag, replayed into another mesh.
        let real = peer_info_to_json(&bobs, true, &bob, MESH);
        assert_eq!(peer_info_needs_lane(&real, b"mesh-b"), None);
    }
}
