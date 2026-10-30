//! A stream hash: the token that reaches one stream.

use std::fmt;
use std::str::FromStr;

use super::{
    ID_LEN, KIND, KNOWN_FLAGS, NO_UDP_BIT, NO_WEBRTC_BIT, RELAY_TRANSPORT_BIT, SECRET_LEN,
    StreamId, StreamSecret, VERSION,
};
use crate::error::HashError;
use habilis_network::iroh::EndpointAddr;
use habilis_network::net::{endpoint_addr_from_json, endpoint_addr_to_json};
use habilis_network::protocol::base58check::{self, take_array};
use habilis_network::protocol::{LookupOpts, Transport, TransportPolicy, ct_eq};
use zeroize::Zeroizing;

/// A decoded stream hash.
///
/// The id and the secret have the same kind of bytes and different types, so a
/// swap does not compile:
///
/// ```compile_fail,E0308
/// fn swap(mut hash: habilis_network_stream::StreamHash) {
///     hash.id = hash.secret;
/// }
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct StreamHash {
    /// The producer's endpoint: its id, its relay, and its direct addresses.
    pub address: EndpointAddr,
    /// How the producer is found, so a consumer binds a compatible endpoint.
    pub lookups: LookupOpts,
    /// The producer's transport list: which direct paths it runs, and whether
    /// the relay may carry the bytes.
    pub transport: TransportPolicy,
    /// Public: the key the producer looks the stream up by.
    pub id: StreamId,
    /// Private: compared in constant time once `id` has found the stream.
    pub secret: StreamSecret,
}

// Hand-written because the secret has no `PartialEq`: it is compared in
// constant time, so two hashes never answer faster for a closer secret. There is no `Eq`: a
// secret-bearing type is not a map key.
impl PartialEq for StreamHash {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
            && self.lookups == other.lookups
            && self.transport == other.transport
            && self.id == other.id
            && ct_eq(self.secret.as_bytes(), other.secret.as_bytes())
    }
}

impl fmt::Debug for StreamHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("StreamHash");
        debug
            .field("addr", &self.address)
            .field("lookups", &self.lookups)
            .field("transport", &self.transport);
        debug.field("id", &self.id).finish_non_exhaustive()
    }
}

impl StreamHash {
    /// Encode as a bare Base58Check token.
    ///
    /// # Panics
    /// Never: an `EndpointAddr` always serializes to JSON.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut framed = vec![VERSION, KIND];
        let mut flags = 0;
        if self.transport.allows(Transport::Relay) {
            flags |= RELAY_TRANSPORT_BIT;
        }
        if !self.transport.allows(Transport::Udp) {
            flags |= NO_UDP_BIT;
        }
        if !self.transport.allows(Transport::WebRtc) {
            flags |= NO_WEBRTC_BIT;
        }
        framed.push(flags);
        framed.extend_from_slice(self.id.as_bytes());
        framed.extend_from_slice(self.secret.as_bytes());
        self.lookups.encode_into(&mut framed);
        let address = serde_json::to_vec(&endpoint_addr_to_json(&self.address))
            .expect("an EndpointAddr always serializes");
        framed.extend_from_slice(&address);
        base58check::encode(&framed)
    }

    /// The bytes a consumer sends first on the stream it opens: `id ‖ secret`.
    /// The producer reads them back in the same order.
    #[must_use]
    pub(crate) fn header_bytes(&self) -> Zeroizing<[u8; ID_LEN + SECRET_LEN]> {
        let mut header = Zeroizing::new([0; ID_LEN + SECRET_LEN]);
        header[..ID_LEN].copy_from_slice(self.id.as_bytes());
        header[ID_LEN..].copy_from_slice(self.secret.as_bytes());
        header
    }

    /// Decode a bare Base58Check token.
    ///
    /// # Errors
    /// # Errors
    /// [`HashError::Field`] when the Base58Check text or a field does not decode,
    /// [`HashError::UnknownVersion`] or [`HashError::UnknownFlags`] for a version or
    /// flags this build does not know, [`HashError::WrongKind`] for another kind of
    /// token, and [`HashError::Truncated`] when the payload ends early.
    pub fn decode(hash: &str) -> Result<Self, HashError> {
        let framed = base58check::decode(hash.trim(), "stream hash")
            .map_err(HashError::field("decode the Base58Check token"))?;
        let version = *framed
            .first()
            .ok_or(HashError::Truncated("stream hash too short"))?;
        if version != VERSION {
            return Err(HashError::UnknownVersion(version));
        }
        let kind = *framed
            .get(1)
            .ok_or(HashError::Truncated("stream hash too short"))?;
        if kind != KIND {
            return Err(HashError::WrongKind);
        }
        let payload = &framed[2..];
        let flags = *payload
            .first()
            .ok_or(HashError::Truncated("stream hash missing flags"))?;
        if flags & !KNOWN_FLAGS != 0 {
            return Err(HashError::UnknownFlags(flags));
        }
        let mut position = 1;
        let id = StreamId::from(
            take_array::<ID_LEN>(payload, &mut position)
                .ok_or(HashError::Truncated("stream hash missing id"))?,
        );
        let secret = StreamSecret::from(
            take_array::<SECRET_LEN>(payload, &mut position)
                .ok_or(HashError::Truncated("stream hash missing secret"))?,
        );
        let lookups = LookupOpts::decode_from(payload, &mut position)
            .map_err(HashError::field("decode the lookups"))?;
        let addr_json = payload
            .get(position..)
            .ok_or(HashError::Truncated("stream hash missing address"))?;
        let value: serde_json::Value = serde_json::from_slice(addr_json)
            .map_err(HashError::field("invalid stream hash address"))?;
        let (_id, address) = endpoint_addr_from_json(&value)
            .map_err(HashError::field("invalid stream hash address"))?;
        let policy = TransportPolicy::default()
            .udp(flags & NO_UDP_BIT == 0)
            .webrtc(flags & NO_WEBRTC_BIT == 0);
        // A stream is one direct lane: its node has no multi-hop.
        let transport = policy
            .multihop(false)
            .gossip(false)
            .relay_transport(flags & RELAY_TRANSPORT_BIT != 0);
        Ok(Self {
            address,
            lookups,
            transport,
            id,
            secret,
        })
    }
}

impl fmt::Display for StreamHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.encode())
    }
}

impl FromStr for StreamHash {
    type Err = HashError;

    fn from_str(hash: &str) -> Result<Self, HashError> {
        Self::decode(hash)
    }
}
