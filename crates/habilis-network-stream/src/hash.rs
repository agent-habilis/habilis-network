//! The stream hash: everything a consumer needs to reach one stream, as a bare
//! Base58Check token.
//!
//! It is a bearer ticket, not a digest. Whoever holds it can take the stream's
//! one consumer slot, so hand it only to the reader you mean.
//!
//! Wire: Base58Check(`VERSION ‖ KIND ‖ flags ‖ id(16) ‖ secret(32) ‖ lookups ‖
//! address-json`). `lookups` is self-delimiting, so the address takes the
//! remainder. The `KIND` byte keeps a blob ticket, an invite or a mesh id from
//! decoding as a stream hash.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use habilis_network::iroh::EndpointAddr;
use habilis_network::net::{endpoint_addr_from_json, endpoint_addr_to_json};
use habilis_network::protocol::base58check::{self, take_array};
use habilis_network::protocol::{LookupOpts, TransportPolicy};

/// Framing version. An unknown version is rejected on decode.
const VERSION: u8 = 1;

/// Ticket kind: 1 is a blob ticket, 2 a bridge ticket, 3 an invite.
const KIND: u8 = 4;

/// The producer lets the relay carry the stream. Absent, both ends refuse a
/// connection whose only path is the relay.
const RELAY_TRANSPORT_BIT: u8 = 0b0000_0001;

/// The producer's transport list leaves `udp` or `webrtc` out. Restrictive,
/// like the mesh id's bits, so the default `udp,webrtc` sets neither.
const NO_UDP_BIT: u8 = 0b0000_0010;
const NO_WEBRTC_BIT: u8 = 0b0000_0100;

const KNOWN_FLAGS: u8 = RELAY_TRANSPORT_BIT | NO_UDP_BIT | NO_WEBRTC_BIT;

/// Length of the public id a producer files the stream under.
pub const ID_LEN: usize = 16;

/// Length of the bearer secret.
pub const SECRET_LEN: usize = 32;

/// A decoded stream hash.
#[derive(Clone, PartialEq, Eq)]
pub struct StreamHash {
    /// The producer's endpoint: its id, its relay, and its direct addresses.
    pub addr: EndpointAddr,
    /// How the producer is found, so a consumer binds a compatible endpoint.
    pub lookups: LookupOpts,
    /// The producer's transport list: which direct paths it runs, and whether
    /// the relay may carry the bytes.
    pub transport: TransportPolicy,
    /// Public: the key the producer looks the stream up by.
    pub id: [u8; ID_LEN],
    /// Private: compared in constant time once `id` has found the stream.
    pub secret: [u8; SECRET_LEN],
}

impl fmt::Debug for StreamHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamHash")
            .field("addr", &self.addr)
            .field("lookups", &self.lookups)
            .field("transport", &self.transport)
            .field("id", &self.id)
            .finish_non_exhaustive()
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
        if self.transport.relay_transport {
            flags |= RELAY_TRANSPORT_BIT;
        }
        if !self.transport.udp {
            flags |= NO_UDP_BIT;
        }
        if !self.transport.webrtc {
            flags |= NO_WEBRTC_BIT;
        }
        framed.push(flags);
        framed.extend_from_slice(&self.id);
        framed.extend_from_slice(&self.secret);
        self.lookups.encode_into(&mut framed);
        let addr = serde_json::to_vec(&endpoint_addr_to_json(&self.addr))
            .expect("an EndpointAddr always serializes");
        framed.extend_from_slice(&addr);
        base58check::encode(&framed)
    }

    /// Decode a bare Base58Check token.
    ///
    /// # Errors
    /// A bad checksum, another kind of token, an unknown version, or a
    /// malformed payload.
    pub fn decode(hash: &str) -> Result<Self> {
        let framed = base58check::decode(hash.trim(), "stream hash")?;
        let version = *framed.first().context("stream hash too short")?;
        if version != VERSION {
            bail!("unsupported stream hash version: {version}");
        }
        let kind = *framed.get(1).context("stream hash too short")?;
        if kind != KIND {
            bail!("not a stream hash: wrong ticket kind");
        }
        let payload = &framed[2..];
        let flags = *payload.first().context("stream hash missing flags")?;
        if flags & !KNOWN_FLAGS != 0 {
            bail!("unsupported stream hash flags {flags:#04x}: upgrade to a newer build");
        }
        let mut pos = 1;
        let id = take_array::<ID_LEN>(payload, &mut pos).context("stream hash missing id")?;
        let secret =
            take_array::<SECRET_LEN>(payload, &mut pos).context("stream hash missing secret")?;
        let lookups = LookupOpts::decode_from(payload, &mut pos)?;
        let addr_json = payload.get(pos..).context("stream hash missing address")?;
        let value: serde_json::Value =
            serde_json::from_slice(addr_json).context("invalid stream hash address")?;
        let (_id, addr) = endpoint_addr_from_json(&value)?;
        Ok(Self {
            addr,
            lookups,
            transport: TransportPolicy {
                udp: flags & NO_UDP_BIT == 0,
                webrtc: flags & NO_WEBRTC_BIT == 0,
                // A stream is one direct lane: its node has no multi-hop.
                multihop: false,
                gossip: false,
                relay_transport: flags & RELAY_TRANSPORT_BIT != 0,
            },
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
    type Err = anyhow::Error;

    fn from_str(hash: &str) -> Result<Self> {
        Self::decode(hash)
    }
}

#[cfg(test)]
mod tests {
    use habilis_network::iroh::{EndpointAddr, SecretKey, TransportAddr};

    use super::*;

    fn sample(transport: TransportPolicy) -> StreamHash {
        let id = SecretKey::from_bytes(&[7; 32]).public();
        StreamHash {
            addr: EndpointAddr::from_parts(
                id,
                [TransportAddr::Ip(
                    "127.0.0.1:4433".parse().expect("socket addr"),
                )],
            ),
            lookups: LookupOpts::loopback(),
            transport,
            id: [1; ID_LEN],
            secret: [2; SECRET_LEN],
        }
    }

    fn policy(udp: bool, webrtc: bool, relay_transport: bool) -> TransportPolicy {
        TransportPolicy {
            udp,
            webrtc,
            multihop: false,
            gossip: false,
            relay_transport,
        }
    }

    #[test]
    fn a_hash_round_trips_every_transport_list() {
        for transport in [
            policy(true, true, false),
            policy(true, true, true),
            policy(true, false, false),
            policy(false, true, false),
            policy(false, true, true),
        ] {
            let hash = sample(transport);
            assert_eq!(StreamHash::decode(&hash.encode()).expect("decodes"), hash);
            assert_eq!(
                hash.to_string().parse::<StreamHash>().expect("parses"),
                hash
            );
        }
    }

    #[test]
    fn an_unknown_flag_is_refused() {
        let mut framed =
            base58check::decode(&sample(TransportPolicy::default()).encode(), "stream hash")
                .expect("decodes");
        framed[2] |= 0b1000_0000;
        let error = StreamHash::decode(&base58check::encode(&framed)).expect_err("unknown flag");
        assert!(error.to_string().contains("flag"), "{error}");
    }

    #[test]
    fn a_flipped_character_fails_the_checksum() {
        let mut encoded = sample(TransportPolicy::default()).encode().into_bytes();
        let last = encoded.len() - 1;
        encoded[last] = if encoded[last] == b'2' { b'3' } else { b'2' };
        let encoded = String::from_utf8(encoded).expect("ascii");
        assert!(StreamHash::decode(&encoded).is_err());
    }

    #[test]
    fn another_kind_or_version_is_refused() {
        let reframe = |version: u8, kind: u8| {
            let mut framed =
                base58check::decode(&sample(TransportPolicy::default()).encode(), "stream hash")
                    .expect("decodes");
            framed[0] = version;
            framed[1] = kind;
            base58check::encode(&framed)
        };
        let blob = StreamHash::decode(&reframe(VERSION, 1)).expect_err("a blob ticket");
        assert!(blob.to_string().contains("wrong ticket kind"), "{blob}");
        let invite = StreamHash::decode(&reframe(VERSION, 3)).expect_err("an invite");
        assert!(invite.to_string().contains("wrong ticket kind"), "{invite}");
        let future = StreamHash::decode(&reframe(2, KIND)).expect_err("a newer version");
        assert!(future.to_string().contains("version"), "{future}");
    }

    #[test]
    fn a_mesh_id_is_not_a_stream_hash() {
        let mesh =
            habilis_network::runtime::derive_topic_mesh_with("standup", LookupOpts::loopback())
                .expect("mesh");
        assert!(StreamHash::decode(&mesh.to_string()).is_err());
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let shown = format!("{:?}", sample(TransportPolicy::default()));
        assert!(!shown.contains("secret"), "{shown}");
    }
}
