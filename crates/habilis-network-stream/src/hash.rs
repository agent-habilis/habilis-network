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
use habilis_network::protocol::identity::write_hex;
use habilis_network::protocol::{LookupOpts, MeshConfig, TransportPolicy, ct_eq};
use zeroize::Zeroizing;

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

/// The public id a producer files a stream under. It names the stream and
/// opens nothing: [`StreamSecret`] does that.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId([u8; ID_LEN]);

impl StreamId {
    /// Wrap the 16 bytes of an id.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, borrowed.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, &self.0)
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "StreamId({self})")
    }
}

/// The bearer secret of a stream. Whoever holds it can take the consumer slot,
/// so `Debug` prints no byte, and the type has no `PartialEq`: compare two with
/// [`ct_eq`] on [`Self::as_bytes`]. Its bytes are wiped on drop (best-effort: a
/// copy that a caller made from [`Self::as_bytes`] is not tracked).
#[derive(Clone)]
pub struct StreamSecret(Zeroizing<[u8; SECRET_LEN]>);

impl StreamSecret {
    /// Wrap the 32 bytes of a secret. The array passed in is a copy that the
    /// caller still holds: keep it in a [`Zeroizing`] when it is a secret.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Take a buffer that is already wiped on drop, whole, so that the code
    /// makes no plain copy of the secret on the way in. This is the constructor
    /// for a secret that is already in a [`Zeroizing`] (bytes read off a stream,
    /// a random draw). [`Self::from_bytes`] stays for raw input at an edge.
    #[must_use]
    pub fn from_zeroizing(bytes: Zeroizing<[u8; SECRET_LEN]>) -> Self {
        Self(bytes)
    }

    /// The raw bytes, borrowed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }
}

// The only field is a `Zeroizing`.
impl zeroize::ZeroizeOnDrop for StreamSecret {}

impl fmt::Debug for StreamSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StreamSecret(***)")
    }
}

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
pub struct StreamHash {
    /// The producer's endpoint: its id, its relay, and its direct addresses.
    pub addr: EndpointAddr,
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
// constant time, so two hashes never answer faster for a closer secret.
impl PartialEq for StreamHash {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
            && self.lookups == other.lookups
            && self.transport == other.transport
            && self.id == other.id
            && ct_eq(self.secret.as_bytes(), other.secret.as_bytes())
    }
}

impl Eq for StreamHash {}

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
        framed.extend_from_slice(self.id.as_bytes());
        framed.extend_from_slice(self.secret.as_bytes());
        self.lookups.encode_into(&mut framed);
        let addr = serde_json::to_vec(&endpoint_addr_to_json(&self.addr))
            .expect("an EndpointAddr always serializes");
        framed.extend_from_slice(&addr);
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
        let id = StreamId::from_bytes(
            take_array::<ID_LEN>(payload, &mut pos).context("stream hash missing id")?,
        );
        let secret = StreamSecret::from_bytes(
            take_array::<SECRET_LEN>(payload, &mut pos).context("stream hash missing secret")?,
        );
        let lookups = LookupOpts::decode_from(payload, &mut pos)?;
        let addr_json = payload.get(pos..).context("stream hash missing address")?;
        let value: serde_json::Value =
            serde_json::from_slice(addr_json).context("invalid stream hash address")?;
        let (_id, addr) = endpoint_addr_from_json(&value)?;
        // A stream is one direct lane: its node has no multi-hop and never gossips.
        let transport = TransportPolicy {
            udp: flags & NO_UDP_BIT == 0,
            webrtc: flags & NO_WEBRTC_BIT == 0,
            multihop: false,
            gossip: false,
            relay_transport: flags & RELAY_TRANSPORT_BIT != 0,
        };
        // The rules a mesh id meets on decode: `pkarr` needs `relay`, plain
        // http for pkarr needs an all-loopback ladder, and the transports
        // need a direct path. A hash carries no password or invite.
        MeshConfig {
            lookups: lookups.clone(),
            password: None,
            issuer_pubkey: None,
            transport,
        }
        .validate()?;
        Ok(Self {
            addr,
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
    type Err = anyhow::Error;

    fn from_str(hash: &str) -> Result<Self> {
        Self::decode(hash)
    }
}

#[cfg(test)]
mod tests {
    use habilis_network::iroh::{EndpointAddr, SecretKey, TransportAddr};

    use habilis_network::protocol::{PkarrChoice, RelayChoice};

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
            lookups: LookupOpts::public_preset(),
            transport,
            id: StreamId::from_bytes([1; ID_LEN]),
            secret: StreamSecret::from_bytes([2; SECRET_LEN]),
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

    /// A hash is read like a mesh id, so the rules that join its lookups and
    /// its transport hold for it too. A forged one is encoded without them.
    #[test]
    fn a_hash_the_mesh_rules_refuse_is_refused() {
        let forged = |lookups: LookupOpts| StreamHash {
            lookups,
            ..sample(TransportPolicy::default())
        };
        // Pkarr names the home relay and nothing else: with no relay lookup
        // its record holds no address.
        let no_relay = forged(LookupOpts {
            pkarr: PkarrChoice::Pinned,
            ..LookupOpts::loopback()
        });
        let pkarr_only = StreamHash::decode(&no_relay.encode()).expect_err("pkarr without relay");
        assert!(pkarr_only.to_string().contains("pkarr"), "{pkarr_only}");
        // Plain http for pkarr is for a mesh whose relay is on this machine.
        let http = forged(LookupOpts {
            relay_lookup: RelayChoice::Pinned,
            pkarr: PkarrChoice::Custom(vec!["http://127.0.0.1:1/pkarr".parse().unwrap()]),
            ..LookupOpts::loopback()
        });
        let plain_http = StreamHash::decode(&http.encode()).expect_err("http pkarr, public relay");
        assert!(
            plain_http.to_string().contains("plain http"),
            "{plain_http}"
        );
        // A transport with no direct path, or a relay that carries payload
        // with no relay lookup to carry it.
        let no_path = sample(policy(false, false, true));
        assert!(StreamHash::decode(&no_path.encode()).is_err());
        let relay_payload = StreamHash {
            lookups: LookupOpts::loopback(),
            ..sample(policy(true, true, true))
        };
        let no_lookup = StreamHash::decode(&relay_payload.encode()).expect_err("no relay lookup");
        assert!(no_lookup.to_string().contains("relay"), "{no_lookup}");
        // The same hash, well formed, decodes.
        let ok = sample(policy(true, true, false));
        assert_eq!(StreamHash::decode(&ok.encode()).expect("decodes"), ok);
    }

    /// The bytes of a hash minted before pkarr joined the public preset. A change
    /// here is a wire change: tokens of this shape exist outside the code.
    const GOLDEN: &str = "JNa7ZgZwvMzW441NiDGTgK654QRhVajAbdBBcye6WJ3gqu3uyqWdEZZAUNs5cyu9H6FsQrdy5dPUHcXeYCWTt4axrbcFDhWuoDBjr4zRLF98ACN2SN8hF96pm2WHcREaPriXuG613yAxqeRHKVaXq4QbTPe8me6qUV3Q7exwREKfQQUDgzxzjrV6N39HD5pHWydqyxYeiHnqMGNtHPvQqeLoA93LabKCNiK";

    #[test]
    fn encode_matches_the_golden_string() {
        assert_eq!(sample(policy(true, true, true)).encode(), GOLDEN);
    }

    /// The golden before pkarr joined the default lookups. It encodes a loopback sample with a
    /// relay transport, and the decoder refuses that: a relay transport needs a relay lookup.
    const GOLDEN_BEFORE_PKARR: &str = "JNa7ZgZwvMzW441NiDGTgK654QRhVajAbdBBcye6WJ3gqu3uyqWdEZZAUNs5cyu9H6FsPMQhkgfib2UHxLsS7a3Xq8jURe1VErA8rdM3UdgvXdmQH74aYiQHPj6hFUCK8dkMb5eFCLZy8D3f3cYXiScH5c7Uk23z4gfeoEbH3ZPX2DSk8niKsyZG1C2mtWdpeMuYQc5f4ytXUKRb5vPHyKrKT4BKPSjA3rK";

    #[test]
    fn a_golden_from_before_pkarr_is_refused() {
        let refused = StreamHash::decode(GOLDEN_BEFORE_PKARR).expect_err("refused");
        assert!(refused.to_string().contains("relay"), "{refused}");
    }

    #[test]
    fn decode_of_the_golden_string_gives_the_same_fields() {
        assert_eq!(
            StreamHash::decode(GOLDEN).expect("decodes"),
            sample(policy(true, true, true))
        );
    }

    // `unsafe_code` is denied, so a test cannot read the freed bytes: it pins the
    // type of the field instead. A `Zeroizing` buffer wipes on drop.
    #[test]
    fn the_secret_is_held_in_a_wiped_buffer() {
        let secret = StreamSecret::from_bytes([9; SECRET_LEN]);
        let _: &Zeroizing<[u8; SECRET_LEN]> = &secret.0;
    }

    #[test]
    fn from_zeroizing_keeps_the_bytes() {
        let secret = StreamSecret::from_zeroizing(Zeroizing::new([4; SECRET_LEN]));
        assert_eq!(secret.as_bytes(), &[4; SECRET_LEN]);
    }

    #[test]
    fn header_bytes_are_the_id_then_the_secret() {
        let mut expected = vec![1; ID_LEN];
        expected.extend_from_slice(&[2; SECRET_LEN]);
        assert_eq!(
            sample(TransportPolicy::default()).header_bytes().as_slice(),
            expected.as_slice()
        );
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
    fn a_secret_prints_no_byte_and_one_byte_makes_two_hashes_differ() {
        let hash = sample(TransportPolicy::default());
        assert_eq!(format!("{:?}", hash.secret), "StreamSecret(***)");
        let mut other = hash.clone();
        assert_eq!(hash, other);
        let mut bytes = *other.secret.as_bytes();
        bytes[SECRET_LEN - 1] ^= 1;
        other.secret = StreamSecret::from_bytes(bytes);
        assert_ne!(hash, other);
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let shown = format!("{:?}", sample(TransportPolicy::default()));
        assert!(!shown.contains("secret"), "{shown}");
    }
}
