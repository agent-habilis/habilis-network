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

mod stream_hash;
mod stream_id;
mod stream_secret;

pub use stream_hash::StreamHash;
pub use stream_id::StreamId;
pub use stream_secret::StreamSecret;

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

#[cfg(test)]
mod tests {
    use habilis_network::iroh::{EndpointAddr, SecretKey, TransportAddr};
    use habilis_network_test_tracing::test;

    use habilis_network::protocol::{LookupOpts, TransportPolicy, base58check};
    use zeroize::Zeroizing;

    use super::{ID_LEN, KIND, SECRET_LEN, StreamHash, StreamId, StreamSecret, VERSION};
    fn sample(transport: TransportPolicy) -> StreamHash {
        let id = SecretKey::from_bytes(&[7; 32]).public();
        StreamHash {
            address: EndpointAddr::from_parts(
                id,
                [TransportAddr::Ip(
                    "127.0.0.1:4433".parse().expect("socket addr"),
                )],
            ),
            lookups: LookupOpts::loopback(),
            transport,
            id: StreamId::from([1; ID_LEN]),
            secret: StreamSecret::from([2; SECRET_LEN]),
        }
    }

    fn policy(udp: bool, webrtc: bool, relay_transport: bool) -> TransportPolicy {
        let policy = TransportPolicy::default().with_udp(udp).with_webrtc(webrtc);
        policy
            .with_multihop(false)
            .with_gossip(false)
            .with_relay_transport(relay_transport)
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
            assert_eq!(
                StreamHash::decode(&hash.encode()).expect("decodes"),
                hash,
                "a hash round trips every transport list"
            );
            let reparsed: StreamHash = hash.to_string().parse().expect("parses");
            assert_eq!(reparsed, hash, "the reparsed hash equals the hash");
        }
    }

    /// The bytes of a hash minted by the code at the base commit. A change
    /// here is a wire change: tokens of this shape exist outside the code.
    const GOLDEN: &str = "JNa7ZgZwvMzW441NiDGTgK654QRhVajAbdBBcye6WJ3gqu3uyqWdEZZAUNs5cyu9H6FsPMQhkgfib2UHxLsS7a3Xq8jURe1VErA8rdM3UdgvXdmQH74aYiQHPj6hFUCK8dkMb5eFCLZy8D3f3cYXiScH5c7Uk23z4gfeoEbH3ZPX2DSk8niKsyZG1C2mtWdpeMuYQc5f4ytXUKRb5vPHyKrKT4BKPSjA3rK";

    #[test]
    fn encode_matches_the_golden_string() {
        assert_eq!(
            sample(policy(true, true, true)).encode(),
            GOLDEN,
            "the encoding matches the golden string"
        );
    }

    #[test]
    fn decode_of_the_golden_string_gives_the_same_fields() {
        assert_eq!(
            StreamHash::decode(GOLDEN).expect("decodes"),
            sample(policy(true, true, true)),
            "the golden string decodes to the same fields"
        );
    }

    // `unsafe_code` is denied, so a test cannot read the freed bytes: it pins the
    // type of the field instead. A `Zeroizing` buffer wipes on drop.
    #[test]
    fn the_secret_is_held_in_a_wiped_buffer() {
        let secret = StreamSecret::from([9; SECRET_LEN]);
        let _: &Zeroizing<[u8; SECRET_LEN]> = &secret.0;
    }

    #[test]
    fn zeroizing_keeps_the_bytes() {
        let secret = StreamSecret::from(Zeroizing::new([4; SECRET_LEN]));
        assert_eq!(
            secret.as_bytes(),
            &[4; SECRET_LEN],
            "from_zeroizing keeps the secret bytes"
        );
    }

    #[test]
    fn header_bytes_are_the_id_then_the_secret() {
        let mut expected = vec![1; ID_LEN];
        expected.extend_from_slice(&[2; SECRET_LEN]);
        assert_eq!(
            sample(TransportPolicy::default()).header_bytes().as_slice(),
            expected.as_slice(),
            "the header bytes are the id then the secret"
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
        assert!(
            StreamHash::decode(&encoded).is_err(),
            "a flipped character fails the checksum"
        );
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
        assert!(
            StreamHash::decode(&mesh.to_string()).is_err(),
            "a mesh id is not a stream hash"
        );
    }

    #[test]
    fn a_secret_prints_no_byte_and_one_byte_makes_two_hashes_differ() {
        let hash = sample(TransportPolicy::default());
        assert_eq!(
            format!("{:?}", hash.secret),
            "StreamSecret(***)",
            "a secret prints no byte in its debug form"
        );
        let mut other = hash.clone();
        assert_eq!(hash, other, "equal inputs give equal hashes");
        let mut bytes = *other.secret.as_bytes();
        bytes[SECRET_LEN - 1] ^= 1;
        other.secret = StreamSecret::from(bytes);
        assert_ne!(
            hash, other,
            "one byte of difference makes two hashes differ"
        );
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let shown = format!("{:?}", sample(TransportPolicy::default()));
        assert!(!shown.contains("secret"), "{shown}");
    }
}
