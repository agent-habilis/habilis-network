//! The blob ticket — a bare Base58Check token carrying everything a consumer
//! needs to fetch one content-addressed blob from its producer: the bearer
//! secret, the content hash + size, the mesh's discovery config, and the
//! producer's blob-endpoint address. Payload layout: `secret(32) ‖ flags(1) ‖
//! sha256(32) ‖ size(8, LE) ‖ lookups ‖ address-json` (lookups is
//! self-delimiting, so the address occupies the remainder). Bit 0 of the flags
//! byte marks a password-protected ticket.
//!
//! Wire: bare Base58Check(`version ‖ kind ‖ payload`) with a `SHA256d`
//! checksum. The `kind` byte marks this as a *blob* ticket so a wrong-kind
//! token (invite / bridge) fails cleanly on decode.

mod blob_ticket;

pub use blob_ticket::BlobTicket;

/// Framing version. Bumped only on a breaking framing change; an unknown
/// version is rejected on decode.
const VERSION: u8 = 1;

/// Ticket-kind discriminant, framed after [`VERSION`]. Distinct from invite
/// (`3`) and bridge tickets so a wrong-kind token is rejected on decode.
const KIND: u8 = 1;

/// Bit 0 of the flags byte: the password flag.
const PASSWORD_BIT: u8 = 0b0000_0001;
/// The producer's mesh lets the relay carry payload. Absent — every ticket
/// minted before the policy existed — the fetch must run on a direct path,
/// and both ends refuse a relayed one.
const RELAY_TRANSPORT_BIT: u8 = 0b0000_0010;

/// Read `N` bytes at `*pos` into a fixed array, advancing `*pos`. `None` if the
/// slice is too short.
#[cfg(test)]
mod tests {
    use super::BlobTicket;
    use crate::blob::{BlobDigest, HASH_LEN, SECRET_LEN};
    use crate::protocol::crypto::TicketSecret;
    use crate::protocol::mesh::LookupOpts;
    use crate::transport::PayloadPath;
    use habilis_network_test_tracing::test;
    use iroh::{EndpointAddr, SecretKey};

    use crate::protocol::mesh;
    fn sample_addr(byte: u8) -> EndpointAddr {
        let id = SecretKey::from_bytes(&[byte; 32]).public();
        EndpointAddr::new(id).with_ip_addr("127.0.0.1:4242".parse().unwrap())
    }

    fn sample(password: bool) -> BlobTicket {
        BlobTicket {
            address: sample_addr(3),
            secret: TicketSecret::from_bytes([9u8; SECRET_LEN]),
            sha256: BlobDigest::from_bytes([7u8; HASH_LEN]),
            size: 1_234_567,
            lookups: LookupOpts::public_preset(),
            password,
            relay_transport: PayloadPath::RelayAllowed,
        }
    }

    #[test]
    fn ticket_round_trips() {
        let ticket = sample(false);
        let encoded = ticket.encode();
        assert!(encoded.is_ascii());
        assert!(!encoded.contains("://"));
        let decoded = BlobTicket::decode(&encoded).expect("decode");
        assert_eq!(decoded.address.id, ticket.address.id);
        assert_eq!(decoded.secret.as_bytes(), &[9u8; SECRET_LEN]);
        assert_eq!(decoded.sha256, BlobDigest::from_bytes([7u8; HASH_LEN]));
        assert_eq!(decoded.size, 1_234_567);
        assert_eq!(decoded.lookups, LookupOpts::public_preset());
        assert!(!decoded.password);
    }

    /// The bytes of a ticket minted by the code at the base commit. A change
    /// here is a wire change: tokens of this shape exist outside the code.
    const GOLDEN: &str = "7uoCFwgsTez8XFb4njvMAMtE2vJeBnmBrmZUx5yWRCWRQLMdHteB1NQfJibHEK1WioE5QiSF1L29xXB7Jz1Q6z65hGReoUL4qgUyMJ8FijN6j5dJoGV4Z6HZ7iHiabPLdgWqXbLdBMpo7d1DKBM99xrYT79PaLDPMCAtbwHF13yJQ99G9G9LNVeEaaYs9b1Jdex66d8drD2vYGnZvoeJo2dyennE6g8TTVCogg6xvo4ev6RKcaTVLaipT1a6XzUVQg2S";

    #[test]
    fn encode_matches_the_golden_string() {
        assert_eq!(sample(false).encode(), GOLDEN);
    }

    #[test]
    fn decode_of_the_golden_string_gives_the_same_fields() {
        let decoded = BlobTicket::decode(GOLDEN).expect("decode");
        let expected = sample(false);
        assert_eq!(decoded.address, expected.address);
        assert_eq!(decoded.secret.as_bytes(), expected.secret.as_bytes());
        assert_eq!(decoded.sha256, expected.sha256);
        assert_eq!(decoded.size, expected.size);
        assert_eq!(decoded.lookups, expected.lookups);
        assert_eq!(decoded.password, expected.password);
        assert_eq!(decoded.relay_transport, expected.relay_transport);
    }

    #[test]
    fn password_flag_round_trips() {
        let decoded = BlobTicket::decode(&sample(true).encode()).expect("decode");
        assert!(decoded.password);
        assert_eq!(decoded.relay_transport, PayloadPath::RelayAllowed);
    }

    #[test]
    fn relay_transport_flag_round_trips_and_is_off_by_default() {
        let ticket = BlobTicket {
            relay_transport: PayloadPath::DirectOnly,
            ..sample(true)
        };
        let decoded = BlobTicket::decode(&ticket.encode()).expect("decode");
        assert_eq!(decoded.relay_transport, PayloadPath::DirectOnly);
        assert!(decoded.password, "the two flags share a byte");
        let on = BlobTicket {
            relay_transport: PayloadPath::RelayAllowed,
            ..sample(false)
        };
        assert_eq!(
            BlobTicket::decode(&on.encode()).unwrap().relay_transport,
            PayloadPath::RelayAllowed
        );
    }

    #[test]
    fn sha256_hex_is_the_lowercase_content_hash() {
        // The receiver lands the fetched bytes under this name, so it must equal
        // the producer's spool filename (lowercase hex of the SHA-256).
        let ticket = sample(false); // sha256 == [7u8; HASH_LEN]
        assert_eq!(ticket.sha256_hex(), "07".repeat(HASH_LEN));
    }

    #[test]
    fn rejects_a_mesh_token() {
        // A mesh id shares the bare-base58 shape but has a different payload;
        // blob decode must refuse it (wrong kind / structure).
        let mesh = mesh::Mesh::try_new(
            crate::protocol::Seed::from_bytes([1u8; 32]),
            mesh::MeshName::try_new("t").unwrap(),
            mesh::MeshConfig::loopback(),
        )
        .unwrap()
        .to_string();
        assert!(BlobTicket::decode(&mesh).is_err());
    }

    #[test]
    fn an_invite_and_a_blob_ticket_never_cross_parse() {
        // Both are bare Base58Check with the same framing, so only the `kind`
        // byte keeps them apart. The assertion lives on this side because
        // `habilis-network-protocol` (where invites moved) cannot see `blob`, while this
        // crate depends on it and can see both.
        use crate::protocol::mesh::{Mesh, MeshConfig, MeshName};

        let mut creator = Mesh::try_new(
            crate::protocol::Seed::from_bytes([1u8; 32]),
            MeshName::try_new("t").unwrap(),
            MeshConfig::loopback(),
        )
        .unwrap();
        creator.set_invite();
        let invite = crate::invite::mint(&creator, Some(std::time::Duration::from_hours(1)), None)
            .expect("mint");
        let blob = sample(false).encode();

        assert!(crate::protocol::InviteTicket::decode(&blob).is_err());
        assert!(BlobTicket::decode(&invite).is_err());
    }

    #[test]
    fn debug_never_prints_the_secret() {
        // A byte array prints in decimal and a hex dump prints in hex, so the
        // check covers both forms, and it asks for the redaction itself.
        let shown = format!("{:?}", sample(false));
        assert!(
            !shown.contains(&format!("{:?}", [9u8; SECRET_LEN])),
            "the bearer secret leaked through Debug in decimal: {shown}"
        );
        assert!(
            !shown.contains(&"09".repeat(SECRET_LEN)),
            "the bearer secret leaked through Debug in hex: {shown}"
        );
        assert!(
            shown.contains("TicketSecret(***)"),
            "the secret is not redacted: {shown}"
        );
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut encoded = sample(false).encode();
        let last = encoded.pop().unwrap();
        encoded.push(if last == '1' { '2' } else { '1' });
        assert!(BlobTicket::decode(&encoded).is_err());
    }
}
