use super::{LookupOpts, Mesh, MeshConfig, MeshName, RelayChoice, SEED_LEN, TransportPolicy};
use crate::mesh::lookup::MAX_RELAY_URL_BYTES;

fn dummy_seed() -> [u8; SEED_LEN] {
    [7u8; SEED_LEN]
}

fn dummy_name() -> MeshName {
    MeshName::new("test").unwrap()
}

fn custom_config() -> MeshConfig {
    MeshConfig {
        lookups: LookupOpts {
            mdns: true,
            dht: false,
            relay_lookup: RelayChoice::Custom(vec![
                "https://a.example".parse().unwrap(),
                "https://b.example".parse().unwrap(),
            ]),
        },
        password: None,
        issuer_pubkey: None,
        transport: TransportPolicy::default(),
    }
}

#[test]
fn round_trip_loopback() {
    let mesh = Mesh::new(dummy_seed(), dummy_name(), MeshConfig::loopback());
    let encoded = mesh.to_string();
    assert!(
        encoded.bytes().all(|byte| byte.is_ascii_alphanumeric()),
        "id must be bare ASCII Base58: {encoded}"
    );
    let decoded: Mesh = encoded.parse().unwrap();
    assert_eq!(decoded.seed(), mesh.seed());
    assert_eq!(decoded.name, mesh.name);
    assert_eq!(decoded.config, mesh.config);
    assert!(decoded.is_loopback());
}

#[test]
fn round_trip_public_preset() {
    let mesh = Mesh::new(
        [0xABu8; SEED_LEN],
        dummy_name(),
        MeshConfig::public_preset(),
    );
    let decoded: Mesh = mesh.to_string().parse().unwrap();
    assert_eq!(decoded.seed(), &[0xABu8; SEED_LEN]);
    assert_eq!(decoded.config, mesh.config);
    assert!(!decoded.is_loopback());
    assert_eq!(decoded.network_label(), "public");
}

#[test]
fn round_trip_custom_relay_ladder() {
    let mesh = Mesh::new(dummy_seed(), dummy_name(), custom_config());
    let decoded: Mesh = mesh.to_string().parse().unwrap();
    assert_eq!(decoded.config, custom_config());
}

/// A config whose custom ladder holds `count` distinct relay URLs.
fn ladder_config(count: usize) -> MeshConfig {
    let ladder = (0..count)
        .map(|index| format!("https://r{index}.example").parse().unwrap())
        .collect();
    MeshConfig {
        lookups: LookupOpts {
            mdns: false,
            dht: false,
            relay_lookup: RelayChoice::Custom(ladder),
        },
        password: None,
        issuer_pubkey: None,
        transport: TransportPolicy::default(),
    }
}

#[test]
fn validate_rejects_a_ladder_over_the_wire_ceiling() {
    // One past `MAX_RELAY_LADDER`: encodes fine, then no joiner can decode it.
    let error = ladder_config(17).validate().unwrap_err();
    assert!(error.to_string().contains("relay ladder"), "got: {error}");
    ladder_config(16)
        .validate()
        .expect("the ceiling itself fits");
}

#[test]
fn validate_rejects_a_ladder_the_count_byte_cannot_hold() {
    // Past 255 the count no longer fits a `u8` and the encoder panics.
    let error = ladder_config(300).validate().unwrap_err();
    assert!(error.to_string().contains("relay ladder"), "got: {error}");
}

#[test]
fn validate_rejects_a_relay_url_over_the_wire_ceiling() {
    let host = "a".repeat(MAX_RELAY_URL_BYTES);
    let config = MeshConfig {
        lookups: LookupOpts {
            mdns: false,
            dht: false,
            relay_lookup: RelayChoice::Custom(vec![
                format!("https://{host}.example").parse().unwrap(),
            ]),
        },
        password: None,
        issuer_pubkey: None,
        transport: TransportPolicy::default(),
    };
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("relay URL"), "got: {error}");
}

#[test]
fn seed_drives_rendezvous_identity() {
    let mesh = Mesh::new(dummy_seed(), dummy_name(), MeshConfig::public_preset());
    let decoded: Mesh = mesh.to_string().parse().unwrap();
    assert_eq!(decoded.rendezvous_id(), mesh.rendezvous_id());
    assert_eq!(decoded.rendezvous_ports(), mesh.rendezvous_ports());
}

#[test]
fn different_seeds_yield_different_ids() {
    let one = Mesh::new([1u8; SEED_LEN], dummy_name(), MeshConfig::loopback()).to_string();
    let two = Mesh::new([2u8; SEED_LEN], dummy_name(), MeshConfig::loopback()).to_string();
    assert_ne!(one, two);
}

#[test]
fn different_config_yields_different_id() {
    let one = Mesh::new(dummy_seed(), dummy_name(), MeshConfig::loopback()).to_string();
    let two = Mesh::new(dummy_seed(), dummy_name(), MeshConfig::public_preset()).to_string();
    assert_ne!(one, two, "config is part of the id");
}

#[test]
fn password_verifier_yields_different_id_and_round_trips() {
    let passworded = MeshConfig {
        lookups: LookupOpts::public_preset(),
        password: Some([0x5Au8; 16]),
        issuer_pubkey: None,
        transport: TransportPolicy::default(),
    };
    let one = Mesh::new(dummy_seed(), dummy_name(), MeshConfig::public_preset());
    let two = Mesh::new(dummy_seed(), dummy_name(), passworded.clone());
    assert_ne!(one.to_string(), two.to_string());
    let decoded: Mesh = two.to_string().parse().unwrap();
    assert_eq!(decoded.config, passworded);
}

#[test]
fn set_password_bakes_verifier_and_apply_verifies_it() {
    use crate::crypto::Password;
    let password = Password::new("hunter2".to_owned());

    let mut creator = Mesh::new(dummy_seed(), dummy_name(), MeshConfig::public_preset());
    let passwordless_topic = creator.topic_id();
    let passwordless_rendezvous = creator.rendezvous_id();
    creator.set_password(&password);
    assert!(creator.requires_password());

    // Every derivation switched onto the stretched key.
    assert_ne!(creator.topic_id(), passwordless_topic);
    assert_ne!(creator.rendezvous_id(), passwordless_rendezvous);

    // A joiner decoding the id verifies and lands on identical derivations.
    let mut joiner: Mesh = creator.to_string().parse().unwrap();
    assert!(joiner.requires_password());
    joiner.apply_password(&password).unwrap();
    assert_eq!(joiner.topic_id(), creator.topic_id());
    assert_eq!(joiner.rendezvous_id(), creator.rendezvous_id());
    assert_eq!(joiner.rendezvous_ports(), creator.rendezvous_ports());

    // Wrong password fails locally, against the verifier.
    let mut wrong: Mesh = creator.to_string().parse().unwrap();
    let error = wrong
        .apply_password(&Password::new("hunter3".to_owned()))
        .unwrap_err();
    assert!(error.to_string().contains("wrong password"), "got: {error}");
}

#[test]
fn apply_password_on_passwordless_id_is_rejected() {
    use crate::crypto::Password;
    let mut mesh = Mesh::new(dummy_seed(), dummy_name(), MeshConfig::public_preset());
    let error = mesh
        .apply_password(&Password::new("hunter2".to_owned()))
        .unwrap_err();
    assert!(error.to_string().contains("no password"), "got: {error}");
}

#[test]
#[should_panic(expected = "passworded mesh derived before the password was applied")]
fn passworded_mesh_refuses_to_derive_without_the_password() {
    let mut mesh = Mesh::new(dummy_seed(), dummy_name(), MeshConfig::public_preset());
    mesh.config.password = Some([1u8; 16]);
    let _ = mesh.topic_id();
}

#[test]
fn golden_passwordless_id_and_topic_are_pinned() {
    // Byte-for-byte pin on a passwordless id and its topic. Neither is
    // allowed to move by accident (both moved once on purpose: mesh id
    // version 2 writes the transport policy as its own byte); if this fails and you did not mean to
    // change the encoding, the format regressed.
    //
    // The two constants are pinned against different accidents and do not
    // move together. The id encodes only seed/name/config, so nothing about
    // a rename should ever reach it — if the id changes, something leaked
    // into the encoding that does not belong there. The topic mixes
    // `crypto::DOMAIN`, so it moves whenever that domain is rebranded; it
    // last moved when the domains dropped the product's name for the
    // engine's (`habilis-mesh/…`), which is why
    // `message::VERSION` is `12.0`.
    //
    // That split is the point: this pair is what proved the de-branding
    // reached the key-derivation transcript (topic moved) without leaking
    // into the id encoding (id held).
    let mesh = Mesh::new(dummy_seed(), dummy_name(), MeshConfig::public_preset());
    assert_eq!(
        mesh.to_string(),
        "DqrLWcbLaiVzMV2mvqefxWxWmgLCYmGWAK5jCxeTgFqc6dk1MQrfiqazmpTSgH"
    );
    let topic = super::crypto::derive_topic_id(mesh.seed(), &mesh.name, &mesh.config_bytes());
    assert_eq!(
        format!("{topic:?}"),
        "TopicId(1898d0078596295e6f69e42e9284e139d69921f2db46026b16611a924e65bd1d)"
    );
}

// The golden id and topic of a mesh that an older build made (the default had no gossip). The id
// decodes, gossip reads as off, and the id and the topic come out the same: nothing that exists
// moves when the default turns gossip on.
#[test]
fn an_id_of_an_older_default_mesh_keeps_its_id_and_its_topic() {
    let older = "DqrLWcbLaiVzMV2mvqefxWxWmgLCYmGWAK5jCxeTgFqc6dk1MQrfiqay2YxkRe";
    let mesh: Mesh = older.parse().expect("an older id decodes");
    assert!(!mesh.config.transport.gossip, "it has no gossip");
    assert_eq!(mesh.to_string(), older, "and it keeps its id");
    let topic = super::crypto::derive_topic_id(mesh.seed(), &mesh.name, &mesh.config_bytes());
    assert_eq!(
        format!("{topic:?}"),
        "TopicId(0efae5467ad7c26c9b6a3f0a64a97d1799412ac891282711077401b8ecd8c0e7)"
    );
}

#[test]
fn from_topic_is_deterministic() {
    let one = Mesh::from_topic("habilis-network", MeshConfig::public_preset());
    let two = Mesh::from_topic("habilis-network", MeshConfig::public_preset());
    assert_eq!(one.to_string(), two.to_string());
}

#[test]
fn from_topic_name_is_the_sanitized_string() {
    let mesh = Mesh::from_topic(
        "https://github.com/example-org/example-project",
        MeshConfig::public_preset(),
    );
    // Scheme stripped, `/`s kept; the 38-char URL exceeds the 32-char cap,
    // so the tail truncates to `…`.
    assert_eq!(mesh.name.as_str(), "github.com/example-org/example…");
}

#[test]
fn from_topic_differs_by_string() {
    let one = Mesh::from_topic("alpha", MeshConfig::public_preset());
    let two = Mesh::from_topic("beta", MeshConfig::public_preset());
    assert_ne!(one.to_string(), two.to_string());
}

#[test]
fn from_topic_round_trips_through_from_str() {
    let mesh = Mesh::from_topic("habilis-network", MeshConfig::public_preset());
    let decoded: Mesh = mesh.to_string().parse().expect("decode failed");
    assert_eq!(decoded.seed(), mesh.seed());
    assert_eq!(decoded.name, mesh.name);
    assert_eq!(decoded.config, mesh.config);
}

#[test]
fn a_prefixed_id_is_rejected() {
    // An id is bare Base58Check, so anything glued to the front is not a
    // brand to strip — it is corruption, and the checksum says so. Covers
    // both a stale glyph paste and the ASCII brands other tools use.
    let encoded = Mesh::new(dummy_seed(), dummy_name(), MeshConfig::loopback()).to_string();
    for prefix in ["💬", "💬://", "sw1", "xyz", "ahs"] {
        let bad = format!("{prefix}{encoded}");
        assert!(
            bad.parse::<Mesh>().is_err(),
            "expected reject for prefix {prefix}",
        );
    }
}

#[test]
fn invalid_checksum_rejected() {
    let encoded = Mesh::new(dummy_seed(), dummy_name(), MeshConfig::loopback()).to_string();
    let mut bad = encoded.clone();
    let last_index = bad.len() - 1;
    let replacement = if bad.ends_with('1') { "2" } else { "1" };
    bad.replace_range(last_index.., replacement);
    assert!(bad.parse::<Mesh>().is_err());
}

#[test]
fn truncated_bytes_rejected() {
    assert!(Mesh::decode_bytes(&[0u8; 10]).is_err());
}

#[test]
fn a_mesh_id_carries_the_transport_policy_for_every_list() {
    use super::lookup::Lookup;
    use super::transport::Transport::{Gossip, Multihop, Relay, Udp, WebRtc};
    let lists: [&[super::transport::Transport]; 10] = [
        &[],
        &[Udp],
        &[WebRtc],
        &[Udp, WebRtc],
        &[Udp, Multihop],
        &[Udp, WebRtc, Multihop],
        &[Udp, Multihop, Relay],
        &[Udp, WebRtc, Multihop, Relay],
        &[Udp, Gossip],
        &[Udp, WebRtc, Multihop, Gossip],
    ];
    let mut seen: Vec<(TransportPolicy, String)> = Vec::new();
    for list in lists {
        let config = MeshConfig::resolve(&[Lookup::Relay], None, list).expect("a valid list");
        let id = Mesh::new(dummy_seed(), dummy_name(), config.clone()).to_string();
        let decoded: Mesh = id.parse().expect("the id decodes");
        assert_eq!(decoded.config, config, "{list:?}");
        // Same policy, same id; a different policy, a different id.
        for (policy, other) in &seen {
            assert_eq!(*policy == config.transport, *other == id, "{list:?}");
        }
        seen.push((config.transport, id));
    }
    // An empty list is the default, `udp,webrtc,multihop,gossip`. A list names what it carries:
    // the same list without `gossip` is not the default.
    let policy = |list: &[super::transport::Transport]| {
        MeshConfig::resolve(&[Lookup::Relay], None, list)
            .unwrap()
            .transport
    };
    assert_eq!(policy(&[]), policy(&[Udp, WebRtc, Multihop, Gossip]));
    assert_ne!(policy(&[]), policy(&[Udp, WebRtc, Multihop]));
}

#[test]
fn a_version_1_mesh_id_is_rejected_with_upgrade() {
    let mesh = Mesh::new(dummy_seed(), dummy_name(), MeshConfig::loopback());
    let mut bytes = mesh.encode_bytes();
    bytes[0] = 1; // the format before the transport policy had its own byte
    let error = Mesh::decode_bytes(&bytes).expect_err("a version 1 id is refused");
    assert!(
        error.to_string().contains("upgrade"),
        "the error must tell the member what to do: {error}"
    );
}

#[test]
fn unknown_version_rejected() {
    let mesh = Mesh::new(dummy_seed(), dummy_name(), MeshConfig::loopback());
    let mut bytes = mesh.encode_bytes();
    bytes[0] = 3; // an unknown version byte
    assert!(Mesh::decode_bytes(&bytes).is_err());
}

#[test]
fn mesh_id_round_trips_unicode_name() {
    let name = MeshName::new("café-日本-🎉").unwrap();
    let mesh = Mesh::new(dummy_seed(), name.clone(), MeshConfig::loopback());
    let decoded: Mesh = mesh.to_string().parse().expect("decode failed");
    assert_eq!(decoded.name, name);
}

#[test]
fn mesh_id_round_trips_max_byte_name() {
    // 32 four-byte scalars = 128 bytes = the most the 1-byte name
    // length field can carry; exercises the encode/decode upper edge.
    let name = MeshName::new("🎉".repeat(32)).unwrap();
    assert_eq!(name.as_bytes().len(), 128);
    let mesh = Mesh::new(dummy_seed(), name.clone(), MeshConfig::public_preset());
    let decoded: Mesh = mesh.to_string().parse().expect("decode failed");
    assert_eq!(decoded.name, name);
}

mod prop {
    use proptest::{
        array::{uniform16, uniform32},
        prelude::any,
        prop_assert, prop_assert_eq, prop_assert_ne, prop_assume, proptest,
        strategy::Strategy,
    };

    use super::{Mesh, MeshConfig, MeshName, SEED_LEN};

    fn arb_seed() -> impl Strategy<Value = [u8; SEED_LEN]> {
        uniform32(0u8..)
    }

    fn arb_name() -> impl Strategy<Value = MeshName> {
        "[a-z][a-z0-9_-]{0,31}".prop_map(|raw| MeshName::new(raw).unwrap())
    }

    fn arb_config() -> impl Strategy<Value = MeshConfig> {
        (any::<bool>(), proptest::option::of(uniform16(0u8..))).prop_map(build_config)
    }

    fn build_config((public, verifier): (bool, Option<[u8; 16]>)) -> MeshConfig {
        let mut config = if public {
            MeshConfig::public_preset()
        } else {
            MeshConfig::loopback()
        };
        config.password = verifier;
        config
    }

    proptest! {
        #![proptest_config(crate::proptest_support::config())]
        #[test]
        fn prop_round_trip(
            seed in arb_seed(),
            name in arb_name(),
            config in arb_config(),
        ) {
            let mesh = Mesh::new(seed, name.clone(), config.clone());
            let decoded: Mesh = mesh.to_string().parse().expect("decode failed");
            prop_assert_eq!(decoded.seed(), mesh.seed());
            prop_assert_eq!(decoded.name, mesh.name);
            prop_assert_eq!(decoded.config, config);
        }

        #[test]
        fn prop_bare_base58(seed in arb_seed(), name in arb_name()) {
            let id = Mesh::new(seed, name, MeshConfig::loopback()).to_string();
            prop_assert!(!id.contains("://"));
            prop_assert!(id.is_ascii());
            prop_assert!(!id.is_empty());
        }

        #[test]
        fn prop_deterministic(
            seed in arb_seed(),
            name in arb_name(),
            config in arb_config(),
        ) {
            let mesh = Mesh::new(seed, name, config);
            prop_assert_eq!(mesh.to_string(), mesh.to_string());
        }

        #[test]
        fn prop_distinct_seeds_distinct_ids(
            seed_a in arb_seed(),
            seed_b in arb_seed(),
            name in arb_name(),
        ) {
            prop_assume!(seed_a != seed_b);
            let one = Mesh::new(seed_a, name.clone(), MeshConfig::loopback()).to_string();
            let two = Mesh::new(seed_b, name, MeshConfig::loopback()).to_string();
            prop_assert_ne!(one, two);
        }
    }
}
