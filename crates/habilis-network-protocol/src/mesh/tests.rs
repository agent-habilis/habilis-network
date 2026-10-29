use super::{
    LockedMesh, LookupOpts, Mesh, MeshConfig, MeshName, RelayChoice, SEED_LEN, TransportPolicy,
    UnlockError,
};
use crate::crypto::{Password, Seed};
use crate::mesh::lookup::MAX_RELAY_URL_BYTES;

fn dummy_seed() -> Seed {
    Seed::new([7u8; SEED_LEN])
}

fn dummy_name() -> MeshName {
    MeshName::try_new("test").unwrap()
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
    let _guard = ::habilis_network_test_tracing::init();
    let mesh = Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::loopback()).unwrap();
    let encoded = mesh.to_string();
    assert!(
        encoded.bytes().all(|byte| byte.is_ascii_alphanumeric()),
        "id must be bare ASCII Base58: {encoded}"
    );
    let decoded: LockedMesh = encoded.parse().unwrap();
    assert_eq!(
        decoded.seed(),
        mesh.seed(),
        "the decoded seed matches the mesh seed"
    );
    assert_eq!(
        decoded.name(),
        mesh.name(),
        "the decoded name matches the mesh name"
    );
    assert_eq!(
        decoded.config(),
        mesh.config(),
        "the decoded config matches the mesh config"
    );
    assert!(
        decoded.is_loopback(),
        "the decoded loopback mesh is loopback"
    );
}

#[test]
fn round_trip_public_preset() {
    let _guard = ::habilis_network_test_tracing::init();
    let mesh = Mesh::try_new(
        Seed::new([0xABu8; SEED_LEN]),
        dummy_name(),
        MeshConfig::public_preset(),
    )
    .unwrap();
    let decoded: LockedMesh = mesh.to_string().parse().unwrap();
    assert_eq!(
        decoded.seed().as_bytes(),
        &[0xABu8; SEED_LEN],
        "the decoded public preset keeps its seed bytes"
    );
    assert_eq!(
        decoded.config(),
        mesh.config(),
        "the decoded public preset keeps its config"
    );
    assert!(
        !decoded.is_loopback(),
        "the decoded public preset is not loopback"
    );
    assert_eq!(
        decoded.network_label(),
        "public",
        "the decoded public preset is labelled public"
    );
}

#[test]
fn round_trip_custom_relay_ladder() {
    let _guard = ::habilis_network_test_tracing::init();
    let mesh = Mesh::try_new(dummy_seed(), dummy_name(), custom_config()).unwrap();
    let decoded: LockedMesh = mesh.to_string().parse().unwrap();
    assert_eq!(
        decoded.config(),
        &custom_config(),
        "the decoded custom relay ladder keeps its config"
    );
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
    let _guard = ::habilis_network_test_tracing::init();
    // One past `MAX_RELAY_LADDER`: encodes fine, then no joiner can decode it.
    let error = ladder_config(17).validate().unwrap_err();
    assert!(error.to_string().contains("relay ladder"), "got: {error}");
    ladder_config(16)
        .validate()
        .expect("the ceiling itself fits");
}

#[test]
fn validate_rejects_a_ladder_the_count_byte_cannot_hold() {
    let _guard = ::habilis_network_test_tracing::init();
    // Past 255 the count no longer fits a `u8` and the encoder panics.
    let error = ladder_config(300).validate().unwrap_err();
    assert!(error.to_string().contains("relay ladder"), "got: {error}");
}

#[test]
fn validate_rejects_a_relay_url_over_the_wire_ceiling() {
    let _guard = ::habilis_network_test_tracing::init();
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
    let _guard = ::habilis_network_test_tracing::init();
    let mesh = Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::public_preset()).unwrap();
    let locked: LockedMesh = mesh.to_string().parse().unwrap();
    let decoded = locked.unlock(None).unwrap();
    assert_eq!(
        decoded.rendezvous_id(),
        mesh.rendezvous_id(),
        "the decoded rendezvous id matches the mesh rendezvous id"
    );
    assert_eq!(
        decoded.rendezvous_ports(),
        mesh.rendezvous_ports(),
        "the decoded rendezvous ports match the mesh rendezvous ports"
    );
}

#[test]
fn different_seeds_yield_different_ids() {
    let _guard = ::habilis_network_test_tracing::init();
    let one = Mesh::try_new(
        Seed::new([1u8; SEED_LEN]),
        dummy_name(),
        MeshConfig::loopback(),
    )
    .unwrap()
    .to_string();
    let two = Mesh::try_new(
        Seed::new([2u8; SEED_LEN]),
        dummy_name(),
        MeshConfig::loopback(),
    )
    .unwrap()
    .to_string();
    assert_ne!(one, two, "two different seeds give two different ids");
}

#[test]
fn different_config_yields_different_id() {
    let _guard = ::habilis_network_test_tracing::init();
    let one = Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::loopback())
        .unwrap()
        .to_string();
    let two = Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::public_preset())
        .unwrap()
        .to_string();
    assert_ne!(one, two, "config is part of the id");
}

#[test]
fn password_verifier_yields_different_id_and_round_trips() {
    let _guard = ::habilis_network_test_tracing::init();
    let passworded = MeshConfig {
        lookups: LookupOpts::public_preset(),
        password: Some([0x5Au8; 16]),
        issuer_pubkey: None,
        transport: TransportPolicy::default(),
    };
    let one = Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::public_preset()).unwrap();
    // `Mesh::try_new` refuses a passworded config, so the id is built as it sits on
    // the wire: the secret is never in it.
    let two = LockedMesh {
        name: dummy_name(),
        seed: dummy_seed(),
        config: passworded.clone(),
    };
    assert_ne!(
        one.to_string(),
        two.to_string(),
        "a password verifier gives a different id text"
    );
    let decoded: LockedMesh = two.to_string().parse().unwrap();
    assert_eq!(
        decoded.config(),
        &passworded,
        "the passworded mesh keeps its config after a round trip"
    );
}

#[test]
fn constructors_refuse_a_config_that_names_a_secret() {
    let _guard = ::habilis_network_test_tracing::init();
    let with_password = MeshConfig {
        password: Some([1u8; 16]),
        ..MeshConfig::public_preset()
    };
    let with_issuer = MeshConfig {
        issuer_pubkey: Some([2u8; 32]),
        ..MeshConfig::public_preset()
    };
    for config in [with_password, with_issuer] {
        let by_new = Mesh::try_new(dummy_seed(), dummy_name(), config.clone()).unwrap_err();
        assert!(by_new.to_string().contains("set_password"), "got: {by_new}");
        let by_topic = Mesh::for_topic("topic", config).unwrap_err();
        assert!(
            by_topic.to_string().contains("set_invite"),
            "got: {by_topic}"
        );
    }
}

#[test]
fn set_password_bakes_verifier_and_unlock_verifies_it() {
    let _guard = ::habilis_network_test_tracing::init();
    let password = Password::new("hunter2".to_owned());

    let mut creator =
        Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::public_preset()).unwrap();
    let passwordless_topic = creator.topic_id();
    let passwordless_rendezvous = creator.rendezvous_id();
    creator.set_password(password.clone());
    assert!(
        creator.requires_password(),
        "a mesh with a password requires one"
    );

    // Every derivation switched onto the stretched key.
    assert_ne!(
        creator.topic_id(),
        passwordless_topic,
        "the password changes the topic id"
    );
    assert_ne!(
        creator.rendezvous_id(),
        passwordless_rendezvous,
        "the password changes the rendezvous id"
    );

    // A joiner decoding the id unlocks it with the password and lands on
    // identical derivations.
    let locked: LockedMesh = creator.to_string().parse().unwrap();
    assert!(
        locked.requires_password(),
        "the locked mesh requires a password"
    );
    let joiner = locked.unlock(Some(&password)).unwrap();
    assert_eq!(
        joiner.topic_id(),
        creator.topic_id(),
        "the joiner gets the creator's topic id"
    );
    assert_eq!(
        joiner.rendezvous_id(),
        creator.rendezvous_id(),
        "the joiner gets the creator's rendezvous id"
    );
    assert_eq!(
        joiner.rendezvous_ports(),
        creator.rendezvous_ports(),
        "the joiner gets the creator's rendezvous ports"
    );

    // Wrong password fails locally, against the verifier.
    let creator_locked: LockedMesh = creator.to_string().parse().unwrap();
    let error = creator_locked
        .unlock(Some(&Password::new("hunter3".to_owned())))
        .unwrap_err();
    assert_eq!(
        error,
        UnlockError::WrongPassword,
        "a wrong password is refused"
    );
}

#[test]
fn unlock_with_a_password_on_a_passwordless_id_is_rejected() {
    let _guard = ::habilis_network_test_tracing::init();
    let locked = Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::public_preset())
        .unwrap()
        .locked();
    let error = locked
        .unlock(Some(&Password::new("hunter2".to_owned())))
        .unwrap_err();
    assert_eq!(
        error,
        UnlockError::NoPassword,
        "a password on a passwordless id is refused"
    );
}

#[test]
fn unlock_without_the_password_on_a_passworded_id_is_rejected() {
    let _guard = ::habilis_network_test_tracing::init();
    let mut creator =
        Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::public_preset()).unwrap();
    creator.set_password(Password::new("hunter2".to_owned()));
    let error = creator.locked().unlock(None).unwrap_err();
    assert_eq!(
        error,
        UnlockError::PasswordRequired,
        "a passworded id without its password is refused"
    );
}

#[test]
fn unlock_refuses_an_invite_only_id() {
    let _guard = ::habilis_network_test_tracing::init();
    let mut creator =
        Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::public_preset()).unwrap();
    creator.set_invite();
    let error = creator.locked().unlock(None).unwrap_err();
    assert_eq!(
        error,
        UnlockError::InviteOnly,
        "an invite-only id is refused on unlock"
    );
}

#[test]
fn unlock_without_a_password_on_a_passwordless_id_derives_from_the_wire_seed() {
    let _guard = ::habilis_network_test_tracing::init();
    let mesh = Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::public_preset()).unwrap();
    let unlocked = mesh.locked().unlock(None).unwrap();
    assert_eq!(
        unlocked.topic_id(),
        mesh.topic_id(),
        "a passwordless id unlocks to the same topic id"
    );
    assert_eq!(
        unlocked.rendezvous_id(),
        mesh.rendezvous_id(),
        "a passwordless id unlocks to the same rendezvous id"
    );
}

#[test]
fn golden_passwordless_id_and_topic_are_pinned() {
    let _guard = ::habilis_network_test_tracing::init();
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
    let mesh = Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::public_preset()).unwrap();
    assert_eq!(
        mesh.to_string(),
        "DqrLWcbLaiVzMV2mvqefxWxWmgLCYmGWAK5jCxeTgFqc6dk1MQrfiqazmpTSgH",
        "the passwordless id is pinned to its golden text"
    );
    let topic = crate::crypto::derive_topic_id(
        crate::crypto::Keying::Wire(mesh.seed()),
        mesh.name(),
        &mesh.config_bytes(),
    );
    assert_eq!(
        format!("{topic:?}"),
        "TopicId(1898d0078596295e6f69e42e9284e139d69921f2db46026b16611a924e65bd1d)",
        "the passwordless topic is pinned to its golden text"
    );
}

// The golden derivations of a passworded mesh, for a fixed seed and password. They equal what the
// code before the newtype refactor (795c4f88) gives: the password key replaces the seed in every
// derivation, and none of the outputs moved.
#[test]
fn golden_passworded_mesh_id_topic_and_rendezvous_are_pinned() {
    let _guard = ::habilis_network_test_tracing::init();
    let mut mesh = Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::public_preset()).unwrap();
    mesh.set_password(Password::new("hunter2".to_owned()));
    assert_eq!(
        mesh.to_string(),
        "Xts3MujFJ6LPpDwNyubQmyofWgxZkrhDTx3ohPc8iYvUxpTMyBg1yWJBJ39x2RSLzPzUV1nGDdx7YL5nX41SP",
        "the passworded mesh id is pinned to its golden text"
    );
    assert_eq!(
        format!("{:?}", mesh.topic_id()),
        "TopicId(47afc8fd71963d7bcbc78dac9588dbb142b4ae79013489ff3d0f09361479a322)",
        "the passworded topic is pinned to its golden text"
    );
    assert_eq!(
        mesh.rendezvous_id().to_string(),
        "0114a2e8ae14744cb2573befc064f196108e6a403eadc32a51b752e22be3517a",
        "the passworded rendezvous id is pinned to its golden text"
    );
    assert_eq!(
        mesh.rendezvous_ports(),
        [9654, 21191, 1453, 23441, 31705, 5703, 10814, 29199],
        "the passworded rendezvous ports are pinned"
    );
    assert_ne!(
        mesh.rendezvous_ports(),
        [9654, 21191, 64941, 55185, 63449, 5703, 10814, 29199],
        "the ladder of the range 1024..=65535 is no longer derived"
    );
}

// The golden id and topic of a mesh that an older build made (the default had no gossip). The id
// decodes, gossip reads as off, and the id and the topic come out the same: nothing that exists
// moves when the default turns gossip on.
#[test]
fn an_id_of_an_older_default_mesh_keeps_its_id_and_its_topic() {
    let _guard = ::habilis_network_test_tracing::init();
    let older = "DqrLWcbLaiVzMV2mvqefxWxWmgLCYmGWAK5jCxeTgFqc6dk1MQrfiqay2YxkRe";
    let mesh: LockedMesh = older.parse().expect("an older id decodes");
    assert!(!mesh.config().transport.gossip, "it has no gossip");
    assert_eq!(mesh.to_string(), older, "and it keeps its id");
    let topic = crate::crypto::derive_topic_id(
        crate::crypto::Keying::Wire(mesh.seed()),
        mesh.name(),
        &mesh.config_bytes(),
    );
    assert_eq!(
        format!("{topic:?}"),
        "TopicId(0efae5467ad7c26c9b6a3f0a64a97d1799412ac891282711077401b8ecd8c0e7)",
        "an older default mesh keeps its topic"
    );
}

#[test]
fn topic_is_deterministic() {
    let _guard = ::habilis_network_test_tracing::init();
    let one = Mesh::for_topic("habilis-network", MeshConfig::public_preset()).unwrap();
    let two = Mesh::for_topic("habilis-network", MeshConfig::public_preset()).unwrap();
    assert_eq!(
        one.to_string(),
        two.to_string(),
        "the same topic string gives the same id"
    );
}

#[test]
fn topic_name_is_the_sanitized_string() {
    let _guard = ::habilis_network_test_tracing::init();
    let mesh = Mesh::for_topic(
        "https://github.com/example-org/example-project",
        MeshConfig::public_preset(),
    )
    .unwrap();
    // Scheme stripped, `/`s kept; the 38-char URL exceeds the 32-char cap,
    // so the tail truncates to `…`.
    assert_eq!(
        mesh.name().as_str(),
        "github.com/example-org/example…",
        "a long topic name is sanitized to its prefix"
    );
}

#[test]
fn topic_differs_by_string() {
    let _guard = ::habilis_network_test_tracing::init();
    let one = Mesh::for_topic("alpha", MeshConfig::public_preset()).unwrap();
    let two = Mesh::for_topic("beta", MeshConfig::public_preset()).unwrap();
    assert_ne!(
        one.to_string(),
        two.to_string(),
        "a different topic string gives a different id"
    );
}

#[test]
fn topic_round_trips_through_from_str() {
    let _guard = ::habilis_network_test_tracing::init();
    let mesh = Mesh::for_topic("habilis-network", MeshConfig::public_preset()).unwrap();
    let decoded: LockedMesh = mesh.to_string().parse().expect("decode failed");
    assert_eq!(
        decoded.seed(),
        mesh.seed(),
        "a topic mesh keeps its seed through from_str"
    );
    assert_eq!(
        decoded.name(),
        mesh.name(),
        "a topic mesh keeps its name through from_str"
    );
    assert_eq!(
        decoded.config(),
        mesh.config(),
        "a topic mesh keeps its config through from_str"
    );
}

#[test]
fn a_prefixed_id_is_rejected() {
    let _guard = ::habilis_network_test_tracing::init();
    // An id is bare Base58Check, so anything glued to the front is not a
    // brand to strip — it is corruption, and the checksum says so. Covers
    // both a stale glyph paste and the ASCII brands other tools use.
    let encoded = Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::loopback())
        .unwrap()
        .to_string();
    for prefix in ["💬", "💬://", "sw1", "xyz", "ahs"] {
        let bad = format!("{prefix}{encoded}");
        let parsed: Result<LockedMesh, _> = bad.parse();
        assert!(parsed.is_err(), "expected reject for prefix {prefix}");
    }
}

#[test]
fn invalid_checksum_rejected() {
    let _guard = ::habilis_network_test_tracing::init();
    let encoded = Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::loopback())
        .unwrap()
        .to_string();
    let mut bad = encoded;
    let last_index = bad.len() - 1;
    let replacement = if bad.ends_with('1') { "2" } else { "1" };
    bad.replace_range(last_index.., replacement);
    let parsed: Result<LockedMesh, _> = bad.parse();
    assert!(parsed.is_err(), "an invalid checksum is refused");
}

#[test]
fn truncated_bytes_rejected() {
    let _guard = ::habilis_network_test_tracing::init();
    assert!(
        LockedMesh::decode_bytes(&[0u8; 10]).is_err(),
        "truncated bytes are refused"
    );
}

#[test]
fn a_mesh_id_carries_the_transport_policy_for_every_list() {
    use super::lookup::Lookup;
    use super::transport::Transport::{Gossip, Multihop, Relay, Udp, WebRtc};
    let _guard = ::habilis_network_test_tracing::init();
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
        let id = Mesh::try_new(dummy_seed(), dummy_name(), config.clone())
            .unwrap()
            .to_string();
        let decoded: LockedMesh = id.parse().expect("the id decodes");
        assert_eq!(decoded.config(), &config, "{list:?}");
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
    assert_eq!(
        policy(&[]),
        policy(&[Udp, WebRtc, Multihop, Gossip]),
        "an empty transport list gives the default policy and the full list gives every path"
    );
    assert_ne!(
        policy(&[]),
        policy(&[Udp, WebRtc, Multihop]),
        "the full transport policy differs from the multihop-only one"
    );
}

#[test]
fn a_version_1_mesh_id_is_rejected_with_upgrade() {
    let _guard = ::habilis_network_test_tracing::init();
    let mesh = Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::loopback()).unwrap();
    let mut bytes = mesh.encode_bytes();
    bytes[0] = 1; // the format before the transport policy had its own byte
    let error = LockedMesh::decode_bytes(&bytes).expect_err("a version 1 id is refused");
    assert!(
        error.to_string().contains("upgrade"),
        "the error must tell the member what to do: {error}"
    );
}

#[test]
fn unknown_version_rejected() {
    let _guard = ::habilis_network_test_tracing::init();
    let mesh = Mesh::try_new(dummy_seed(), dummy_name(), MeshConfig::loopback()).unwrap();
    let mut bytes = mesh.encode_bytes();
    bytes[0] = 3; // an unknown version byte
    assert!(
        LockedMesh::decode_bytes(&bytes).is_err(),
        "an unknown version is refused"
    );
}

#[test]
fn mesh_id_round_trips_unicode_name() {
    let _guard = ::habilis_network_test_tracing::init();
    let name = MeshName::try_new("café-日本-🎉").unwrap();
    let mesh = Mesh::try_new(dummy_seed(), name.clone(), MeshConfig::loopback()).unwrap();
    let decoded: LockedMesh = mesh.to_string().parse().expect("decode failed");
    assert_eq!(
        decoded.name(),
        &name,
        "a unicode name survives a round trip"
    );
}

#[test]
fn mesh_id_round_trips_max_byte_name() {
    let _guard = ::habilis_network_test_tracing::init();
    // 32 four-byte scalars = 128 bytes = the most the 1-byte name
    // length field can carry; exercises the encode/decode upper edge.
    let name = MeshName::try_new(&"🎉".repeat(32)).unwrap();
    assert_eq!(name.as_bytes().len(), 128, "the largest name is 128 bytes");
    let mesh = Mesh::try_new(dummy_seed(), name.clone(), MeshConfig::public_preset()).unwrap();
    let decoded: LockedMesh = mesh.to_string().parse().expect("decode failed");
    assert_eq!(
        decoded.name(),
        &name,
        "the largest name survives a round trip"
    );
}

mod prop {
    use super::LockedMesh;
    use proptest::array::{uniform16, uniform32};
    use proptest::prelude::any;
    use proptest::strategy::Strategy;
    use proptest::{prop_assert, prop_assert_eq, prop_assert_ne, prop_assume, proptest};

    use super::{Mesh, MeshConfig, MeshName, SEED_LEN};
    use crate::crypto::Seed;

    fn arb_seed() -> impl Strategy<Value = [u8; SEED_LEN]> {
        uniform32(0u8..)
    }

    fn arb_name() -> impl Strategy<Value = MeshName> {
        "[a-z][a-z0-9_-]{0,31}".prop_map(|raw| MeshName::try_new(&raw).unwrap())
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
            let _guard = ::habilis_network_test_tracing::init();
            // Built as the id on the wire, since `Mesh::try_new` refuses a secret config.
            let wire = Seed::new(seed);
            let locked = LockedMesh { name: name.clone(), seed: wire, config: config.clone() };
            let decoded: LockedMesh = locked.to_string().parse().expect("decode failed");
            prop_assert_eq!(decoded.seed(), &wire);
            prop_assert_eq!(decoded.name(), &name);
            prop_assert_eq!(decoded.config(), &config);
                }

        #[test]
        fn prop_bare_base58(seed in arb_seed(), name in arb_name()) {
            let _guard = ::habilis_network_test_tracing::init();
            let id = Mesh::try_new(Seed::new(seed), name, MeshConfig::loopback()).unwrap().to_string();
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
            let _guard = ::habilis_network_test_tracing::init();
            let locked = LockedMesh { name, seed: Seed::new(seed), config };
            prop_assert_eq!(locked.to_string(), locked.to_string());
                }

        #[test]
        fn prop_distinct_seeds_distinct_ids(
            seed_a in arb_seed(),
            seed_b in arb_seed(),
            name in arb_name(),
        ) {
            let _guard = ::habilis_network_test_tracing::init();
            prop_assume!(seed_a != seed_b);
            let one = Mesh::try_new(Seed::new(seed_a), name.clone(), MeshConfig::loopback()).unwrap().to_string();
            let two = Mesh::try_new(Seed::new(seed_b), name, MeshConfig::loopback()).unwrap().to_string();
            prop_assert_ne!(one, two);
                }
    }
}
