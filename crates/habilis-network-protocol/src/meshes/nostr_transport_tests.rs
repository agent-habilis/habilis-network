use url::Url;

use super::{
    Lookup, LookupOpts, MeshConfig, NostrChoice, TRANSPORT_NOSTR, Transport, TransportPolicy,
};

/// The transport bits the decoder of `origin/main` knows: udp, webrtc, multihop, relay and
/// gossip. A byte with any other bit makes it return "unsupported transport policy bits ...
/// upgrade to a newer build", so this is the check that a build without the Nostr transport
/// refuses an id that has it.
const MAIN_KNOWN_TRANSPORT_BITS: u8 = 0b1_1111;

fn relays() -> Vec<Url> {
    let mut urls = Vec::new();
    for text in ["wss://a.example/", "wss://b.example/"] {
        urls.push(text.parse().expect("a valid relay URL"));
    }
    urls
}

/// A config that carries payload over a custom Nostr list, as the rule asks.
fn carrying() -> MeshConfig {
    MeshConfig {
        lookups: LookupOpts::loopback().nostr(NostrChoice::Custom(relays())),
        transport: TransportPolicy::default().nostr_transport(true),
        ..MeshConfig::loopback()
    }
}

#[test]
fn the_nostr_transport_bit_is_the_sixth_and_an_old_build_refuses_it() {
    let _guard = ::habilis_network_test_tracing::init();
    assert_eq!(TRANSPORT_NOSTR, 0b10_0000, "the bit after gossip");
    let config = carrying();
    let bytes = config.to_bytes();
    assert_eq!(
        bytes[1], 0b11_0111,
        "the transport byte is the default plus the Nostr bit"
    );
    assert_ne!(
        bytes[1] & !MAIN_KNOWN_TRANSPORT_BITS,
        0,
        "a build that predates the Nostr transport refuses the byte"
    );
    let decoded: MeshConfig = MeshConfig::try_from(bytes.as_slice()).expect("the config decodes");
    assert_eq!(decoded, config, "the Nostr transport survives a round trip");
    let without = MeshConfig {
        transport: TransportPolicy::default(),
        ..carrying()
    };
    assert_eq!(
        without.to_bytes()[1] & !MAIN_KNOWN_TRANSPORT_BITS,
        0,
        "a config without the Nostr transport keeps the bits an old build knows"
    );
}

#[test]
fn a_decoded_id_with_the_nostr_bit_and_no_custom_list_is_refused() {
    let _guard = ::habilis_network_test_tracing::init();
    for (name, nostr) in [
        ("disabled", NostrChoice::Disabled),
        ("pinned", NostrChoice::Pinned),
    ] {
        let config: MeshConfig = MeshConfig {
            lookups: LookupOpts::loopback().nostr(nostr),
            ..carrying()
        };
        let error: String = MeshConfig::try_from(config.to_bytes().as_slice())
            .expect_err("an id with the bit and no custom list is refused")
            .to_string();
        assert!(error.contains("transport `nostr` needs"), "{name}: {error}");
        assert!(
            config.validate().is_err(),
            "{name}: validate refuses the same config"
        );
    }
    assert!(
        carrying().validate().is_ok(),
        "the bit with a custom list is valid"
    );
}

#[test]
fn a_custom_list_with_no_transport_list_turns_the_nostr_transport_on() {
    let _guard = ::habilis_network_test_tracing::init();
    let config: MeshConfig =
        MeshConfig::resolve_with_nostr(&[Lookup::Nostr], None, Some(relays()), &[])
            .expect("a custom list resolves");
    assert!(
        config.transport.allows(Transport::Nostr),
        "an empty transport list and a custom list turn it on"
    );
    assert_eq!(
        config.to_bytes()[1] & TRANSPORT_NOSTR,
        TRANSPORT_NOSTR,
        "the id carries the bit"
    );
}

#[test]
fn a_named_transport_list_decides_the_nostr_transport_itself() {
    let _guard = ::habilis_network_test_tracing::init();
    let off: MeshConfig = MeshConfig::resolve_with_nostr(
        &[Lookup::Nostr],
        None,
        Some(relays()),
        &[Transport::Udp, Transport::WebRtc],
    )
    .expect("a list without nostr resolves");
    assert!(
        !off.transport.allows(Transport::Nostr),
        "a list that leaves nostr out turns it off"
    );
    let on: MeshConfig = MeshConfig::resolve_with_nostr(
        &[Lookup::Nostr],
        None,
        Some(relays()),
        &[Transport::Udp, Transport::Nostr],
    )
    .expect("a list with nostr resolves");
    assert!(
        on.transport.allows(Transport::Nostr),
        "a list that names nostr turns it on"
    );
    let error: String = MeshConfig::resolve_with_nostr(
        &[Lookup::Nostr],
        None,
        None,
        &[Transport::Udp, Transport::Nostr],
    )
    .expect_err("nostr with the pinned list is refused")
    .to_string();
    assert!(error.contains("transport `nostr` needs"), "{error}");
}

#[test]
fn no_custom_list_leaves_the_nostr_transport_off() {
    let _guard = ::habilis_network_test_tracing::init();
    let pinned: MeshConfig = MeshConfig::resolve_with_nostr(&[Lookup::Nostr], None, None, &[])
        .expect("the pinned list resolves");
    assert!(
        !pinned.transport.allows(Transport::Nostr),
        "the pinned relays carry no payload"
    );
    assert!(
        !TransportPolicy::default().allows(Transport::Nostr),
        "the default policy does not add it"
    );
    assert!(
        !TransportPolicy::try_from(&[] as &[Transport])
            .expect("an empty list is the default")
            .allows(Transport::Nostr),
        "an empty list does not add it at this layer"
    );
}

#[test]
fn the_nostr_transport_has_its_name() {
    let _guard = ::habilis_network_test_tracing::init();
    assert_eq!(Transport::Nostr.as_str(), "nostr", "the name on the wire");
    let parsed: Transport = "nostr".parse().expect("the name parses");
    assert_eq!(parsed, Transport::Nostr, "the name parses to the transport");
}
