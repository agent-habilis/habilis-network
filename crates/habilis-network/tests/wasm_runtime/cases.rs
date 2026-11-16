use std::time::Duration;

use habilis_network::protocol::{MeshId, Message, Nickname};
use habilis_network::util::{clock, unix_secs};
use n0_future::{task, time, time as n0future_time};
use wasm_bindgen_test::wasm_bindgen_test;

// Deliberately *not* `wasm_bindgen_test_configure!(run_in_browser)`: that needs
// a webdriver on the machine, which a CI box will not have, and the default
// Safari driver is killed on this host. Node exercises the same primitives —
// `performance.now()`, `Date.now()`, `setTimeout`, `globalThis.crypto` — so it
// catches the same regressions.
//
// What node does *not* cover is browser-only behaviour: `RTCPeerConnection`,
// the WebRTC transport, and iroh's relay path. Those are validated by hand
// against a real Chrome (see the mesh peer panel on the lab page); this file
// deliberately stays out of that territory and guards only the primitives.

/// `Instant::now()` — via the `web-time` façade rather than `std::time`.
#[wasm_bindgen_test]
fn monotonic_clock_runs() {
    let first = clock::Instant::now();
    let second = clock::Instant::now();
    // Monotonic, and readable at all. `Performance.now()` has sub-millisecond
    // resolution but is coarsened for privacy, so two adjacent reads may be
    // equal — assert ordering, never a strict increase.
    assert!(second >= first, "monotonic clock went backwards");
}

/// `SystemTime::now()`, through the wire-path helper that stamps every frame.
#[wasm_bindgen_test]
fn wall_clock_stamps_a_plausible_time() {
    let secs = unix_secs::UnixSecs::now().as_secs();
    // 2020-01-01. Guards against the "returns 0 on failure" path silently
    // becoming the normal case, which would put epoch timestamps on the wire.
    assert!(secs > 1_577_836_800, "implausible unix time: {secs}");
}

/// The timer driver: `n0_future::time`, not `tokio::time`.
#[wasm_bindgen_test]
async fn timers_fire() {
    let before = clock::Instant::now();
    n0future_time::sleep(Duration::from_millis(20)).await;
    assert!(
        clock::Instant::now() >= before,
        "clock did not advance across a sleep"
    );
}

/// Task spawning: `n0_future::task::spawn` is `spawn_local` here, and needs no
/// reactor. This is the exact primitive that panicked in a real browser.
#[wasm_bindgen_test]
async fn tasks_spawn() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // the spawned task and the test share the counter
    let counter = Arc::new(AtomicUsize::new(0));
    let inner = Arc::clone(&counter);
    task::spawn(async move {
        n0future_time::sleep(Duration::from_millis(5)).await;
        inner.store(7, Ordering::Relaxed);
    });
    // Yield long enough for the spawned task to be driven. No channel, so the
    // test depends on nothing beyond the two primitives under test.
    time::sleep(Duration::from_millis(60)).await;
    assert_eq!(counter.load(Ordering::Relaxed), 7, "spawned task never ran");
}

/// Author one signed-shaped frame end to end.
///
/// Covers more than the clock: `MessageId::random()` pulls from `getrandom`,
/// which needs both its `wasm_js` feature *and* the `getrandom_backend`
/// rustflag — a combination that fails at runtime, not at compile time, when
/// only one of the two is set.
#[wasm_bindgen_test]
fn a_message_can_be_authored() {
    let mesh =
        MeshId::try_new("2GQJSpKX5vEMq2owsG3v2ogLga3CESfHDQMoEKwLFuGHAgViR3vDstEekpHE3KNqALrk")
            .expect("a well-formed mesh id");
    let nick = Nickname::try_new("wasm-guard").expect("a well-formed nickname");
    let message = Message::new_joined(&mesh, &nick);
    assert!(
        message.timestamp.as_secs() > 1_577_836_800,
        "frame carries no real time"
    );
    assert!(!message.id.to_string().is_empty(), "frame carries no id");
}

/// A browser endpoint on a Nostr-only mesh: no relay, no IP, only the `WebRTC`
/// hub. It must bind. Its address is empty by design; the signed lane flag,
/// not the address, tells peers to reach it over a data channel.
#[wasm_bindgen_test]
async fn a_relayless_webrtc_endpoint_binds() {
    use habilis_network::iroh::SecretKey;
    use habilis_network::net::{TransportHandles, TransportOpts, build_endpoint};
    use habilis_network::protocol::LookupOpts;
    use habilis_network::protocol::meshes::NostrChoice;
    use habilis_network_iroh_webrtc_transport::WebRtcHandle;

    let key = SecretKey::generate();
    let hub = WebRtcHandle::hub(key.public());
    let lookups = LookupOpts::loopback().nostr(NostrChoice::Pinned);
    let mut transports = TransportHandles::default();
    transports.webrtc = Some(hub);
    transports.options = TransportOpts::default()
        .udp(false)
        .relay(false)
        .webrtc(true)
        .gossip(false);
    let endpoint = build_endpoint(&lookups, Some(key), None, Vec::new(), transports)
        .await
        .expect("a relay-less WebRTC endpoint binds");
    // Empty on purpose: this is why peers learn the lane from a signed flag.
    // An address here would mean a path the browser does not have.
    assert!(
        endpoint.addr().addrs.is_empty(),
        "a browser with no relay advertises no address"
    );
    endpoint.close().await;
}

/// A browser endpoint whose only transport is Nostr: no relay, no IP, no data channel. It must
/// bind, and a mesh that lists Nostr must count it as a way to carry payload without UDP.
#[wasm_bindgen_test]
async fn a_nostr_only_browser_endpoint_binds_and_carries() {
    use habilis_network::iroh::SecretKey;
    use habilis_network::net::{TransportHandles, TransportOpts, build_endpoint};
    use habilis_network::protocol::meshes::NostrChoice;
    use habilis_network::protocol::{LookupOpts, TransportPolicy};
    use habilis_network_iroh_nostr_transport::NostrTransport;

    let key = SecretKey::generate();
    let custom = "wss://relay.example".parse().expect("a relay URL");
    let lookups = LookupOpts::loopback().nostr(NostrChoice::Custom(vec![custom]));
    let mut transports = TransportHandles::default();
    transports.nostr = Some(NostrTransport::new(key.public()));
    transports.options = TransportOpts::default()
        .udp(false)
        .relay(false)
        .webrtc(false)
        .gossip(false)
        .nostr(true);
    let endpoint = build_endpoint(&lookups, Some(key), None, Vec::new(), transports)
        .await
        .expect("a Nostr-only endpoint binds");
    endpoint.close().await;

    let policy = TransportPolicy::default().nostr_transport(true);
    let opts = TransportOpts::default()
        .udp(false)
        .webrtc(false)
        .within(&policy);
    assert!(
        opts.carry_without_udp(&policy),
        "a browser carries payload over Nostr when the mesh lists it"
    );
}

/// A tab has no UDP socket, whatever the mesh's list allows. The paths a node
/// runs come from `within`, so it must say so there: code that reads
/// `TransportOpts::udp` then needs no browser special case.
#[wasm_bindgen_test]
fn a_tab_runs_no_udp_path() {
    use habilis_network::net::TransportOpts;
    use habilis_network::protocol::TransportPolicy;
    let paths = TransportOpts::default().within(&TransportPolicy::default());
    assert!(!paths.udp, "a tab reads as having UDP: {paths:?}");
    assert!(paths.webrtc, "the data channel stays");
}
