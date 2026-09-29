//! The wasm runtime guard: the things that compile fine and then panic.
//!
//! ```sh
//! CC=$(brew --prefix llvm)/bin/clang \
//! CC_wasm32_unknown_unknown=$(brew --prefix llvm)/bin/clang \
//!   cargo test -p fofoca --no-default-features \
//!     --target wasm32-unknown-unknown
//! ```
//!
//! Every wasm breakage this crate has had was invisible to `cargo check`:
//!
//! - `std::time::Instant::now()` and `SystemTime::now()` do not fail to
//!   compile on `wasm32-unknown-unknown`. They compile, and then `panic!`
//!   ("time not implemented on this platform") — and `unix_secs` stamps every
//!   `Message`, so a browser peer could not author a single frame.
//! - `tokio::time` compiles and panics the same way: there is no timer driver.
//! - `tokio::spawn` compiles and panics with "there is no reactor running".
//!   This one shipped: the browser mesh peer died on it at `setup.rs:115`
//!   *after* the wasm CI check was green.
//!
//! So this file's job is not to test logic. It is to **execute** the handful of
//! primitives whose failure mode is a runtime panic, so the next one is caught
//! by CI rather than by a blank browser tab. Keep it cheap and keep it boring;
//! its value is that it runs at all.

#![cfg(target_arch = "wasm32")]

use std::time::Duration;

use fofoca::protocol::{MeshId, Message, Nickname};
use fofoca::util::clock;
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
    let secs = clock::unix_secs();
    // 2020-01-01. Guards against the "returns 0 on failure" path silently
    // becoming the normal case, which would put epoch timestamps on the wire.
    assert!(secs > 1_577_836_800, "implausible unix time: {secs}");
}

/// The timer driver: `n0_future::time`, not `tokio::time`.
#[wasm_bindgen_test]
async fn timers_fire() {
    let before = clock::Instant::now();
    n0_future::time::sleep(Duration::from_millis(20)).await;
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

    let counter = Arc::new(AtomicUsize::new(0));
    let inner = Arc::clone(&counter);
    n0_future::task::spawn(async move {
        n0_future::time::sleep(Duration::from_millis(5)).await;
        inner.store(7, Ordering::Relaxed);
    });
    // Yield long enough for the spawned task to be driven. No channel, so the
    // test depends on nothing beyond the two primitives under test.
    n0_future::time::sleep(Duration::from_millis(60)).await;
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
    let mesh = MeshId::new("2GQJSpKX5vEMq2owsG3v2ogLga3CESfHDQMoEKwLFuGHAgViR3vDstEekpHE3KNqALrk")
        .expect("a well-formed mesh id");
    let nick = Nickname::new("wasm-guard").expect("a well-formed nickname");
    let message = Message::new_joined(&mesh, &nick);
    assert!(
        message.timestamp > 1_577_836_800,
        "frame carries no real time"
    );
    assert!(!message.id.to_string().is_empty(), "frame carries no id");
}

/// A tab has no UDP socket, whatever the mesh's list allows. The paths a node
/// runs come from `within`, so it must say so there: code that reads
/// `TransportOpts::udp` then needs no browser special case.
#[wasm_bindgen_test]
fn a_tab_runs_no_udp_path() {
    use fofoca::net::TransportOpts;
    use fofoca::protocol::TransportPolicy;
    let paths = TransportOpts::default().within(&TransportPolicy::default());
    assert!(!paths.udp, "a tab reads as having UDP: {paths:?}");
    assert!(paths.webrtc, "the data channel stays");
}
