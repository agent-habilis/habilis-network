//! Shared machinery for the two browser test targets: a negotiated
//! browser↔browser [`Pair`] and a bulk protocol to drive over it.
//!
//! Included by `browser_loopback.rs` (the fast regression suite) and
//! `browser_matrix.rs` (the slow configuration sweep) with `mod
//! browser_harness;`. It lives in a subdirectory because cargo auto-discovers
//! test targets only from `tests/*.rs`, so a shared module cannot sit beside
//! them without becoming a third, empty target.
//!
//! ## Running either target
//!
//! ```sh
//! export CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang
//! export AR_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/llvm-ar
//! CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
//! CHROMEDRIVER=/path/to/chromedriver \
//! WASM_BINDGEN_TEST_WEBDRIVER_JSON=/path/to/webdriver.json \
//!   cargo test --release --target wasm32-unknown-unknown \
//!     -p habilis-network-iroh-webrtc-transport --features web,bench --test browser_loopback
//! ```
//!
//! `cargo task e2e` does all of that for you, over several browsers, and
//! drives the Chromium ones through CDP instead of a webdriver. Four things
//! about the invocation are load-bearing, and each fails in a way that does not
//! name its cause:
//!
//! - **Homebrew clang.** `ring` compiles its C core for wasm32 and Apple clang
//!   has no wasm backend, so without this the link silently leaves 44
//!   `ring_core_*` symbols as imports from a module called `env`. The browser
//!   then refuses the module with `Failed to resolve module specifier "env"`,
//!   and the runner reports only `Failed to detect test as having been run`.
//!   `examples/chat-webrtc/build-wasm.ts` says the same thing.
//! - **`--release`.** The debug build is ~137 MB of wasm and the browser gives
//!   up loading it, with the same unhelpful message.
//! - **A `chromedriver` matching the Chrome it drives** — only on the webdriver
//!   path. A mismatch fails session creation with a bare HTTP 404. The CDP path
//!   `cargo task e2e` uses for Chromium needs no driver at all.
//! - **Stop the browser hiding local IPs behind mDNS**
//!   (`--disable-features=WebRtcHideLocalIpsWithMdns` on Chrome; every engine
//!   has its own switch). Otherwise the only host candidate is a `.local`
//!   name, and a headless
//!   browser has no mDNS responder to resolve its own — ICE never leaves `new`
//!   and the channel never opens. Real tabs are unaffected; this is a property
//!   of the harness, not of the transport.
//!
//! ## What a pass here does and does not mean
//!
//! Two `BrowserHubTransport`s and two iroh endpoints **in one tab**, JSEP'd in
//! memory exactly as `../tests/loopback.rs` does natively. One tab rather than
//! two is not a shortcut: both ends run the same `web::` code either way, and
//! the pair is what is under test, not the page they live on.
//!
//! It is, though, the *easiest* case that exists — same process, loopback
//! candidates, no NAT — so a pass does not retire a report from two separate
//! browsers on a real network. That gap is why `browser_matrix.rs` exists.

mod pair;

pub(crate) use habilis_network_iroh_webrtc_transport::bench::{
    BENCH_ALPN, Bench, Direction, browser_endpoint, exchange, on_webrtc,
};
pub(crate) use pair::Pair;

/// A browser peer: WebRTC is its only data path, and no relay, so a run that
/// claims to be browser↔browser can be shown to be one.
/// `JsValue` is not an `Error`, so it cannot cross `?` on its own.
pub(crate) fn js_error(error: &wasm_bindgen::JsValue) -> anyhow::Error {
    anyhow::anyhow!("{error:?}")
}
