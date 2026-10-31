//! QUIC datagrams over a `WebRTC` data channel, as an iroh custom transport —
//! on the host and in the browser.
//!
//! One data channel per remote peer, one QUIC datagram per binary SCTP
//! message, no extra framing. The channel is negotiated **unreliable and
//! unordered** (`maxRetransmits: 0`): QUIC above it owns loss recovery and
//! congestion control, so reliable ordered SCTP underneath would stack a
//! second retransmission loop on every loss. Structure follows
//! [habilis-network-iroh-multihop-transport](https://github.com/agent-habilis/habilis-network/tree/main/crates/habilis-network-iroh-multihop-transport)
//! and the upstream
//! [iroh-tor-transport](https://github.com/n0-computer/iroh-tor-transport):
//! a transport factory, a per-endpoint receiver, a registry-backed sender, and
//! a per-session driver pumping the connection.
//!
//! # Why one crate with two backends
//!
//! `str0m` and `tokio` do not target `wasm32`; `web-sys` does not exist off the
//! browser. The *drivers* therefore cannot be one implementation. But the
//! protocol — the JSEP envelope, the transport id, the address convention — is
//! identical, and it is exactly the part that must not drift: two peers that
//! disagree about the transport id or the envelope shape fail to connect with
//! no useful error.
//!
//! So the protocol half lives at the crate root, always compiled and free of
//! host- and browser-only dependencies, and each backend sits behind a feature:
//!
//! - `native` — sans-io [`str0m`] driven by tokio, plus STUN gathering ([`stun`]).
//! - `web` — the browser's own `RTCPeerConnection` through `web-sys`.
//!
//! Neither is on by default; a consumer enables the one matching its target.
//!
//! # NAT traversal
//!
//! `str0m` gathers no candidates — it owns no sockets, so discovery is the
//! caller's job. Skipping it (as the experiment this was ported from did) means
//! advertising a single host candidate on a private interface, which connects
//! on one LAN and nowhere else. [`stun`] closes that on the host side; the
//! browser's ICE agent does it natively once given `iceServers`.
//!
//! The iroh relay carries the SDP exchange. **TURN is refused** — see
//! [`accept_ice_uri`]: a consumer that cannot pair directly falls back to that
//! same iroh relay rather than to a second relay at the ICE layer. Neither
//! backend has a TURN client, and neither should grow one.

#![cfg_attr(target_family = "wasm", deny(clippy::disallowed_methods))]

mod address;
mod consts;
mod drop_policy;
mod ice_uri;
// The session table both backends use. The host backend had a verbatim copy in
// `native::session`; that copy is gone and `SessionRegistry` is now an alias
// for `Registry<SessionHandle>`.
//
// Compiled in every configuration even so, because this is the only place that
// logic is provable *cheaply*: the browser backend needs a real browser and a
// webdriver to test (there is no `RTCPeerConnection` in node, and CI has no
// webdriver), so its decisions were pulled out into a payload-generic type that
// `cargo test` reaches whatever features are on.
//
// "Cheaply", not "at all", as this used to say: `tests/browser_loopback.rs`
// does drive the browser backend end to end against Chrome, and it is where a
// question about the *transport* — as opposed to this registry's bookkeeping —
// gets answered. It is a local run, not a CI one.
// Still gated on `web` rather than on "no backend": both backends use the type
// now, but `live_ids`, `clear` and `SessionGuard::remote` are reached only from
// the browser one.
#[cfg_attr(
    not(feature = "web"),
    expect(dead_code, reason = "the browser-only methods; its tests still run")
)]
mod registry;
// Same shape as `registry`: DOM-free so its tests run on the host, reached
// only from the browser backend.
#[cfg_attr(
    all(not(feature = "web"), not(test)),
    expect(dead_code, reason = "the browser hub's watchdog; its tests still run")
)]
mod connection_phase;
#[cfg_attr(
    all(not(feature = "web"), not(test)),
    expect(dead_code, reason = "the browser hub's watchdog; its tests still run")
)]
mod verdict;
#[cfg(any(feature = "native", feature = "web"))]
mod web_rtc_preferred;
#[cfg(feature = "test-hooks")]
pub use habilis_network_iroh_transport_util::{Rung, expected_rung};
#[cfg(feature = "test-hooks")]
pub use web_rtc_preferred::{block_ip_paths, block_ip_to, block_rung, block_rung_to};
mod signal_envelope;
mod signal_error;

pub use address::{WEBRTC_TRANSPORT_ID, custom_addr, parse_custom_addr};
pub use consts::{DATA_CHANNEL_LABEL, DEFAULT_STUN_HOSTS};
#[cfg(any(feature = "native", feature = "web"))]
pub(crate) use consts::{IN_QUEUE, OUT_QUEUE};
#[cfg(any(feature = "native", feature = "web"))]
pub(crate) use drop_policy::{drops_are_sustained, should_log_drop};
pub use ice_uri::accept_ice_uri;
pub use signal_envelope::{MAX_ENVELOPE_BYTES, SIGNAL_VERSION, SignalEnvelope};
pub use signal_error::SignalError;

/// The iroh this crate is built against. **Take it from here, never as your own
/// dependency.**
///
/// The transport implements traits from a fork pin (`unstable-custom-transports`
/// is not on crates.io yet). A consumer that names `iroh` itself resolves a
/// second copy, and the `CustomTransport` impls below then stop satisfying the
/// trait iroh hands back — an E0308 whose message points nowhere near the
/// manifest at fault. Re-exporting is what lets a consumer carry no version, no
/// git rev and no `[patch.crates-io]`; see the workspace `Cargo.toml` for the
/// rule this preserves.
///
/// Only present when a backend is on: `iroh` is an optional dependency, and the
/// always-compiled protocol half deliberately reaches no further than
/// [`iroh_base`].
#[cfg(any(feature = "native", feature = "web"))]
pub use iroh;
/// The dependency-light half — keys, endpoint addresses, relay URLs, no QUIC or
/// TLS. Always available, so a wasm-clean wire crate can name an
/// [`iroh_base::EndpointAddr`] without pulling in a network stack. Same
/// take-it-from-here rule as [`iroh`].
pub use iroh_base;

#[cfg(all(feature = "bench", any(feature = "native", feature = "web")))]
pub mod bench;
#[cfg(all(feature = "bench", any(feature = "native", feature = "web")))]
mod bench_error;
#[cfg(all(feature = "bench", any(feature = "native", feature = "web")))]
pub use bench_error::BenchError;

#[cfg(any(feature = "native", feature = "web"))]
mod attach_error;
#[cfg(any(feature = "native", feature = "web"))]
pub use attach_error::AttachError;

#[cfg(feature = "native")]
mod native;

#[cfg(feature = "native")]
pub use native::{
    IceConfig, JsepError, NegotiatedSession, PendingAnswer, PendingOffer, WebRtcTransport, answer,
    answer_with, offer, offer_with, stun,
};

#[cfg(feature = "web")]
mod web;

#[cfg(feature = "web")]
pub use web::{
    BrowserHubTransport, BrowserRtcTransport, BrowserSession, BrowserSessionGuard,
    DataChannelCounters, IceServer, IceServers, PendingAnswer as BrowserPendingAnswer,
    PendingOffer as BrowserPendingOffer, SelectedPairStats, SessionCounters, SessionCounts,
    answer as browser_answer, log_signal_sdps, offer as browser_offer,
};

#[cfg(any(feature = "native", feature = "web"))]
mod web_rtc_handle;
#[cfg(any(feature = "native", feature = "web"))]
pub use web_rtc_handle::WebRtcHandle;
