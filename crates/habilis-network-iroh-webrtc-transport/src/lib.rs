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

mod addr;
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
mod liveness;
#[cfg(any(feature = "native", feature = "web"))]
mod selector;
#[cfg(feature = "test-hooks")]
pub use selector::{block_ip_paths, block_ip_to};
mod signaling;

pub use addr::{WEBRTC_TRANSPORT_ID, custom_addr, parse_custom_addr};
pub use ice_uri::accept_ice_uri;
pub use signaling::{MAX_ENVELOPE_BYTES, SIGNAL_VERSION, SignalEnvelope};

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

/// Label of the single data channel each session carries. Both ends must use
/// the same string or the channel never opens.
pub const DATA_CHANNEL_LABEL: &str = "iroh";

/// Bound on queued outbound datagrams per session. Overflow drops the datagram
/// (QUIC above retransmits); blocking would stall iroh's shared send loop
/// across every transport.
#[cfg(any(feature = "native", feature = "web"))]
pub(crate) const OUT_QUEUE: usize = 256;

/// Bound on inbound datagrams fanned in from all sessions toward QUIC.
#[cfg(any(feature = "native", feature = "web"))]
pub(crate) const IN_QUEUE: usize = 512;

/// The default STUN servers, as `host:port`. Both backends derive their own
/// spelling from this — the native gather uses these verbatim, the browser
/// prefixes each with `stun:`.
///
/// Two servers, deliberately, and from two *operators* — that is the redundancy
/// that counts, so one being down is not an outage. These only ever learn our
/// public ip:port; no traffic flows through them.
///
/// `stun1`, not the bare `stun.l.google.com`: blocklists name the latter
/// explicitly and null-route it to 0.0.0.0, which is worse than NXDOMAIN — the
/// agent waits out a timeout on an unroutable address instead of failing fast.
/// Measured behind an `AdGuard` resolver: `stun.l.google.com` → 0.0.0.0,
/// `stun1..4.l.google.com` → 74.125.250.129. `stun2/3/4` share one address with
/// `stun1`, so they would be redundancy in name only, and every extra server
/// costs a srflx candidate per local interface.
pub const DEFAULT_STUN_HOSTS: [&str; 2] = ["stun1.l.google.com:19302", "stun.cloudflare.com:3478"];

/// Whether a drop counter has reached a value worth logging: the first one,
/// then every 256th.
///
/// Both backends are lossy by design, so a congested lane is indistinguishable
/// from a broken one unless it says something — but saying it per datagram
/// would itself be the problem. `total` is the counter *after* the increment.
#[cfg(any(feature = "native", feature = "web"))]
pub(crate) fn should_log_drop(total: u64) -> bool {
    total == 1 || total.is_multiple_of(256)
}

#[cfg(all(feature = "bench", any(feature = "native", feature = "web")))]
pub mod bench;

#[cfg(feature = "native")]
mod native;

#[cfg(feature = "native")]
pub use native::{
    IceConfig, NegotiatedSession, PendingAnswer, PendingOffer, WebRtcTransport, answer,
    answer_with, offer, offer_with, stun,
};

#[cfg(feature = "web")]
mod web;

#[cfg(feature = "web")]
pub use web::{
    AttachError, BrowserHubTransport, BrowserRtcTransport, BrowserSession, BrowserSessionGuard,
    DataChannelCounters, IceServer, IceServers, PendingAnswer as BrowserPendingAnswer,
    PendingOffer as BrowserPendingOffer, SelectedPairStats, SessionCounters, SessionCounts,
    answer as browser_answer, log_signal_sdps, offer as browser_offer,
};

/// A registered `WebRTC` transport, ready to hand to an iroh endpoint builder.
///
/// The same name on both targets so a consumer's wiring code is written once:
/// which backend it wraps is decided by the feature, not by the caller. Cheap
/// to clone — it is a handle, and every clone shares one session registry.
#[cfg(any(feature = "native", feature = "web"))]
#[derive(Debug, Clone)]
pub struct WebRtcHandle {
    #[cfg(feature = "native")]
    inner: std::sync::Arc<WebRtcTransport>,
    #[cfg(all(feature = "web", not(feature = "native")))]
    inner: std::sync::Arc<BrowserHubTransport>,
}

#[cfg(feature = "native")]
impl WebRtcHandle {
    /// Wrap a host transport.
    #[must_use]
    pub fn new(transport: std::sync::Arc<WebRtcTransport>) -> Self {
        Self { inner: transport }
    }

    /// The transport to register with `Builder::add_custom_transport`.
    ///
    /// Registration is deliberately additive rather than a `Preset`: a preset
    /// would make `WebRTC` the endpoint's *only* transport, which is right for a
    /// browser and wrong for a native peer that should still prefer iroh's own
    /// hole-punched paths.
    #[must_use]
    pub fn transport(&self) -> std::sync::Arc<WebRtcTransport> {
        std::sync::Arc::clone(&self.inner)
    }

    /// The path selector that keeps the relay a rendezvous, for
    /// `Builder::path_selector`. Install it wherever [`Self::transport`] is
    /// registered — see [`crate::selector`] for why registering the transport
    /// alone is not enough.
    #[must_use]
    pub fn path_selector(&self) -> std::sync::Arc<dyn iroh::endpoint::transports::PathSelector> {
        std::sync::Arc::new(selector::WebRtcPreferred::new(self.inner.local_id()))
    }

    /// Attach a negotiated session for `remote`.
    ///
    /// # Errors
    /// The registry rejects the session (already attached).
    pub fn attach(
        &self,
        remote: iroh_base::EndpointId,
        session: NegotiatedSession,
    ) -> anyhow::Result<()> {
        self.inner.attach(remote, session)
    }

    /// Whether a usable session for `remote` exists.
    #[must_use]
    pub fn has_session(&self, remote: &iroh_base::EndpointId) -> bool {
        self.inner.has_session(remote)
    }

    /// How many usable sessions this handle's registry holds.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.inner.session_count()
    }

    /// Tear down the session for `remote`, if any.
    #[must_use]
    pub fn detach(&self, remote: &iroh_base::EndpointId) -> bool {
        self.inner.detach(remote)
    }

    /// Tests only: abort every session without a close. See
    /// `WebRtcTransport::abort_sessions`.
    #[cfg(feature = "test-hooks")]
    #[must_use]
    pub fn abort_sessions(&self) -> usize {
        self.inner.abort_sessions()
    }
}

#[cfg(all(feature = "web", not(feature = "native")))]
impl WebRtcHandle {
    /// Wrap a browser hub transport (consumer or producer).
    #[must_use]
    pub fn new(transport: std::sync::Arc<BrowserHubTransport>) -> Self {
        Self { inner: transport }
    }

    /// Empty hub for `local`, ready to register and later [`Self::attach`].
    #[must_use]
    pub fn hub(local: iroh_base::EndpointId) -> Self {
        Self::new(BrowserHubTransport::new(local))
    }

    /// The transport to register with `Builder::add_custom_transport`.
    #[must_use]
    pub fn transport(&self) -> std::sync::Arc<BrowserHubTransport> {
        std::sync::Arc::clone(&self.inner)
    }

    /// The path selector that keeps the relay a rendezvous, for
    /// `Builder::path_selector`. Install it wherever [`Self::transport`] is
    /// registered — see [`crate::selector`] for why registering the transport
    /// alone is not enough.
    #[must_use]
    pub fn path_selector(&self) -> std::sync::Arc<dyn iroh::endpoint::transports::PathSelector> {
        std::sync::Arc::new(selector::WebRtcPreferred::new(self.inner.local_id()))
    }

    /// Attach a negotiated browser session for `remote`.
    ///
    /// Prefer calling [`BrowserPendingOffer::complete`] /
    /// [`BrowserPendingAnswer::complete`], which attach themselves; this is
    /// the escape hatch when the session pieces are already in hand.
    ///
    /// # Errors
    /// The peer's slot is already claimed. The handles passed in are closed
    /// before returning.
    pub fn attach_parts(
        &self,
        remote: iroh_base::EndpointId,
        peer_connection: web_sys::RtcPeerConnection,
        data_channel: web_sys::RtcDataChannel,
        callbacks: Vec<wasm_bindgen::JsValue>,
    ) -> Result<BrowserSessionGuard, AttachError> {
        self.inner
            .attach(remote, peer_connection, data_channel, callbacks)
    }

    /// Whether a usable session for `remote` exists.
    #[must_use]
    pub fn has_session(&self, remote: &iroh_base::EndpointId) -> bool {
        self.inner.has_session(remote)
    }

    /// How many usable sessions this handle's registry holds.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.inner.session_count()
    }

    /// Endpoint ids of every live session.
    #[must_use]
    pub fn live_peer_ids(&self) -> Vec<iroh_base::EndpointId> {
        self.inner.live_peer_ids()
    }

    /// `RTCPeerConnection.connectionState` of a live session, if any.
    #[must_use]
    pub fn session_state(
        &self,
        remote: &iroh_base::EndpointId,
    ) -> Option<web_sys::RtcPeerConnectionState> {
        self.inner.session_state(remote)
    }

    /// The peer connection behind a live session, if any.
    #[must_use]
    pub fn peer_connection(
        &self,
        remote: &iroh_base::EndpointId,
    ) -> Option<web_sys::RtcPeerConnection> {
        self.inner.peer_connection(remote)
    }

    /// Selected ICE remote candidate for a live session, if any.
    pub async fn selected_remote_candidate(
        &self,
        remote: &iroh_base::EndpointId,
    ) -> Option<(String, String)> {
        self.inner.selected_remote_candidate(remote).await
    }

    /// Bytes and messages this session's data channel has carried.
    ///
    /// The measure to use when the question is "did our traffic move?" — see
    /// [`BrowserHubTransport::data_channel_bytes`] for why the ICE candidate
    /// pair is not a dependable stand-in for it.
    pub async fn data_channel_bytes(
        &self,
        remote: &iroh_base::EndpointId,
    ) -> Option<DataChannelCounters> {
        self.inner.data_channel_bytes(remote).await
    }

    /// What this session's outbound lane did with the datagrams QUIC handed it
    /// — sent, and dropped by each of the three routes that can drop one.
    ///
    /// The lane is lossy by design and silent by consequence: `poll_send`
    /// cannot park without stalling every transport, so it discards and
    /// reports success. A consumer diagnosing a stalled transfer — or deciding
    /// whether to demote a peer to the relay — otherwise has nothing to go on
    /// but the transfer not finishing. See [`SessionCounters`].
    #[must_use]
    pub fn session_counters(&self, remote: &iroh_base::EndpointId) -> Option<SessionCounts> {
        self.inner.session_counters(remote)
    }

    /// Tear down the session for `remote`, if any.
    #[must_use]
    pub fn detach(&self, remote: &iroh_base::EndpointId) -> bool {
        self.inner.detach(remote)
    }
}
