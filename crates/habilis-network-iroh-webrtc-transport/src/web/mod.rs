//! The browser backend: the platform's own `RTCPeerConnection` via `web-sys`.
//!
//! Browser-only by construction — `web-sys` does not exist off the browser,
//! and its handles are `!Send`, so the driver here is a `spawn_local` pump
//! rather than a tokio task. The protocol types this shares with the host
//! backend live at the crate root, not here.
//!
//! Unlike the experiment this was ported from, the peer connection is built
//! with an `RtcConfiguration` carrying `iceServers`, so the browser's ICE agent
//! gathers server-reflexive candidates too. Without them a tab advertises host
//! candidates only and connects on one LAN.
//!
//! STUN only — relay candidates are deliberately unavailable, because
//! [`crate::accept_ice_uri`] refuses `turn:`. A peer that cannot pair directly
//! falls back to the iroh relay, which this project already runs.

mod jsep;
mod transport;

pub use jsep::{
    BrowserSession, IceServer, IceServers, PendingAnswer, PendingOffer, answer, log_signal_sdps,
    offer,
};
pub use transport::{
    AttachError, BrowserHubTransport, BrowserRtcTransport, BrowserSessionGuard,
    DataChannelCounters, SelectedPairStats, SessionCounters, SessionCounts,
};
