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

mod browser_session;
mod ice_server;
mod ice_servers;
mod jsep;
mod open_peer_connection;
mod pending_answer;
mod pending_offer;
mod pre_attach_backlog;
mod transport;

pub use browser_session::BrowserSession;
pub use ice_server::IceServer;
pub use ice_servers::IceServers;
pub use jsep::{answer, log_signal_sdps, offer};
pub use pending_answer::PendingAnswer;
pub use pending_offer::PendingOffer;
pub use transport::{
    BrowserHubTransport, BrowserRtcTransport, BrowserSessionGuard, DataChannelCounters,
    SelectedPairStats, SessionCounters, SessionCounts,
};
