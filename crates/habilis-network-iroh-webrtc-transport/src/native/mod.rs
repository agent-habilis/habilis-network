//! The native backend: sans-io `str0m` driven by tokio.
//!
//! Host-only by construction — `str0m` and `tokio` do not build for `wasm32`.
//! The protocol types this shares with the browser backend live at the crate
//! root, not here.

mod channel_ready_target;
mod driver;
mod ice_config;
mod inbound_packet;
mod jsep_error;
mod negotiated_session;
mod negotiating;
mod note_dropped;
mod pending_answer;
mod pending_offer;
mod session_handle;
mod session_registry;
pub mod stun;
mod web_rtc_endpoint;
mod web_rtc_sender;
mod web_rtc_transport;

pub use ice_config::IceConfig;
pub use jsep_error::JsepError;
pub use negotiated_session::NegotiatedSession;
pub use pending_answer::{PendingAnswer, answer, answer_with};
pub use pending_offer::{PendingOffer, offer, offer_with};
pub use web_rtc_transport::WebRtcTransport;
