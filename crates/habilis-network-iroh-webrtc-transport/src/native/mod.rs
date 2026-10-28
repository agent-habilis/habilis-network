//! The native backend: sans-io `str0m` driven by tokio.
//!
//! Host-only by construction — `str0m` and `tokio` do not build for `wasm32`.
//! The protocol types this shares with the browser backend live at the crate
//! root, not here.

mod driver;
mod inbound_packet;
mod jsep;
mod note_dropped;
mod session_handle;
mod session_registry;
pub mod stun;
mod web_rtc_endpoint;
mod web_rtc_sender;
mod web_rtc_transport;

pub use driver::NegotiatedSession;
pub use jsep::{JsepError, PendingAnswer, PendingOffer, answer, answer_with, offer, offer_with};
pub use stun::IceConfig;
pub use web_rtc_transport::WebRtcTransport;
