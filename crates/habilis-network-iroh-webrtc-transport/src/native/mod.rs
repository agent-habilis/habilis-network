//! The native backend: sans-io `str0m` driven by tokio.
//!
//! Host-only by construction — `str0m` and `tokio` do not build for `wasm32`.
//! The protocol types this shares with the browser backend live at the crate
//! root, not here.

mod driver;
mod endpoint;
mod jsep;
mod sender;
mod session;
pub mod stun;
mod transport;

pub use driver::NegotiatedSession;
pub use jsep::{PendingAnswer, PendingOffer, answer, answer_with, offer, offer_with};
pub use stun::IceConfig;
pub use transport::WebRtcTransport;
