//! Developer-log plumbing: the tracing directive filter ([`log_filter`]),
//! the deferred per-member file sink (`sink`), and the per-message
//! [`messages`] logger on the `habilis_network::messages` target.
//! `--output json` (stdout) is a separate path and is unaffected by
//! anything here.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "host")] {
//! let filter = habilis_network_logging::log_filter("");
//! # let _filter = filter;
//! # }
//! ```

#![cfg_attr(target_family = "wasm", deny(clippy::disallowed_methods))]

#[cfg(feature = "host")]
mod log_sink;
pub mod messages;

#[cfg(feature = "host")]
pub use log_sink::LogSink;
#[cfg(feature = "host")]
pub use log_sink::{attach, flush_pending_to_stderr, install};

#[cfg(feature = "host")]
mod filter;
#[cfg(feature = "host")]
pub use filter::log_filter;
