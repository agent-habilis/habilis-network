//! Developer-log plumbing: the tracing directive filter ([`log_filter`]),
//! the deferred per-member file sink (`sink`), and the per-message
//! [`messages`] logger on the `habilis_network::messages` target.
//! `--output json` (stdout) is a separate path and is unaffected by
//! anything here.

pub mod messages;
#[cfg(feature = "host")]
mod sink;

#[cfg(feature = "host")]
pub use sink::LogSink;
#[cfg(feature = "host")]
pub use sink::{attach, flush_pending_to_stderr, install};

#[cfg(feature = "host")]
mod filter;
#[cfg(feature = "host")]
pub use filter::log_filter;
