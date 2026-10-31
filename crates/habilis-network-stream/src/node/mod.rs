//! A stream node: one endpoint that produces streams, opens them, or both.

mod stream_node;
mod stream_opts;

pub use stream_node::StreamNode;
pub use stream_opts::StreamOpts;

use std::time::Duration;

/// How long `create` waits for the endpoint to reach its home relay, so the
/// hash it mints carries it. Best effort: it never blocks past this.
pub(super) const ONLINE_WAIT: Duration = Duration::from_secs(5);

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
