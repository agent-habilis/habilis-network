//! Developer-log plumbing: the tracing directive filter ([`log_filter`]),
//! the deferred per-member file sink ([`sink`]), and the per-message
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

/// Default tracing directives when `RUST_LOG` is unset (`RUST_LOG`
/// wins). Quiets benign `noq_proto::connection`; release also drops the
/// env-dependent `mainline::rpc` DHT-bootstrap ERROR; the `messages`
/// target is pinned on so it lands at any base level. See AGENTS.md.
///
/// Our own operational subsystems (gossip/lookup/beacon/lifecycle/directory)
/// are pinned to `info` in BOTH profiles so the always-on log file
/// carries the connectivity/lifecycle story even in a release build
/// (whose `error` base would otherwise drop every diagnostic) — the
/// same rationale as the `messages=info` pin. tracing writes only to
/// the file sink; `--output json` (stdout) is a separate path, so this
/// never affects the event stream.
#[cfg(feature = "host")]
#[must_use]
pub fn log_filter(consumer_pins: &str) -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;
    const SUBSYSTEMS: &str = "habilis_network::gossip=info,\
        habilis_network::lookup=info,\
        habilis_network::beacon=info,\
        habilis_network::lifecycle=info,\
        habilis_network::directory=info,\
        habilis_network::messages=info";
    EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let base = if cfg!(debug_assertions) {
            "info,noq_proto::connection=off"
        } else {
            "error,noq_proto::connection=off,mainline::rpc=off"
        };
        let mut directives = format!("{base},{SUBSYSTEMS}");
        if !consumer_pins.is_empty() {
            directives.push(',');
            directives.push_str(consumer_pins);
        }
        EnvFilter::new(directives)
    })
}
