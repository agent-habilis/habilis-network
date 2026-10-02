//! The crate's clock: the portable [`Instant`] / [`SystemTime`] every other
//! module imports, and the unix-epoch timestamps the wire protocol and state
//! file expect.
//!
//! Load-bearing on wasm, not a nicety. On `wasm32-unknown-unknown` the `std`
//! constructors route to `sys/time/unsupported.rs` and **panic**
//! (`"time not implemented on this platform"`) — and [`unix_secs`] stamps every
//! `Message`, so a browser peer could not author a single frame. A panic is
//! invisible to `cargo check`, which is why the wasm CI leg is green today
//! while nothing has ever actually run there.
//!
//! `web-time` is a drop-in rather than a shim: off wasm32 it is
//! `pub use std::time::*` and pulls in no dependencies, so on the host these
//! *are* the std types and nothing about their behaviour changes. Only a
//! browser gets the `Performance.now()` / `Date.now()` implementation. That is
//! why this is a re-export instead of a hand-rolled `cfg` façade — and why
//! `Duration`, which never reads a clock, keeps coming straight from `std`.
//!
//! Import the two clock types from here, never from `std::time`. Note the
//! browser caveat on [`Instant`]: outside Windows it stops ticking while the
//! tab is asleep.

pub use web_time::{Instant, SystemTime};

use std::time::Duration;

use web_time::UNIX_EPOCH;

/// Seconds since the Unix epoch, or 0 if the system clock is set
/// before 1970 or beyond the year 2554 (i64 fits >290 billion
/// seconds, far beyond any real system clock).
#[must_use]
pub fn unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since_epoch| i64::try_from(since_epoch.as_secs()).ok())
        .unwrap_or(0)
}

/// Nanoseconds since the Unix epoch. Returns 0 on pre-1970 clocks
/// or after the year 2262 (i64 nanosecond overflow). Only used by
/// tests today (unique tmp-file suffixes); gated on `test-fixtures`
/// to avoid a dead-code lint in release builds.
#[cfg(any(test, feature = "test-fixtures"))]
#[must_use]
pub fn unix_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since_epoch| i64::try_from(since_epoch.as_nanos()).ok())
        .unwrap_or(0)
}

/// A `Duration` in whole milliseconds, saturating instead of wrapping.
///
/// Every tracing field that reports an elapsed time wants this, and each site
/// was spelling out the same `u64::try_from(d.as_millis()).unwrap_or(u64::MAX)`.
/// The saturation is unreachable in practice — `u128` milliseconds only exceed
/// `u64` past ~584 million years — but a silent wrap in a log field is worse
/// than a clamp.
#[must_use]
pub fn millis_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
