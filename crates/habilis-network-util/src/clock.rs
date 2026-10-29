//! The crate's clock: the portable [`Instant`] / [`SystemTime`] every other
//! module imports, and the unix-epoch timestamps the wire protocol and state
//! file expect.
//!
//! Load-bearing on wasm, not a nicety. On `wasm32-unknown-unknown` the `std`
//! constructors route to `sys/time/unsupported.rs` and **panic**
//! (`"time not implemented on this platform"`) — and [`UnixSecs::now`](crate::unix_secs::UnixSecs::now) stamps every
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

#[cfg(any(test, feature = "test-fixtures"))]
use web_time::UNIX_EPOCH;

/// Nanoseconds since the Unix epoch. Returns 0 on pre-1970 clocks
/// or after the year 2262 (i64 nanosecond overflow). Only used by
/// tests today (unique tmp-file suffixes); gated on `test-fixtures`
/// to avoid a dead-code lint in release builds.
#[cfg(any(test, feature = "test-fixtures"))]
#[must_use]
pub fn unix_nanos() -> i64 {
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).ok();
    since_epoch
        .and_then(|elapsed| i64::try_from(elapsed.as_nanos()).ok())
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
pub const fn millis_saturating(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_mul(1000)
        .saturating_add(duration.subsec_millis() as u64)
}

#[cfg(test)]
mod millis_saturating_tests {
    use habilis_network_test_tracing::test;
    use std::time::Duration;

    const ONE_SECOND: u64 = super::millis_saturating(Duration::from_secs(1));

    #[test]
    fn it_counts_the_whole_seconds_and_the_subsecond_part() {
        assert_eq!(ONE_SECOND, 1000, "one second is a thousand milliseconds");
        assert_eq!(
            super::millis_saturating(Duration::ZERO),
            0,
            "a zero duration is zero milliseconds"
        );
        assert_eq!(
            super::millis_saturating(Duration::from_millis(1500)),
            1500,
            "a second and a half is 1500 milliseconds"
        );
        // A part of a millisecond is cut, as `Duration::as_millis` cuts it.
        assert_eq!(
            super::millis_saturating(Duration::new(2, 999_999_999)),
            2999,
            "a sub-millisecond part is truncated"
        );
    }

    #[test]
    fn it_saturates_where_a_u64_of_milliseconds_overflows() {
        assert_eq!(
            super::millis_saturating(Duration::from_secs(u64::MAX)),
            u64::MAX,
            "milliseconds saturate where a u64 would overflow"
        );
        assert_eq!(
            super::millis_saturating(Duration::MAX),
            u64::MAX,
            "the largest duration saturates to u64 max"
        );
    }
}
