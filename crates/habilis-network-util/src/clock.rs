//! The crate's clock: the portable [`Instant`] / [`SystemTime`] every other
//! module imports, and the unix-epoch timestamps the wire protocol and state
//! file expect.
//!
//! Load-bearing on wasm, not a nicety. On `wasm32-unknown-unknown` the `std`
//! constructors route to `sys/time/unsupported.rs` and **panic**
//! (`"time not implemented on this platform"`) — and [`UnixSecs::now`] stamps every
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

/// A point in time as whole seconds since the Unix epoch: the unit of a message timestamp, of
/// the join time, of a digest window bound and of an invite expiry.
///
/// It is a count, so it does not take a number of seconds where a point is meant: a raw
/// `i64` does not compare with it, and the sum of a point and a [`Duration`] is a point.
///
/// ```compile_fail,E0308
/// use habilis_network_util::clock::UnixSecs;
///
/// let _ = UnixSecs::from_secs(0) == 0i64;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixSecs(i64);

impl UnixSecs {
    /// The epoch. An invite uses it for "never expires".
    pub const ZERO: Self = Self(0);
    /// The latest point: the open end of a digest window, and the expiry that nothing reaches.
    pub const MAX: Self = Self(i64::MAX);

    /// A point `secs` seconds after the epoch.
    #[must_use]
    pub const fn from_secs(secs: i64) -> Self {
        Self(secs)
    }

    /// The seconds since the epoch, for a wire field or a log line.
    #[must_use]
    pub const fn as_secs(self) -> i64 {
        self.0
    }

    /// The system clock now, or [`UnixSecs::ZERO`] if it is set before 1970 or past the range of
    /// an `i64` (more than 290 billion seconds, far beyond any real system clock).
    #[must_use]
    pub fn now() -> Self {
        Self(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|since_epoch| i64::try_from(since_epoch.as_secs()).ok())
                .unwrap_or(0),
        )
    }

    /// The time from `earlier` to this point. Zero when `earlier` is not earlier, so a clock that
    /// was set back is no negative span and no panic.
    #[must_use]
    pub fn since(self, earlier: Self) -> Duration {
        u64::try_from(self.0.saturating_sub(earlier.0)).map_or(Duration::ZERO, Duration::from_secs)
    }

    /// The point at the exact count `secs`, or the nearest end of the range. An `i128` holds the
    /// sum of an `i64` count and a `u64` span, so the clamp is the only place that loses range.
    fn clamped(secs: i128) -> Self {
        Self(i64::try_from(secs).unwrap_or(if secs < 0 { i64::MIN } else { i64::MAX }))
    }

    /// The 8 little-endian bytes of the count: what a signature and an invite carry.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// The point whose count is the 8 little-endian bytes `bytes`.
    #[must_use]
    pub const fn from_le_bytes(bytes: [u8; 8]) -> Self {
        Self(i64::from_le_bytes(bytes))
    }
}

/// The point `rhs` after `self`, saturating at [`UnixSecs::MAX`].
impl std::ops::Add<Duration> for UnixSecs {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self {
        Self::clamped(i128::from(self.0) + i128::from(rhs.as_secs()))
    }
}

/// The point `rhs` before `self`, saturating at the lowest count.
impl std::ops::Sub<Duration> for UnixSecs {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self {
        Self::clamped(i128::from(self.0) - i128::from(rhs.as_secs()))
    }
}

impl std::fmt::Display for UnixSecs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
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
pub const fn millis_saturating(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_mul(1000)
        .saturating_add(duration.subsec_millis() as u64)
}

#[cfg(test)]
mod unix_secs_tests {
    use std::time::Duration;

    use super::UnixSecs;

    #[test]
    fn it_adds_and_subtracts_a_duration() {
        let point = UnixSecs::from_secs(1_700_000_000);
        assert_eq!((point + Duration::from_mins(1)).as_secs(), 1_700_000_060);
        assert_eq!((point - Duration::from_mins(1)).as_secs(), 1_699_999_940);
    }

    #[test]
    fn a_sum_past_the_range_saturates_at_max() {
        let point = UnixSecs::from_secs(i64::MAX - 5);
        assert_eq!(point + Duration::from_mins(1), UnixSecs::MAX);
        // A u64 count of seconds that does not fit an i64 clamps too, as an invite ttl does.
        assert_eq!(
            UnixSecs::from_secs(10) + Duration::from_secs(u64::MAX),
            UnixSecs::MAX
        );
        assert_eq!(
            UnixSecs::from_secs(i64::MIN + 1) - Duration::from_secs(u64::MAX),
            UnixSecs::from_secs(i64::MIN)
        );
    }

    /// The sum and the difference are exact, then clamped: a span of any `u64` seconds moves a
    /// point of any count to the end of the range, never to a point short of it.
    #[test]
    fn a_span_past_the_range_saturates_at_the_end_of_the_range() {
        let span = Duration::from_secs(u64::MAX);
        assert_eq!(UnixSecs::ZERO - span, UnixSecs::from_secs(i64::MIN));
        assert_eq!(UnixSecs::from_secs(i64::MIN) + span, UnixSecs::MAX);
        assert_eq!(UnixSecs::MAX - span, UnixSecs::from_secs(i64::MIN));
        assert_eq!(
            UnixSecs::from_secs(i64::MIN) - span,
            UnixSecs::from_secs(i64::MIN)
        );
    }

    #[test]
    fn since_is_the_span_and_never_negative() {
        let earlier = UnixSecs::from_secs(100);
        let later = UnixSecs::from_secs(160);
        assert_eq!(later.since(earlier), Duration::from_mins(1));
        // A clock set back between two readings is a zero span, not a wrap.
        assert_eq!(earlier.since(later), Duration::ZERO);
        assert_eq!(
            UnixSecs::MAX.since(UnixSecs::from_secs(-1)).as_secs(),
            i64::MAX as u64
        );
    }

    #[test]
    fn it_orders_as_its_count_and_keeps_the_open_end() {
        assert!(UnixSecs::ZERO < UnixSecs::from_secs(1));
        assert!(UnixSecs::from_secs(1) < UnixSecs::MAX);
        assert_eq!(UnixSecs::MAX.as_secs(), i64::MAX);
    }

    #[test]
    fn it_round_trips_its_little_endian_bytes() {
        let point = UnixSecs::from_secs(1_700_000_000);
        assert_eq!(point.to_le_bytes(), 1_700_000_000_i64.to_le_bytes());
        assert_eq!(UnixSecs::from_le_bytes(point.to_le_bytes()), point);
    }

    #[test]
    fn it_prints_its_count() {
        assert_eq!(UnixSecs::from_secs(42).to_string(), "42");
        assert_eq!(format!("{:?}", UnixSecs::from_secs(42)), "UnixSecs(42)");
    }

    #[test]
    fn now_is_the_system_clock() {
        let before = UnixSecs::now();
        let now = UnixSecs::now();
        let after = UnixSecs::now();
        assert!(before <= now && now <= after);
        // 2020-01-01: the "0 on failure" path is not the normal case.
        assert!(before > UnixSecs::from_secs(1_577_836_800));
    }
}

#[cfg(test)]
mod millis_saturating_tests {
    use std::time::Duration;

    use super::millis_saturating;

    const ONE_SECOND: u64 = millis_saturating(Duration::from_secs(1));

    #[test]
    fn it_counts_the_whole_seconds_and_the_subsecond_part() {
        assert_eq!(ONE_SECOND, 1000);
        assert_eq!(millis_saturating(Duration::ZERO), 0);
        assert_eq!(millis_saturating(Duration::from_millis(1500)), 1500);
        // A part of a millisecond is cut, as `Duration::as_millis` cuts it.
        assert_eq!(millis_saturating(Duration::new(2, 999_999_999)), 2999);
    }

    #[test]
    fn it_saturates_where_a_u64_of_milliseconds_overflows() {
        assert_eq!(millis_saturating(Duration::from_secs(u64::MAX)), u64::MAX);
        assert_eq!(millis_saturating(Duration::MAX), u64::MAX);
    }
}
