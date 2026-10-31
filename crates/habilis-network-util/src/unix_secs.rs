//! A point in time as whole seconds since the Unix epoch, for the wire protocol and the state file.

use std::time::Duration;

use web_time::UNIX_EPOCH;

use crate::clock::SystemTime;

use std::{fmt, ops};
/// A point in time as whole seconds since the Unix epoch: the unit of a message timestamp, of
/// the join time, of a digest window bound and of an invite expiry.
///
/// It is a count, so it does not take a number of seconds where a point is meant: a raw
/// `i64` does not compare with it, and the sum of a point and a [`Duration`] is a point.
///
/// ```compile_fail,E0308
/// use habilis_network_util::unix_secs::UnixSecs;
///
/// let _ = UnixSecs::from(0) == 0i64;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixSecs(i64);

/// A point `secs` seconds after the epoch.
impl From<i64> for UnixSecs {
    fn from(secs: i64) -> Self {
        Self::from_secs(secs)
    }
}

/// The point whose count is the 8 little-endian bytes `bytes`.
impl From<[u8; 8]> for UnixSecs {
    fn from(bytes: [u8; 8]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl UnixSecs {
    /// The epoch. An invite uses it for "never expires".
    pub const ZERO: Self = Self(0);
    /// The latest point: the open end of a digest window, and the expiry that nothing reaches.
    pub const MAX: Self = Self(i64::MAX);

    /// The seconds since the epoch, for a wire field or a log line.
    #[must_use]
    pub fn as_secs(self) -> i64 {
        self.0
    }

    /// The system clock now, or [`UnixSecs::ZERO`] if it is set before 1970 or past the range of
    /// an `i64` (more than 290 billion seconds, far beyond any real system clock).
    #[must_use]
    pub fn now() -> Self {
        let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).ok();
        Self(
            since_epoch
                .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
                .unwrap_or(0),
        )
    }

    /// The time from `earlier` to this point. Zero when `earlier` is not earlier, so a clock that
    /// was set back is no negative span and no panic. The span is exact: an `i128` holds the
    /// difference of two counts, and a `u64` of seconds holds every span that is not negative.
    #[must_use]
    pub fn since(self, earlier: Self) -> Duration {
        u64::try_from(i128::from(self.0) - i128::from(earlier.0))
            .map_or(Duration::ZERO, Duration::from_secs)
    }

    /// The point at the exact count `secs`, or the nearest end of the range. An `i128` holds the
    /// sum of an `i64` count and a `u64` span, so the clamp is the only place that loses range.
    fn clamped(secs: i128) -> Self {
        Self(i64::try_from(secs).unwrap_or(if secs < 0 { i64::MIN } else { i64::MAX }))
    }

    /// The 8 little-endian bytes of the count: what a signature and an invite carry.
    #[must_use]
    pub fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Make a time from whole seconds since the epoch.
    #[must_use]
    pub fn from_secs(secs: i64) -> Self {
        Self(secs)
    }

    /// Make a time from its eight little-endian bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(i64::from_le_bytes(bytes))
    }
}

/// The point `rhs` after `self`, saturating at [`UnixSecs::MAX`].
impl ops::Add<Duration> for UnixSecs {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self {
        Self::clamped(i128::from(self.0) + i128::from(rhs.as_secs()))
    }
}

/// The point `rhs` before `self`, saturating at the lowest count.
impl ops::Sub<Duration> for UnixSecs {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self {
        Self::clamped(i128::from(self.0) - i128::from(rhs.as_secs()))
    }
}

impl fmt::Display for UnixSecs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod unix_secs_tests {
    use std::time::Duration;

    use super::UnixSecs;

    #[test]
    fn it_adds_and_subtracts_a_duration() {
        let _guard = ::habilis_network_test_tracing::init();
        let point = UnixSecs::from(1_700_000_000);
        assert_eq!(
            (point + Duration::from_mins(1)).as_secs(),
            1_700_000_060,
            "adding a minute moves the point forward"
        );
        assert_eq!(
            (point - Duration::from_mins(1)).as_secs(),
            1_699_999_940,
            "subtracting a minute moves the point back"
        );
    }

    #[test]
    fn a_sum_past_the_range_saturates_at_max() {
        let _guard = ::habilis_network_test_tracing::init();
        let point = UnixSecs::from(i64::MAX - 5);
        assert_eq!(
            point + Duration::from_mins(1),
            UnixSecs::MAX,
            "a sum past the range saturates at max"
        );
        // A u64 count of seconds that does not fit an i64 clamps too, as an invite ttl does.
        assert_eq!(
            UnixSecs::from(10) + Duration::from_secs(u64::MAX),
            UnixSecs::MAX,
            "a sum of ten seconds and a huge span saturates at max"
        );
        assert_eq!(
            UnixSecs::from(i64::MIN + 1) - Duration::from_secs(u64::MAX),
            UnixSecs::from(i64::MIN),
            "a difference past the minimum saturates at the minimum"
        );
    }

    /// The sum and the difference are exact, then clamped: a span of any `u64` seconds moves a
    /// point of any count to the end of the range, never to a point short of it.
    #[test]
    fn a_span_past_the_range_saturates_at_the_end_of_the_range() {
        let _guard = ::habilis_network_test_tracing::init();
        let span = Duration::from_secs(u64::MAX);
        assert_eq!(
            UnixSecs::ZERO - span,
            UnixSecs::from(i64::MIN),
            "subtracting a huge span from zero saturates at the start of the range"
        );
        assert_eq!(
            UnixSecs::from(i64::MIN) + span,
            UnixSecs::MAX,
            "subtracting from the minimum saturates at the start of the range"
        );
        assert_eq!(
            UnixSecs::MAX - span,
            UnixSecs::from(i64::MIN),
            "subtracting a huge span from max keeps the range end"
        );
        assert_eq!(
            UnixSecs::from(i64::MIN) - span,
            UnixSecs::from(i64::MIN),
            "subtracting a span from the minimum plus one saturates at the start"
        );
    }

    #[test]
    fn since_is_the_span_and_never_negative() {
        let _guard = ::habilis_network_test_tracing::init();
        let earlier = UnixSecs::from(100);
        let later = UnixSecs::from(160);
        assert_eq!(
            later.since(earlier),
            Duration::from_mins(1),
            "since is the span between two points"
        );
        // A clock set back between two readings is a zero span, not a wrap.
        assert_eq!(
            earlier.since(later),
            Duration::ZERO,
            "since is zero when the later point comes first"
        );
        assert_eq!(
            UnixSecs::MAX.since(UnixSecs::from(-1)).as_secs(),
            i64::MAX as u64 + 1,
            "since from max to minus one is the exact span"
        );
    }

    /// The span between two points is exact: it can be wider than `i64::MAX` seconds, and a
    /// `u64` holds it.
    #[test]
    fn a_span_wider_than_i64_max_is_exact() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            UnixSecs::MAX.since(UnixSecs::from(i64::MIN)),
            Duration::from_secs(u64::MAX),
            "a span wider than i64 max is exact from max"
        );
        assert_eq!(
            UnixSecs::MAX.since(UnixSecs::from(-1)),
            Duration::from_secs(i64::MAX as u64 + 1),
            "a span from minus one to max is exact"
        );
        assert_eq!(
            UnixSecs::from(i64::MIN).since(UnixSecs::MAX),
            Duration::ZERO,
            "a span from the minimum to minus one is exact"
        );
    }

    #[test]
    fn it_orders_as_its_count_and_keeps_the_open_end() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(UnixSecs::ZERO < UnixSecs::from(1), "zero orders before one");
        assert!(
            UnixSecs::from(1) < UnixSecs::MAX,
            "one orders before the open end"
        );
        assert_eq!(
            UnixSecs::MAX.as_secs(),
            i64::MAX,
            "max holds i64 max as its count"
        );
    }

    #[test]
    fn it_round_trips_its_little_endian_bytes() {
        let _guard = ::habilis_network_test_tracing::init();
        let point = UnixSecs::from(1_700_000_000);
        assert_eq!(
            point.to_le_bytes(),
            1_700_000_000_i64.to_le_bytes(),
            "the little endian bytes are the count's bytes"
        );
        assert_eq!(
            UnixSecs::from(point.to_le_bytes()),
            point,
            "the little endian bytes round trip"
        );
    }

    #[test]
    fn it_prints_its_count() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            UnixSecs::from(42).to_string(),
            "42",
            "a point prints its count"
        );
        assert_eq!(
            format!("{:?}", UnixSecs::from(42)),
            "UnixSecs(42)",
            "a point debug prints its count"
        );
    }

    #[test]
    fn now_is_the_system_clock() {
        let _guard = ::habilis_network_test_tracing::init();
        let before = UnixSecs::now();
        let now = UnixSecs::now();
        let after = UnixSecs::now();
        assert!(
            before <= now && now <= after,
            "now lies between the two clock reads"
        );
        // 2020-01-01: the "0 on failure" path is not the normal case.
        assert!(before > UnixSecs::from(1_577_836_800), "now is after 2020");
    }
}
