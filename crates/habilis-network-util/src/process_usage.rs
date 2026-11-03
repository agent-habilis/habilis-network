//! The CPU time of this process, for the `mesh census` line. The reading is
//! `None` off a unix host, so the callers need no `cfg` of their own.

use std::time::Duration;

/// The CPU time of this process so far, user and system together, from
/// `clock_gettime(CLOCK_PROCESS_CPUTIME_ID)`.
///
/// # Examples
///
/// ```
/// use habilis_network_util::process_usage::cpu_time;
///
/// if let Some(time) = cpu_time() {
///     assert!(time > std::time::Duration::ZERO);
/// }
/// ```
#[cfg(all(unix, feature = "host"))]
#[must_use]
pub fn cpu_time() -> Option<Duration> {
    use rustix::time::{ClockId, clock_gettime};

    let spec = clock_gettime(ClockId::ProcessCPUTime);
    let secs = u64::try_from(spec.tv_sec).ok()?;
    let nanos = u32::try_from(spec.tv_nsec).ok()?;
    Some(Duration::new(secs, nanos))
}

/// No reading off a unix host.
#[cfg(not(all(unix, feature = "host")))]
#[must_use]
pub const fn cpu_time() -> Option<Duration> {
    None
}

#[cfg(all(test, unix, feature = "host"))]
mod tests {
    use super::cpu_time;

    #[test]
    fn the_reading_exists_on_a_unix_host() {
        assert!(cpu_time().is_some());
    }
}
