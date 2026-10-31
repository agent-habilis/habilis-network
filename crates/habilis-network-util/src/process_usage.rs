//! The CPU time of this process and the load average of the host, for the
//! `mesh census` line. Each reading is `None` off a libc host, so the callers
//! need no `cfg` of their own.

#[cfg(all(unix, feature = "host"))]
use std::mem;
use std::time::Duration;

/// The user and system CPU time of a process.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CpuTimes {
    /// Time spent in user mode.
    pub user: Duration,
    /// Time spent in the kernel on behalf of the process.
    pub system: Duration,
}

impl CpuTimes {
    /// The time spent since `earlier`, field by field. Zero, not a wrap, if a
    /// field went back.
    #[must_use]
    pub const fn since(self, earlier: Self) -> Self {
        Self {
            user: self.user.saturating_sub(earlier.user),
            system: self.system.saturating_sub(earlier.system),
        }
    }
}

/// The CPU time of this process so far, from `getrusage(RUSAGE_SELF)`.
///
/// # Examples
///
/// ```
/// use habilis_network_util::process_usage::cpu_times;
///
/// if let Some(times) = cpu_times() {
///     assert!(times.user + times.system > std::time::Duration::ZERO);
/// }
/// ```
#[cfg(all(unix, feature = "host"))]
#[must_use]
#[expect(
    unsafe_code,
    reason = "libc getrusage FFI; no safe wrapper for RUSAGE_SELF"
)]
pub fn cpu_times() -> Option<CpuTimes> {
    // SAFETY: an all-zero `rusage` is a valid input value; `getrusage` fully
    // overwrites the fields it reports. We pass a valid unique pointer to it
    // and the documented `RUSAGE_SELF` selector.
    let usage = unsafe {
        let mut usage: libc::rusage = mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) != 0 {
            return None;
        }
        usage
    };
    Some(CpuTimes {
        user: timeval_span(usage.ru_utime)?,
        system: timeval_span(usage.ru_stime)?,
    })
}

/// No reading off a libc host.
#[cfg(not(all(unix, feature = "host")))]
#[must_use]
pub const fn cpu_times() -> Option<CpuTimes> {
    None
}

#[cfg(all(unix, feature = "host"))]
fn timeval_span(tv: libc::timeval) -> Option<Duration> {
    let secs = u64::try_from(tv.tv_sec).ok()?;
    let micros = u64::try_from(tv.tv_usec).ok()?;
    Some(Duration::from_secs(secs).saturating_add(Duration::from_micros(micros)))
}

/// The 1-minute load average of the host, from `getloadavg`.
///
/// # Examples
///
/// ```
/// use habilis_network_util::process_usage::load_average_1m;
///
/// if let Some(load) = load_average_1m() {
///     assert!(load >= 0.0);
/// }
/// ```
#[cfg(all(unix, feature = "host"))]
#[must_use]
#[expect(unsafe_code, reason = "libc getloadavg FFI; no safe wrapper")]
pub fn load_average_1m() -> Option<f64> {
    let mut loads = [0.0_f64; 1];
    // SAFETY: the pointer is valid for one `f64`, and we ask for one sample.
    let filled = unsafe { libc::getloadavg(loads.as_mut_ptr(), 1) };
    (filled == 1).then_some(loads[0])
}

/// No reading off a libc host.
#[cfg(not(all(unix, feature = "host")))]
#[must_use]
pub const fn load_average_1m() -> Option<f64> {
    None
}

#[cfg(all(test, unix, feature = "host"))]
mod tests {
    use super::*;

    #[test]
    fn since_is_the_difference_and_saturates() {
        let earlier = CpuTimes {
            user: Duration::from_millis(30),
            system: Duration::from_millis(50),
        };
        let later = CpuTimes {
            user: Duration::from_millis(80),
            system: Duration::from_millis(40),
        };
        let delta = later.since(earlier);
        assert_eq!(delta.user, Duration::from_millis(50));
        assert_eq!(
            delta.system,
            Duration::ZERO,
            "a field that went back reads zero"
        );
    }

    #[test]
    fn readings_exist_on_a_unix_host() {
        assert!(cpu_times().is_some());
        assert!(load_average_1m().is_some_and(|load| load >= 0.0));
    }
}
