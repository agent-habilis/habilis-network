//! This process's **resident memory** — the physical RAM it currently holds
//! (a.k.a. the resident set size, RSS) — for the warn-only leak signal.
//!
//! The distributed soak that crashed a host had **no in-process leak
//! visibility** — resident memory was only observable from an external `ps`
//! sampler. This reads our own so the daemon can emit a `warn` when it crosses
//! a soft threshold ([`crate::tuning::RESIDENT_MEMORY_WARN_MB`]).
//! Warn-only by design: host safety comes from the scenario runbook's OS resource
//! caps, not from the daemon exiting.

/// This process's peak resident memory in **bytes**, or `None` if it can't
/// be read on this platform.
///
/// Backed by `getrusage(RUSAGE_SELF).ru_maxrss`. We report *peak* rather than
/// instantaneous deliberately: a memory leak climbs monotonically, so peak ==
/// current in the case we care about, and crossing the threshold is exactly
/// the leak signal — with one cheap syscall and no `/proc` parsing or mach FFI.
#[must_use]
pub fn peak_resident_memory_bytes() -> Option<u64> {
    maxrss_bytes()
}

/// This process's peak resident memory in `MiB`, or `None` on platforms where
/// it can't be read.
///
/// The leak gauge the periodic `mesh census` log line carries: peak resident
/// memory is monotonic, so a churn-proportional leak shows as a rising slope on
/// one always-on timeline next to the roster/link counts — no external `ps`
/// sampler needed (the gap the distributed-soak runbook had to work around).
#[must_use]
pub fn peak_resident_memory_mb() -> Option<u64> {
    peak_resident_memory_bytes().map(|bytes| bytes / (1024 * 1024))
}

/// This process's **current** resident memory in bytes, or `None` where it cannot
/// be read (not macOS or Linux, no `host` feature, or a browser).
///
/// The peak above cannot show that memory grew after a point: it includes the
/// burst at start-up, and it never falls. A measurement of what a feature costs
/// reads this before and after.
#[must_use]
pub fn current_resident_memory_bytes() -> Option<u64> {
    current_rss_bytes()
}

/// [`current_resident_memory_bytes`] in `MiB`.
#[must_use]
pub fn current_resident_memory_mb() -> Option<u64> {
    current_resident_memory_bytes().map(|bytes| bytes / (1024 * 1024))
}

/// macOS: the resident size of the task, from `task_info` (`mach_task_basic_info`).
#[cfg(all(target_os = "macos", feature = "host"))]
#[expect(
    unsafe_code,
    reason = "libc task_info FFI; there is no safe wrapper for the resident size of the task"
)]
#[expect(
    deprecated,
    reason = "libc points to the mach2 crate for the mach calls; one read does not warrant a dependency"
)]
fn current_rss_bytes() -> Option<u64> {
    let mut info: libc::mach_task_basic_info = unsafe { std::mem::zeroed() };
    let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
    // SAFETY: `info` is a valid, unique `mach_task_basic_info`, `count` is its size
    // in `natural_t` units as the call needs, and the selector is the documented
    // `MACH_TASK_BASIC_INFO` for the current task.
    let status = unsafe {
        libc::task_info(
            libc::mach_task_self_,
            libc::MACH_TASK_BASIC_INFO,
            (&raw mut info).cast::<libc::integer_t>(),
            &raw mut count,
        )
    };
    (status == libc::KERN_SUCCESS).then_some(info.resident_size)
}

/// Linux: the resident pages of `/proc/self/statm` (its second field), times the
/// size of a page.
#[cfg(all(target_os = "linux", feature = "host"))]
#[expect(unsafe_code, reason = "libc sysconf FFI for the page size")]
fn current_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    // SAFETY: `sysconf` with a valid name has no memory effects.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(page).ok()?.checked_mul(pages)
}

/// No reading: another target, or no `host` feature.
#[cfg(not(all(any(target_os = "macos", target_os = "linux"), feature = "host")))]
fn current_rss_bytes() -> Option<u64> {
    None
}

// `unix` alone is not the right gate: `libc` is an optional dependency the
// `host` feature turns on, so a `--no-default-features` build on a unix host
// would take this arm with nothing to call into. Both conditions, or neither.
#[cfg(all(unix, feature = "host"))]
#[expect(
    unsafe_code,
    reason = "libc getrusage FFI; no safe wrapper for RUSAGE_SELF maxrss"
)]
fn maxrss_bytes() -> Option<u64> {
    // SAFETY: an all-zero `rusage` is a valid input value; `getrusage` fully
    // overwrites the fields it reports. We pass a valid unique pointer to it
    // and the documented `RUSAGE_SELF` selector.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) != 0 {
            return None;
        }
        usage
    };
    let maxrss = u64::try_from(usage.ru_maxrss).ok()?;
    // `ru_maxrss` units differ by platform: KiB on Linux, bytes on macOS/BSD.
    #[cfg(target_os = "linux")]
    {
        Some(maxrss.saturating_mul(1024))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Some(maxrss)
    }
}

/// No reading available: a non-unix host, or any target without `libc` — which
/// includes the browser, where a tab has no meaningful RSS of its own anyway.
/// The leak gauge simply reports 0 there.
#[cfg(not(all(unix, feature = "host")))]
fn maxrss_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::peak_resident_memory_bytes;

    /// The current reading falls when memory is given back, which the peak never
    /// does. A block of 128 `MiB` is mapped, touched, read, unmapped and read again;
    /// `munmap` returns the pages at once, whereas `free` on macOS leaves them
    /// resident until the system needs them.
    #[cfg(all(any(target_os = "macos", target_os = "linux"), feature = "host"))]
    #[test]
    #[expect(
        unsafe_code,
        reason = "libc mmap and munmap: the pages must go back at once"
    )]
    fn the_current_resident_memory_falls_when_memory_is_given_back() {
        use super::current_resident_memory_bytes;

        const BLOCK: usize = 128 * 1024 * 1024;
        const MIB: u64 = 1024 * 1024;
        let before = current_resident_memory_bytes().expect("readable");
        // SAFETY: an anonymous private mapping of BLOCK bytes that nothing else
        // uses; every write is inside it, and it is unmapped once, with the same
        // length.
        let (with_block, after) = unsafe {
            let base = libc::mmap(
                std::ptr::null_mut(),
                BLOCK,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            );
            assert_ne!(base, libc::MAP_FAILED, "the mapping");
            let bytes = base.cast::<u8>();
            for page in (0..BLOCK).step_by(4096) {
                bytes.add(page).write_volatile(1);
            }
            let with_block = current_resident_memory_bytes().expect("readable");
            assert_eq!(libc::munmap(base, BLOCK), 0, "the unmapping");
            (
                with_block,
                current_resident_memory_bytes().expect("readable"),
            )
        };
        assert!(
            with_block >= before + 96 * MIB,
            "the block shows: {before} then {with_block}"
        );
        assert!(
            after + 64 * MIB <= with_block,
            "memory given back shows: {with_block} then {after}"
        );
    }

    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn reads_a_plausible_resident_memory() {
        // The test process holds a real address space, so resident memory is
        // readable and non-trivial — guards against a units/selector regression
        // returning 0.
        let bytes = peak_resident_memory_bytes().expect("resident memory readable on unix");
        assert!(
            bytes > 1024 * 1024,
            "resident memory should exceed 1 MiB, got {bytes} bytes"
        );
    }
}
