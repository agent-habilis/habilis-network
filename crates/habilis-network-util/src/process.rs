use std::io;
use std::io::ErrorKind;

use rustix::io::Errno;
use rustix::process::{Pid, Signal, kill_process, test_kill_process};
#[cfg(target_os = "macos")]
use std::mem;
/// Bound on the parent-walk in [`ancestry_contains`]: real process trees are
/// far shallower, and the bound keeps a pathological ppid cycle (pid reuse
/// mid-walk) from looping forever.
const MAX_ANCESTRY_DEPTH: usize = 64;

#[cfg(target_os = "macos")]
#[expect(unsafe_code, reason = "libc::proc_pidinfo FFI; no safe wrapper exists")]
fn bsdinfo_for(pid: u32) -> Option<libc::proc_bsdinfo> {
    let pid = libc::pid_t::try_from(pid).ok()?;
    // SAFETY: `proc_bsdinfo` is a plain C struct of integers and byte arrays, so all-zero bytes
    // are a valid value.
    let mut info = unsafe { mem::zeroed::<libc::proc_bsdinfo>() };
    let size = i32::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    // SAFETY: `info` is a live, unique local of exactly `size` bytes, and `size` is the size that
    // the call gets, so the kernel writes inside the buffer. The kernel checks `pid`.
    let written =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    // A short read means the pid vanished mid-call or the struct layout
    // disagrees — either way the data is not trustworthy.
    (written == size).then_some(info)
}

/// The parent pid of `pid`, or `None` if the lookup fails.
///
/// # Examples
///
/// The parent of a running process is a process too.
///
/// ```
/// use habilis_network_util::process::parent_of;
///
/// assert!(parent_of(std::process::id()).is_some());
/// ```
#[cfg(target_os = "macos")]
#[must_use]
pub fn parent_of(pid: u32) -> Option<u32> {
    Some(bsdinfo_for(pid)?.pbi_ppid)
}

/// The command name of `pid`, or `None` if the lookup fails or the name is not UTF-8.
///
/// # Examples
///
/// A running process has a command name.
///
/// ```
/// use habilis_network_util::process::comm_of;
///
/// assert!(comm_of(std::process::id()).is_some());
/// ```
#[cfg(target_os = "macos")]
#[must_use]
pub fn comm_of(pid: u32) -> Option<String> {
    let info = bsdinfo_for(pid)?;
    let name = info.pbi_comm.iter().take_while(|&&byte| byte != 0);
    let bytes: Vec<u8> = name
        .map(|&byte| u8::from_ne_bytes(byte.to_ne_bytes()))
        .collect();
    String::from_utf8(bytes).ok()
}

/// The start time of a live process, in microseconds since the epoch. `None`
/// for a pid with no process, or a zombie: an exited owner that its parent has
/// not reaped yet is gone for every purpose but `kill(pid, 0)`.
///
/// # Examples
///
/// A running process has a start time.
///
/// ```
/// use habilis_network_util::process::live_start_time;
///
/// assert!(live_start_time(std::process::id()).is_some());
/// ```
#[cfg(target_os = "macos")]
#[must_use]
pub fn live_start_time(pid: u32) -> Option<u64> {
    let info = bsdinfo_for(pid)?;
    (info.pbi_status != libc::SZOMB)
        .then(|| info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
}

/// The parent pid of `pid`, or `None` if the lookup fails.
///
/// # Examples
///
/// The parent of a running process is a process too.
///
/// ```
/// use habilis_network_util::process::parent_of;
///
/// assert!(parent_of(std::process::id()).is_some());
/// ```
#[cfg(target_os = "linux")]
#[must_use]
pub fn parent_of(pid: u32) -> Option<u32> {
    use std::fs;

    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The comm field is parenthesized and may itself contain spaces and `)`,
    // so fields are only positional after the *last* `)`.
    let after_comm = stat.rsplit_once(')')?.1;
    let mut fields = after_comm.split_whitespace();
    let _run_state = fields.next()?;
    fields.next()?.parse().ok()
}

/// The start time of a live process, in clock ticks since boot (`stat` field
/// 22). `None` for a pid with no process, or a zombie (see the macOS twin). The
/// units differ from macOS, which is fine: a caller only compares two values
/// from one host for equality.
///
/// # Examples
///
/// A running process has a start time.
///
/// ```
/// use habilis_network_util::process::live_start_time;
///
/// assert!(live_start_time(std::process::id()).is_some());
/// ```
#[cfg(target_os = "linux")]
#[must_use]
pub fn live_start_time(pid: u32) -> Option<u64> {
    use std::fs;

    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    if fields.next()? == "Z" {
        return None;
    }
    // Fields 4..=21 lie between the state (3) and the start time (22).
    fields.nth(18)?.parse().ok()
}

/// The command name of `pid`, or `None` if the lookup fails or the name is not UTF-8.
///
/// # Examples
///
/// A running process has a command name.
///
/// ```
/// use habilis_network_util::process::comm_of;
///
/// assert!(comm_of(std::process::id()).is_some());
/// ```
#[cfg(target_os = "linux")]
#[must_use]
pub fn comm_of(pid: u32) -> Option<String> {
    use std::fs;

    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(comm.trim_end().to_string())
}

/// Whether a process with this pid exists (regardless of whether we could
/// signal it: `EPERM` still proves existence).
///
/// # Examples
///
/// The running test process is alive.
///
/// ```
/// use habilis_network_util::process::is_alive;
///
/// assert!(is_alive(std::process::id()));
/// ```
#[must_use]
pub fn is_alive(pid: u32) -> bool {
    let Some(pid) = process_id(pid) else {
        return false;
    };
    match test_kill_process(pid) {
        Ok(()) => true,
        Err(error) => error == Errno::PERM,
    }
}

/// The pid as rustix names it. Zero is refused: `kill(2)` reads it as our own process group.
fn process_id(pid: u32) -> Option<Pid> {
    Pid::from_raw(i32::try_from(pid).ok()?)
}

/// Ask a process to terminate (SIGTERM) — the graceful path: a mesh daemon
/// catches it, broadcasts `left`, and removes its state file.
/// # Errors
/// `InvalidInput` for pid 0, which `kill(2)` reads as our own process group, and for a pid that
/// does not fit a `pid_t`. Otherwise it propagates the `kill(2)` failure — no such process, or
/// no permission.
///
/// # Examples
///
/// It sends a signal that stops a process, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_util::process::terminate;
///
/// # fn demo(child_pid: u32) -> std::io::Result<()> {
/// terminate(child_pid)?;
/// # Ok(())
/// # }
/// ```
pub fn terminate(pid: u32) -> io::Result<()> {
    let pid = process_id(pid).ok_or_else(|| io::Error::from(ErrorKind::InvalidInput))?;
    kill_process(pid, Signal::TERM).map_err(io::Error::from)
}

/// Whether `ancestor` appears in `pid`'s parent chain (proper ancestors
/// only). This is the session-ownership test: a daemon belongs to an agent
/// session iff the session's process is one of its ancestors. Never relax
/// this to "shares an ancestor" — every process shares init/launchd, and
/// two sessions in one terminal share the login shell.
///
/// # Examples
///
/// A process has its parent in its ancestry.
///
/// ```
/// use habilis_network_util::process::{ancestry_contains, parent_of};
///
/// let pid = std::process::id();
/// if let Some(parent) = parent_of(pid) {
///     assert!(ancestry_contains(pid, parent));
/// }
/// ```
#[must_use]
pub fn ancestry_contains(pid: u32, ancestor: u32) -> bool {
    let mut current = pid;
    for _ in 0..MAX_ANCESTRY_DEPTH {
        let Some(parent) = parent_of(current) else {
            return false;
        };
        if parent == ancestor {
            return true;
        }
        if parent <= 1 {
            return false;
        }
        current = parent;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{ancestry_contains, comm_of, is_alive, live_start_time, parent_of, terminate};
    use rustix::process::getppid;

    use std::io::ErrorKind;
    use std::process;
    fn self_pid() -> u32 {
        process::id()
    }

    #[test]
    fn terminate_refuses_pid_zero() {
        let _guard = ::habilis_network_test_tracing::init();
        // `kill(0, SIGTERM)` would signal every process of our own group, the test run included.
        let error = terminate(0).expect_err("pid 0 must be refused");
        assert_eq!(
            error.kind(),
            ErrorKind::InvalidInput,
            "terminating pid zero is refused as invalid input"
        );
    }

    #[test]
    fn parent_of_self_is_our_ppid() {
        let _guard = ::habilis_network_test_tracing::init();
        let ppid = getppid().map(|pid| pid.as_raw_nonzero().get());
        assert_eq!(
            parent_of(self_pid()),
            ppid.and_then(|ppid| u32::try_from(ppid).ok()),
            "the parent of this process is its ppid"
        );
    }

    #[test]
    fn ancestry_contains_own_parent() {
        let _guard = ::habilis_network_test_tracing::init();
        let parent = parent_of(self_pid()).expect("self has a parent");
        assert!(
            ancestry_contains(self_pid(), parent),
            "the ancestry of this process contains its parent"
        );
    }

    #[test]
    fn ancestry_excludes_self() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            !ancestry_contains(self_pid(), self_pid()),
            "the ancestry excludes this process itself"
        );
    }

    #[test]
    fn is_alive_self_true_absurd_false() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(is_alive(self_pid()), "this process is alive");
        assert!(!is_alive(u32::MAX - 1), "an absurd pid is not alive");
    }

    #[test]
    fn comm_of_self_names_the_test_binary() {
        let _guard = ::habilis_network_test_tracing::init();
        let comm = comm_of(self_pid()).expect("self has a comm");
        assert!(
            !comm.is_empty(),
            "the command name of this process is not empty"
        );
    }

    #[test]
    fn live_start_time_is_stable_for_self_and_absent_for_a_dead_pid() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = live_start_time(self_pid()).expect("self is live");
        assert_eq!(
            live_start_time(self_pid()),
            Some(start),
            "the live start time of this process is stable"
        );
        assert_eq!(
            live_start_time(u32::MAX - 1),
            None,
            "a dead pid has no live start time"
        );
    }

    #[test]
    fn terminate_rejects_a_dead_pid() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            terminate(u32::MAX - 1).is_err(),
            "terminating a dead pid is an error"
        );
    }
}
