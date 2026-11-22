use std::io;
use std::io::ErrorKind;

use crate::process_start::ProcessStart;

use rustix::io::Errno;
use rustix::process::{Pid, Signal, kill_process, test_kill_process};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "macos")]
use std::mem;
/// Bound on the parent-walk in [`ancestry_contains`]: real process trees are
/// far shallower, and the bound keeps a pathological ppid cycle (pid reuse
/// mid-walk) from looping forever.
const MAX_ANCESTRY_DEPTH: usize = 64;

#[cfg(target_os = "macos")]
#[expect(unsafe_code, reason = "libc::proc_pidinfo FFI; no safe wrapper exists")]
fn bsdinfo_of(pid: u32) -> io::Result<libc::proc_bsdinfo> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
    // SAFETY: `proc_bsdinfo` is a plain C struct of integers and byte arrays, so all-zero bytes
    // are a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
    let size = i32::try_from(size_of::<libc::proc_bsdinfo>())
        .map_err(|_| io::Error::from(ErrorKind::InvalidData))?;
    // SAFETY: `info` is a live, unique local of exactly `size` bytes, and `size` is the size that
    // the call gets, so the kernel writes inside the buffer. The kernel checks `pid`.
    let written =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    if written == size {
        return Ok(info);
    }
    // No process has the pid: `ESRCH`. A short read means that the struct layout disagrees, and the
    // data is not trustworthy.
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    Err(io::Error::new(
        ErrorKind::UnexpectedEof,
        "proc_pidinfo wrote a short proc_bsdinfo",
    ))
}

/// Whether the error says that no process has the pid.
fn is_gone(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ESRCH) || error.kind() == ErrorKind::NotFound
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
    Some(bsdinfo_of(pid).ok()?.pbi_ppid)
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
    let info = bsdinfo_of(pid).ok()?;
    let name = info.pbi_comm.iter().take_while(|&&byte| byte != 0);
    let bytes: Vec<u8> = name
        .map(|&byte| u8::from_ne_bytes(byte.to_ne_bytes()))
        .collect();
    String::from_utf8(bytes).ok()
}

/// The start of the process `pid`, in microseconds since the epoch. A zombie is `Gone`: an exited owner
/// that its parent has not reaped yet is gone for every purpose but `kill(pid, 0)`.
///
/// # Examples
///
/// A running process has a start time.
///
/// ```
/// use habilis_network_util::process::start_of;
/// use habilis_network_util::process_start::ProcessStart;
///
/// assert!(matches!(start_of(std::process::id()), ProcessStart::Live(_)));
/// ```
#[cfg(target_os = "macos")]
#[must_use]
pub fn start_of(pid: u32) -> ProcessStart {
    match bsdinfo_of(pid) {
        Ok(info) if info.pbi_status == libc::SZOMB => ProcessStart::Gone,
        Ok(info) => ProcessStart::Live(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec),
        Err(error) if is_gone(&error) => ProcessStart::Gone,
        Err(error) => ProcessStart::Unknown(error),
    }
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
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The comm field is parenthesized and may itself contain spaces and `)`,
    // so fields are only positional after the *last* `)`.
    let after_comm = stat.rsplit_once(')')?.1;
    let mut fields = after_comm.split_whitespace();
    let _run_state = fields.next()?;
    fields.next()?.parse().ok()
}

/// The start of the process `pid`, in clock ticks since boot (`stat` field 22). A zombie (`Z`) and a dead
/// process (`X`) are `Gone`. The units differ from macOS, which is fine: a caller only compares two values
/// from one host for equality. The value counts from boot, so where `/tmp` survives a reboot, the same pid
/// with the same tick (10 ms) after the reboot reads as the same process.
///
/// # Examples
///
/// A running process has a start time.
///
/// ```
/// use habilis_network_util::process::start_of;
/// use habilis_network_util::process_start::ProcessStart;
///
/// assert!(matches!(start_of(std::process::id()), ProcessStart::Live(_)));
/// ```
#[cfg(target_os = "linux")]
#[must_use]
pub fn start_of(pid: u32) -> ProcessStart {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => start_from_stat(&stat),
        Err(error) if is_gone(&error) => ProcessStart::Gone,
        Err(error) => ProcessStart::Unknown(error),
    }
}

/// The start in the text of `/proc/<pid>/stat`.
#[cfg(target_os = "linux")]
fn start_from_stat(stat: &str) -> ProcessStart {
    // The comm field is parenthesized and may itself contain spaces and `)`, so fields are only
    // positional after the *last* `)`.
    let Some((_, after_comm)) = stat.rsplit_once(')') else {
        return unreadable_stat();
    };
    let mut fields = after_comm.split_whitespace();
    let state = fields.next();
    if matches!(state, Some("Z" | "X")) {
        return ProcessStart::Gone;
    }
    // Fields 4..=21 lie between the state (3) and the start time (22).
    let ticks = state.and(fields.nth(18));
    ticks
        .and_then(|ticks| ticks.parse().ok())
        .map_or_else(unreadable_stat, ProcessStart::Live)
}

#[cfg(target_os = "linux")]
fn unreadable_stat() -> ProcessStart {
    ProcessStart::Unknown(io::Error::new(
        ErrorKind::InvalidData,
        "the stat of the process has no start time",
    ))
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
    use super::{ancestry_contains, comm_of, is_alive, parent_of, start_of, terminate};
    use crate::process_start::ProcessStart;
    use rustix::process::getppid;

    use std::io::ErrorKind;
    use std::process::{self, Child, Command};
    use std::thread;
    use std::time::{Duration, Instant};
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
    fn pid_zero_is_no_process() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            !is_alive(0),
            "pid 0 names our process group, which is no process"
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

    /// A process that runs for a while, so that its start can be read.
    fn sleeper() -> Child {
        Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("a child that sleeps")
    }

    #[test]
    fn two_reads_of_the_start_of_a_live_process_give_the_same_value() {
        let _guard = ::habilis_network_test_tracing::init();
        let ProcessStart::Live(first) = start_of(self_pid()) else {
            panic!("this process is live");
        };
        thread::sleep(Duration::from_secs(1));

        assert!(
            matches!(start_of(self_pid()), ProcessStart::Live(second) if second == first),
            "the start of a process does not change"
        );
    }

    #[test]
    fn two_live_children_differ_by_pid_and_by_start() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut first = sleeper();
        let mut second = sleeper();

        let starts = (start_of(first.id()), start_of(second.id()));
        first.kill().expect("the first child ends");
        first.wait().expect("the first child is reaped");
        second.kill().expect("the second child ends");
        second.wait().expect("the second child is reaped");

        assert_ne!(first.id(), second.id(), "two live children have two pids");
        let (ProcessStart::Live(first_start), ProcessStart::Live(second_start)) = starts else {
            panic!("both children are live: {starts:?}");
        };
        assert_ne!(
            first_start, second_start,
            "two children that start apart have two starts"
        );
    }

    #[test]
    fn a_reaped_child_is_gone() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut child = sleeper();
        let pid = child.id();
        child.kill().expect("the child ends");
        child.wait().expect("the child is reaped");

        assert!(
            matches!(start_of(pid), ProcessStart::Gone),
            "a pid that no process has is gone: {:?}",
            start_of(pid)
        );
    }

    #[test]
    fn a_child_that_ended_and_is_not_reaped_is_gone() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut child = sleeper();
        let pid = child.id();
        child.kill().expect("the child ends");

        // The child is a zombie until the parent reaps it: it ended, and nobody has waited for it.
        let deadline = Instant::now() + Duration::from_secs(5);
        while matches!(start_of(pid), ProcessStart::Live(_)) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        let seen = start_of(pid);
        child.wait().expect("the child is reaped");

        assert!(
            matches!(seen, ProcessStart::Gone),
            "a zombie is gone for the start: {seen:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_stat_of_a_process_gives_its_state_and_its_start() {
        let _guard = ::habilis_network_test_tracing::init();
        // Fields after the comm: the state, then 18 fields, then the start (field 22).
        let stat = |state: &str| {
            format!("4242 (a b) c) {state} 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777 1")
        };
        let running = super::start_from_stat(&stat("S"));
        let zombie = super::start_from_stat(&stat("Z"));
        let dead = super::start_from_stat(&stat("X"));
        let cut = super::start_from_stat("4242 (x) S 1");
        let garbage = super::start_from_stat("garbage");

        assert!(
            matches!(running, ProcessStart::Live(777)),
            "a running process has its start: {running:?}"
        );
        assert!(
            matches!(zombie, ProcessStart::Gone),
            "a zombie is gone: {zombie:?}"
        );
        assert!(
            matches!(dead, ProcessStart::Gone),
            "a dead process is gone: {dead:?}"
        );
        assert!(
            matches!(cut, ProcessStart::Unknown(_)),
            "a cut stat says nothing: {cut:?}"
        );
        assert!(
            matches!(garbage, ProcessStart::Unknown(_)),
            "a stat with no comm says nothing: {garbage:?}"
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
