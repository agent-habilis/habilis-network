/// Bound on the parent-walk in [`ancestry_contains`]: real process trees are
/// far shallower, and the bound keeps a pathological ppid cycle (pid reuse
/// mid-walk) from looping forever.
const MAX_ANCESTRY_DEPTH: usize = 64;

#[cfg(target_os = "macos")]
#[expect(unsafe_code, reason = "libc::proc_pidinfo FFI; no safe wrapper exists")]
fn bsdinfo_for(pid: u32) -> Option<libc::proc_bsdinfo> {
    let pid = libc::pid_t::try_from(pid).ok()?;
    let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
    let size = i32::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    let written =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    // A short read means the pid vanished mid-call or the struct layout
    // disagrees — either way the data is not trustworthy.
    (written == size).then_some(info)
}

#[cfg(target_os = "macos")]
#[must_use]
pub fn parent_of(pid: u32) -> Option<u32> {
    Some(bsdinfo_for(pid)?.pbi_ppid)
}

#[cfg(target_os = "macos")]
#[must_use]
pub fn comm_of(pid: u32) -> Option<String> {
    let info = bsdinfo_for(pid)?;
    let bytes: Vec<u8> = info
        .pbi_comm
        .iter()
        .take_while(|&&byte| byte != 0)
        .map(|&byte| u8::from_ne_bytes(byte.to_ne_bytes()))
        .collect();
    String::from_utf8(bytes).ok()
}

/// The start time of a live process, in microseconds since the epoch. `None`
/// for a pid with no process, or a zombie: an exited owner that its parent has
/// not reaped yet is gone for every purpose but `kill(pid, 0)`.
#[cfg(target_os = "macos")]
#[must_use]
pub fn live_start_time(pid: u32) -> Option<u64> {
    let info = bsdinfo_for(pid)?;
    (info.pbi_status != libc::SZOMB)
        .then(|| info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn parent_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
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
#[cfg(target_os = "linux")]
#[must_use]
pub fn live_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    if fields.next()? == "Z" {
        return None;
    }
    // Fields 4..=21 lie between the state (3) and the start time (22).
    fields.nth(18)?.parse().ok()
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn comm_of(pid: u32) -> Option<String> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(comm.trim_end().to_string())
}

/// The Windows process queries. A handle is an [`OwnedHandle`], so each one
/// closes on every path out.
#[cfg(windows)]
mod windows {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, FILETIME, INVALID_HANDLE_VALUE, STILL_ACTIVE,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    /// 100 ns intervals from 1601-01-01 (`FILETIME`) to 1970-01-01.
    const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

    /// `MAX_PATH` is not a limit of the image name that the kernel returns, so
    /// the buffer holds the longest path that NTFS allows.
    const IMAGE_NAME_UTF16_MAX: usize = 32_768;

    /// The error is read here, next to the call, so no other call can replace
    /// `GetLastError` before the caller looks at it.
    #[expect(unsafe_code, reason = "OpenProcess FFI; no safe std wrapper exists")]
    fn open(pid: u32) -> std::io::Result<OwnedHandle> {
        // SAFETY: the arguments are plain values. The call returns a new handle,
        // or null with the error in `GetLastError`.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `raw` is a handle that `OpenProcess` just made and nothing else
        // owns or closes.
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }

    /// Whether the process has not exited. A handle outlives its process, so a
    /// process that has exited but that someone still holds open exists, and
    /// reads as not active here.
    ///
    /// The two systems differ for an exited process that is not yet reaped (a
    /// zombie): the Unix `is_alive` is `true` for it, because `kill(pid, 0)`
    /// succeeds, and the Windows `is_alive` is `false`. `live_start_time` is
    /// `None` for both.
    ///
    /// The limit is the R4 table as written: a process that exited with the
    /// code 259 (`STILL_ACTIVE`) reads as active for as long as a handle to it
    /// is open.
    #[expect(unsafe_code, reason = "GetExitCodeProcess FFI; no safe std wrapper")]
    fn still_active(handle: &OwnedHandle) -> Option<bool> {
        let mut code = 0_u32;
        // SAFETY: `handle` is open for the call, and `code` is a valid pointer
        // to one `u32`.
        let ok = unsafe { GetExitCodeProcess(handle.as_raw_handle(), &raw mut code) };
        (ok != 0).then(|| code == STILL_ACTIVE.cast_unsigned())
    }

    pub(super) fn is_alive(pid: u32) -> bool {
        match open(pid) {
            Ok(handle) => still_active(&handle).unwrap_or(false),
            // The twin of `EPERM`: a protected process refuses the query, and
            // that refusal proves that it exists. A pid with no process gives
            // `ERROR_INVALID_PARAMETER`.
            Err(error) => error.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED).ok(),
        }
    }

    /// The creation time of an open process as the raw `FILETIME` value: ticks
    /// of 100 ns since 1601-01-01. The one source of the start time and of the
    /// guard of `parent_of`, so the two times that the guard compares have the
    /// same unit and the same clock.
    #[expect(unsafe_code, reason = "GetProcessTimes FFI; no safe std wrapper")]
    fn creation_ticks(handle: &OwnedHandle) -> Option<u64> {
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: `handle` is open for the call, and the four pointers are valid
        // and distinct. Only the creation time is read.
        let ok = unsafe {
            GetProcessTimes(
                handle.as_raw_handle(),
                &raw mut created,
                &raw mut exited,
                &raw mut kernel,
                &raw mut user,
            )
        };
        (ok != 0)
            .then(|| (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    /// The creation time, in microseconds since the Unix epoch.
    pub(super) fn live_start_time(pid: u32) -> Option<u64> {
        let handle = open(pid).ok()?;
        if !still_active(&handle)? {
            return None;
        }
        let ticks = creation_ticks(&handle)?;
        Some(ticks.saturating_sub(FILETIME_UNIX_EPOCH) / 10)
    }

    #[expect(
        unsafe_code,
        reason = "QueryFullProcessImageNameW FFI; no safe wrapper"
    )]
    pub(super) fn comm_of(pid: u32) -> Option<String> {
        let handle = open(pid).ok()?;
        let mut buffer = vec![0_u16; IMAGE_NAME_UTF16_MAX];
        let mut length = u32::try_from(buffer.len()).ok()?;
        // SAFETY: `handle` is open for the call. `buffer` holds `length` code
        // units, and the call writes at most that many, the terminating null
        // included, then sets `length` to the count of units before the null.
        let ok = unsafe {
            QueryFullProcessImageNameW(
                handle.as_raw_handle(),
                0,
                buffer.as_mut_ptr(),
                &raw mut length,
            )
        };
        if ok == 0 {
            return None;
        }
        // `OsString`, not `String`: a path with an unpaired surrogate is a valid
        // Windows path, and `String::from_utf16` would fail for the whole of it.
        let image = OsString::from_wide(buffer.get(..usize::try_from(length).ok()?)?);
        // The file stem, so `node.exe` and `node` compare equal: the Unix `comm`
        // has no extension.
        let stem = std::path::Path::new(&image).file_stem()?;
        Some(stem.to_string_lossy().into_owned())
    }

    /// Walk a snapshot of the processes, and return the first value that `pick`
    /// makes from an entry.
    #[expect(unsafe_code, reason = "Toolhelp snapshot FFI; no safe std wrapper")]
    pub(super) fn find_in_snapshot<T>(
        mut pick: impl FnMut(&PROCESSENTRY32W) -> Option<T>,
    ) -> Option<T> {
        // SAFETY: the arguments are plain values. The call returns a new
        // snapshot handle, or `INVALID_HANDLE_VALUE`.
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if raw == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: `raw` is a handle that the call above just made and nothing
        // else owns or closes.
        let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut entry = PROCESSENTRY32W {
            dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).ok()?,
            ..PROCESSENTRY32W::default()
        };
        // SAFETY: `snapshot` is open for the call, and `entry` is a valid pointer
        // to a `PROCESSENTRY32W` with `dwSize` set, as the API requires.
        let mut more = unsafe { Process32FirstW(snapshot.as_raw_handle(), &raw mut entry) } != 0;
        while more {
            if let Some(found) = pick(&entry) {
                return Some(found);
            }
            // SAFETY: as for `Process32FirstW` above.
            more = unsafe { Process32NextW(snapshot.as_raw_handle(), &raw mut entry) } != 0;
        }
        None
    }

    /// A parent is plausible when it was created no later than its child. Windows
    /// does not reparent: after a creator exits, its pid can name a process that
    /// was created after the child, and that process is not the parent.
    pub(super) fn accepts_parent(parent_created: u64, child_created: u64) -> bool {
        parent_created <= child_created
    }

    /// The creator of `pid`, when the creator is still a live process that was
    /// created no later than `pid`. Both times come from `GetProcessTimes`. A
    /// process that this user may not query has no verified parent, so it has
    /// `None`: the guard fails closed.
    pub(super) fn parent_of(pid: u32) -> Option<u32> {
        let creator = find_in_snapshot(|entry| {
            (entry.th32ProcessID == pid).then_some(entry.th32ParentProcessID)
        })?;
        let child_created = creation_ticks(&open(pid).ok()?)?;
        let parent = open(creator).ok()?;
        if !still_active(&parent)? {
            return None;
        }
        accepts_parent(creation_ticks(&parent)?, child_created).then_some(creator)
    }
}

/// The parent of `pid`: the process that created it. `None` for a pid that is
/// not in the process snapshot, and for a creator that has exited or that was
/// created after its child, because Windows does not reparent and the pid of an
/// exited creator can name an unrelated process now. This guard goes beyond the
/// R4 table of `docs/windows.md`. A process that this user may not query has no
/// verified parent, so it also gives `None`.
#[cfg(windows)]
#[must_use]
pub fn parent_of(pid: u32) -> Option<u32> {
    windows::parent_of(pid)
}

/// The start time of a live process, in microseconds since the epoch. `None`
/// for a pid with no process, or one that has exited but is still held open.
#[cfg(windows)]
#[must_use]
pub fn live_start_time(pid: u32) -> Option<u64> {
    windows::live_start_time(pid)
}

/// The image name of the process without `.exe`. `None` when the process is not
/// there, or is one that this user may not query.
///
/// The names are not the same on every OS. Windows keeps the case of the file
/// name and has no length limit, and Linux cuts `comm` at 15 bytes. A caller
/// that compares a name must compare it on one OS only, or by a prefix.
#[cfg(windows)]
#[must_use]
pub fn comm_of(pid: u32) -> Option<String> {
    windows::comm_of(pid)
}

/// Whether a process with this pid exists and has not exited. A protected
/// process that refuses the query still counts as alive, as `EPERM` does on
/// Unix. An exited process that is held open does not; see `still_active` for
/// the difference from the Unix zombie.
#[cfg(windows)]
#[must_use]
pub fn is_alive(pid: u32) -> bool {
    windows::is_alive(pid)
}

/// Whether a process with this pid exists (regardless of whether we could
/// signal it: `EPERM` still proves existence).
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "libc::kill(pid, 0) FFI; no safe existence probe exists"
)]
#[must_use]
pub fn is_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    let status = unsafe { libc::kill(pid, 0) };
    status == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Ask a process to terminate (SIGTERM) — the graceful path: a mesh daemon
/// catches it, broadcasts `left`, and removes its state file.
///
/// This only signals a pid. To stop a daemon on every OS, use
/// `runtime::ipc::terminate` of `habilis-network`: on Windows it sends the IPC
/// `quit`, and on Unix it sends this signal.
#[cfg(unix)]
#[expect(unsafe_code, reason = "libc::kill FFI; no safe wrapper")]
/// # Errors
/// Propagates the `kill(2)` failure — no such process, or no permission.
pub fn terminate(pid: u32) -> std::io::Result<()> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let status = unsafe { libc::kill(pid, libc::SIGTERM) };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Windows has no polite signal, and `TerminateProcess` is a hard kill that
/// skips the `left` broadcast. This crate sits below the IPC and holds only the
/// pid, so it cannot stop a daemon here. `runtime::ipc::terminate` of
/// `habilis-network` does, with the IPC `quit` command.
///
/// # Errors
/// Always [`std::io::ErrorKind::Unsupported`].
#[cfg(windows)]
pub fn terminate(_pid: u32) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Whether `ancestor` appears in `pid`'s parent chain (proper ancestors
/// only). This is the session-ownership test: a daemon belongs to an agent
/// session iff the session's process is one of its ancestors. Never relax
/// this to "shares an ancestor" — every process shares init/launchd, and
/// two sessions in one terminal share the login shell.
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
    use habilis_network_test_tracing::test;

    fn self_pid() -> u32 {
        std::process::id()
    }

    /// A child that lives long enough for a test to look at it, and that the
    /// test must `kill` and `wait`. Each OS has its own idle command.
    fn idle_child() -> std::process::Child {
        use std::process::{Command, Stdio};
        #[cfg(unix)]
        let mut command = {
            let mut command = Command::new("sleep");
            command.arg("30");
            command
        };
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("ping");
            command.args(["-n", "30", "127.0.0.1"]);
            command
        };
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn an idle child")
    }

    #[test]
    fn parent_of_a_child_is_this_process() {
        let mut child = idle_child();
        let parent = parent_of(child.id());
        child.kill().expect("kill the child");
        child.wait().expect("wait for the child");
        assert_eq!(parent, Some(self_pid()));
    }

    /// The rule of the guard of `parent_of`, without a process: the parent is
    /// accepted when it is not newer than the child. The rejection by a pid that
    /// was reused cannot be made with real processes without a race.
    #[cfg(windows)]
    #[test]
    fn a_parent_created_after_its_child_is_rejected() {
        use super::windows::accepts_parent;
        assert!(accepts_parent(100, 200));
        assert!(accepts_parent(200, 200));
        assert!(!accepts_parent(201, 200));
    }

    /// A launcher starts a child and exits, so the child's creator is gone. The
    /// kept `Child` holds the launcher's handle, so its pid cannot be reused, and
    /// the guard sees a dead creator.
    #[cfg(windows)]
    #[test]
    fn parent_of_a_child_whose_creator_has_exited_is_none() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let mut launcher = Command::new("cmd")
            .args(["/C", "start /B ping -n 10 127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the launcher");
        let launcher_pid = launcher.id();
        launcher.wait().expect("wait for the launcher");
        let deadline = Instant::now() + Duration::from_secs(5);
        let orphan = loop {
            let found = super::windows::find_in_snapshot(|entry| {
                (entry.th32ParentProcessID == launcher_pid).then_some(entry.th32ProcessID)
            });
            if let Some(pid) = found {
                break pid;
            }
            assert!(
                Instant::now() < deadline,
                "the launcher's child is not there"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        // Not vacuous: the child is a live process, and only its creator is gone.
        assert!(is_alive(orphan));
        assert_eq!(parent_of(orphan), None);
        drop(launcher);
    }

    /// The child is waited for and the `Child` is kept. On Windows, `Child` holds
    /// the process handle, so the process still exists and its pid cannot be
    /// reused: the case "exited, but held open". On Unix the wait reaps the
    /// child, and no process has the pid.
    #[test]
    fn an_exited_child_has_no_live_start_time() {
        let mut child = idle_child();
        let pid = child.id();
        assert!(live_start_time(pid).is_some(), "the child is live");
        child.kill().expect("kill the child");
        child.wait().expect("wait for the child");
        assert_eq!(live_start_time(pid), None);
        // Only here is the pid sure to be unused by another process: the handle
        // of `child` is still open.
        #[cfg(windows)]
        assert!(!is_alive(pid));
        drop(child);
    }

    /// The Unix case that the Windows test above cannot have: a killed child
    /// that nobody has waited for is a zombie. It still exists, so `is_alive` is
    /// `true`, and it has no start time. The Windows `is_alive` is `false` here;
    /// see `still_active`.
    #[cfg(unix)]
    #[test]
    fn a_zombie_child_is_alive_but_has_no_live_start_time() {
        let mut child = idle_child();
        let pid = child.id();
        child.kill().expect("kill the child");
        // SIGKILL is asynchronous: wait for the child to become a zombie.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while live_start_time(pid).is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "the child did not die"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let alive = is_alive(pid);
        child.wait().expect("wait for the child");
        assert!(alive, "a zombie still exists");
    }

    #[cfg(unix)]
    #[test]
    fn parent_of_self_is_our_ppid() {
        #[expect(unsafe_code, reason = "libc::getppid FFI; always succeeds")]
        let ppid = unsafe { libc::getppid() };
        assert_eq!(parent_of(self_pid()), u32::try_from(ppid).ok());
    }

    #[test]
    fn ancestry_contains_own_parent() {
        let parent = parent_of(self_pid()).expect("self has a parent");
        assert!(ancestry_contains(self_pid(), parent));
    }

    #[test]
    fn ancestry_excludes_self() {
        assert!(!ancestry_contains(self_pid(), self_pid()));
    }

    #[test]
    fn is_alive_self_true_absurd_false() {
        assert!(is_alive(self_pid()));
        assert!(!is_alive(u32::MAX - 1));
    }

    #[test]
    fn comm_of_self_names_the_test_binary() {
        let comm = comm_of(self_pid()).expect("self has a comm");
        assert!(!comm.is_empty());
    }

    #[test]
    fn live_start_time_is_stable_for_self_and_absent_for_a_dead_pid() {
        let start = live_start_time(self_pid()).expect("self is live");
        assert_eq!(live_start_time(self_pid()), Some(start));
        assert_eq!(live_start_time(u32::MAX - 1), None);
    }

    #[test]
    fn terminate_rejects_a_dead_pid() {
        assert!(terminate(u32::MAX - 1).is_err());
    }
}
