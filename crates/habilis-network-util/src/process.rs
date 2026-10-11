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

    #[expect(unsafe_code, reason = "OpenProcess FFI; no safe std wrapper exists")]
    fn open(pid: u32) -> Option<OwnedHandle> {
        // SAFETY: the arguments are plain values. The call returns a new handle,
        // or null with the error in `GetLastError`.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() {
            return None;
        }
        // SAFETY: `raw` is a handle that `OpenProcess` just made and nothing else
        // owns or closes.
        Some(unsafe { OwnedHandle::from_raw_handle(raw) })
    }

    /// Whether the process has not exited. A handle outlives its process, so an
    /// exited process that someone still holds open is "gone" here, the same as
    /// the zombie of the Unix twins.
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
            Some(handle) => still_active(&handle).unwrap_or(false),
            // The twin of `EPERM`: a protected process refuses the query, and
            // that refusal proves that it exists. A pid with no process gives
            // `ERROR_INVALID_PARAMETER`.
            None => {
                std::io::Error::last_os_error().raw_os_error()
                    == i32::try_from(ERROR_ACCESS_DENIED).ok()
            }
        }
    }

    /// The creation time, in microseconds since the Unix epoch.
    #[expect(unsafe_code, reason = "GetProcessTimes FFI; no safe std wrapper")]
    pub(super) fn live_start_time(pid: u32) -> Option<u64> {
        let handle = open(pid)?;
        if !still_active(&handle)? {
            return None;
        }
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
        if ok == 0 {
            return None;
        }
        let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        Some(ticks.saturating_sub(FILETIME_UNIX_EPOCH) / 10)
    }

    #[expect(
        unsafe_code,
        reason = "QueryFullProcessImageNameW FFI; no safe wrapper"
    )]
    pub(super) fn comm_of(pid: u32) -> Option<String> {
        let handle = open(pid)?;
        let mut buffer = vec![0_u16; IMAGE_NAME_UTF16_MAX];
        let mut length = u32::try_from(buffer.len()).ok()?;
        // SAFETY: `handle` is open for the call. `buffer` holds `length` code
        // units, and the call writes at most that many, then sets `length` to the
        // count that it wrote, with no terminator.
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
        let image = String::from_utf16(buffer.get(..usize::try_from(length).ok()?)?).ok()?;
        // The file stem, so `claude.exe` and `claude` compare equal: the Unix
        // `comm` has no extension.
        let stem = std::path::Path::new(&image).file_stem()?;
        Some(stem.to_string_lossy().into_owned())
    }

    #[expect(unsafe_code, reason = "Toolhelp snapshot FFI; no safe std wrapper")]
    pub(super) fn parent_of(pid: u32) -> Option<u32> {
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
            if entry.th32ProcessID == pid {
                return Some(entry.th32ParentProcessID);
            }
            // SAFETY: as for `Process32FirstW` above.
            more = unsafe { Process32NextW(snapshot.as_raw_handle(), &raw mut entry) } != 0;
        }
        None
    }
}

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
#[cfg(windows)]
#[must_use]
pub fn comm_of(pid: u32) -> Option<String> {
    windows::comm_of(pid)
}

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
/// skips the `left` broadcast. The graceful stop is an IPC `Quit` command: R5
/// of `docs/windows.md`, not built yet, so this returns an error.
///
/// # Errors
/// Always [`std::io::ErrorKind::Unsupported`], until R5 lands.
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
