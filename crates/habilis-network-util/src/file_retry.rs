//! A short retry for a rename or a remove that a reader blocks (R8 of
//! `docs/windows.md`).
//!
//! On Windows a reader that opens a file without `FILE_SHARE_DELETE` blocks a
//! rename over it (error 5, `ERROR_ACCESS_DENIED`) and a remove of it (error 32,
//! `ERROR_SHARING_VIOLATION`) while it holds the file. The readers of
//! `PowerShell` (`Get-Content`, `[IO.File]::ReadAllText`) open that way. A read
//! takes well under a millisecond, so a retry every millisecond gets through:
//! with a reader in a tight loop, the worst wait measured was 18 ms, for a
//! remove. `std::fs`
//! opens with `FILE_SHARE_DELETE`, so a reader of this workspace never blocks.
//!
//! On Unix a rename and a remove do not depend on readers, so the retry calls
//! the operation once.

use std::io;
use std::time::Duration;

use crate::tuning::SHARED_FILE_RETRY_DEADLINE;

/// Run `op`, and on Windows run it again while a reader blocks it, up to
/// [`SHARED_FILE_RETRY_DEADLINE`]. See [`retry_while_shared_for`].
///
/// # Errors
/// The last error of `op`.
pub fn retry_while_shared<T>(op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    retry_while_shared_for(op, SHARED_FILE_RETRY_DEADLINE)
}

/// Run `op`. On Windows, while it fails with an error of a reader that holds
/// the file ([`is_shared_file_error`]), sleep
/// [`SHARED_FILE_RETRY_STEP`](crate::tuning::SHARED_FILE_RETRY_STEP) and run it
/// again, until `deadline` has passed since the first run. On Unix, run it once.
///
/// The worst wait is `deadline` plus one step that sleeps long: about 65 ms for
/// the default deadline, when a 1 ms sleep lands on a 15.6 ms clock tick.
///
/// # Errors
/// The last error of `op`. An error that is not of a reader comes back at once.
pub fn retry_while_shared_for<T>(
    mut op: impl FnMut() -> io::Result<T>,
    deadline: Duration,
) -> io::Result<T> {
    #[cfg(windows)]
    {
        let start = std::time::Instant::now();
        loop {
            match op() {
                Err(error) if is_shared_file_error(&error) && start.elapsed() < deadline => {
                    std::thread::sleep(crate::tuning::SHARED_FILE_RETRY_STEP);
                }
                result => return result,
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = deadline;
        op()
    }
}

/// Whether `error` is what a reader that holds a file gives on Windows: 5
/// (`ERROR_ACCESS_DENIED`, also how `ERROR_DELETE_PENDING` comes back) or 32
/// (`ERROR_SHARING_VIOLATION`). A real refusal also gives 5, such as a rename
/// over a directory; the retry only delays it. 33 (`ERROR_LOCK_VIOLATION`) is a
/// byte-range lock on a read or a write, not a rename or a remove, so it is
/// left out. False on Unix.
#[must_use]
pub fn is_shared_file_error(error: &io::Error) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};

        error.raw_os_error().is_some_and(|code| {
            u32::try_from(code)
                .is_ok_and(|code| code == ERROR_ACCESS_DENIED || code == ERROR_SHARING_VIOLATION)
        })
    }
    #[cfg(not(windows))]
    {
        let _ = error;
        false
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_test_tracing::test;
    use std::io;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{is_shared_file_error, retry_while_shared, retry_while_shared_for};

    /// A folder of this test alone, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("hn-file-retry-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("the test folder");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_error_that_is_not_of_a_reader_comes_back_at_once() {
        let mut runs = 0;
        let start = std::time::Instant::now();
        let result: io::Result<()> = retry_while_shared_for(
            || {
                runs += 1;
                Err(io::Error::from(io::ErrorKind::NotFound))
            },
            Duration::from_secs(10),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(runs, 1);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_success_runs_once() {
        let mut runs = 0;
        let result = retry_while_shared(|| {
            runs += 1;
            Ok(7)
        });
        assert_eq!(result.unwrap(), 7);
        assert_eq!(runs, 1);
    }

    #[test]
    fn the_codes_of_a_reader_are_retried_on_windows_only() {
        for code in [5, 32] {
            assert_eq!(
                is_shared_file_error(&io::Error::from_raw_os_error(code)),
                cfg!(windows),
                "{code}"
            );
        }
        for code in [2, 33, 145] {
            assert!(
                !is_shared_file_error(&io::Error::from_raw_os_error(code)),
                "{code}"
            );
        }
        assert!(!is_shared_file_error(&io::Error::other("no code")));
    }

    #[test]
    fn a_rename_over_a_file_is_retried_until_its_reader_closes() {
        let dir = TempDir::new("rename");
        let target = dir.0.join("state.json");
        let tmp = dir.0.join("state.json.tmp");
        std::fs::write(&target, b"old").expect("the target");
        std::fs::write(&tmp, b"new").expect("the tmp");
        let reader = hold_without_share_delete(&target);
        let closer = close_after(reader, Duration::from_millis(10));
        retry_while_shared_for(|| std::fs::rename(&tmp, &target), Duration::from_secs(10))
            .expect("the rename");
        closer.join().expect("the closer");
        assert_eq!(std::fs::read(&target).expect("the target"), b"new");
    }

    #[test]
    fn a_remove_is_retried_until_its_reader_closes() {
        let dir = TempDir::new("remove");
        let target = dir.0.join("state.json");
        std::fs::write(&target, b"old").expect("the target");
        let reader = hold_without_share_delete(&target);
        let closer = close_after(reader, Duration::from_millis(10));
        retry_while_shared_for(|| std::fs::remove_file(&target), Duration::from_secs(10))
            .expect("the remove");
        closer.join().expect("the closer");
        assert!(!target.exists());
    }

    /// On Windows a reader that never closes makes the retry give up at the
    /// deadline, not before. No upper bound: a slow runner can overshoot.
    #[cfg(windows)]
    #[test]
    fn a_reader_that_stays_makes_the_retry_give_up_at_the_deadline() {
        let dir = TempDir::new("stays");
        let target = dir.0.join("state.json");
        let tmp = dir.0.join("state.json.tmp");
        std::fs::write(&target, b"old").expect("the target");
        std::fs::write(&tmp, b"new").expect("the tmp");
        let _reader = hold_without_share_delete(&target);
        let start = std::time::Instant::now();
        let error = retry_while_shared(|| std::fs::rename(&tmp, &target)).unwrap_err();
        assert!(is_shared_file_error(&error), "{error}");
        assert!(start.elapsed() >= crate::tuning::SHARED_FILE_RETRY_DEADLINE);
    }

    /// Open `path` as a `PowerShell` reader does: with no `FILE_SHARE_DELETE` on
    /// Windows. On Unix a plain open, which blocks nothing.
    fn hold_without_share_delete(path: &std::path::Path) -> std::fs::File {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;

            use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
            options.share_mode(FILE_SHARE_READ);
        }
        options.open(path).expect("the reader")
    }

    fn close_after(reader: std::fs::File, wait: Duration) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            std::thread::sleep(wait);
            drop(reader);
        })
    }
}
