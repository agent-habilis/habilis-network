//! The registry of the daemons of a runtime base: one lock file for each mesh and nickname, in the folder
//! `<runtime base>/locks`. A daemon takes the lock of its file for its whole run and writes a
//! [`DaemonRecord`] into it. The files stay when the daemons end, so the registry holds one small file
//! for each mesh and nickname that was used, until the runtime base goes.
//!
//! A reader lists the files with [`registry`] and reads a record with [`read_record`], which take no
//! lock; [`DaemonRecord::state`] says from the pid and the start whether the daemon runs. The lock has one
//! mode, exclusive, and two holders: the daemon that runs, for its whole run, and a caller that waits for the
//! end of a daemon with [`wait_daemon_lock`] and drops the [`FreeGuard`] at once. No function here creates or
//! removes a file.

mod daemon_record;
mod daemon_state;
mod free_guard;

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

pub use daemon_record::DaemonRecord;
pub use daemon_state::DaemonState;
pub use free_guard::FreeGuard;

use crate::protocol::{MeshId, Nickname};
use crate::util;

/// The folder of the lock files, under the runtime base.
const LOCKS_FOLDER: &str = "locks";

/// The lock file of the daemon of `nickname` on `mesh`: `<runtime base>/locks/<mesh folder>-<nickname>.lock`.
/// The mesh folder is the first 16 characters of the mesh id.
///
/// # Examples
///
/// The lock file is in the locks folder of the runtime base.
///
/// ```
/// use std::path::Path;
/// use habilis_network::protocol::{MeshId, Nickname};
/// use habilis_network::runtime::daemon_lock_path;
///
/// # fn demo(mesh: &MeshId, nickname: &Nickname) {
/// let path = daemon_lock_path(Path::new("/tmp/base"), mesh, nickname);
/// assert!(path.starts_with("/tmp/base/locks"));
/// # }
/// ```
#[must_use]
pub fn daemon_lock_path(base: &Path, mesh: &MeshId, nickname: &Nickname) -> PathBuf {
    let folder = util::mesh_prefix(mesh.as_str());
    base.join(LOCKS_FOLDER)
        .join(format!("{folder}-{nickname}.lock"))
}

/// The lock files of the runtime base: the regular files of `<runtime base>/locks`, in no fixed order. A link or a
/// folder is not listed, and a base with no locks folder has no lock files. The listing reads the folder as the
/// caller goes on, and an entry that cannot be read is an error item.
///
/// # Errors
/// The locks folder cannot be opened.
pub fn registry(base: &Path) -> io::Result<impl Iterator<Item = io::Result<PathBuf>>> {
    let entries = match fs::read_dir(base.join(LOCKS_FOLDER)) {
        Ok(entries) => Some(entries),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    Ok(entries.into_iter().flatten().filter_map(lock_file_of))
}

/// The path of a regular file among the entries of the locks folder. The type of a directory entry does not follow
/// a link, so a link is not a lock file.
fn lock_file_of(entry: io::Result<fs::DirEntry>) -> Option<io::Result<PathBuf>> {
    let entry = match entry {
        Ok(entry) => entry,
        Err(error) => return Some(Err(error)),
    };
    match entry.file_type() {
        Ok(kind) if kind.is_file() => Some(Ok(entry.path())),
        Ok(_) => None,
        Err(error) => Some(Err(error)),
    }
}

/// The record in the lock file `lock_path`, read with no lock. `None` for an empty or a cut line: the
/// daemon has taken the lock and has not written its record yet. The record of a daemon that is gone stays
/// in the file, so check [`DaemonRecord::state`].
///
/// # Errors
/// The file cannot be read. A file that does not exist is [`io::ErrorKind::NotFound`]: no such member.
pub fn read_record(lock_path: &Path) -> io::Result<Option<DaemonRecord>> {
    let text = fs::read_to_string(lock_path)?;
    Ok(DaemonRecord::parse(&text))
}

/// Take the lock of `lock_path`, and wait for the daemon that holds it to end: the call returns when the daemon is
/// gone, which is when it has removed its files. The wait has no time limit inside it, so the caller sets one, and
/// it blocks the thread that calls it. Drop the guard at once: a daemon that starts for the member while the guard
/// lives is refused.
///
/// # Errors
/// The file cannot be opened or locked. A file that does not exist is [`io::ErrorKind::NotFound`].
pub fn wait_daemon_lock(lock_path: &Path) -> io::Result<FreeGuard> {
    let file = open_existing(lock_path)?;
    file.lock()?;
    Ok(FreeGuard::new(file))
}

/// The lock file as it is, read only: a missing file is no member, and none is made.
fn open_existing(lock_path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(lock_path)
}

#[cfg(test)]
mod tests {
    use std::fs::{OpenOptions, TryLockError};
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::{env, fs, io, process};

    use super::{DaemonRecord, read_record, registry, wait_daemon_lock};
    use crate::protocol::{Mesh, MeshConfig, MeshId, MeshName, Nickname, Seed};

    /// A folder that goes away when the test ends, also when an assert fails.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = env::temp_dir().join(format!("{name}-{}", process::id()));
            drop(fs::remove_dir_all(&dir));
            fs::create_dir_all(&dir).expect("a temp dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.0));
        }
    }

    /// The record of a daemon, on the id of a real mesh.
    fn a_record() -> DaemonRecord {
        let name = MeshName::try_new("chat").expect("a name");
        let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback config");
        let mesh = Mesh::try_new(Seed::new([4u8; 32]), name, config).expect("a mesh");
        let id = MeshId::try_new(&mesh.to_string()).expect("the id of a real mesh");
        let nickname = Nickname::try_new("swift-cedar").expect("a nickname");
        DaemonRecord::new(4242, 7, id, nickname, PathBuf::from("/tmp/state.json"))
    }

    /// The registry lists the regular files of the locks folder, and no link and no folder.
    #[test]
    fn the_registry_lists_the_regular_files_of_the_locks_folder_only() {
        let _guard = ::habilis_network_test_tracing::init();
        let dir = TempDir::new("registry-list");
        let locks = dir.path().join("locks");
        fs::create_dir_all(locks.join("a-folder.lock")).expect("a folder");
        fs::write(locks.join("b-member.lock"), "").expect("a lock file");
        fs::write(locks.join("a-member.lock"), "").expect("a lock file");
        symlink(locks.join("a-member.lock"), locks.join("c-link.lock")).expect("a link");

        let entries = registry(dir.path()).expect("the locks folder is read");
        let mut listed: Vec<PathBuf> = entries
            .map(|entry| entry.expect("an entry is read"))
            .collect();
        listed.sort();

        assert_eq!(
            listed,
            vec![locks.join("a-member.lock"), locks.join("b-member.lock")],
            "two regular files: no folder, no link"
        );
    }

    /// A runtime base with no locks folder has no daemons, and reading it makes nothing.
    #[test]
    fn a_base_with_no_locks_folder_lists_nothing_and_makes_nothing() {
        let _guard = ::habilis_network_test_tracing::init();
        let dir = TempDir::new("registry-none");

        let listed = registry(dir.path()).expect("a base with no locks folder is read");

        assert_eq!(listed.count(), 0, "no lock files");
        assert!(
            !dir.path().join("locks").exists(),
            "reading the registry makes no folder"
        );
    }

    /// A record is read with no lock, and a missing file, an empty file and a cut line say so.
    #[test]
    fn a_record_is_read_and_a_missing_or_cut_record_is_not_one() {
        let _guard = ::habilis_network_test_tracing::init();
        let dir = TempDir::new("registry-record");
        let file = dir.path().join("member.lock");
        let written = a_record();
        let line = written.to_line().expect("the record is text");
        fs::write(&file, &line).expect("a record");

        let read = read_record(&file).expect("the file is read");

        assert_eq!(
            read,
            Some(written),
            "the record comes back as it was written"
        );
        assert_eq!(line.lines().count(), 1, "one line: {line:?}");

        fs::write(&file, "").expect("an empty file");
        assert!(
            read_record(&file).expect("read").is_none(),
            "an empty file has no record"
        );
        fs::write(&file, &line[..30]).expect("a cut line");
        assert!(
            read_record(&file).expect("read").is_none(),
            "a cut line has no record"
        );
        let missing = read_record(&dir.path().join("none.lock")).expect_err("no such file");
        assert_eq!(missing.kind(), io::ErrorKind::NotFound, "no such member");
    }

    /// The wait takes the lock of an existing file, holds it while the guard lives, and makes no file.
    #[test]
    fn the_wait_takes_the_lock_of_an_existing_file_and_makes_none() {
        let _guard = ::habilis_network_test_tracing::init();
        let dir = TempDir::new("registry-lock");
        let file = dir.path().join("member.lock");
        let missing = dir.path().join("none.lock");
        fs::write(&file, "").expect("a lock file");

        let guard = wait_daemon_lock(&file).expect("the lock is free");
        let other = OpenOptions::new()
            .read(true)
            .open(&file)
            .expect("the file opens");
        let held = other.try_lock();
        drop(guard);
        let freed = other.try_lock();
        let wait_missing = wait_daemon_lock(&missing).expect_err("no such file");

        assert!(
            matches!(held, Err(TryLockError::WouldBlock)),
            "the guard holds the lock: {held:?}"
        );
        assert!(
            freed.is_ok(),
            "the lock is free when the guard drops: {freed:?}"
        );
        assert_eq!(
            wait_missing.kind(),
            io::ErrorKind::NotFound,
            "no such member"
        );
        assert!(!missing.exists(), "the wait makes no lock file");
    }
}
