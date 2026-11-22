//! A member of a node whose owner process is gone, held for its removal.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::util::process;

/// The member key and the run counter of a node whose owner process is gone, with the lock of the key
/// held. A sweep that removes the files of dead members takes one of these first: while it lives, no
/// start of that member can take the lock and read the key that is about to go.
#[derive(Debug)]
#[must_use]
pub struct DeadMember {
    state: PathBuf,
    _lock: File,
}

impl DeadMember {
    /// The state path that the member files live beside.
    #[must_use]
    pub fn state_path(&self) -> &Path {
        &self.state
    }

    /// Remove the member key and the run counter, while the lock is held. The lock files stay, because
    /// a lock file that is deleted while another process waits for it makes a second lock.
    ///
    /// # Errors
    /// A file that exists could not be removed.
    pub fn remove(self) -> io::Result<()> {
        let mut failure = None;
        for extension in ["key", "run", "run.tmp"] {
            match fs::remove_file(self.state.with_extension(extension)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => failure = Some(error),
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

/// Take the member of `state` when its owner is gone. The key file names the start time of the process
/// that the member was bound to, and `owner_pid` is the pid of that process, which the caller knows from
/// its own naming (the engine does not record it). The member is dead when no process has `owner_pid`
/// with that start time. **The caller must pass the pid that the member was bound to.** A wrong pid
/// reads as an owner that is gone and gives the guard, and the removal then loses a member key that a
/// live node uses. The answer is `None` when there is no key file, when the key file records no
/// owner, when the owner is alive, and when a live daemon holds the lock of the key.
///
/// # Errors
/// The key file or the lock file could not be read or opened.
pub fn take_dead_member(state: &Path, owner_pid: u32) -> io::Result<Option<DeadMember>> {
    let key_path = state.with_extension("key");
    if !key_path.exists() {
        return Ok(None);
    }
    let lock = super::open_key_lock(state).map_err(io::Error::other)?;
    if !super::try_key_lock(&lock, state).map_err(io::Error::other)? {
        return Ok(None);
    }
    // Read under the lock: a start that replaced the key before the lock was taken is read as it is now.
    let mut reading = OpenOptions::new();
    reading.read(true);
    let mut file = match super::open_trusted_key_file(&key_path, &mut reading) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    // The buffer holds the seed, so it wipes itself.
    let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    file.read_to_end(&mut bytes)?;
    let tail = bytes.get(32..40);
    let recorded = tail.and_then(|tail| <[u8; 8]>::try_from(tail).ok());
    let start = recorded.map_or(0, u64::from_le_bytes);
    if start == 0 || process::live_start_time(owner_pid) == Some(start) {
        return Ok(None);
    }
    Ok(Some(DeadMember {
        state: state.to_path_buf(),
        _lock: lock,
    }))
}

#[cfg(all(test, unix, feature = "host"))]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::path::{Path, PathBuf};
    use std::{env, fs, process};

    use crate::util::process as process_util;

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

    /// A key file that the engine wrote for an owner that started at `start`: the seed, the start of the
    /// owner (8 bytes), and the run (8 bytes).
    fn write_member(state: &Path, start: u64) {
        let mut bytes = vec![7u8; 32];
        bytes.extend_from_slice(&start.to_le_bytes());
        bytes.extend_from_slice(&3u64.to_le_bytes());
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options
            .open(state.with_extension("key"))
            .expect("a key file");
        file.write_all(&bytes).expect("the key bytes");
        fs::write(state.with_extension("run"), b"3").expect("a run counter file");
        fs::write(state.with_extension("key.lock"), b"").expect("a lock file");
    }

    /// A child process that has ended: its pid and the start time that it had.
    fn ended_process() -> (u32, u64) {
        let mut child: process::Child = process::Command::new("sleep")
            .arg("120")
            .spawn()
            .expect("a sleep process");
        let pid = child.id();
        let start = process_util::live_start_time(pid).expect("a live process has a start time");
        drop(child.kill());
        drop(child.wait());
        (pid, start)
    }

    /// An owner that is gone gives its member, and the removal takes the key and the run counter while
    /// the lock files stay.
    #[test]
    fn a_member_whose_owner_is_gone_is_taken_and_removed_with_the_lock_files_kept() {
        let _guard = ::habilis_network_test_tracing::init();
        let dir = TempDir::new("dead-member-gone");
        let state = dir.path().join("session.json");
        let (pid, start) = ended_process();
        write_member(&state, start);

        let dead = super::take_dead_member(&state, pid)
            .expect("the files are readable")
            .expect("the owner is gone");
        dead.remove().expect("the files go");

        assert!(!state.with_extension("key").exists(), "the key goes");
        assert!(
            !state.with_extension("run").exists(),
            "the run counter goes"
        );
        assert!(
            state.with_extension("key.lock").exists(),
            "the lock file stays"
        );
    }

    /// While the guard lives, a start of the member cannot take the lock of its key.
    #[test]
    fn a_start_of_the_member_cannot_take_the_lock_while_the_guard_lives() {
        let _guard = ::habilis_network_test_tracing::init();
        let dir = TempDir::new("dead-member-guard");
        let state = dir.path().join("session.json");
        let (pid, start) = ended_process();
        write_member(&state, start);
        let dead = super::take_dead_member(&state, pid)
            .expect("the files are readable")
            .expect("the owner is gone");

        let rival: fs::File = fs::OpenOptions::new()
            .write(true)
            .open(state.with_extension("key.lock"))
            .expect("a second handle on the lock file");
        assert!(
            rival.try_lock().is_err(),
            "a start of the member finds the lock held"
        );
        drop(dead);
        assert!(rival.try_lock().is_ok(), "the lock is free after the guard");
    }

    /// A live owner, a key with no owner, no key file, and a held lock all give no member.
    #[test]
    fn a_live_owner_no_owner_no_file_and_a_held_lock_give_no_member() {
        let _guard = ::habilis_network_test_tracing::init();
        let dir = TempDir::new("dead-member-none");
        let state = dir.path().join("session.json");
        assert!(
            super::take_dead_member(&state, 4242)
                .expect("no file is no error")
                .is_none(),
            "no key file"
        );

        let live: process::Child = process::Command::new("sleep")
            .arg("120")
            .spawn()
            .expect("a sleep process");
        let pid = live.id();
        let _killer = Killer(Some(live));
        let start = process_util::live_start_time(pid).expect("a start time");
        write_member(&state, start);
        assert!(
            super::take_dead_member(&state, pid)
                .expect("the files are readable")
                .is_none(),
            "the owner is alive with that start time"
        );

        write_member(&state, 0);
        assert!(
            super::take_dead_member(&state, pid)
                .expect("the files are readable")
                .is_none(),
            "a key that records no owner is no dead member"
        );

        let (gone, gone_start) = ended_process();
        write_member(&state, gone_start);
        let holder: fs::File = fs::OpenOptions::new()
            .write(true)
            .open(state.with_extension("key.lock"))
            .expect("the lock file opens");
        holder.try_lock().expect("the lock is free");
        assert!(
            super::take_dead_member(&state, gone)
                .expect("the files are readable")
                .is_none(),
            "a live daemon holds the lock"
        );
        drop(holder);
    }

    /// Kills the child when it drops.
    struct Killer(Option<process::Child>);

    impl Drop for Killer {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                drop(child.kill());
                drop(child.wait());
            }
        }
    }
}
