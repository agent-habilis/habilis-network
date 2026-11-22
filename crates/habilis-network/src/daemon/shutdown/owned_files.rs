//! The files that a run makes under the runtime base and that nobody else owns.

use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::{fs, io};

/// The device, the inode and the creation time of a file: what tells the file that a run made from a file
/// that a later run made at the same path. A file system can give the inode of a file that is gone to the
/// next file in the folder, and then the creation time tells them apart.
type FileId = (u64, u64, SystemTime);

/// The control socket that a run bound and the chunk folder of its store. A clean end of the run
/// removes both, so a run does not leave its files behind: the socket is of no use once the process is
/// gone, and a node that keeps its identity starts again with a socket and a folder of its own. The
/// removal is only for the files that this run made: a path that holds another file by then, made by a
/// later run of the same nickname, stays. The lock files and the tracing log stay, because a flock race
/// follows a deleted lock and the log is for the operator.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(in crate::daemon) struct OwnedFiles {
    pub(in crate::daemon) socket: Option<PathBuf>,
    pub(in crate::daemon) chunks: Option<PathBuf>,
    socket_id: Option<FileId>,
    chunks_id: Option<FileId>,
}

impl OwnedFiles {
    /// The files that this run made, with the identity that they have now. Both files must exist before
    /// the claim: a path with no file yet has no identity, and the run then proves no claim on it and
    /// removes nothing there, with no error.
    #[cfg(feature = "host")]
    pub(in crate::daemon) fn claim(socket: Option<PathBuf>, chunks: Option<PathBuf>) -> Self {
        let socket_id = socket.as_deref().and_then(file_id);
        let chunks_id = chunks.as_deref().and_then(file_id);
        Self {
            socket,
            chunks,
            socket_id,
            chunks_id,
        }
    }

    /// Removes what the run made, and only that: a path that holds another file now, or none, is left as
    /// it is. A file that is already gone is no fault.
    pub(in crate::daemon) fn remove(&self) {
        if let Some(socket) = self.socket.as_ref()
            && is_the_file(socket, self.socket_id)
        {
            note_failure(socket, fs::remove_file(socket));
        }
        if let Some(chunks) = self.chunks.as_ref()
            && is_the_file(chunks, self.chunks_id)
        {
            note_failure(chunks, fs::remove_dir_all(chunks));
        }
    }
}

/// The identity of the file at `path`, with no link followed. `None` when there is no file, and where the
/// system has no inode (the run then claims nothing).
#[cfg(unix)]
fn file_id(path: &Path) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::symlink_metadata(path).ok()?;
    // Where the system gives no creation time, the run claims nothing. The log says so, because a clean
    // leave then leaves the file.
    let created = match metadata.created() {
        Ok(created) => created,
        Err(error) => {
            tracing::debug!(target: "habilis_network::lifecycle", path = %path.display(), %error, "no creation time: the run claims no identity for this file and will not remove it");
            return None;
        }
    };
    Some((metadata.dev(), metadata.ino(), created))
}

#[cfg(not(unix))]
fn file_id(_path: &Path) -> Option<FileId> {
    None
}

/// Whether the file at `path` is the one with the identity `claimed`, which the run recorded.
fn is_the_file(path: &Path, claimed: Option<FileId>) -> bool {
    claimed.is_some() && file_id(path) == claimed
}

/// A file that is already gone is what the run wants, so it is no fault. Another failure goes to the
/// log: the files are left, and the next sweep of the operator takes them.
fn note_failure(path: &Path, result: io::Result<()>) {
    if let Err(error) = result
        && error.kind() != io::ErrorKind::NotFound
    {
        tracing::debug!(target: "habilis_network::lifecycle", path = %path.display(), %error, "a file of the run stays");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use std::{env, fs, process};

    use super::OwnedFiles;

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

    /// A clean end removes the socket and the chunk folder with its files, and it leaves the lock
    /// files and the tracing log of the same member.
    #[test]
    fn a_clean_end_removes_the_socket_and_the_chunk_folder_and_keeps_the_locks_and_the_log() {
        let _guard = ::habilis_network_test_tracing::init();
        let dir = TempDir::new("owned-files-removed");
        let folder = dir.path();
        let socket = folder.join("swift-cedar.ipc.sock");
        let chunks = folder.join("swift-cedar.chunks");
        let kept = [
            folder.join("swift-cedar.state.key.lock"),
            folder.join("swift-cedar.state.run.lock"),
            folder.join("swift-cedar.tracing.log"),
        ];
        let chunk_bucket = chunks.join("ab");
        fs::write(&socket, b"").expect("a socket file");
        fs::create_dir_all(&chunk_bucket).expect("a chunk folder");
        fs::write(chunk_bucket.join("chunk"), b"bytes").expect("a chunk");
        for path in &kept {
            fs::write(path, b"").expect("a kept file");
        }

        let owned = OwnedFiles::claim(Some(socket.clone()), Some(chunks.clone()));
        owned.remove();

        assert!(!socket.exists(), "the control socket is removed");
        assert!(
            !chunks.exists(),
            "the chunk folder is removed with its files"
        );
        for path in &kept {
            assert!(path.exists(), "{} stays", path.display());
        }
        owned.remove();
    }

    /// The files that this run made are removed, and the files that a later run of the same nickname made at
    /// the same paths stay: the old run ends after the new one bound its socket and opened its folder.
    #[test]
    fn a_clean_end_leaves_the_files_that_a_later_run_made_at_the_same_paths() {
        let _guard = ::habilis_network_test_tracing::init();
        let dir = TempDir::new("owned-files-later-run");
        let folder = dir.path();
        let socket = folder.join("swift-cedar.ipc.sock");
        let chunks = folder.join("swift-cedar.chunks");
        fs::write(&socket, b"old").expect("the socket of the old run");
        fs::create_dir_all(chunks.join("ab")).expect("the chunk folder of the old run");
        let old_run = OwnedFiles::claim(Some(socket.clone()), Some(chunks.clone()));

        // A later run makes its own files at the same paths while the old ones still exist, so that
        // the new files cannot take the inode of the old ones.
        let new_socket = folder.join("new.sock");
        fs::write(&new_socket, b"new").expect("the socket of the new run");
        fs::rename(&new_socket, &socket).expect("the new socket takes the path");
        let aside = folder.join("old.chunks");
        fs::rename(&chunks, &aside).expect("the old folder moves aside");
        fs::create_dir_all(chunks.join("cd")).expect("the chunk folder of the new run");

        old_run.remove();

        assert_eq!(
            fs::read(&socket).expect("the new socket is still there"),
            b"new",
            "the socket of the later run stays"
        );
        assert!(
            chunks.join("cd").exists(),
            "the chunk folder of the later run stays"
        );
    }

    /// A file system can give the inode of a file that is gone to the next file in the folder, so the
    /// device and the inode alone can name a later run's file as this run's. The creation time is part of
    /// the identity too: a file with the same inode and another creation time is another file.
    #[test]
    fn a_file_with_the_same_inode_and_another_creation_time_is_another_file() {
        let _guard = ::habilis_network_test_tracing::init();
        let dir = TempDir::new("owned-files-same-inode");
        let socket = dir.path().join("swift-cedar.ipc.sock");
        fs::write(&socket, b"later").expect("the socket of the later run");
        let mut run = OwnedFiles::claim(Some(socket.clone()), None);
        // The run recorded the creation time of another file that had this inode before.
        run.socket_id = run
            .socket_id
            .map(|(device, inode, created)| (device, inode, created - Duration::from_secs(60)));

        run.remove();

        assert!(socket.exists(), "a file with another creation time stays");
    }

    /// A run that bound no socket and opened no folder owns nothing, and a second removal of the
    /// same files is no fault.
    #[test]
    fn a_run_that_owns_no_file_removes_nothing() {
        let _guard = ::habilis_network_test_tracing::init();
        let dir = TempDir::new("owned-files-none");
        let other = dir.path().join("other-nick.ipc.sock");
        fs::write(&other, b"").expect("another member's socket");

        OwnedFiles::default().remove();

        assert!(other.exists(), "a file that the run does not own stays");
    }
}
