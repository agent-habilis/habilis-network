//! The files that a run makes under the runtime base and that nobody else owns.

use std::path::{Path, PathBuf};
use std::{fs, io};

/// The control socket that a run bound and the chunk folder of its store. A clean end of the run
/// removes both, so a run does not leave its files behind: the socket is of no use once the process is
/// gone, and a node that keeps its identity starts again with a socket and a folder of its own. The
/// runtime base holds one live daemon for each mesh and nickname (the daemon lock), so no other run
/// makes a file at these paths while this run lives. The lock files and the tracing log stay, because
/// a flock race follows a deleted lock and the log is for the operator.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(in crate::daemon) struct OwnedFiles {
    pub(in crate::daemon) socket: Option<PathBuf>,
    pub(in crate::daemon) chunks: Option<PathBuf>,
}

impl OwnedFiles {
    /// Removes what the run made. A file that is already gone is no fault.
    pub(in crate::daemon) fn remove(&self) {
        if let Some(socket) = self.socket.as_ref() {
            note_failure(socket, fs::remove_file(socket));
        }
        if let Some(chunks) = self.chunks.as_ref() {
            note_failure(chunks, fs::remove_dir_all(chunks));
        }
    }
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
        let kept: [PathBuf; 3] = [
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

        let owned = OwnedFiles {
            socket: Some(socket.clone()),
            chunks: Some(chunks.clone()),
        };
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
