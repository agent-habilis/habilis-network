use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::DaemonState;
use crate::protocol::{MeshId, Nickname};
use crate::util::process;
use crate::util::process_start::ProcessStart;

/// What a daemon wrote into its registry file, after it took the lock of the file: one line of JSON,
/// `{"pid":N,"start":N,"mesh":"<mesh id>","nickname":"<nickname>","state_file":"<absolute path>"}`.
///
/// The record is a hint for a person or a tool, and the lock is the truth for a caller that removes
/// files: read a record to list the daemons, and take the lock before you remove anything. The state
/// file is the real path of the daemon, or, for a run with no state file of its own, the default path
/// of the mesh and the nickname.
///
/// # Examples
///
/// A record that names a pid with another start is not live.
///
/// ```
/// use habilis_network::runtime::{DaemonRecord, DaemonState};
///
/// # fn demo(record: &DaemonRecord) {
/// // A reused pid has another start, so it reads as gone, not live.
/// let _state: DaemonState = record.state();
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DaemonRecord {
    /// The pid of the daemon.
    pub pid: u32,
    /// The start of the daemon process, as [`process::start_of`] gave it.
    pub start: u64,
    /// The mesh of the daemon.
    pub mesh: MeshId,
    /// The nickname of the daemon on the mesh.
    pub nickname: Nickname,
    /// The state file of the daemon, as an absolute path.
    pub state_file: PathBuf,
}

/// The text of a record, as it is written.
#[derive(Serialize)]
struct LineOut<'record> {
    pid: u32,
    start: u64,
    mesh: &'record str,
    nickname: &'record str,
    state_file: &'record Path,
}

/// The text of a record, as it is read: strings, so that a value that is no valid id reads as no record.
#[derive(Deserialize)]
struct LineIn {
    pid: u32,
    start: u64,
    mesh: String,
    nickname: String,
    state_file: PathBuf,
}

impl DaemonRecord {
    pub(in crate::daemon) fn new(
        pid: u32,
        start: u64,
        mesh: MeshId,
        nickname: Nickname,
        state_file: PathBuf,
    ) -> Self {
        Self {
            pid,
            start,
            mesh,
            nickname,
            state_file,
        }
    }

    /// The record as one line of text, with the newline.
    pub(in crate::daemon) fn to_line(&self) -> serde_json::Result<String> {
        let line = LineOut {
            pid: self.pid,
            start: self.start,
            mesh: self.mesh.as_str(),
            nickname: self.nickname.as_str(),
            state_file: &self.state_file,
        };
        serde_json::to_string(&line).map(|text| format!("{text}\n"))
    }

    /// The record in `text`, or `None` for an empty or cut line, and for a value that is no valid id.
    pub(super) fn parse(text: &str) -> Option<Self> {
        let line: LineIn = serde_json::from_str(text.trim()).ok()?;
        Some(Self {
            pid: line.pid,
            start: line.start,
            mesh: MeshId::try_new(&line.mesh).ok()?,
            nickname: Nickname::try_new(&line.nickname).ok()?,
            state_file: line.state_file,
        })
    }

    /// Whether the daemon of this record runs: the pid and the start say it, with no lock taken.
    #[must_use]
    pub fn state(&self) -> DaemonState {
        let now = process::start_of(self.pid);
        if let ProcessStart::Live(start) = now {
            return if start == self.start {
                DaemonState::Live
            } else {
                DaemonState::Gone
            };
        }
        if matches!(now, ProcessStart::Unknown(_)) {
            DaemonState::Unknown
        } else {
            DaemonState::Gone
        }
    }
}
