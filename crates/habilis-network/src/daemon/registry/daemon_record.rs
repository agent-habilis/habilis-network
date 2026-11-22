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
        self.state_given(&process::start_of(self.pid))
    }

    /// The state of the daemon of this record, given what the system says of its pid.
    fn state_given(&self, now: &ProcessStart) -> DaemonState {
        match now {
            ProcessStart::Live(start) if *start == self.start => DaemonState::Live,
            ProcessStart::Live(_) | ProcessStart::Gone => DaemonState::Gone,
            ProcessStart::Unknown(_) => DaemonState::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;
    use std::process::{self, Command};

    use super::{DaemonRecord, DaemonState};
    use crate::protocol::{Mesh, MeshConfig, MeshId, MeshName, Nickname, Seed};
    use crate::util::process as system;
    use crate::util::process_start::ProcessStart;

    /// The record of a daemon with this pid and start, on the id of a real mesh.
    fn record(pid: u32, start: u64) -> DaemonRecord {
        let name = MeshName::try_new("chat").expect("a name");
        let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback config");
        let mesh = Mesh::try_new(Seed::new([4u8; 32]), name, config).expect("a mesh");
        let id = MeshId::try_new(&mesh.to_string()).expect("the id of a real mesh");
        let nickname = Nickname::try_new("swift-cedar").expect("a nickname");
        DaemonRecord::new(pid, start, id, nickname, PathBuf::from("/tmp/state.json"))
    }

    /// The decision that leave acts on, in its 3 cases: it signals a pid only for a record that is live.
    #[test]
    fn the_state_of_a_daemon_follows_what_the_system_says_of_its_pid_and_start() {
        let _guard = ::habilis_network_test_tracing::init();
        let record = record(4242, 7);

        let same = record.state_given(&ProcessStart::Live(7));
        let reused = record.state_given(&ProcessStart::Live(8));
        let gone = record.state_given(&ProcessStart::Gone);
        let failed =
            record.state_given(&ProcessStart::Unknown(io::Error::other("the read failed")));

        assert_eq!(same, DaemonState::Live, "the pid has the recorded start");
        assert_eq!(
            reused,
            DaemonState::Gone,
            "a process that reuses the pid is not the daemon"
        );
        assert_eq!(gone, DaemonState::Gone, "no process has the pid");
        assert_eq!(failed, DaemonState::Unknown, "a failed read says nothing");
    }

    /// The same decision on real processes: this process with its own start is live, the same pid with another
    /// start is gone, and the pid of a child that was reaped is gone.
    #[test]
    fn the_state_of_a_record_is_read_from_the_real_process() {
        let _guard = ::habilis_network_test_tracing::init();
        let pid = process::id();
        let ProcessStart::Live(start) = system::start_of(pid) else {
            panic!("this process is live");
        };
        let mut child = Command::new("true").spawn().expect("a child");
        let child_pid = child.id();
        let child_start = match system::start_of(child_pid) {
            ProcessStart::Live(started) => started,
            ProcessStart::Gone | ProcessStart::Unknown(_) => 0,
        };
        child.wait().expect("the child is reaped");

        let own = record(pid, start).state();
        let reused = record(pid, start + 1).state();
        let reaped = record(child_pid, child_start).state();

        assert_eq!(own, DaemonState::Live, "this process with its own start");
        assert_eq!(reused, DaemonState::Gone, "this pid with another start");
        assert_eq!(reaped, DaemonState::Gone, "the pid of a reaped child");
    }
}
