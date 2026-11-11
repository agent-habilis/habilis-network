//! Session state file — the daemon writes its
//! view of the mesh into this file so external tools (e.g. a shell
//! statusline) and the `/gossip-*` skills can render the current mesh,
//! nickname, and peer count with a plain local file read. No
//! IPC, no gossip, no subprocess.
//!
//! The daemon is the **sole writer**: the `/gossip-*` skills are
//! read-only and never touch this file. The daemon owns every key —
//! `gossip`, `name`, `nickname`, `topic` (topic gossips only), `pid`,
//! `owner_pid` (daemons with an owner only), `ready`, `peer_count`,
//! `last_updated` — and writes a fresh,
//! complete document on each update (no read-merge: there are no foreign
//! keys to preserve).
//!
//! `topic` is the raw string a topic gossip was derived from. The derived
//! `name` is lossy (URL scheme and query stripped, truncated), so the
//! string is persisted whole — it is what a consumer's `leave` and its
//! skills echo for a topic gossip.
//!
//! `ready` is `false` at the early identity write and flips to `true`
//! once the event loop is serving IPC, so a reader (e.g. a readiness gate)
//! can gate on it rather than on the file's mere existence.
//! `peer_count` is the total number of agents in the mesh,
//! including self. `last_updated` is a unix timestamp the daemon
//! refreshes on a fixed heartbeat (see `tuning::STATE_REFRESH`)
//! even when membership is unchanged, so a reader can treat a fresh
//! value as a liveness signal. `pubkey` is the author key of the daemon
//! (64 lowercase hex digits), which is the identity of the member on the wire; the
//! nickname is a label. `pid` is the daemon's own process id —
//! what lets a consumer's `leave`/`session` map a state file back to a
//! running daemon (and, via its ancestry, to the agent session that
//! spawned it).
//!
//! File shape (keys are serialized in sorted order — `serde_json::Map` is a
//! `BTreeMap` here, no `preserve_order` feature):
//! ```json
//! {"last_updated":1776720604,"name":"cool-team","nickname":"treat-empire","peer_count":3,"pid":34299,"pubkey":"ab…ab","ready":true,"gossip":"..."}
//! ```
//!
//! Writes are atomic (tempfile + rename on the same filesystem), so a
//! reader that opens the file mid-update always sees a consistent JSON
//! document, and each write fully replaces any existing file.
//!
//! On Windows a reader that opens the file without `FILE_SHARE_DELETE` (the
//! `Get-Content` of `PowerShell`) blocks the rename and the remove while it
//! holds the file, so both run again for a short time
//! (`util::file_retry::retry_while_shared`). A reader that uses `std::fs` never
//! blocks them.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::protocol::meshes::MeshName;
use crate::protocol::{AuthorKey, MeshId, Nickname};
use crate::util::{file_retry, unix_secs};

use crate::util;
use std::io::ErrorKind;
use std::sync::atomic;
use std::{error, ffi, fmt, fs, io, process, sync};
/// Owns a session state file for the lifetime of a daemon process.
/// Drop removes the file (best effort), but because the daemon exits
/// via `std::process::exit`, callers must also call `remove()`
/// explicitly before exiting on SIGINT/SIGTERM.
///
/// # Examples
///
/// A state file holds the discovery fields that a daemon publishes for its peers. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::state_file::StateFile;
///
/// # fn demo(file: &StateFile) {
/// file.set_discovery(serde_json::Map::new());
/// # }
/// ```
#[derive(Debug)]
#[must_use]
pub struct StateFile {
    path: PathBuf,
    /// The consumer's runtime base, for the fail-closed squat check before each
    /// write. `None` when the consumer configured none — there is then no
    /// protected directory to validate, only a parent to create.
    base: Option<PathBuf>,
    mesh: String,
    name: String,
    nickname: String,
    /// The author key of the daemon, as 64 lowercase hex digits.
    pubkey: String,
    topic: Option<String>,
    owner_pid: Option<u32>,
    /// Extra fields the application publishes for its local clients to discover
    /// (see [`Self::set_discovery`]). Opaque to the engine, and the reason every
    /// write is 0o600: an app may put a bearer token in here.
    discovery: sync::Mutex<serde_json::Map<String, serde_json::Value>>,
    write_failing: atomic::AtomicBool,
    /// The lock on the member key of this start. The cleanup of this file deletes the member key
    /// and the run counter that live beside it, so the lock belongs to the value that does the
    /// cleanup: a replacement that waits for the lock gets it after the files are gone, and its own
    /// key and run counter cannot be deleted under it. Held, never read.
    // shared with the loop state, which holds the same lock for as long as this node runs
    key_lock: Option<sync::Arc<fs::File>>,
}

/// The keys of the state file that the daemon owns. A discovery field of the application never
/// replaces one of them.
const ENGINE_KEYS: [&str; 10] = [
    "gossip",
    "name",
    "nickname",
    "pubkey",
    "topic",
    "pid",
    "owner_pid",
    "ready",
    "peer_count",
    "last_updated",
];

impl StateFile {
    pub(crate) fn new(
        path: PathBuf,
        mesh: &MeshId,
        nickname: &Nickname,
        name: &MeshName,
        pubkey: &AuthorKey,
    ) -> Self {
        let mesh = mesh.as_str().to_string();
        let name = name.as_str().to_string();
        let nickname = nickname.as_str().to_string();
        Self {
            path,
            base: None,
            mesh,
            name,
            nickname,
            pubkey: pubkey.to_string(),
            topic: None,
            owner_pid: None,
            key_lock: None,
            discovery: sync::Mutex::new(serde_json::Map::new()),
            write_failing: atomic::AtomicBool::new(false),
        }
    }

    /// Attach the consumer's runtime base, so every write can run the
    /// fail-closed squat check against it. Left `None` by [`Self::new`] — a
    /// target outside any base (a `--state-file` override, a test temp dir) has
    /// no base to validate.
    pub(crate) fn base(mut self, base: Option<PathBuf>) -> Self {
        self.base = base;
        self
    }

    /// Attach the raw topic string a topic gossip was derived from, so every
    /// write publishes it as `topic`. A no-op `None` keeps the one
    /// construction site unconditional.
    pub(crate) fn topic(mut self, topic: Option<&str>) -> Self {
        self.topic = topic.map(str::to_owned);
        self
    }

    /// Attach the pid of the process the daemon lives for, so every write
    /// publishes it as `owner_pid`. A no-op `None`, as for [`Self::topic`].
    /// Hold the lock on the member key until this file is cleaned up (see the field of the same
    /// name).
    pub(crate) fn key_lock(mut self, key_lock: Option<sync::Arc<fs::File>>) -> Self {
        self.key_lock = key_lock;
        self
    }

    pub(crate) fn owner_pid(mut self, owner_pid: Option<u32>) -> Self {
        self.owner_pid = owner_pid;
        self
    }

    /// Merge application-owned fields into the document every subsequent write
    /// publishes — how an app advertises a locally-reachable binding to its own
    /// clients.
    ///
    /// The engine never interprets these. It does not know that a consumer
    /// writes its own port/token keys here, only that whatever an app puts in
    /// may be secret, which is why the file is born 0o600. Keys are merged, not
    /// replaced, so repeated calls accumulate. The keys of the daemon itself (`gossip`, `name`,
    /// `nickname`, `pubkey`, `topic`, `pid`, `owner_pid`, `ready`, `peer_count`, `last_updated`)
    /// cannot be replaced: the daemon writes its own value after the fields of the application,
    /// and drops a field of the application under a key that it does not write.
    ///
    /// # Panics
    /// Panics if an internal invariant is violated.
    pub fn set_discovery(&self, fields: serde_json::Map<String, serde_json::Value>) {
        let mut held = self
            .discovery
            .lock()
            .expect("state-file discovery mutex not poisoned");
        for (key, value) in fields {
            held.insert(key, value);
        }
    }

    /// Write a fresh, complete state document — `gossip`, `name`,
    /// `nickname`, `ready`, `peer_count`, and a fresh
    /// `last_updated` — atomically, fully replacing any existing file.
    /// `ready` is `false` at the early identity write and `true` once the
    /// daemon's event loop is serving IPC, so a reader can gate on it. The
    /// daemon is the sole writer (skills are read-only), so there is
    /// nothing to merge. Creates parent directories as needed. Errors are
    /// logged but not propagated — the statusline going stale must not
    /// crash the daemon.
    pub(crate) fn write(&self, peer_count: usize, ready: bool) {
        use std::sync::atomic::Ordering;

        match self.try_write(peer_count, ready) {
            Ok(()) => self.write_failing.store(false, Ordering::Relaxed),
            Err(error) => {
                let _ = fs::remove_file(tmp_sibling(&self.path));
                // Warn once per failing streak: the heartbeat retries every
                // few seconds, and a full disk fails every one of them.
                if !self.write_failing.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        target: "habilis_network::lifecycle",
                        path = %self.path.display(),
                        %error,
                        "state file write failed"
                    );
                }
            }
        }
    }

    fn try_write(&self, peer_count: usize, ready: bool) -> io::Result<()> {
        // The state file carries the full mesh id, and whatever the application
        // published as discovery fields (possibly a bearer token).
        // It is born 0o600 below, but the enclosing directory must
        // also be private. `ensure_parent_private` validates the base and fails
        // closed when the target is under it (the default path, and the plugin's
        // `--state-file <base>/sessions/...`), and just creates
        // the parent for an override that points elsewhere.
        util::ensure_parent_private(self.base.as_deref(), &self.path)?;
        // The fields of the application go in first, and the fields of the daemon replace them:
        // a discovery key can shadow no key of the daemon, and a key that the daemon does not
        // write (no topic, no owner) is not the application's to write either.
        let mut obj = self
            .discovery
            .lock()
            .expect("state-file discovery mutex not poisoned")
            .clone();
        for key in ENGINE_KEYS {
            obj.remove(key);
        }
        obj.insert("gossip".into(), self.mesh.clone().into());
        obj.insert("name".into(), self.name.clone().into());
        obj.insert("nickname".into(), self.nickname.clone().into());
        obj.insert("pubkey".into(), self.pubkey.clone().into());
        if let Some(topic) = &self.topic {
            obj.insert("topic".into(), topic.clone().into());
        }
        obj.insert("pid".into(), process::id().into());
        if let Some(owner_pid) = self.owner_pid {
            obj.insert("owner_pid".into(), owner_pid.into());
        }
        obj.insert("ready".into(), ready.into());
        obj.insert("peer_count".into(), peer_count.into());
        obj.insert(
            "last_updated".into(),
            unix_secs::UnixSecs::now().as_secs().into(),
        );
        let mut json = serde_json::to_vec(&obj).map_err(io::Error::other)?;
        json.push(b'\n');

        write_private_atomic(&self.path, &json)
    }

    /// Delete the state file, and the member key and the run counter that live beside it. A process
    /// that leaves takes its identity with it: the next process with the same pid, which names the
    /// same state file, starts as a new member. Safe to call on a path that does not exist. On
    /// Windows the delete of the state file runs again for a short time while a reader holds the
    /// file, and a file that still stays is logged. On Unix an error is ignored.
    pub(crate) fn remove(&self) {
        #[cfg(not(windows))]
        let _ = fs::remove_file(&self.path);
        #[cfg(windows)]
        match file_retry::retry_while_shared(|| fs::remove_file(&self.path)) {
            Err(error) if error.kind() != ErrorKind::NotFound => {
                tracing::warn!(
                    target: "habilis_network::lifecycle",
                    path = %self.path.display(),
                    %error,
                    "state file remove failed"
                );
            }
            _ => {}
        }
        for extension in ["key", "run", "run.tmp"] {
            let _ = fs::remove_file(self.path.with_extension(extension));
        }
    }
}

impl Drop for StateFile {
    fn drop(&mut self) {
        self.remove();
    }
}

/// What a readiness gate needs out of a state file on every poll: whether
/// the daemon is serving (`ready`) and how fresh that claim is (`last_updated`,
/// unix seconds — the daemon rewrites it on a fixed heartbeat, so a stale
/// `ready: true` left by a prior daemon killed with SIGKILL is rejected). The
/// session identity is read separately ([`read_identity`]) only on the success
/// path, so the poll loop allocates nothing beyond these two fields.
///
/// # Examples
///
/// A snapshot is read from a state file, and a missing file has none.
///
/// ```
/// use std::path::Path;
///
/// use habilis_network::runtime::state_file::read_snapshot;
///
/// assert!(read_snapshot(Path::new("/nonexistent/ready.json")).expect("a missing file is not an error").is_none());
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ReadySnapshot {
    /// Whether the daemon is ready.
    pub ready: bool,
    /// When the file was last written, in seconds since the epoch.
    pub last_updated: u64,
}

/// Best-effort session identity for a consumer's readiness report. Each field is
/// `None` when the state file is unreadable, not JSON, or predates that field
/// — so the JSON the gate prints carries only the keys actually present.
///
/// # Examples
///
/// An identity read from a missing session file names no mesh.
///
/// ```
/// use std::path::Path;
///
/// use habilis_network::runtime::state_file::read_identity;
///
/// let identity = read_identity(Path::new("/nonexistent/session.json"));
/// assert!(identity.mesh.is_none());
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SessionIdentity {
    /// The mesh id, as text.
    pub mesh: Option<String>,
    /// The name of the mesh.
    pub name: Option<String>,
    /// The nickname of the member.
    pub nickname: Option<String>,
    /// The author key of the member, as 64 lowercase hex digits.
    pub pubkey: Option<String>,
    /// The raw topic string; present only for a topic gossip.
    pub topic: Option<String>,
}

/// Read the session identity from the state file. Best-effort: a read/parse
/// failure yields all-`None` rather than an error, since identity is a
/// convenience on top of the gate, not part of what it blocks on. Called once,
/// on success — never in the poll loop (see [`ReadySnapshot`]).
///
/// # Examples
///
/// It reads the mesh identity of a session, and a missing file names no mesh.
///
/// ```
/// use std::path::Path;
///
/// use habilis_network::runtime::state_file::read_identity;
///
/// let identity = read_identity(Path::new("/nonexistent/session.json"));
/// assert!(identity.mesh.is_none());
/// ```
#[must_use]
pub fn read_identity(path: &Path) -> SessionIdentity {
    let parsed: Option<serde_json::Value> = fs::read_to_string(path)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok());
    let field = |key: &str| {
        let value = parsed.as_ref().and_then(|doc| doc.get(key));
        value.and_then(serde_json::Value::as_str).map(str::to_owned)
    };
    SessionIdentity {
        mesh: parsed.as_ref().and_then(mesh_field),
        name: field("name"),
        nickname: field("nickname"),
        pubkey: field("pubkey"),
        topic: field("topic"),
    }
}

/// The mesh-id key, falling back to the pre-rename `room` spelling: a daemon
/// from the previous release may still be running, and `ready`/`session`/
/// `leave` must map its file. The one home for that rule — retire the
/// fallback here when the compat window closes.
fn mesh_field(doc: &serde_json::Value) -> Option<String> {
    let keys = ["gossip", "room"];
    let spelling = keys.iter().find_map(|key| {
        let field = doc.get(key);
        field.and_then(serde_json::Value::as_str)
    });
    spelling.map(str::to_owned)
}

/// One running daemon as seen through its state file — what a consumer's
/// `leave` / `session` need to map the file back to a live process and decide
/// whether the calling session owns it. Every field is `Option`: a file
/// written by an older binary predates `pid`, and discovery must still be
/// able to *report* such an entry rather than error on it.
///
/// # Examples
///
/// A session entry is read from a session file, and a missing file has none.
///
/// ```
/// use std::path::Path;
///
/// use habilis_network::runtime::state_file::read_session_entry;
///
/// assert!(read_session_entry(Path::new("/nonexistent/session.json")).is_none());
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SessionEntry {
    /// The mesh id, as text.
    pub mesh: Option<String>,
    /// The name of the mesh.
    pub name: Option<String>,
    /// The nickname of the member.
    pub nickname: Option<String>,
    /// The raw topic string; present only for a topic gossip.
    pub topic: Option<String>,
    /// The process id of the daemon.
    pub pid: Option<u32>,
    /// The process the daemon lives for; present only for a daemon started
    /// with an owner (see `EventLoopConfig::owner_pid`).
    pub owner_pid: Option<u32>,
}

/// Read a state file as a [`SessionEntry`]. Best-effort: `None` only when
/// the file is unreadable or not a JSON object — a *degenerate* object still
/// yields an entry (all-`None` fields) so callers can decide per-field.
///
/// # Examples
///
/// It reads a session entry, and a missing file has none.
///
/// ```
/// use std::path::Path;
///
/// use habilis_network::runtime::state_file::read_session_entry;
///
/// assert!(read_session_entry(Path::new("/nonexistent/session.json")).is_none());
/// ```
#[must_use]
pub fn read_session_entry(path: &Path) -> Option<SessionEntry> {
    let parsed: serde_json::Value = fs::read_to_string(path)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())?;
    parsed.as_object()?;
    let text = |key: &str| {
        parsed
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let pid_field = |key: &str| {
        let value = parsed.get(key).and_then(serde_json::Value::as_u64);
        value.and_then(|pid| u32::try_from(pid).ok())
    };
    Some(SessionEntry {
        mesh: mesh_field(&parsed),
        name: text("name"),
        nickname: text("nickname"),
        topic: text("topic"),
        pid: pid_field("pid"),
        owner_pid: pid_field("owner_pid"),
    })
}

/// Read the readiness fields from the state file at `path`. `Ok(None)` when
/// the file does not exist yet (the daemon has not written it — a caller
/// polling for readiness should retry). `Ok(Some)` once it carries a valid
/// `ready` + `last_updated`.
///
/// # Errors
/// The file exists but is not valid JSON, or is missing the `ready` /
/// `last_updated` fields.
///
/// # Examples
///
/// It reads the ready snapshot of a daemon, and a missing file is not an error.
///
/// ```
/// use std::path::Path;
///
/// use habilis_network::runtime::state_file::read_snapshot;
///
/// assert!(read_snapshot(Path::new("/nonexistent/ready.json")).expect("a missing file is not an error").is_none());
/// ```
pub fn read_snapshot(path: &Path) -> Result<Option<ReadySnapshot>, StateFileError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StateFileError::Unreadable {
                path: path.to_path_buf(),
                source: Box::new(source),
            });
        }
    };
    let value: serde_json::Value =
        serde_json::from_str(&contents).map_err(|source| StateFileError::Unparsable {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;
    let ready = value["ready"]
        .as_bool()
        .ok_or_else(|| StateFileError::MissingField {
            path: path.to_path_buf(),
            what: "bool field `ready`",
        })?;
    let last_updated =
        value["last_updated"]
            .as_u64()
            .ok_or_else(|| StateFileError::MissingField {
                path: path.to_path_buf(),
                what: "integer field `last_updated`",
            })?;
    Ok(Some(ReadySnapshot {
        ready,
        last_updated,
    }))
}

/// Write `bytes` to `path` so that a reader sees the old file or the new one,
/// never half of one: a sibling `<file>.tmp.<pid>`, then a rename over the
/// target. The one writer of the state file and of the IPC marker.
///
/// On Windows the rename runs again for a short time while a reader holds the
/// target without `FILE_SHARE_DELETE` (R8 of `docs/windows.md`). The rename of
/// `std` already replaces a file that a reader holds with `FILE_SHARE_DELETE`.
///
/// The tmp name carries the pid and is opened with `create` + `truncate`, not
/// `create_new`: a tmp file that a killed process left behind is reused, and
/// does not make every later write fail.
///
/// # Errors
/// The create, the write, or the rename fails.
pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    // No fsync: statusline is best-effort; kernel buffer-writeback
    // is plenty. Atomic rename still gives readers a consistent view.
    let temp = tmp_sibling(path);
    // 0o600 at create, not chmod-after: an app's discovery fields may carry
    // a bearer token, and a create-then-chmod sequence leaves a
    // window where the token is written at the umask-default mode (often
    // world-readable) — a local co-tenant polling the predictable tmp
    // path could open an fd during that window (POSIX checks perms at
    // open, not per read). Being born at 0o600 closes the window; the
    // uniform mode also keeps the common (no-token) case indistinguishable.
    let mut file = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true).mode(0o600);
            options.open(&temp)?
        }
        #[cfg(not(unix))]
        {
            fs::File::create(&temp)?
        }
    };
    file.write_all(bytes)?;
    drop(file);
    let renamed = file_retry::retry_while_shared(|| fs::rename(&temp, path));
    // On Windows a failed rename removes the tmp file here, for the IPC
    // marker. `StateFile::write` removes it on every OS after any error, as
    // before the port.
    #[cfg(windows)]
    if renamed.is_err() {
        let _ = fs::remove_file(&temp);
    }
    renamed
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(ffi::OsStr::to_os_string)
        .unwrap_or_default();
    file_name.push(format!(".tmp.{}", process::id()));
    path.with_file_name(file_name)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::StateFileError;

    use crate::testing;
    use std::error::Error;
    #[cfg(windows)]
    use std::path;
    #[cfg(unix)]
    use std::sync::Arc;
    #[cfg(windows)]
    use std::thread;
    #[cfg(windows)]
    use std::time;
    use std::{env, fs, io, process};
    /// The variants of a public error hold a boxed source, so no third-party type is named in
    /// the public API. This builds them that way.
    #[test]
    fn the_state_file_variants_hold_boxed_sources() {
        let _guard = ::habilis_network_test_tracing::init();
        let decoded: serde_json::Result<u8> = serde_json::from_str("x");
        let parse = decoded.expect_err("not a number");
        let unparsable = StateFileError::Unparsable {
            path: PathBuf::from("state.json"),
            source: Box::new(parse),
        };
        let io = io::Error::other("unreadable");
        let unreadable = StateFileError::Unreadable {
            path: PathBuf::from("state.json"),
            source: Box::new(io),
        };
        assert!(
            Error::source(&unparsable).is_some(),
            "an unparsable state file keeps its parse source"
        );
        assert!(
            Error::source(&unreadable).is_some(),
            "an unreadable state file keeps its io source"
        );
    }

    use super::{MeshId, MeshName, Nickname, StateFile};
    use crate::protocol::AuthorKey;

    fn author() -> AuthorKey {
        AuthorKey::from([0xab; 32])
    }
    use crate::util::clock;

    fn name(value: &str) -> MeshName {
        MeshName::try_new(value).expect("valid mesh name")
    }

    fn unique_path(tag: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "habilis-network-state-test-{}-{}-{}.json",
            tag,
            process::id(),
            clock::unix_nanos(),
        ))
    }

    #[test]
    fn failed_write_removes_temp_file() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("failed");
        // A non-empty directory at the target makes the final rename fail
        // after the temp file is fully written.
        fs::create_dir_all(path.join("occupied")).expect("the test directory can be created");
        let state_file = StateFile::new(
            path.clone(),
            &MeshId::from("abcd"),
            &Nickname::from("treat-empire"),
            &name("cool-team"),
            &author(),
        );
        let (logs, guard) = testing::LogCapture::start(tracing::Level::INFO);
        state_file.write(1, true);
        state_file.write(1, true);
        drop(guard);
        let temp = super::tmp_sibling(&path);
        let leftover = temp.exists();
        let _ = fs::remove_file(&temp);
        fs::remove_dir_all(&path).expect("the test directory can be removed");
        assert!(
            !leftover,
            "a failed write must not leave {}",
            temp.display()
        );
        let logged = logs.text();
        assert_eq!(
            logged.matches("state file write failed").count(),
            1,
            "two failed writes must warn once, got: {logged}"
        );
    }

    #[test]
    fn owner_pid_round_trips_through_the_session_entry() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("owner");
        let state_file = StateFile::new(
            path.clone(),
            &MeshId::from("abcd"),
            &Nickname::from("treat-empire"),
            &name("cool-team"),
            &author(),
        );
        state_file.write(1, true);
        let unowned = super::read_session_entry(&path).expect("entry");
        assert_eq!(unowned.owner_pid, None, "an unowned entry has no owner pid");
        let state_file = state_file.owner_pid(Some(4242));
        state_file.write(1, true);
        let owned = super::read_session_entry(&path).expect("entry");
        assert_eq!(
            owned.owner_pid,
            Some(4242),
            "an owned entry keeps its owner pid"
        );
        assert_eq!(
            owned.pid,
            Some(process::id()),
            "the entry records this process's pid"
        );
    }

    #[test]
    fn the_state_file_carries_the_author_key_of_the_daemon() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("pubkey");
        let state_file = StateFile::new(
            path.clone(),
            &MeshId::from("abcd"),
            &Nickname::from("treat-empire"),
            &name("cool-team"),
            &author(),
        );
        state_file.write(1, true);
        let hex = "ab".repeat(32);
        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("the state file can be read"))
                .expect("the state file the test wrote is json");
        assert_eq!(
            parsed["pubkey"], hex,
            "the file names the author key as 64 lowercase hex digits"
        );
        assert_eq!(
            super::read_identity(&path).pubkey.as_deref(),
            Some(hex.as_str()),
            "the identity reads the author key back"
        );
        state_file.remove();
    }

    #[test]
    fn the_fields_of_the_daemon_win_over_the_discovery_fields() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("shadow");
        let mesh = MeshId::from("abcd");
        let state_file = StateFile::new(
            path.clone(),
            &mesh,
            &Nickname::from("treat-empire"),
            &name("cool-team"),
            &author(),
        );
        let mut fields = serde_json::Map::new();
        for key in [
            "gossip",
            "name",
            "nickname",
            "pubkey",
            "topic",
            "pid",
            "owner_pid",
            "ready",
            "peer_count",
            "last_updated",
        ] {
            fields.insert(key.into(), serde_json::json!("from the app"));
        }
        fields.insert("extra".into(), serde_json::json!(7));
        state_file.set_discovery(fields);
        state_file.write(3, true);
        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("the state file can be read"))
                .expect("the state file the test wrote is json");
        assert_eq!(
            parsed["gossip"],
            mesh.as_str(),
            "a discovery field replaced the gossip"
        );
        assert_eq!(
            parsed["name"], "cool-team",
            "a discovery field replaced the name"
        );
        assert_eq!(
            parsed["nickname"], "treat-empire",
            "a discovery field replaced the nickname"
        );
        assert_eq!(
            parsed["pubkey"],
            "ab".repeat(32),
            "a discovery field replaced the author key"
        );
        assert_eq!(
            parsed["pid"],
            process::id(),
            "a discovery field replaced the pid"
        );
        assert_eq!(
            parsed["ready"], true,
            "a discovery field replaced the ready flag"
        );
        assert_eq!(
            parsed["peer_count"], 3,
            "a discovery field replaced the peer count"
        );
        assert!(
            parsed["last_updated"].is_number(),
            "a discovery field replaced the update time"
        );
        assert!(
            parsed.get("topic").is_none() && parsed.get("owner_pid").is_none(),
            "a discovery field stood in for a key that the daemon does not write"
        );
        assert_eq!(parsed["extra"], 7, "a field of the application was lost");
        state_file.remove();
    }

    #[test]
    fn writes_expected_shape() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("shape");
        let mesh = MeshId::from("abcd");
        let state_file = StateFile::new(
            path.clone(),
            &mesh,
            &Nickname::from("treat-empire"),
            &name("cool-team"),
            &author(),
        );
        state_file.write(3, true);
        let contents = fs::read_to_string(&path).expect("the written state file can be read");
        let parsed: serde_json::Value =
            serde_json::from_str(&contents).expect("the state file the test wrote is json");
        assert_eq!(
            parsed["gossip"],
            mesh.as_str(),
            "the written file names the gossip"
        );
        assert_eq!(
            parsed["name"], "cool-team",
            "the written file names the team"
        );
        assert_eq!(
            parsed["nickname"], "treat-empire",
            "the written file names the nickname"
        );
        assert_eq!(parsed["ready"], true, "the written file is marked ready");
        assert_eq!(
            parsed["peer_count"], 3,
            "the written file counts three peers"
        );
        assert_eq!(
            parsed["pid"],
            process::id(),
            "the written file records this process's pid"
        );
        assert!(
            parsed["last_updated"].is_number(),
            "the written file stamps the last update time"
        );
        assert!(
            parsed.get("topic").is_none(),
            "non-topic gossips carry no topic key"
        );
        state_file.remove();
    }

    #[test]
    fn topic_string_round_trips_whole() {
        // The derived name is lossy (`www.youtube.com/watch`); the raw string
        // must survive verbatim, query string and all, so leave can echo it.
        let _guard = ::habilis_network_test_tracing::init();
        let raw = "https://www.youtube.com/watch?v=jSqCL7Npln0";
        let path = unique_path("topic");
        let state_file = StateFile::new(
            path.clone(),
            &MeshId::from("topic"),
            &Nickname::from("treat-empire"),
            &name("www.youtube.com/watch"),
            &author(),
        )
        .topic(Some(raw));
        state_file.write(1, true);
        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("the state file can be read"))
                .expect("the state file the test wrote is json");
        assert_eq!(
            parsed["topic"], raw,
            "the topic is written whole to the file"
        );
        assert_eq!(
            super::read_identity(&path).topic.as_deref(),
            Some(raw),
            "the topic is read back whole from the identity"
        );
        let entry = super::read_session_entry(&path).expect("present");
        assert_eq!(
            entry.topic.as_deref(),
            Some(raw),
            "the topic is read back whole from the entry"
        );
        state_file.remove();
    }

    #[test]
    fn overwrites_on_subsequent_writes() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("overwrite");
        let state_file = StateFile::new(
            path.clone(),
            &MeshId::from("xyzw"),
            &Nickname::from("swift-cedar"),
            &name("cool-team"),
            &author(),
        );
        state_file.write(0, false);
        state_file.write(1, true);
        state_file.write(7, true);
        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("the state file can be read"))
                .expect("the state file the test wrote is json");
        assert_eq!(
            parsed["peer_count"], 7,
            "a second write updates the peer count to seven"
        );
        assert_eq!(parsed["ready"], true, "a second write keeps the file ready");
        state_file.remove();
    }

    /// The file holds the lock on the member key, so the key and the run counter are gone before a
    /// replacement can take the lock: a replacement that took it first would have its own key
    /// deleted by this cleanup. The order follows from the lock being a field of this value, which
    /// Rust drops after the body of `Drop`.
    #[cfg(unix)]
    #[test]
    fn the_lock_of_the_member_key_is_held_while_the_key_and_the_run_counter_go() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("key-lock");
        let lock_path = path.with_extension("key.lock");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(false);
        let held: fs::File = options.open(&lock_path).expect("the lock file opens");
        held.try_lock().expect("the lock is free");
        fs::write(path.with_extension("key"), b"key").expect("a member key file");
        fs::write(path.with_extension("run"), b"7").expect("a run counter file");
        let state_file = StateFile::new(
            path.clone(),
            &MeshId::from("test"),
            &Nickname::from("n"),
            &name("cool-team"),
            &author(),
        )
        // shared with the loop state in production; here the file is the only holder
        .key_lock(Some(Arc::new(held)));
        let mut rival_options = fs::OpenOptions::new();
        rival_options.write(true);
        let rival: fs::File = rival_options
            .open(&lock_path)
            .expect("a second handle on the lock file");
        assert!(
            rival.try_lock().is_err(),
            "the premise: the state file holds the lock of the member key"
        );

        drop(state_file);

        assert!(
            !path.with_extension("key").exists(),
            "the cleanup deletes the member key"
        );
        assert!(
            !path.with_extension("run").exists(),
            "and the run counter beside it"
        );
        assert!(
            rival.try_lock().is_ok(),
            "the lock is free once the files are gone, so a replacement starts with its own key"
        );
        let _ = fs::remove_file(&lock_path);
    }

    #[test]
    fn remove_clears_file() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("remove");
        let state_file = StateFile::new(
            path.clone(),
            &MeshId::from("test"),
            &Nickname::from("n"),
            &name("cool-team"),
            &author(),
        );
        state_file.write(0, false);
        assert!(path.exists(), "the file exists before remove is called");
        state_file.remove();
        assert!(!path.exists(), "remove deletes the file");
    }

    /// The member key and the run counter live beside the state file, named for it. A process that
    /// leaves must not leave them for the next process with the same pid: that process would take the
    /// member identity and the run count of the one that left.
    #[test]
    fn remove_clears_the_member_key_and_the_run_counter() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("remove-keys");
        let state_file = StateFile::new(
            path.clone(),
            &MeshId::from("test"),
            &Nickname::from("n"),
            &name("cool-team"),
            &author(),
        );
        state_file.write(0, false);
        let beside: Vec<PathBuf> = ["key", "run", "run.tmp"]
            .map(|extension| path.with_extension(extension))
            .into();
        for file in &beside {
            fs::write(file, b"x").expect("a file beside the state file");
        }

        state_file.remove();

        for file in &beside {
            assert!(!file.exists(), "remove deletes {}", file.display());
        }
    }

    /// A reader that uses `std::fs` opens with `FILE_SHARE_DELETE` on Windows,
    /// so it never blocks a write. The readers of this workspace and of
    /// agent-gossip all use `std::fs`.
    #[test]
    fn a_std_reader_does_not_block_a_write() {
        let path = unique_path("std-reader");
        let state_file = StateFile::new(
            path.clone(),
            &MeshId::from("test"),
            &Nickname::from("n"),
            &name("cool-team"),
            &author(),
        );
        state_file.write(1, false);
        let reader = fs::File::open(&path).expect("open the state file");
        super::write_private_atomic(&path, b"{}\n").expect("the write");
        drop(reader);
        assert_eq!(
            fs::read(&path).expect("read the state file"),
            b"{}\n",
            "the write replaced the file"
        );
        state_file.remove();
    }

    /// `FILE_SHARE_READ` of Windows, with no `FILE_SHARE_DELETE`. This crate
    /// has no `windows-sys`.
    #[cfg(windows)]
    const FILE_SHARE_READ: u32 = 1;

    /// Open `path` as the `Get-Content` of `PowerShell` does: with no
    /// `FILE_SHARE_DELETE`, and close it after 2 ms in a thread. The reader is
    /// open before the call under test, so its first try always meets it, and
    /// the short hold leaves most of the 50 ms deadline to a slow runner.
    #[cfg(windows)]
    fn hold_briefly(path: &path::Path) -> thread::JoinHandle<()> {
        use std::os::windows::fs::OpenOptionsExt as _;

        let reader: fs::File = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .expect("open the state file");
        thread::spawn(move || {
            thread::sleep(time::Duration::from_millis(2));
            drop(reader);
        })
    }

    #[cfg(windows)]
    #[test]
    fn a_write_waits_for_a_reader_without_share_delete() {
        let path = unique_path("held-write");
        let state_file = StateFile::new(
            path.clone(),
            &MeshId::from("test"),
            &Nickname::from("n"),
            &name("cool-team"),
            &author(),
        );
        state_file.write(1, false);
        let closer = hold_briefly(&path);
        state_file.write(2, true);
        closer.join().expect("the reader thread ends");
        let snapshot = super::read_snapshot(&path)
            .expect("the snapshot reads")
            .expect("a snapshot");
        state_file.remove();
        assert!(snapshot.ready, "the second write replaced the file");
    }

    #[cfg(windows)]
    #[test]
    fn a_remove_waits_for_a_reader_without_share_delete() {
        let path = unique_path("held-remove");
        let state_file = StateFile::new(
            path.clone(),
            &MeshId::from("test"),
            &Nickname::from("n"),
            &name("cool-team"),
            &author(),
        );
        state_file.write(1, false);
        let closer = hold_briefly(&path);
        state_file.remove();
        closer.join().expect("the reader thread ends");
        assert!(!path.exists(), "the remove waited for the reader");
    }

    #[test]
    fn drop_removes_file() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("drop");
        {
            let state_file = StateFile::new(
                path.clone(),
                &MeshId::from("test"),
                &Nickname::from("n"),
                &name("cool-team"),
                &author(),
            );
            state_file.write(0, false);
            assert!(path.exists(), "the file exists before drop");
        }
        assert!(!path.exists(), "drop deletes the file");
    }

    #[test]
    fn creates_parent_dir() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut path = env::temp_dir();
        path.push(format!(
            "habilis-network-state-test-parent-{}",
            process::id()
        ));
        path.push("sessions");
        path.push("x.json");
        let _ = fs::remove_dir_all(path.parent().expect("the test path has a parent"));
        let state_file = StateFile::new(
            path.clone(),
            &MeshId::from("test"),
            &Nickname::from("n"),
            &name("cool-team"),
            &author(),
        );
        state_file.write(2, true);
        assert!(
            path.exists(),
            "the file is written inside the new directory"
        );
        state_file.remove();
        let _ = fs::remove_dir_all(path.parent().expect("the test path has a parent"));
    }

    #[test]
    fn replaces_existing_file() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("replace");
        fs::create_dir_all(path.parent().expect("the test path has a parent"))
            .expect("the test directory can be created");
        // A pre-existing file with stale/foreign keys is fully replaced —
        // the daemon is the sole writer, so nothing is merged or preserved.
        fs::write(&path, br#"{"name":"stale","auto_reply":false,"junk":1}"#)
            .expect("the stale state file can be written");
        let mesh = MeshId::from("fresh");
        let state_file = StateFile::new(
            path.clone(),
            &mesh,
            &Nickname::from("swift-cedar"),
            &name("cool-team"),
            &author(),
        );
        state_file.write(3, true);
        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("the state file can be read"))
                .expect("the state file the test wrote is json");
        assert_eq!(
            parsed["gossip"],
            mesh.as_str(),
            "the replacing write names the gossip"
        );
        assert_eq!(
            parsed["name"], "cool-team",
            "the replacing write names the team"
        );
        assert_eq!(
            parsed["nickname"], "swift-cedar",
            "the replacing write sets the nickname"
        );
        assert_eq!(
            parsed["peer_count"], 3,
            "the replacing write counts three peers"
        );
        assert!(
            parsed["last_updated"].is_number(),
            "the replacing write stamps the last update time"
        );
        assert!(
            parsed.get("auto_reply").is_none(),
            "the replacing write drops the auto-reply key"
        );
        assert!(
            parsed.get("junk").is_none(),
            "the replacing write drops the junk key"
        );
        state_file.remove();
    }

    #[test]
    fn read_snapshot_round_trips_write() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("snapshot");
        let state_file = StateFile::new(
            path.clone(),
            &MeshId::from("round"),
            &Nickname::from("treat-empire"),
            &name("cool-team"),
            &author(),
        );
        // Missing file → None (the caller polls and retries).
        assert!(
            super::read_snapshot(&path)
                .expect("the snapshot file reads")
                .is_none(),
            "a missing file reads as no snapshot"
        );

        state_file.write(1, false);
        let snap = super::read_snapshot(&path)
            .expect("the snapshot file reads")
            .expect("present");
        assert!(!snap.ready, "wrote ready:false");
        assert!(snap.last_updated > 0, "last_updated populated");

        state_file.write(1, true);
        assert!(
            super::read_snapshot(&path)
                .expect("the snapshot file reads")
                .expect("present")
                .ready,
            "wrote ready:true"
        );
        state_file.remove();
    }

    #[test]
    fn read_identity_carries_session_fields() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("identity");
        let mesh = MeshId::from("round");
        let state_file = StateFile::new(
            path.clone(),
            &mesh,
            &Nickname::from("treat-empire"),
            &name("cool-team"),
            &author(),
        );
        state_file.write(2, true);
        let identity = super::read_identity(&path);
        assert_eq!(
            identity.mesh.as_deref(),
            Some(mesh.as_str()),
            "the identity carries the mesh"
        );
        assert_eq!(
            identity.name.as_deref(),
            Some("cool-team"),
            "the identity carries the team name"
        );
        assert_eq!(
            identity.nickname.as_deref(),
            Some("treat-empire"),
            "the identity carries the nickname"
        );
        state_file.remove();
    }

    #[test]
    fn read_session_entry_round_trips_write() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("session-entry");
        let mesh = MeshId::from("round");
        let state_file = StateFile::new(
            path.clone(),
            &mesh,
            &Nickname::from("treat-empire"),
            &name("cool-team"),
            &author(),
        );
        state_file.write(2, true);
        let entry = super::read_session_entry(&path).expect("present");
        assert_eq!(
            entry.mesh.as_deref(),
            Some(mesh.as_str()),
            "the entry carries the mesh"
        );
        assert_eq!(
            entry.name.as_deref(),
            Some("cool-team"),
            "the entry carries the team name"
        );
        assert_eq!(
            entry.nickname.as_deref(),
            Some("treat-empire"),
            "the entry carries the nickname"
        );
        assert_eq!(
            entry.pid,
            Some(process::id()),
            "the entry carries this process's pid"
        );
        state_file.remove();
    }

    #[test]
    fn read_session_entry_tolerates_a_pre_pid_file() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("session-entry-old");
        fs::create_dir_all(path.parent().expect("the test path has a parent"))
            .expect("the test directory can be created");
        fs::write(
            &path,
            r#"{"last_updated":1,"name":"old","nickname":"n-n","peer_count":1,"ready":true,"gossip":"old"}"#,
        )
        .expect("the test state file can be written");
        let entry = super::read_session_entry(&path).expect("present");
        assert_eq!(
            entry.mesh.as_deref(),
            Some("old"),
            "an old entry without a pid still reads its mesh"
        );
        assert_eq!(entry.pid, None, "an old entry without a pid has no pid");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn legacy_room_keyed_file_still_maps_its_mesh() {
        // A daemon from the previous release writes `room`, not `gossip`;
        // `session`/`leave`/`ready` must still map (and reap) it. Pins the
        // `mesh_field` fallback — deleting it must go red here, not in the
        // field as an unreapable orphan daemon.
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("session-entry-legacy-room");
        fs::create_dir_all(path.parent().expect("the test path has a parent"))
            .expect("the test directory can be created");
        fs::write(
            &path,
            r#"{"last_updated":1,"name":"old","nickname":"n-n","participant_count":1,"pid":7,"ready":true,"room":"legacy"}"#,
        )
        .expect("the test state file can be written");
        let entry = super::read_session_entry(&path).expect("present");
        assert_eq!(
            entry.mesh.as_deref(),
            Some("legacy"),
            "a room-keyed file maps its mesh in the entry"
        );
        let identity = super::read_identity(&path);
        assert_eq!(
            identity.mesh.as_deref(),
            Some("legacy"),
            "a room-keyed file maps its mesh in the identity"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn read_session_entry_is_none_on_missing_or_malformed() {
        let _guard = ::habilis_network_test_tracing::init();
        let missing = unique_path("session-entry-missing");
        assert!(
            super::read_session_entry(&missing).is_none(),
            "a missing session file reads as no entry"
        );
        let malformed = unique_path("session-entry-malformed");
        fs::create_dir_all(malformed.parent().expect("the test path has a parent"))
            .expect("the test directory can be created");
        fs::write(&malformed, b"not json").expect("the malformed state file can be written");
        assert!(
            super::read_session_entry(&malformed).is_none(),
            "a malformed session file reads as no entry"
        );
        let _ = fs::remove_file(&malformed);
    }

    #[test]
    fn read_identity_is_all_none_on_a_missing_file() {
        // Best-effort: a missing/identity-less file yields all-None, so the
        // gate's JSON omits the keys rather than printing nulls.
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("identity-missing");
        let identity = super::read_identity(&path);
        assert!(
            identity.mesh.is_none(),
            "a missing file gives an identity with no mesh"
        );
        assert!(
            identity.name.is_none(),
            "a missing file gives an identity with no name"
        );
        assert!(
            identity.nickname.is_none(),
            "a missing file gives an identity with no nickname"
        );
    }

    #[test]
    fn read_snapshot_errors_on_malformed() {
        let _guard = ::habilis_network_test_tracing::init();
        let path = unique_path("malformed");
        fs::create_dir_all(path.parent().expect("the test path has a parent"))
            .expect("the test directory can be created");
        // Not JSON.
        fs::write(&path, b"not json").expect("the malformed state file can be written");
        assert!(
            super::read_snapshot(&path).is_err(),
            "a malformed snapshot reads as an error"
        );
        // JSON object missing the `ready` / `last_updated` fields the gate needs.
        fs::write(&path, r#"{"gossip":"x","name":"n"}"#)
            .expect("the test state file can be written");
        assert!(
            super::read_snapshot(&path).is_err(),
            "a malformed snapshot reads as an error"
        );
        // Has `ready` but still missing `last_updated`.
        fs::write(&path, r#"{"ready":true,"gossip":"round"}"#)
            .expect("the test state file can be written");
        assert!(
            super::read_snapshot(&path).is_err(),
            "a malformed snapshot reads as an error"
        );
        let _ = fs::remove_file(&path);
    }
}

/// Why a state file cannot be read as a snapshot.
///
/// # Examples
///
/// A state file that exists but is not JSON is an error, not a missing file.
///
/// ```
/// use std::{env, fs, process};
///
/// use habilis_network::runtime::state_file::read_snapshot;
///
/// let path = env::temp_dir().join(format!("state-file-doc-{}.json", process::id()));
/// fs::write(&path, b"not json").expect("write the file");
/// assert!(read_snapshot(&path).is_err());
/// fs::remove_file(&path).expect("remove the file");
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum StateFileError {
    /// The file exists but cannot be read.
    Unreadable {
        /// The file.
        path: PathBuf,
        /// The read error.
        source: Box<dyn error::Error + Send + Sync>,
    },
    /// The file is not valid JSON.
    Unparsable {
        /// The file.
        path: PathBuf,
        /// The parse error.
        source: Box<dyn error::Error + Send + Sync>,
    },
    /// The file lacks a field the snapshot needs.
    MissingField {
        /// The file.
        path: PathBuf,
        /// The field and its type, for example: bool field `ready`.
        what: &'static str,
    },
}

impl fmt::Display for StateFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { path, .. } => write!(formatter, "reading {}", path.display()),
            Self::Unparsable { path, .. } => write!(formatter, "parsing {}", path.display()),
            Self::MissingField { path, what } => {
                write!(formatter, "state file {} missing {what}", path.display())
            }
        }
    }
}

impl error::Error for StateFileError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Unreadable { source, .. } | Self::Unparsable { source, .. } => {
                Some(source.as_ref())
            }
            Self::MissingField { .. } => None,
        }
    }
}
