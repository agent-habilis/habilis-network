use std::time::Duration;

use anyhow::Result;
// `ListenerOptions` is only for the unix socket: the Windows listener comes
// with the named pipe of R3.
#[cfg(unix)]
use interprocess::local_socket::ListenerOptions;
use interprocess::local_socket::{
    Name,
    tokio::{Listener, Stream, prelude::*},
};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::protocol::{MeshId, MessageId, Nickname};
use crate::util::bounded_read::{LineRead, read_bounded_line};
use crate::util::clock::millis_saturating;
use crate::util::consts::{MAX_IPC_COMMAND_BYTES, MAX_IPC_RESPONSE_BYTES};
use crate::util::tuning::{IPC_ACCEPT_BACKOFF_MAX, IPC_ACCEPT_BACKOFF_MIN, IPC_IO_TIMEOUT};
use crate::util::{ensure_mesh_runtime_dir, mesh_runtime_dir};

/// The longest marker line that a reader takes. A real name is a socket path
/// inside the runtime base, or the 48 characters of a pipe name.
const MAX_IPC_NAME_BYTES: usize = 512;

/// The name of the local control endpoint of one daemon: the path of a unix
/// socket on Unix, the name of a named pipe (`\\.\pipe\…`) on Windows.
///
/// A daemon writes it in its marker (`<mesh folder>/<nick>.ipc`), and a client
/// reads it from there, so discovery does not depend on the endpoint being a
/// file. Not a secret: on Windows any local account can list pipe names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpcName(String);

impl IpcName {
    /// Check a raw name, such as a marker line. Not `const`: the field is a
    /// `String`.
    ///
    /// # Errors
    /// The name is empty, longer than 512 bytes, holds a line break, or is not
    /// an endpoint of this OS: an absolute path on Unix, a local pipe
    /// (`\\.\pipe\` and a name) on Windows. A remote pipe (`\\host\pipe\…`) is
    /// refused.
    pub fn new(raw: String) -> Result<Self> {
        anyhow::ensure!(!raw.is_empty(), "an IPC name is empty");
        anyhow::ensure!(
            raw.len() <= MAX_IPC_NAME_BYTES,
            "an IPC name is longer than {MAX_IPC_NAME_BYTES} bytes"
        );
        anyhow::ensure!(
            !raw.contains(['\n', '\r']),
            "an IPC name holds a line break"
        );
        #[cfg(unix)]
        anyhow::ensure!(
            std::path::Path::new(&raw).is_absolute(),
            "the IPC name {raw:?} is not an absolute socket path"
        );
        #[cfg(windows)]
        anyhow::ensure!(
            raw.strip_prefix(r"\\.\pipe\")
                .is_some_and(|rest| !rest.is_empty() && !rest.contains('\\')),
            "the IPC name {raw:?} is not a local named pipe"
        );
        Ok(Self(raw))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The one conversion into an `interprocess` name, for the server and the
    /// client alike. `GenericFilePath` takes a socket path on Unix, and on
    /// Windows a `\\.\pipe\…` path as it is.
    fn to_name(&self) -> Result<Name<'_>> {
        use interprocess::local_socket::{GenericFilePath, ToFsName};
        Ok(self.0.as_str().to_fs_name::<GenericFilePath>()?)
    }
}

impl std::fmt::Display for IpcName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The endpoint name of a new daemon. On Unix it is the socket path in the
/// mesh folder, beside `<nick>.tracing.log` and `<nick>.state.json`.
#[cfg(unix)]
fn new_endpoint_name(
    base: &std::path::Path,
    mesh: &MeshId,
    nickname: &Nickname,
) -> Result<IpcName> {
    let path = mesh_runtime_dir(base, mesh.as_str()).join(format!("{nickname}.ipc.sock"));
    let text = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("the socket path {} is not UTF-8", path.display()))?;
    IpcName::new(text.to_owned())
}

/// The path of the marker of `nickname` on `mesh`: `<mesh folder>/<nick>.ipc`.
fn marker_path(base: &std::path::Path, mesh: &MeshId, nickname: &Nickname) -> std::path::PathBuf {
    mesh_runtime_dir(base, mesh.as_str()).join(format!("{nickname}.ipc"))
}

/// Read a marker. `Ok(None)` when there is no marker: no daemon is bound.
///
/// # Errors
/// The marker exists but cannot be read, or its line is no valid [`IpcName`].
fn read_marker(path: &std::path::Path) -> Result<Option<IpcName>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => anyhow::bail!("read the IPC marker {}: {error}", path.display()),
    };
    // We write LF only; a CRLF from a hand edit is read the same way.
    let line = text.trim_end_matches(['\r', '\n']);
    IpcName::new(line.to_owned())
        .map(Some)
        .map_err(|error| anyhow::anyhow!("the IPC marker {}: {error}", path.display()))
}

/// The marker that one daemon wrote, kept on the event-loop state so the
/// shutdown removes it.
#[derive(Debug)]
pub(crate) struct IpcMarker {
    path: std::path::PathBuf,
    name: IpcName,
}

impl IpcMarker {
    /// Write `name` to the marker at `path`, atomically and born `0600`.
    fn write(path: std::path::PathBuf, name: IpcName) -> std::io::Result<Self> {
        let line = format!("{name}\n");
        crate::daemon::state_file::write_private_atomic(&path, line.as_bytes())?;
        Ok(Self { path, name })
    }

    /// Remove the marker only while it still names this daemon. On Windows the
    /// pipe name is per process, so a second daemon with the same nickname on
    /// the same mesh writes another name over ours, and an unconditional remove
    /// at our exit would hide that live daemon. On Unix both daemons have the
    /// same socket path, so the names are equal and the check cannot tell them
    /// apart; there the second bind has already unlinked our socket, which was
    /// the behavior before the marker. The read and the remove are two steps,
    /// so a write between them is possible; the worst case is that same old
    /// behavior.
    pub(crate) fn remove_if_ours(&self) {
        match read_marker(&self.path) {
            Ok(Some(current)) if current == self.name => {
                if let Err(error) = std::fs::remove_file(&self.path) {
                    tracing::warn!(
                        target: "habilis_network::lifecycle",
                        path = %self.path.display(),
                        %error,
                        "IPC: could not remove the marker"
                    );
                }
            }
            _ => {}
        }
    }
}

/// What [`bind`] gives back: the accepting listener and the marker that makes
/// it findable.
pub(crate) struct Bound {
    pub(crate) listener: Listener,
    pub(crate) marker: IpcMarker,
}

pub(crate) use super::IpcMessage;

/// A mesh-addressed IPC command. The engine derives the per-mesh socket path
/// from the mesh id in [`send`]; `None` means the command is addressed by
/// endpoint directly (via [`send_to_endpoint`]) and carries no mesh — the
/// concrete command type is defined app-side, the engine only needs the address.
pub trait Addressed {
    fn mesh_id(&self) -> Option<&MeshId>;
}

/// Richer `ok` response for the `msg` IPC that also echoes back
/// the authoritative message record. The echo has the same shape
/// `poll` returns per entry — `serde_json::to_value(msg)` — so
/// agents can treat it uniformly with `fetch_messages` results.
///
/// A caller that only reads `response["id"]` gets the id; the MCP server
/// reads the embedded `"message"` field for the full record.
#[must_use]
/// # Panics
/// Panics if an internal invariant is violated.
pub fn json_ok_msg(id: &MessageId, msg: &crate::protocol::message::Verified) -> String {
    serde_json::json!({
        "ok": true,
        "id": id,
        "message": serde_json::to_value(msg).expect("Message serialize is infallible"),
    })
    .to_string()
}

/// Lean `{ok, id}` response — used by IPC commands that don't have
/// a message to echo back (currently test-only).
#[cfg(test)]
pub(crate) fn json_ok(id: &str) -> String {
    serde_json::json!({"ok": true, "id": id}).to_string()
}

/// Bare `{ok:true}` ack for fire-and-forget IPC commands (`ping`) that
/// have no id or payload to return.
#[must_use]
pub fn json_ack() -> String {
    serde_json::json!({"ok": true}).to_string()
}

#[must_use]
pub fn json_error(error: &str) -> String {
    serde_json::json!({"ok": false, "error": error}).to_string()
}

/// Bind the local IPC endpoint synchronously and write its marker, returning
/// both. Done *before* the daemon marks itself ready so that "ready" can never
/// precede an accepting endpoint: the listener exists before the marker, and
/// both before readiness, so a reader that finds the marker can connect.
///
/// A failed marker write fails the whole bind: an endpoint with no marker is a
/// daemon that no client can find.
///
/// # Errors
/// The runtime folder is rejected, the OS refuses the bind, or the marker
/// cannot be written. On Windows, always for now: the named pipe of R3 comes in
/// the next step, and a file path is no endpoint there.
pub(crate) fn bind(base: &std::path::Path, mesh: &MeshId, nickname: &Nickname) -> Result<Bound> {
    // The runtime base must exist and be private (0700) before the socket is
    // created inside it: this control socket has no in-band auth, so the base's
    // permissions are what keep another local user from reaching it. The choke
    // point validates the base (fails closed on a squat/symlink) and creates
    // the mesh folder in one step.
    ensure_mesh_runtime_dir(base, mesh.as_str())
        .map_err(|error| anyhow::anyhow!("failed to prepare runtime dir: {error}"))?;
    let (listener, name) = listen(base, mesh, nickname)?;
    let marker_at = marker_path(base, mesh, nickname);
    let marker = match IpcMarker::write(marker_at.clone(), name.clone()) {
        Ok(marker) => marker,
        Err(error) => {
            drop(listener);
            #[cfg(unix)]
            let _ = std::fs::remove_file(name.as_str());
            anyhow::bail!(
                "failed to write the IPC marker {}: {error}",
                marker_at.display()
            );
        }
    };
    tracing::info!(
        target: "habilis_network::lifecycle",
        name = %name,
        marker = %marker_at.display(),
        "IPC listening"
    );
    Ok(Bound { listener, marker })
}

/// Create the listener of a unix socket in the mesh folder.
#[cfg(unix)]
fn listen(
    base: &std::path::Path,
    mesh: &MeshId,
    nickname: &Nickname,
) -> Result<(Listener, IpcName)> {
    let name = new_endpoint_name(base, mesh, nickname)?;
    // Best-effort cleanup of a stale socket file.
    let _ = std::fs::remove_file(name.as_str());
    let listener = ListenerOptions::new()
        .name(name.to_name()?)
        .create_tokio()
        .map_err(|error| anyhow::anyhow!("failed to bind IPC socket {name}: {error}"))?;
    // The socket is a full control plane — inject broadcasts, read and merge
    // mesh/meta state — with no bearer token (unlike the localhost HTTP TCP
    // binding). Restrict it to the owner. The 0700 base already blocks other
    // users; this is defense in depth against a permissive umask on the socket.
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(error) =
            std::fs::set_permissions(name.as_str(), std::fs::Permissions::from_mode(0o600))
        {
            tracing::warn!(
                target: "habilis_network::lifecycle",
                name = %name,
                %error,
                "IPC socket: could not restrict to 0600"
            );
        }
    }
    Ok((listener, name))
}

/// The Windows endpoint is a named pipe with a security descriptor of the
/// current user, which is R3 of `docs/windows.md` and the next step. Until
/// then there is no IPC on Windows, and the bind says so instead of failing on
/// a file path.
#[cfg(windows)]
fn listen(
    _base: &std::path::Path,
    _mesh: &MeshId,
    _nickname: &Nickname,
) -> Result<(Listener, IpcName)> {
    anyhow::bail!("IPC over a named pipe does not exist yet on Windows (R3 of docs/windows.md)")
}

/// Server-side accept loop over an already-[`bind`]-ed socket: forward
/// each connection's command to the event loop. Spawned after `bind`
/// returns, so by the time this runs the socket is already accepting.
pub(crate) async fn serve<C>(
    listener: Listener,
    tx: mpsc::Sender<IpcMessage<C>>,
    sink: std::sync::Arc<dyn crate::gossip::event::NodeSink>,
) where
    C: DeserializeOwned + Send + 'static,
{
    // Accept errors are retried forever: they are almost always
    // transient (fd exhaustion under load, an aborted handshake), and
    // the old `break` permanently killed msg/poll for the process
    // lifetime on the first one — a silent partial outage on a daemon
    // meant to run for weeks. The backoff keeps a persistently failing
    // listener from spinning; the operator-facing error event fires
    // once per failure streak, not once per retry.
    let mut backoff = IPC_ACCEPT_BACKOFF_MIN;
    let mut failing = false;
    loop {
        match listener.accept().await {
            Ok(stream) => {
                backoff = IPC_ACCEPT_BACKOFF_MIN;
                failing = false;
                let tx = tx.clone();
                tokio::spawn(handle_connection::<C>(stream, tx));
            }
            Err(error) => {
                if !failing {
                    sink.emit(crate::gossip::event::NodeEvent::Error(format!(
                        "IPC: accept error (retrying): {error}"
                    )));
                    failing = true;
                }
                tracing::warn!(
                    target: "habilis_network::lifecycle",
                    %error,
                    backoff_ms = millis_saturating(backoff),
                    "IPC: accept error; retrying"
                );
                tokio::time::sleep(backoff).await;
                backoff = next_accept_backoff(backoff);
            }
        }
    }
}

/// Double the accept backoff up to its cap.
fn next_accept_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(IPC_ACCEPT_BACKOFF_MAX)
}

async fn handle_connection<C>(stream: Stream, tx: mpsc::Sender<IpcMessage<C>>)
where
    C: DeserializeOwned + Send + 'static,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // I/O deadline on both legs: a client that connects and goes silent
    // (or stops draining the response) would otherwise pin this task and
    // its fd for the daemon's lifetime.
    let io_deadline = IPC_IO_TIMEOUT;
    let line = match tokio::time::timeout(
        io_deadline,
        read_bounded_line(&mut reader, MAX_IPC_COMMAND_BYTES),
    )
    .await
    {
        Ok(Ok(LineRead::Line(line))) => line,
        Ok(Ok(LineRead::TooLong)) => {
            let error = json_error("command too large");
            let _ = tokio::time::timeout(
                io_deadline,
                write_half.write_all(format!("{error}\n").as_bytes()),
            )
            .await;
            return;
        }
        Ok(Ok(LineRead::Eof) | Err(_)) => return,
        Err(_idle) => {
            tracing::debug!(
                target: "habilis_network::lifecycle",
                "IPC: connection sent nothing within the read deadline; closing"
            );
            return;
        }
    };

    let response = match serde_json::from_str::<C>(line.trim()) {
        Err(error) => json_error(&format!("parse error: {error}")),
        Ok(cmd) => {
            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
            if tx.send((cmd, resp_tx)).await.is_err() {
                json_error("server channel closed")
            } else {
                match resp_rx.await {
                    Ok(reply) => reply,
                    Err(_) => json_error("response channel dropped"),
                }
            }
        }
    };

    let _ = tokio::time::timeout(
        io_deadline,
        write_half.write_all(format!("{response}\n").as_bytes()),
    )
    .await;
}

/// Nothing is listening on `nickname`'s control socket. Typed rather than a
/// finished sentence: the remedy is "start one with …", which names a command,
/// and only the consumer knows what its commands are called. It appends that
/// half after matching on this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoDaemon {
    pub nickname: Nickname,
}

impl std::fmt::Display for NoDaemon {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "No active gossip server running for nickname '{}'.",
            self.nickname
        )
    }
}

impl std::error::Error for NoDaemon {}

/// Client-side: send an IPC command to the running server and return the raw JSON response.
///
/// The server is found through its marker (`<mesh folder>/<nick>.ipc`).
///
/// # Panics
/// If called with a command that carries no mesh id — never: `Info` uses `send_to_endpoint`.
/// # Errors
/// [`NoDaemon`] when no marker exists or nothing accepts on its name; otherwise
/// an unreadable or invalid marker, or a failed request/response round trip.
pub async fn send<C>(base: &std::path::Path, cmd: &C, nickname: &Nickname) -> Result<String>
where
    C: Serialize + Addressed,
{
    let mesh = cmd
        .mesh_id()
        .expect("send() is only used for mesh-addressed commands; Info uses send_to_endpoint");
    let no_daemon = || NoDaemon {
        nickname: nickname.clone(),
    };
    let Some(name) = read_marker(&marker_path(base, mesh, nickname))? else {
        return Err(no_daemon().into());
    };
    let stream = Stream::connect(name.to_name()?)
        .await
        .map_err(|_| no_daemon())?;
    round_trip(stream, cmd).await
}

/// Client-side: send an IPC command to the endpoint `name`. `doctor` uses this
/// to query each live daemon that [`active_endpoints`] found; a stale endpoint
/// is a plain `Err` that the caller can skip.
///
/// # Errors
/// Nothing accepts on `name` (no live daemon), or the request/response round
/// trip fails.
pub async fn send_to_endpoint<C: Serialize>(name: &IpcName, cmd: &C) -> Result<String> {
    let stream = Stream::connect(name.to_name()?)
        .await
        .map_err(|error| anyhow::anyhow!("connect {name}: {error}"))?;
    round_trip(stream, cmd).await
}

/// Write `cmd`, half-close, and read back the single-line JSON response.
/// The shared body of [`send`] and [`send_to_endpoint`].
async fn round_trip<C: Serialize>(stream: Stream, cmd: &C) -> Result<String> {
    let (read_half, mut write_half) = tokio::io::split(stream);

    let json = serde_json::to_string(cmd)?;
    write_half.write_all(format!("{json}\n").as_bytes()).await?;
    write_half.shutdown().await?;

    let mut reader = BufReader::new(read_half);
    match read_bounded_line(&mut reader, MAX_IPC_RESPONSE_BYTES).await? {
        LineRead::Line(line) => Ok(line.trim().to_string()),
        LineRead::Eof => Ok(String::new()),
        LineRead::TooLong => anyhow::bail!("IPC response too large"),
    }
}

/// The endpoint of every daemon that has a marker under `base`: one
/// `<nick>.ipc` inside each mesh folder (`<base>/<mesh-prefix>/`). Best-effort:
/// a missing base gives an empty list, and a marker that cannot be read or holds
/// no valid name is skipped with a warn. The tmp file of a marker write
/// (`<nick>.ipc.tmp.<pid>`) has another extension and is not read. A marker of
/// a daemon that died stays until a client fails to connect to it, as a stale
/// socket file did. The list is sorted, so its order is stable.
#[must_use]
pub fn active_endpoints(base: &std::path::Path) -> Vec<IpcName> {
    let Ok(mesh_dirs) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    let mut names: Vec<IpcName> = mesh_dirs
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .flat_map(|dir| std::fs::read_dir(dir).into_iter().flatten().flatten())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "ipc") && path.is_file())
        .filter_map(|path| match read_marker(&path) {
            Ok(name) => name,
            Err(error) => {
                tracing::warn!(
                    target: "habilis_network::lifecycle",
                    %error,
                    "IPC: skip a marker"
                );
                None
            }
        })
        .collect();
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use habilis_network_test_tracing::test;
    use serde::{Deserialize, Serialize};

    #[cfg(unix)]
    use super::new_endpoint_name;
    use super::{
        Addressed, IpcMarker, IpcMessage, IpcName, MeshId, Nickname, NoDaemon, active_endpoints,
        bind, json_error, json_ok, marker_path, mpsc, read_marker, send, serve,
    };
    use crate::util::mesh_runtime_dir;

    /// A minimal mesh-addressed command standing in for the app's real
    /// `IpcCommand` (which lives app-side): exercises the engine's generic
    /// socket framing without naming any application type.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "command")]
    enum TestCommand {
        #[serde(rename = "msg")]
        Msg { mesh: MeshId, body: String },
        #[serde(rename = "ping")]
        Ping { mesh: MeshId },
    }

    impl Addressed for TestCommand {
        fn mesh_id(&self) -> Option<&MeshId> {
            match self {
                TestCommand::Msg { mesh, .. } | TestCommand::Ping { mesh } => Some(mesh),
            }
        }
    }

    // ── pure functions ─────────────────────────────────────────────

    #[test]
    fn json_ok_is_valid_json() {
        let json = json_ok("abc-123");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["id"], "abc-123");
    }

    #[test]
    fn json_error_is_valid_json() {
        let json = json_error("something broke");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["error"], "something broke");
    }

    #[test]
    fn json_ok_escapes_special_chars() {
        let json = json_ok(r#"id"with"quotes"#);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], r#"id"with"quotes"#);
    }

    #[test]
    fn json_error_escapes_special_chars() {
        let json = json_error(r#"error: "bad input""#);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["error"], r#"error: "bad input""#);
    }

    /// A runtime base of one test alone, removed when the test ends, also when
    /// an assert fails. A daemon under a product's base never sees it.
    ///
    /// On Unix it is under `/tmp`, not the temp directory: a socket path must
    /// stay inside the `sun_path` limit (about 104 bytes on macOS), and the macOS
    /// temp directory is long.
    struct TestBase(std::path::PathBuf);

    impl TestBase {
        fn new(tag: &str) -> Self {
            let name = format!("hn-ipc-{}-{tag}", std::process::id());
            #[cfg(unix)]
            let path = std::path::Path::new("/tmp").join(name);
            #[cfg(not(unix))]
            let path = std::env::temp_dir().join(name);
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestBase {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A mesh id whose prefix is this process and `tag`, in the Base58 alphabet.
    fn test_mesh(tag: &str) -> MeshId {
        let pid_b58 = bs58::encode(std::process::id().to_le_bytes()).into_string();
        MeshId::from(format!("{tag}{pid_b58}").as_str())
    }

    /// A valid name that no endpoint has.
    fn absent_name(tag: &str) -> IpcName {
        #[cfg(unix)]
        let raw = format!("/tmp/hn-ipc-absent-{}-{tag}.sock", std::process::id());
        #[cfg(windows)]
        let raw = format!(r"\\.\pipe\habilis-absent-{}-{tag}", std::process::id());
        IpcName::new(raw).expect("a valid name")
    }

    #[test]
    fn an_ipc_name_is_an_endpoint_of_this_os() {
        for bad in [
            "",
            "a\nb",
            "relative/x.sock",
            r"\\?\pipe\x",
            r"\\host\pipe\x",
        ] {
            assert!(IpcName::new(bad.to_owned()).is_err(), "{bad:?}");
        }
        assert!(IpcName::new("/".repeat(513)).is_err(), "too long");
        #[cfg(unix)]
        {
            assert!(IpcName::new("/tmp/x/nick.ipc.sock".to_owned()).is_ok());
            assert!(IpcName::new(r"\\.\pipe\habilis-00".to_owned()).is_err());
        }
        #[cfg(windows)]
        {
            assert!(IpcName::new(r"\\.\pipe\habilis-00ff".to_owned()).is_ok());
            assert!(
                IpcName::new(r"\\.\pipe\".to_owned()).is_err(),
                "no pipe name"
            );
            assert!(
                IpcName::new(r"\\.\pipe\a\b".to_owned()).is_err(),
                "a backslash"
            );
            assert!(IpcName::new(r"C:\tmp\nick.ipc.sock".to_owned()).is_err());
        }
    }

    #[test]
    fn a_marker_holds_one_line_and_reads_back() {
        let base = TestBase::new("marker");
        let mesh = test_mesh("marker");
        let nickname = Nickname::from("nick");
        std::fs::create_dir_all(mesh_runtime_dir(base.path(), mesh.as_str())).unwrap();
        let path = marker_path(base.path(), &mesh, &nickname);
        assert_eq!(path.file_name(), Some(std::ffi::OsStr::new("nick.ipc")));
        let name = absent_name("marker");
        let marker = IpcMarker::write(path.clone(), name.clone()).expect("write");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), format!("{name}\n"));
        assert_eq!(read_marker(&path).unwrap(), Some(name));
        drop(marker);
        // An invalid line is an error, not "no daemon".
        std::fs::write(&path, "relative\n").unwrap();
        assert!(read_marker(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        assert_eq!(read_marker(&path).unwrap(), None);
    }

    #[tokio::test]
    async fn send_without_a_marker_is_no_daemon() {
        let base = TestBase::new("nomarker");
        let mesh = test_mesh("nomarker");
        let nickname = Nickname::from("nobody");
        let cmd = TestCommand::Ping { mesh };
        let error = send(base.path(), &cmd, &nickname)
            .await
            .expect_err("no daemon");
        assert!(error.downcast_ref::<NoDaemon>().is_some(), "{error}");
    }

    #[tokio::test]
    async fn send_to_a_stale_marker_is_no_daemon() {
        let base = TestBase::new("stale");
        let mesh = test_mesh("stale");
        let nickname = Nickname::from("ghost");
        std::fs::create_dir_all(mesh_runtime_dir(base.path(), mesh.as_str())).unwrap();
        IpcMarker::write(
            marker_path(base.path(), &mesh, &nickname),
            absent_name("stale"),
        )
        .expect("write");
        let cmd = TestCommand::Ping { mesh };
        let error = send(base.path(), &cmd, &nickname)
            .await
            .expect_err("no daemon");
        assert!(error.downcast_ref::<NoDaemon>().is_some(), "{error}");
    }

    #[test]
    fn active_endpoints_reads_the_markers_sorted_and_skips_the_rest() {
        let base = TestBase::new("discover");
        assert!(active_endpoints(base.path()).is_empty(), "an absent base");
        let first = base.path().join("meshaaaaaaaaaaaa");
        let second = base.path().join("meshbbbbbbbbbbbb");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let late = absent_name("zz");
        let early = absent_name("aa");
        IpcMarker::write(first.join("one.ipc"), late.clone()).unwrap();
        IpcMarker::write(second.join("two.ipc"), early.clone()).unwrap();
        // Not read: an invalid line, the tmp file of a write, a marker that is
        // a folder, and a marker file at the level of the mesh folders.
        std::fs::write(first.join("bad.ipc"), "relative\n").unwrap();
        std::fs::write(first.join("one.ipc.tmp.123"), format!("{early}\n")).unwrap();
        std::fs::create_dir_all(second.join("dir.ipc")).unwrap();
        std::fs::write(base.path().join("loose.ipc"), format!("{early}\n")).unwrap();
        assert_eq!(active_endpoints(base.path()), vec![early, late]);
    }

    // Two names, as two daemons have on Windows, where the pipe name is per
    // process. On Unix the two names would be the same socket path.
    #[test]
    fn a_marker_is_removed_only_by_the_daemon_that_it_names() {
        let base = TestBase::new("ours");
        std::fs::create_dir_all(base.path()).unwrap();
        let path = base.path().join("nick.ipc");
        let first = IpcMarker::write(path.clone(), absent_name("first")).unwrap();
        // A second daemon with the same nickname writes over the first.
        let second = IpcMarker::write(path.clone(), absent_name("second")).unwrap();
        first.remove_if_ours();
        assert!(path.exists(), "the marker of the live second daemon stays");
        second.remove_if_ours();
        assert!(!path.exists(), "the second daemon removes its own marker");
        second.remove_if_ours();
        assert!(!path.exists(), "no marker: nothing to do");
    }

    // A marker that cannot be written fails the bind, and leaves no socket: an
    // endpoint that no client can find is no use. A tokio test, because the
    // unix listener registers with the reactor, as it does inside the daemon.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_marker_write_fails_the_bind_and_leaves_no_socket() {
        let base = TestBase::new("nowrite");
        let mesh = test_mesh("nowrite");
        let nickname = Nickname::from("blocked");
        // A folder where the marker goes makes the rename fail.
        std::fs::create_dir_all(marker_path(base.path(), &mesh, &nickname)).unwrap();
        let error = bind(base.path(), &mesh, &nickname)
            .err()
            .expect("the bind fails");
        assert!(error.to_string().contains("IPC marker"), "{error}");
        let socket = new_endpoint_name(base.path(), &mesh, &nickname).unwrap();
        assert!(!std::path::Path::new(socket.as_str()).exists(), "no socket");
    }

    // ── property-based tests ───────────────────────────────────────

    mod prop {
        use crate::util::mesh_prefix;
        use habilis_network_test_tracing::test;
        use proptest::collection::vec as arb_vec;
        use proptest::{prop_assert, prop_assert_eq, proptest, strategy::Strategy};

        use super::{MeshId, json_error, json_ok};

        fn arb_ascii_body() -> impl Strategy<Value = String> {
            arb_vec(0x20u8..0x7Eu8, 0..200).prop_map(|bytes| String::from_utf8(bytes).unwrap())
        }

        fn arb_mesh() -> impl Strategy<Value = MeshId> {
            "[1-9A-HJ-NP-Za-km-z]{4,24}".prop_map(|label| MeshId::from(label.as_str()))
        }

        proptest! {
            #![proptest_config(crate::proptest_support::config())]
            // ── JSON response validity ────────────────────────────

            #[test]
            fn prop_json_ok_always_valid(id in arb_ascii_body()) {
                let json = json_ok(&id);
                let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
                prop_assert!(parsed["ok"] == true);
                prop_assert_eq!(&parsed["id"], &id as &str);
            }

            #[test]
            fn prop_json_error_always_valid(msg in arb_ascii_body()) {
                let json = json_error(&msg);
                let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
                prop_assert!(parsed["ok"] == false);
                prop_assert_eq!(&parsed["error"], &msg as &str);
            }

            // ── Injection safety ──────────────────────────────────

            #[test]
            fn prop_json_ok_injection_safe(id in r#"["\\/\n\r\t]{1,50}"#) {
                let json = json_ok(&id);
                let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(&parsed["id"], &id as &str);
            }

            #[test]
            fn prop_json_error_injection_safe(msg in r#"["\\/\n\r\t]{1,50}"#) {
                let json = json_error(&msg);
                let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(&parsed["error"], &msg as &str);
            }

            // ── Socket prefix ─────────────────────────────────────

            #[test]
            fn prop_mesh_prefix_max_16_chars(mesh in arb_mesh()) {
                let prefix = mesh_prefix(mesh.as_str());
                prop_assert!(prefix.chars().count() <= 16);
            }

            #[test]
            fn prop_mesh_prefix_is_prefix_of_input(mesh in arb_mesh()) {
                let prefix = mesh_prefix(mesh.as_str());
                prop_assert!(mesh.as_str().starts_with(&prefix));
            }
        }
    }

    // ── IPC round-trip via local socket ────────────────────────────

    /// Answer exactly one inbound command, then return. Split out of
    /// `ipc_listen_and_send_msg` so the match arms aren't nested inside the
    /// spawned future's `if let`.
    async fn respond_once(mut rx: mpsc::Receiver<IpcMessage<TestCommand>>) {
        let Some((cmd, resp_tx)) = rx.recv().await else {
            return;
        };
        match cmd {
            TestCommand::Msg { body, .. } => {
                let _ = resp_tx.send(json_ok(&format!("got: {body}")));
            }
            TestCommand::Ping { .. } => {
                let _ = resp_tx.send(json_error("unexpected command"));
            }
        }
    }

    // On Windows `bind` fails for now: the named pipe of R3 comes in the next
    // step. The attribute expects that error, so the test passes only while
    // `bind` fails; the step that builds the pipe removes the attribute.
    #[cfg_attr(windows, should_panic(expected = "does not exist yet on Windows"))]
    #[test]
    async fn ipc_listen_and_send_msg() {
        let base = TestBase::new("roundtrip");
        let mesh = test_mesh("ipctest");
        let nickname = Nickname::from("test-nick");

        let (tx, rx) = mpsc::channel::<IpcMessage<TestCommand>>(8);

        // Bind synchronously (no sleep needed — the socket is accepting the
        // instant `bind` returns), then spawn the accept loop. The marker
        // exists the moment `bind` returns, too.
        let bound = bind(base.path(), &mesh, &nickname).expect("bind IPC socket");
        assert!(marker_path(base.path(), &mesh, &nickname).is_file());
        let listener_handle = tokio::spawn(serve(
            bound.listener,
            tx,
            std::sync::Arc::new(crate::gossip::event::SilentSink),
        ));

        // Spawn a handler that responds to messages
        let handler = tokio::spawn(respond_once(rx));

        // Send a command
        let cmd = TestCommand::Msg {
            mesh: mesh.clone(),
            body: "test message".to_owned(),
        };
        let response = send(base.path(), &cmd, &nickname).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["id"], "got: test message");

        handler.await.unwrap();
        listener_handle.abort();
    }

    #[test]
    fn accept_backoff_doubles_to_cap() {
        use crate::util::tuning::{IPC_ACCEPT_BACKOFF_MAX, IPC_ACCEPT_BACKOFF_MIN};

        let cap = IPC_ACCEPT_BACKOFF_MAX;
        let mut backoff = IPC_ACCEPT_BACKOFF_MIN;
        let mut previous = backoff;
        for _ in 0..16 {
            backoff = super::next_accept_backoff(backoff);
            assert!(backoff >= previous, "backoff never shrinks");
            assert!(backoff <= cap, "backoff never exceeds the cap");
            previous = backoff;
        }
        assert_eq!(backoff, cap, "sustained failure settles at the cap");
    }

    /// Answer every inbound command with `"healthy"` until the channel
    /// closes. Split out of `idle_connection_is_closed_at_the_read_deadline`
    /// so the loop body isn't nested inside the spawned future's `while let`.
    async fn respond_healthy_forever(mut rx: mpsc::Receiver<IpcMessage<TestCommand>>) {
        while let Some((_cmd, resp_tx)) = rx.recv().await {
            let _ = resp_tx.send(json_ok("healthy"));
        }
    }

    // An idle client (connects, never sends) must be disconnected at the
    // I/O deadline instead of pinning a handler task + fd for the
    // daemon's lifetime, and the listener must keep serving others
    // throughout. Real-time: waits out `IPC_IO_TIMEOUT` (10s).
    //
    // On Windows `bind` fails for now, as in `ipc_listen_and_send_msg`.
    #[cfg_attr(windows, should_panic(expected = "does not exist yet on Windows"))]
    #[test]
    async fn idle_connection_is_closed_at_the_read_deadline() {
        use interprocess::local_socket::{tokio::Stream, tokio::prelude::*};
        use tokio::io::AsyncReadExt;

        let base = TestBase::new("idle");
        let mesh = test_mesh("ipcquiet");
        let nickname = Nickname::from("idle-nick");
        let (tx, rx) = mpsc::channel::<IpcMessage<TestCommand>>(8);
        let bound = bind(base.path(), &mesh, &nickname).expect("bind IPC socket");
        let listener_handle = tokio::spawn(serve(
            bound.listener,
            tx,
            std::sync::Arc::new(crate::gossip::event::SilentSink),
        ));
        // Echo handler so a healthy command still round-trips while the
        // idle connection is parked.
        let handler = tokio::spawn(respond_healthy_forever(rx));

        // Park a silent connection, found through the marker as a client does.
        let name = read_marker(&marker_path(base.path(), &mesh, &nickname))
            .unwrap()
            .expect("a marker");
        let mut idle = Stream::connect(name.to_name().unwrap()).await.unwrap();

        // A healthy command still round-trips while the idle one is parked.
        let cmd = TestCommand::Ping { mesh: mesh.clone() };
        let response = send(base.path(), &cmd, &nickname).await.unwrap();
        assert!(response.contains("healthy"), "listener stalled: {response}");

        // The parked connection is closed (EOF) at the deadline, with margin.
        let mut sink = Vec::new();
        let read = tokio::time::timeout(
            crate::util::tuning::IPC_IO_TIMEOUT + std::time::Duration::from_secs(5),
            idle.read_to_end(&mut sink),
        )
        .await;
        assert!(
            matches!(read, Ok(Ok(0))),
            "idle connection was not closed at the read deadline: {read:?}"
        );

        handler.abort();
        listener_handle.abort();
    }
}
