use std::time::Duration;

use anyhow::Result;
use interprocess::local_socket::{
    ListenerOptions, Name,
    tokio::{Listener, Stream, prelude::*},
};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::protocol::{MeshId, MessageId, Nickname};
use crate::util::bounded_read::{LineRead, read_bounded_line};
use crate::util::clock::millis_saturating;
use crate::util::consts::{MAX_IPC_COMMAND_BYTES, MAX_IPC_RESPONSE_BYTES};
use crate::util::file_retry::retry_while_shared;
use crate::util::tuning::{IPC_ACCEPT_BACKOFF_MAX, IPC_ACCEPT_BACKOFF_MIN, IPC_IO_TIMEOUT};
use crate::util::{ensure_mesh_runtime_dir, mesh_runtime_dir};

/// The longest marker line that a reader takes. A real name is a socket path
/// inside the runtime base, or the 49 characters of a pipe name.
const MAX_IPC_NAME_BYTES: usize = 512;

/// The name of the local control endpoint of one daemon: the path of a unix
/// socket on Unix, the name of a named pipe (`\\.\pipe\…`) on Windows.
///
/// A daemon writes it in its marker (`<mesh folder>/<nick>.ipc`), and a client
/// reads it from there, so discovery does not depend on the endpoint being a
/// file. Not a secret: on Windows any local account can list pipe names. That
/// is why a Windows name carries no mesh prefix and no nickname, only
/// `habilis-` and 128 random bits.
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
                // On Windows a reader without `FILE_SHARE_DELETE` blocks the
                // remove while it holds the marker (R8 of `docs/windows.md`).
                if let Err(error) = retry_while_shared(|| std::fs::remove_file(&self.path)) {
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
///
/// One command name is the engine's own: a JSON object whose `command` is
/// `"quit"` and whose `mesh` is a valid mesh id is answered by the engine
/// ([`quit`]) and never reaches the app.
pub trait Addressed {
    fn mesh_id(&self) -> Option<&MeshId>;
}

/// The commands that the engine answers itself, before the app sees a line.
/// A line that does not parse as one of them goes to the app as before.
#[derive(Debug, Serialize, serde::Deserialize)]
#[serde(tag = "command")]
enum EngineCommand {
    /// Stop the daemon by the path of a signal: the state file and the marker
    /// are removed, then `Left` goes out, then the process exits. `mesh` must be
    /// the mesh of the daemon, so a stale marker cannot stop another session.
    #[serde(rename = "quit")]
    Quit { mesh: MeshId },
}

impl Addressed for EngineCommand {
    fn mesh_id(&self) -> Option<&MeshId> {
        match self {
            Self::Quit { mesh } => Some(mesh),
        }
    }
}

/// What the accept loop needs to answer the engine's own commands: the mesh of
/// this session, and the sender of the quit channel that the signals feed.
pub(crate) struct EngineControl {
    pub(crate) mesh: MeshId,
    pub(crate) quit_tx: mpsc::Sender<()>,
}

/// The start of the error text when a command line does not parse. A daemon
/// that does not know [`EngineCommand::Quit`] answers a quit with it.
const PARSE_ERROR: &str = "parse error";

/// The error text when a quit names another mesh.
const QUIT_OF_ANOTHER_MESH: &str = "command mesh id does not match this daemon";

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
/// cannot be written.
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

/// The prefix of every pipe name of the engine, before the random part.
#[cfg(windows)]
const PIPE_PREFIX: &str = r"\\.\pipe\habilis-";

/// Create the listener of a named pipe (R3 of `docs/windows.md`).
///
/// The name is `\\.\pipe\habilis-` and 128 random bits in hex. Pipe names
/// live in one namespace for the whole machine, and any account can make a pipe
/// with a free name: a fixed name lets another account make it first, so the
/// bind fails and clients reach that account. A random name cannot be taken
/// before it exists. After that it is public (any account lists pipes), so the
/// security descriptor and the client check of the owner protect it.
///
/// The descriptor is `O:<user>D:P(A;;GA;;;<user>)`: the user owns the pipe, also
/// in an elevated process, and nobody else may open it. With no descriptor, a
/// pipe gives read access to Everyone. `interprocess` puts the descriptor on
/// every instance, the first and each one after an accept.
#[cfg(windows)]
fn listen(
    _base: &std::path::Path,
    _mesh: &MeshId,
    _nickname: &Nickname,
) -> Result<(Listener, IpcName)> {
    use interprocess::os::windows::local_socket::ListenerOptionsExt as _;
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;
    use rand::Rng as _;

    let name = IpcName::new(format!(
        "{PIPE_PREFIX}{:032x}",
        rand::rng().random::<u128>()
    ))?;
    let sddl = crate::util::win_security::user_sddl()
        .map_err(|error| anyhow::anyhow!("the security descriptor of the IPC pipe: {error}"))?;
    let sddl = widestring::U16CStr::from_slice(&sddl)
        .map_err(|error| anyhow::anyhow!("the security descriptor of the IPC pipe: {error}"))?;
    let descriptor = SecurityDescriptor::deserialize(sddl)
        .map_err(|error| anyhow::anyhow!("the security descriptor of the IPC pipe: {error}"))?;
    let listener = ListenerOptions::new()
        .name(name.to_name()?)
        .security_descriptor(descriptor)
        .create_tokio()
        .map_err(|error| anyhow::anyhow!("failed to bind IPC pipe {name}: {error}"))?;
    Ok((listener, name))
}

/// Server-side accept loop over an already-[`bind`]-ed socket: forward
/// each connection's command to the event loop, or answer an engine command
/// with `control`. Spawned after `bind` returns, so by the time this runs the
/// socket is already accepting.
pub(crate) async fn serve<C>(
    listener: Listener,
    tx: mpsc::Sender<IpcMessage<C>>,
    control: EngineControl,
    sink: std::sync::Arc<dyn crate::gossip::event::NodeSink>,
) where
    C: DeserializeOwned + Send + 'static,
{
    let control = std::sync::Arc::new(control);
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
                let control = std::sync::Arc::clone(&control);
                tokio::spawn(handle_connection::<C>(stream, tx, control));
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

async fn handle_connection<C>(
    stream: Stream,
    tx: mpsc::Sender<IpcMessage<C>>,
    control: std::sync::Arc<EngineControl>,
) where
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

    // An engine command first. Any other line, also one that is no JSON
    // object, goes to the app's own parse, unchanged.
    if let Ok(EngineCommand::Quit { mesh }) = serde_json::from_str::<EngineCommand>(line.trim()) {
        answer_quit(&mesh, &control, &mut write_half).await;
        return;
    }

    let response = match serde_json::from_str::<C>(line.trim()) {
        Err(error) => json_error(&format!("{PARSE_ERROR}: {error}")),
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

/// Answer a quit, then feed the quit channel. The answer goes first, so the
/// client has it before the process exits: the shutdown still waits for the
/// `Left` broadcast before the exit. The channel is fed whatever the write
/// gave, so a client that does not read cannot keep the daemon up. A full
/// channel holds a quit already, and a closed one belongs to a loop that has
/// ended; the answer is right in both cases.
async fn answer_quit(
    mesh: &MeshId,
    control: &EngineControl,
    write_half: &mut tokio::io::WriteHalf<Stream>,
) {
    if *mesh != control.mesh {
        let error = json_error(QUIT_OF_ANOTHER_MESH);
        let _ = tokio::time::timeout(
            IPC_IO_TIMEOUT,
            write_half.write_all(format!("{error}\n").as_bytes()),
        )
        .await;
        return;
    }
    // No mesh id in the line: without an invite, the id is the secret of the mesh.
    tracing::info!(
        target: "habilis_network::lifecycle",
        "IPC: quit requested"
    );
    let _ = tokio::time::timeout(
        IPC_IO_TIMEOUT,
        write_half.write_all(format!("{}\n", json_ack()).as_bytes()),
    )
    .await;
    let _ = control.quit_tx.try_send(());
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

/// The endpoint that a client reached is owned by another account: on Windows
/// the owner of the pipe is not the current user, or its owner cannot be read.
/// A squat, not an absent daemon, so the remedy "start one" does not fit it. The
/// client sends nothing to such an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignEndpoint {
    /// The nickname that the client asked for; `None` for [`send_to_endpoint`],
    /// which addresses the endpoint by name.
    pub nickname: Option<Nickname>,
    /// The endpoint that was reached.
    pub name: IpcName,
}

impl std::fmt::Display for ForeignEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.nickname {
            Some(nickname) => write!(
                formatter,
                "The IPC endpoint for '{nickname}' is held by another user; refusing to talk to it."
            ),
            None => write!(
                formatter,
                "The IPC endpoint {} is held by another user; refusing to talk to it.",
                self.name
            ),
        }
    }
}

impl std::error::Error for ForeignEndpoint {}

/// Why a client could not reach an endpoint.
enum Unreached {
    /// Nothing accepts on the name: a stale marker, or a pipe whose DACL leaves
    /// us out, which is no endpoint of ours either.
    Absent(std::io::Error),
    /// The endpoint belongs to another account. Only the Windows connect can
    /// tell: on Unix the socket sits in the private runtime folder.
    #[cfg_attr(
        not(windows),
        expect(dead_code, reason = "only the Windows connect reads the owner")
    )]
    Foreign,
    /// The name could not be used.
    Other(anyhow::Error),
}

/// How long to wait before the next try when every instance of the pipe is busy,
/// or `None` to give up. `attempt` counts from 0. A new instance follows every
/// accept and there are 255, so a busy pipe is rare and short.
#[cfg(any(windows, test))]
fn pipe_busy_retry(attempt: u32) -> Option<Duration> {
    const TRIES: u32 = 3;
    (attempt < TRIES).then_some(Duration::from_millis(50))
}

/// Connect to `name`. On Unix the socket sits in the private runtime folder, so
/// a connect is enough. On Windows the client opens the pipe itself with
/// `SECURITY_IDENTIFICATION`, so the server cannot act as the client, and checks
/// that `owner` owns the pipe before it sends a byte.
async fn connect(
    name: &IpcName,
    #[cfg(windows)] owner: &crate::util::win_security::Sid,
) -> std::result::Result<Stream, Unreached> {
    #[cfg(unix)]
    {
        let name_for_os = name.to_name().map_err(Unreached::Other)?;
        Stream::connect(name_for_os)
            .await
            .map_err(Unreached::Absent)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle as _;

        let mut attempt = 0;
        let handle = loop {
            match crate::util::win_security::open_pipe_identification(name.as_str()) {
                Ok(handle) => break handle,
                Err(error) if crate::util::win_security::is_pipe_busy(&error) => {
                    let Some(wait) = pipe_busy_retry(attempt) else {
                        return Err(Unreached::Absent(error));
                    };
                    attempt += 1;
                    tokio::time::sleep(wait).await;
                }
                Err(error) => return Err(Unreached::Absent(error)),
            }
        };
        if !crate::util::win_security::handle_owner_is(handle.as_handle(), owner) {
            tracing::warn!(
                target: "habilis_network::lifecycle",
                name = %name,
                "IPC: the pipe is not owned by this user; refusing it"
            );
            return Err(Unreached::Foreign);
        }
        let pipe =
            interprocess::os::windows::named_pipe::local_socket::tokio::Stream::try_from(handle)
                .map_err(|error| {
                    Unreached::Other(anyhow::anyhow!("open IPC pipe {name}: {error}"))
                })?;
        Ok(Stream::from(pipe))
    }
}

/// The owner that a client expects: the current user.
#[cfg(windows)]
fn current_owner() -> Result<crate::util::win_security::Sid> {
    crate::util::win_security::current_user_sid()
        .map_err(|error| anyhow::anyhow!("read the SID of the current user: {error}"))
}

/// Client-side: send an IPC command to the running server and return the raw JSON response.
///
/// The server is found through its marker (`<mesh folder>/<nick>.ipc`).
///
/// # Panics
/// If called with a command that carries no mesh id — never: `Info` uses `send_to_endpoint`.
/// # Errors
/// [`NoDaemon`] when no marker exists or nothing accepts on its name;
/// [`ForeignEndpoint`] when the endpoint belongs to another account; otherwise
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
    let reached = connect(
        &name,
        #[cfg(windows)]
        &current_owner()?,
    )
    .await;
    match reached {
        Ok(stream) => round_trip(stream, cmd).await,
        Err(Unreached::Absent(_)) => Err(no_daemon().into()),
        Err(Unreached::Foreign) => Err(ForeignEndpoint {
            nickname: Some(nickname.clone()),
            name,
        }
        .into()),
        Err(Unreached::Other(error)) => Err(error),
    }
}

/// Client-side: send an IPC command to the endpoint `name`. `doctor` uses this
/// to query each live daemon that [`active_endpoints`] found; a stale endpoint
/// is a plain `Err` that the caller can skip.
///
/// # Errors
/// Nothing accepts on `name` (no live daemon), [`ForeignEndpoint`] when the
/// endpoint belongs to another account, or the request/response round trip
/// fails.
pub async fn send_to_endpoint<C: Serialize>(name: &IpcName, cmd: &C) -> Result<String> {
    send_to_endpoint_owned_by(
        name,
        cmd,
        #[cfg(windows)]
        &current_owner()?,
    )
    .await
}

/// [`send_to_endpoint`] with the expected owner as a parameter, so a test can
/// expect another account and see the refusal.
async fn send_to_endpoint_owned_by<C: Serialize>(
    name: &IpcName,
    cmd: &C,
    #[cfg(windows)] owner: &crate::util::win_security::Sid,
) -> Result<String> {
    let reached = connect(
        name,
        #[cfg(windows)]
        owner,
    )
    .await;
    match reached {
        Ok(stream) => round_trip(stream, cmd).await,
        Err(Unreached::Absent(error)) => Err(anyhow::anyhow!("connect {name}: {error}")),
        Err(Unreached::Foreign) => Err(ForeignEndpoint {
            nickname: None,
            name: name.clone(),
        }
        .into()),
        Err(Unreached::Other(error)) => Err(error),
    }
}

/// The daemon of one session, at the address that [`send`] takes: the runtime
/// base, the mesh, and the nickname.
#[derive(Debug, Clone, Copy)]
pub struct QuitTarget<'a> {
    pub base: &'a std::path::Path,
    pub mesh: &'a MeshId,
    pub nickname: &'a Nickname,
}

/// Why [`quit`] did not stop a daemon.
#[derive(Debug)]
pub enum QuitError {
    /// The quit was not heard: no marker, nothing accepts on the endpoint, an
    /// endpoint of another account, a failed exchange, or no answer.
    Unreached(anyhow::Error),
    /// The daemon answered that it cannot parse the quit: it is of a version
    /// from before the command. Holds the answer. An app error that starts
    /// with the same text (`parse error`) reads the same.
    OldDaemon(String),
    /// The daemon heard the quit and refused it, for example because the mesh
    /// is not its own, or answered with something that is no JSON. Holds the
    /// answer.
    Refused(String),
}

impl std::fmt::Display for QuitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreached(error) => write!(formatter, "the quit was not heard: {error}"),
            Self::OldDaemon(reply) => write!(
                formatter,
                "the daemon does not know the quit command: {reply}"
            ),
            Self::Refused(reply) => write!(formatter, "the daemon refused the quit: {reply}"),
        }
    }
}

impl std::error::Error for QuitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreached(error) => Some(error.as_ref()),
            Self::OldDaemon(_) | Self::Refused(_) => None,
        }
    }
}

/// Stop a daemon through its IPC endpoint: the engine's `quit` command. The
/// daemon answers, then takes the path of a signal: it removes its state file
/// and its marker, broadcasts `Left`, and exits. `Ok` means that the daemon
/// accepted the quit, not that it is gone already.
///
/// This works on every OS. See [`terminate`] for the version with a signal as
/// the fallback.
///
/// # Errors
/// [`QuitError`]: the quit was not heard, the daemon is too old to know it, or
/// the daemon refused it.
pub async fn quit(target: &QuitTarget<'_>) -> std::result::Result<(), QuitError> {
    let cmd = EngineCommand::Quit {
        mesh: target.mesh.clone(),
    };
    let reply = send(target.base, &cmd, target.nickname)
        .await
        .map_err(QuitError::Unreached)?;
    quit_outcome(&reply)
}

/// What the answer to a quit means.
fn quit_outcome(reply: &str) -> std::result::Result<(), QuitError> {
    if reply.is_empty() {
        return Err(QuitError::Unreached(anyhow::anyhow!(
            "the daemon closed the connection with no answer"
        )));
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(reply) else {
        return Err(QuitError::Refused(reply.to_owned()));
    };
    if value["ok"] == true {
        return Ok(());
    }
    let old = value["error"]
        .as_str()
        .is_some_and(|error| error.starts_with(PARSE_ERROR));
    if old {
        Err(QuitError::OldDaemon(reply.to_owned()))
    } else {
        Err(QuitError::Refused(reply.to_owned()))
    }
}

/// Stop the daemon of `target`: [`quit`] on every OS. On Unix, when the quit
/// was not heard or the daemon is too old to know it, send `SIGTERM` to `pid`
/// instead ([`crate::util::process::terminate`]), which takes the same path in
/// the daemon. A daemon that refused the quit gets no signal.
///
/// Not the same function as `util::process::terminate`: that one only signals
/// a pid, and on Windows it can do nothing. This one stops a daemon.
///
/// The caller must know that `pid` is the daemon of `target`, for example from
/// the `pid` of its `Info` answer. Otherwise the fallback can signal a process
/// that took over the pid. `pid` is not used on Windows.
///
/// # Errors
/// The [`QuitError`] of the quit; on Unix, the error of the signal when the
/// fallback ran.
pub async fn terminate(target: &QuitTarget<'_>, pid: u32) -> Result<()> {
    match quit(target).await {
        Ok(()) => Ok(()),
        #[cfg(unix)]
        Err(error @ (QuitError::Unreached(_) | QuitError::OldDaemon(_))) => {
            tracing::info!(
                target: "habilis_network::lifecycle",
                %error,
                pid,
                "IPC: the quit did not stop the daemon; sending SIGTERM"
            );
            crate::util::process::terminate(pid).map_err(|signal| {
                anyhow::Error::from(signal).context(format!("SIGTERM to pid {pid}, after: {error}"))
            })
        }
        Err(error) => {
            #[cfg(not(unix))]
            let _ = pid;
            Err(error.into())
        }
    }
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
        Addressed, EngineCommand, EngineControl, IpcMarker, IpcMessage, IpcName, MeshId, Nickname,
        NoDaemon, QUIT_OF_ANOTHER_MESH, QuitError, QuitTarget, active_endpoints, bind, json_ack,
        json_error, json_ok, marker_path, mpsc, pipe_busy_retry, quit, quit_outcome, read_marker,
        send, send_to_endpoint, serve, terminate,
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

    // A reader that opens the marker as the `Get-Content` of `PowerShell` does,
    // with no `FILE_SHARE_DELETE`, and closes it after 2 ms: the remove waits
    // for it. The short hold leaves most of the 50 ms deadline to a slow runner.
    #[cfg(windows)]
    #[test]
    fn a_marker_remove_waits_for_a_reader_without_share_delete() {
        use std::os::windows::fs::OpenOptionsExt as _;

        // `FILE_SHARE_READ`, with no `FILE_SHARE_DELETE`. This crate has no
        // `windows-sys`.
        const FILE_SHARE_READ: u32 = 1;

        let base = TestBase::new("held");
        std::fs::create_dir_all(base.path()).unwrap();
        let path = base.path().join("nick.ipc");
        let marker = IpcMarker::write(path.clone(), absent_name("held")).unwrap();
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .unwrap();
        let closer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(2));
            drop(reader);
        });
        marker.remove_if_ours();
        closer.join().unwrap();
        assert!(
            !path.exists(),
            "the marker is removed after the reader closes"
        );
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

    #[test]
    fn a_busy_pipe_is_tried_three_more_times_then_given_up() {
        let waits: Vec<_> = (0..5).map(pipe_busy_retry).collect();
        let fifty = Some(std::time::Duration::from_millis(50));
        assert_eq!(waits, vec![fifty, fifty, fifty, None, None]);
    }

    /// On Windows the endpoint is a pipe with a random name, no mesh prefix and
    /// no nickname in it, and a DACL of the user alone.
    #[cfg(windows)]
    #[tokio::test]
    async fn the_windows_endpoint_is_a_random_pipe_of_the_user() {
        let base = TestBase::new("pipe");
        let mesh = test_mesh("pipe");
        let nickname = Nickname::from("piper");
        let bound = bind(base.path(), &mesh, &nickname).expect("bind");
        let name = read_marker(&marker_path(base.path(), &mesh, &nickname))
            .unwrap()
            .expect("a marker");
        let random = name
            .as_str()
            .strip_prefix(super::PIPE_PREFIX)
            .expect("the engine prefix");
        assert_eq!(random.len(), 32, "{name}");
        assert!(
            random.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{name}"
        );
        assert!(!name.as_str().contains("piper"), "no nickname in {name}");

        // A second bind gets another name.
        let other = bind(base.path(), &test_mesh("pipe2"), &nickname).expect("bind");
        let other_name = read_marker(&marker_path(base.path(), &test_mesh("pipe2"), &nickname))
            .unwrap()
            .expect("a marker");
        assert_ne!(name, other_name);
        drop(other);

        // The DACL of a client handle of the pipe: one entry, the user. The
        // trustee can read back as an alias (`LA` when the test runs as the
        // built-in Administrator), so the test compares the SID.
        let client =
            crate::util::win_security::open_pipe_identification(name.as_str()).expect("open");
        let user = crate::util::win_security::current_user_sid().unwrap();
        let dacl = crate::util::win_security::dacl_text(std::os::windows::io::AsHandle::as_handle(
            &client,
        ))
        .expect("the DACL");
        let trustee = dacl
            .strip_prefix("D:P(A;;FA;;;")
            .and_then(|rest| rest.strip_suffix(')'))
            .unwrap_or_else(|| panic!("one entry with all access: {dacl}"));
        assert_eq!(
            crate::util::win_security::Sid::from_text(trustee).expect("a SID or an alias"),
            user
        );
        drop(bound);
    }

    // The client refuses a pipe that another account owns, and sends it
    // nothing. One user on CI cannot make such a pipe, so the test expects
    // SYSTEM to own our own pipe, and gets the refusal.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_pipe_of_another_owner_is_refused_as_foreign() {
        let base = TestBase::new("foreign");
        let mesh = test_mesh("foreign");
        let nickname = Nickname::from("owner");
        let bound = bind(base.path(), &mesh, &nickname).expect("bind");
        let name = read_marker(&marker_path(base.path(), &mesh, &nickname))
            .unwrap()
            .expect("a marker");
        let system = crate::util::win_security::Sid::from_text("S-1-5-18").expect("SYSTEM");
        let cmd = TestCommand::Ping { mesh };
        let error = super::send_to_endpoint_owned_by(&name, &cmd, &system)
            .await
            .expect_err("a foreign owner");
        let foreign = error
            .downcast_ref::<super::ForeignEndpoint>()
            .expect("a ForeignEndpoint");
        assert_eq!(foreign.name, name);
        assert_eq!(foreign.nickname, None);
        drop(bound);
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
        let (control, mut quit_rx) = test_control(&mesh);
        let listener_handle = tokio::spawn(serve(
            bound.listener,
            tx,
            control,
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
        assert!(quit_rx.try_recv().is_err(), "an app command is no quit");

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
    #[test]
    async fn idle_connection_is_closed_at_the_read_deadline() {
        use interprocess::local_socket::{tokio::Stream, tokio::prelude::*};
        use tokio::io::AsyncReadExt;

        let base = TestBase::new("idle");
        let mesh = test_mesh("ipcquiet");
        let nickname = Nickname::from("idle-nick");
        let (tx, rx) = mpsc::channel::<IpcMessage<TestCommand>>(8);
        let bound = bind(base.path(), &mesh, &nickname).expect("bind IPC socket");
        let (control, _quit_rx) = test_control(&mesh);
        let listener_handle = tokio::spawn(serve(
            bound.listener,
            tx,
            control,
            std::sync::Arc::new(crate::gossip::event::SilentSink),
        ));
        // Echo handler so a healthy command still round-trips while the
        // idle connection is parked.
        let handler = tokio::spawn(respond_healthy_forever(rx));

        // Park a silent connection, found through the marker as a client does.
        let name = read_marker(&marker_path(base.path(), &mesh, &nickname))
            .unwrap()
            .expect("a marker");
        // The parked client uses the plain `interprocess` connect: no SQOS and
        // no owner check. That is fine here: the server is this test's own
        // listener, and the test is about the server's read deadline. The user
        // DACL admits it, because the DACL names who may open, not how.
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

    // ── the engine's quit ──────────────────────────────────────────

    /// An engine control for `mesh`, and the receiver of its quit channel. The
    /// channel holds one quit, as the real one does.
    fn test_control(mesh: &MeshId) -> (EngineControl, mpsc::Receiver<()>) {
        let (quit_tx, quit_rx) = mpsc::channel(1);
        (
            EngineControl {
                mesh: mesh.clone(),
                quit_tx,
            },
            quit_rx,
        )
    }

    /// Whether the quit channel stays empty for a short time.
    async fn no_quit_within(quit_rx: &mut mpsc::Receiver<()>) -> bool {
        tokio::time::timeout(std::time::Duration::from_millis(200), quit_rx.recv())
            .await
            .is_err()
    }

    /// A bound test daemon whose engine control holds `session`, the mesh of
    /// the session; by default the mesh that it is bound under.
    struct TestServer<C> {
        base: TestBase,
        mesh: MeshId,
        nickname: Nickname,
        app_rx: mpsc::Receiver<IpcMessage<C>>,
        quit_rx: mpsc::Receiver<()>,
        accept: tokio::task::JoinHandle<()>,
    }

    impl<C: serde::de::DeserializeOwned + Send + 'static> TestServer<C> {
        fn start(tag: &str, session: Option<&MeshId>) -> Self {
            let base = TestBase::new(tag);
            let mesh = test_mesh(tag);
            let nickname = Nickname::from("quit-nick");
            let (tx, app_rx) = mpsc::channel::<IpcMessage<C>>(8);
            let bound = bind(base.path(), &mesh, &nickname).expect("bind IPC socket");
            let (control, quit_rx) = test_control(session.unwrap_or(&mesh));
            let accept = tokio::spawn(serve(
                bound.listener,
                tx,
                control,
                std::sync::Arc::new(crate::gossip::event::SilentSink),
            ));
            Self {
                base,
                mesh,
                nickname,
                app_rx,
                quit_rx,
                accept,
            }
        }

        fn target(&self) -> QuitTarget<'_> {
            QuitTarget {
                base: self.base.path(),
                mesh: &self.mesh,
                nickname: &self.nickname,
            }
        }

        fn name(&self) -> IpcName {
            read_marker(&marker_path(self.base.path(), &self.mesh, &self.nickname))
                .unwrap()
                .expect("a marker")
        }
    }

    impl<C> Drop for TestServer<C> {
        fn drop(&mut self) {
            self.accept.abort();
        }
    }

    #[test]
    fn the_quit_command_and_its_answer_have_a_fixed_form() {
        let mesh = test_mesh("golden");
        let line = serde_json::to_string(&EngineCommand::Quit { mesh: mesh.clone() }).unwrap();
        assert_eq!(
            line,
            format!(r#"{{"command":"quit","mesh":"{}"}}"#, mesh.as_str())
        );
        assert_eq!(json_ack(), r#"{"ok":true}"#);
    }

    #[test]
    fn the_answer_to_a_quit_reads_as_its_outcome() {
        assert!(quit_outcome(&json_ack()).is_ok());
        assert!(matches!(
            quit_outcome(&json_error("parse error: unknown variant `quit`")),
            Err(QuitError::OldDaemon(_))
        ));
        assert!(matches!(
            quit_outcome(&json_error(QUIT_OF_ANOTHER_MESH)),
            Err(QuitError::Refused(_))
        ));
        assert!(matches!(
            quit_outcome("not json"),
            Err(QuitError::Refused(_))
        ));
        assert!(matches!(quit_outcome(""), Err(QuitError::Unreached(_))));
    }

    #[tokio::test]
    async fn a_quit_for_this_mesh_is_answered_then_fed_to_the_quit_channel() {
        let mut server = TestServer::<TestCommand>::start("quit", None);
        quit(&server.target()).await.expect("the quit is accepted");
        let fed = tokio::time::timeout(std::time::Duration::from_secs(5), server.quit_rx.recv())
            .await
            .expect("the quit channel is fed");
        assert_eq!(fed, Some(()));
        assert!(server.app_rx.try_recv().is_err(), "the app sees no quit");
    }

    #[tokio::test]
    async fn a_quit_for_another_mesh_is_refused_and_feeds_nothing() {
        let mut server = TestServer::<TestCommand>::start("quitother", Some(&test_mesh("other")));
        let error = quit(&server.target()).await.expect_err("refused");
        assert!(matches!(error, QuitError::Refused(_)), "{error}");
        assert!(no_quit_within(&mut server.quit_rx).await);
        assert!(server.app_rx.try_recv().is_err(), "the app sees no quit");
    }

    #[tokio::test]
    async fn a_line_that_is_no_valid_quit_reaches_the_app() {
        let mut server = TestServer::<serde_json::Value>::start("quitapp", None);
        let name = server.name();
        let lines = [
            serde_json::json!({ "command": "quit" }),
            serde_json::json!({ "command": "quit", "mesh": "no mesh id" }),
            serde_json::json!("quit"),
        ];
        let mut app_rx = std::mem::replace(&mut server.app_rx, mpsc::channel(1).1);
        let count = lines.len();
        let app = tokio::spawn(async move {
            let mut seen = Vec::new();
            while seen.len() < count {
                let Some((cmd, resp)) = app_rx.recv().await else {
                    break;
                };
                let _ = resp.send(json_ok("app"));
                seen.push(cmd);
            }
            seen
        });
        for line in &lines {
            let reply = send_to_endpoint(&name, line).await.unwrap();
            assert!(reply.contains(r#""id":"app""#), "{line}: {reply}");
        }
        assert_eq!(app.await.unwrap(), lines);
        assert!(no_quit_within(&mut server.quit_rx).await);
    }

    #[tokio::test]
    async fn a_quit_with_no_marker_is_not_heard() {
        let base = TestBase::new("quitnone");
        let mesh = test_mesh("quitnone");
        let nickname = Nickname::from("nobody");
        let target = QuitTarget {
            base: base.path(),
            mesh: &mesh,
            nickname: &nickname,
        };
        let error = quit(&target).await.expect_err("no daemon");
        assert!(matches!(error, QuitError::Unreached(_)), "{error}");
    }

    #[tokio::test]
    async fn a_line_that_is_no_json_gets_the_parse_error_and_feeds_nothing() {
        use interprocess::local_socket::{tokio::Stream, tokio::prelude::*};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut server = TestServer::<TestCommand>::start("quitraw", None);
        let mut client = Stream::connect(server.name().to_name().unwrap())
            .await
            .unwrap();
        client.write_all(b"not json\n").await.unwrap();
        let mut reply = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_string(&mut reply),
        )
        .await
        .expect("an answer")
        .unwrap();
        let reply: serde_json::Value = serde_json::from_str(reply.trim()).unwrap();
        assert!(
            reply["error"]
                .as_str()
                .is_some_and(|error| error.starts_with("parse error")),
            "{reply}"
        );
        assert!(no_quit_within(&mut server.quit_rx).await);
    }

    #[tokio::test]
    async fn an_app_that_cannot_parse_a_quit_reads_as_an_old_daemon() {
        let mut server = TestServer::<TestCommand>::start("quitold", None);
        // Not an engine quit, so the app parses it, as a daemon from before the
        // command does with a real quit.
        let reply = send_to_endpoint(&server.name(), &serde_json::json!({ "command": "quit" }))
            .await
            .unwrap();
        assert!(
            matches!(quit_outcome(&reply), Err(QuitError::OldDaemon(_))),
            "{reply}"
        );
        assert!(no_quit_within(&mut server.quit_rx).await);
    }

    #[tokio::test]
    async fn a_second_quit_is_answered_and_the_channel_holds_one() {
        let mut server = TestServer::<TestCommand>::start("quittwice", None);
        quit(&server.target()).await.expect("the first quit");
        quit(&server.target()).await.expect("the second quit");
        // The server feeds the channel after its answer, so give both feeds a moment.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(server.quit_rx.try_recv(), Ok(()));
        assert!(no_quit_within(&mut server.quit_rx).await);
    }

    #[tokio::test]
    async fn a_quit_feeds_the_channel_also_when_the_client_does_not_read() {
        use interprocess::local_socket::{tokio::Stream, tokio::prelude::*};
        use tokio::io::AsyncWriteExt;

        let mut server = TestServer::<TestCommand>::start("quitdeaf", None);
        // The plain `interprocess` connect, as in the idle test: this test is
        // about the server.
        let mut client = Stream::connect(server.name().to_name().unwrap())
            .await
            .unwrap();
        let line = serde_json::to_string(&EngineCommand::Quit {
            mesh: server.mesh.clone(),
        })
        .unwrap();
        client
            .write_all(format!("{line}\n").as_bytes())
            .await
            .unwrap();
        let fed = tokio::time::timeout(std::time::Duration::from_secs(5), server.quit_rx.recv())
            .await
            .expect("the quit channel is fed while the answer is unread");
        assert_eq!(fed, Some(()));
        drop(client);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminate_signals_the_pid_when_the_quit_is_not_heard() {
        use std::os::unix::process::ExitStatusExt as _;

        let base = TestBase::new("termunheard");
        let mesh = test_mesh("termunheard");
        let nickname = Nickname::from("nobody");
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let target = QuitTarget {
            base: base.path(),
            mesh: &mesh,
            nickname: &nickname,
        };
        terminate(&target, child.id())
            .await
            .expect("the fallback signals");
        let status = child.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGTERM), "{status}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminate_sends_no_signal_when_the_daemon_refuses() {
        let server = TestServer::<TestCommand>::start("termrefused", Some(&test_mesh("other")));
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let error = terminate(&server.target(), child.id())
            .await
            .expect_err("refused");
        assert!(
            matches!(
                error.downcast_ref::<QuitError>(),
                Some(QuitError::Refused(_))
            ),
            "{error}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(child.try_wait().unwrap().is_none(), "no signal was sent");
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn on_windows_terminate_is_the_quit_alone() {
        let base = TestBase::new("termwin");
        let mesh = test_mesh("termwin");
        let nickname = Nickname::from("nobody");
        let target = QuitTarget {
            base: base.path(),
            mesh: &mesh,
            nickname: &nickname,
        };
        // The pid is not used on Windows, so our own is safe here.
        let error = terminate(&target, std::process::id())
            .await
            .expect_err("no daemon");
        assert!(
            matches!(
                error.downcast_ref::<QuitError>(),
                Some(QuitError::Unreached(_))
            ),
            "{error}"
        );
    }
}
