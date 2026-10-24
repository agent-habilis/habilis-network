use std::time::Duration;

use anyhow::Result;
use interprocess::local_socket::tokio::{Listener, Stream};
use interprocess::local_socket::traits::tokio::{Listener as _, Stream as _};
use interprocess::local_socket::{ListenerOptions, Name};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::gossip::event;
use crate::protocol::{MeshId, MessageId, Nickname, message};
use crate::util::bounded_read::{LineRead, read_bounded_line};
use crate::util::clock::millis_saturating;
use crate::util::consts::{MAX_IPC_COMMAND_BYTES, MAX_IPC_RESPONSE_BYTES};
use crate::util::tuning::{IPC_ACCEPT_BACKOFF_MAX, IPC_ACCEPT_BACKOFF_MIN, IPC_IO_TIMEOUT};
use crate::util::{ensure_mesh_runtime_dir, mesh_runtime_dir};
use tokio::sync::oneshot;

/// Returns the IPC endpoint identifier for a specific agent on a mesh —
/// a filesystem socket path (the project targets Unix only). Lives in the
/// mesh's runtime folder beside its `<nick>.tracing.log` / `<nick>.state.json`.
pub(crate) fn socket_path(base: &std::path::Path, mesh: &MeshId, nickname: &Nickname) -> String {
    format!(
        "{}/{nickname}.ipc.sock",
        mesh_runtime_dir(base, mesh.as_str()).display()
    )
}

fn to_name(path: &str) -> Result<Name<'_>> {
    use interprocess::local_socket::{GenericFilePath, ToFsName};
    Ok(path.to_fs_name::<GenericFilePath>()?)
}

pub(crate) use super::IpcMessage;

/// A mesh-addressed IPC command. The engine derives the per-mesh socket path
/// from the mesh id in [`send`]; `None` means the command is addressed by
/// socket path directly (via [`send_to_path`]) and carries no mesh — the
/// concrete command type is defined app-side, the engine only needs the address.
pub trait Addressed {
    /// The mesh this command is for, or `None` for a command that has none.
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
pub fn json_ok_msg(id: &MessageId, msg: &message::Verified) -> String {
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

/// The JSON reply of a failed IPC command, with `ok` false and the `error` text.
#[must_use]
pub fn json_error(error: &str) -> String {
    serde_json::json!({"ok": false, "error": error}).to_string()
}

/// Bind the local IPC socket synchronously, returning the listening
/// socket. Done *before* the daemon marks itself ready so that "ready"
/// can never precede an accepting socket: a `ready` gate that observes
/// the readiness flag is then guaranteed a subsequent `connect` succeeds.
///
/// # Errors
/// An invalid socket name, or the OS refusing the bind.
pub(crate) fn bind(base: &std::path::Path, mesh: &MeshId, nickname: &Nickname) -> Result<Listener> {
    let path = socket_path(base, mesh, nickname);

    // The runtime base must exist and be private (0700) before the socket is
    // created inside it: this control socket has no in-band auth, so the base's
    // permissions are what keep another local user from reaching it. The choke
    // point validates the base (fails closed on a squat/symlink) and creates
    // the mesh folder in one step.
    ensure_mesh_runtime_dir(base, mesh.as_str())
        .map_err(|error| anyhow::anyhow!("failed to prepare runtime dir: {error}"))?;
    // Best-effort cleanup of a stale socket file.
    let _ = std::fs::remove_file(&path);

    let name = to_name(&path)?;
    let listener = ListenerOptions::new()
        .name(name)
        .create_tokio()
        .map_err(|error| anyhow::anyhow!("failed to bind IPC socket {path}: {error}"))?;
    // The socket is a full control plane — inject broadcasts, read and merge
    // mesh/meta state — with no bearer token (unlike the localhost HTTP TCP
    // binding). Restrict it to the owner. The 0700 base already blocks other
    // users; this is defense in depth against a permissive umask on the socket.
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        {
            tracing::warn!(?path, %error, "IPC socket: could not restrict to 0600");
        }
    }
    tracing::info!(?path, "IPC socket listening");
    Ok(listener)
}

/// Server-side accept loop over an already-[`bind`]-ed socket: forward
/// each connection's command to the event loop. Spawned after `bind`
/// returns, so by the time this runs the socket is already accepting.
pub(crate) async fn serve<C>(
    listener: Listener,
    tx: mpsc::Sender<IpcMessage<C>>,
    sink: std::sync::Arc<dyn event::NodeSink>,
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
                    sink.emit(event::NodeEvent::Error(format!(
                        "IPC: accept error (retrying): {error}"
                    )));
                    failing = true;
                }
                tracing::warn!(
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
        #[expect(
            clippy::match_same_arms,
            reason = "LineRead is non_exhaustive, so rustc needs this wildcard after the arms that name every variant"
        )]
        Ok(_) => return,
        Err(_idle) => {
            tracing::debug!("IPC: connection sent nothing within the read deadline; closing");
            return;
        }
    };

    let response = match serde_json::from_str::<C>(line.trim()) {
        Err(error) => json_error(&format!("parse error: {error}")),
        Ok(cmd) => {
            let (resp_tx, resp_rx) = oneshot::channel();
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
#[non_exhaustive]
pub struct NoDaemon {
    /// The nickname of the member.
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

/// Why a command could not reach its daemon.
///
/// [`IpcError::NoDaemon`] is the one a caller acts on (no live daemon to ask).
/// [`IpcError::Internal`] holds the causes no caller acts on: a bad socket name, a
/// round trip that fails, or a response that is too large.
#[derive(Debug)]
#[non_exhaustive]
pub enum IpcError {
    /// No daemon is listening on the socket.
    NoDaemon(NoDaemon),
    /// A cause no caller acts on. It keeps its text and its chain.
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

impl IpcError {
    /// Wraps a cause no caller acts on, keeping its text and its chain.
    pub(crate) fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDaemon(error) => std::fmt::Display::fmt(error, f),
            Self::Internal(error) => std::fmt::Display::fmt(error.as_ref(), f),
        }
    }
}

impl std::error::Error for IpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(error) => error.source(),
            Self::NoDaemon(_) => None,
        }
    }
}

/// Client-side: send an IPC command to the running server and return the raw JSON response.
///
/// # Panics
/// If called with a command that carries no mesh id — never: `Info` uses `send_to_path`.
/// # Errors
/// [`NoDaemon`] when no server is listening; otherwise an invalid socket name
/// or a failed request/response round trip.
pub async fn send<C>(
    base: &std::path::Path,
    cmd: &C,
    nickname: &Nickname,
) -> Result<String, IpcError>
where
    C: Serialize + Addressed,
{
    let mesh = cmd
        .mesh_id()
        .expect("send() is only used for mesh-addressed commands; Info uses send_to_path");
    let path = socket_path(base, mesh, nickname);
    let name = to_name(&path)
        .map_err(|error| IpcError::internal(anyhow::anyhow!("invalid socket name: {error}")))?;
    let stream = Stream::connect(name).await.map_err(|_| {
        IpcError::NoDaemon(NoDaemon {
            nickname: nickname.clone(),
        })
    })?;
    round_trip(stream, cmd).await.map_err(IpcError::internal)
}

/// Client-side: send an IPC command to a specific socket path. `doctor` uses
/// this to query each live daemon discovered under [`crate::util::runtime_base`] — a
/// missing/dead socket is a plain `Err` the caller can skip.
///
/// # Errors
/// The path is not valid UTF-8, the socket can't be connected (no live
/// daemon), or the request/response round trip fails.
pub async fn send_to_path<C: Serialize>(
    path: &std::path::Path,
    cmd: &C,
) -> Result<String, IpcError> {
    use anyhow::Context;
    let path_str = path
        .to_str()
        .context("socket path is not valid UTF-8")
        .map_err(IpcError::internal)?;
    let name = to_name(path_str)
        .map_err(|error| IpcError::internal(anyhow::anyhow!("invalid socket name: {error}")))?;
    let stream = Stream::connect(name)
        .await
        .map_err(|error| IpcError::internal(anyhow::anyhow!("connect {path_str}: {error}")))?;
    round_trip(stream, cmd).await.map_err(IpcError::internal)
}

/// Write `cmd`, half-close, and read back the single-line JSON response.
/// The shared body of [`send`] and [`send_to_path`].
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
        _ => anyhow::bail!("IPC response unreadable"),
    }
}

/// Every live daemon's IPC socket on this machine — one `<nick>.ipc.sock`
/// inside each mesh's folder (`<base>/<mesh-prefix>/`). Best-effort: a missing
/// base yields an empty list. Drives the consumer's active-mesh discovery, so it
/// walks the per-mesh subfolders.
#[must_use]
pub fn active_socket_paths(base: &std::path::Path) -> Vec<std::path::PathBuf> {
    let Ok(mesh_dirs) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    mesh_dirs
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .flat_map(|dir| std::fs::read_dir(dir).into_iter().flatten().flatten())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sock"))
        .collect()
}

#[cfg(test)]
mod tests {
    use habilis_network_test_tracing::test;
    use serde::{Deserialize, Serialize};

    use super::{
        Addressed, IpcMessage, MeshId, Nickname, bind, json_error, json_ok, mpsc, send, serve,
        socket_path,
    };

    use crate::gossip::event;
    use crate::util::tuning;
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

    /// A base of this suite's own, so a test that binds a real socket can never
    /// collide with (or be found by) a daemon running under a product's base.
    fn test_base() -> std::path::PathBuf {
        crate::util::runtime_base("habilis-network-ipc-test")
    }

    #[test]
    fn socket_path_format() {
        let mesh = MeshId::from("abcdefghijkmnpqr");
        let base = test_base();
        let path = socket_path(&base, &mesh, &Nickname::from("my-nick"));
        assert!(path.starts_with(&*base.to_string_lossy()));
        assert!(path.ends_with("/my-nick.ipc.sock"));
        assert!(path.contains(&crate::util::mesh_prefix(mesh.as_str())));
    }

    // ── property-based tests ───────────────────────────────────────

    mod prop {
        use crate::util::mesh_prefix;
        use habilis_network_test_tracing::test;
        use proptest::collection::vec as arb_vec;
        use proptest::strategy::Strategy;
        use proptest::{prop_assert, prop_assert_eq, proptest};

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
        // Base58-encode the pid so the mesh id passes strict charset validation.
        let pid_b58 = bs58::encode(std::process::id().to_le_bytes()).into_string();
        let mesh = MeshId::from(format!("ipctest{pid_b58}").as_str());
        let nickname = Nickname::from("test-nick");

        let (tx, rx) = mpsc::channel::<IpcMessage<TestCommand>>(8);

        // Bind synchronously (no sleep needed — the socket is accepting the
        // instant `bind` returns), then spawn the accept loop.
        let listener = bind(&test_base(), &mesh, &nickname).expect("bind IPC socket");
        let listener_handle =
            tokio::spawn(serve(listener, tx, std::sync::Arc::new(event::SilentSink)));

        // Spawn a handler that responds to messages
        let handler = tokio::spawn(respond_once(rx));

        // Send a command
        let cmd = TestCommand::Msg {
            mesh: mesh.clone(),
            body: "test message".to_owned(),
        };
        let response = send(&test_base(), &cmd, &nickname).await.unwrap();
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
    #[test]
    async fn idle_connection_is_closed_at_the_read_deadline() {
        use interprocess::local_socket::tokio::Stream;
        use interprocess::local_socket::traits::tokio::Stream as _;
        use interprocess::local_socket::{GenericFilePath, ToFsName};
        use tokio::io::AsyncReadExt;

        let pid_b58 = bs58::encode(std::process::id().to_le_bytes()).into_string();
        let mesh = MeshId::from(format!("ipcquiet{pid_b58}").as_str());
        let nickname = Nickname::from("idle-nick");
        let (tx, rx) = mpsc::channel::<IpcMessage<TestCommand>>(8);
        let listener = bind(&test_base(), &mesh, &nickname).expect("bind IPC socket");
        let listener_handle =
            tokio::spawn(serve(listener, tx, std::sync::Arc::new(event::SilentSink)));
        // Echo handler so a healthy command still round-trips while the
        // idle connection is parked.
        let handler = tokio::spawn(respond_healthy_forever(rx));

        // Park a silent connection.
        let path = socket_path(&test_base(), &mesh, &nickname);
        let name = path.clone().to_fs_name::<GenericFilePath>().unwrap();
        let mut idle = Stream::connect(name).await.unwrap();

        // A healthy command still round-trips while the idle one is parked.
        let cmd = TestCommand::Ping { mesh: mesh.clone() };
        let response = send(&test_base(), &cmd, &nickname).await.unwrap();
        assert!(response.contains("healthy"), "listener stalled: {response}");

        // The parked connection is closed (EOF) at the deadline, with margin.
        let mut sink = Vec::new();
        let read = tokio::time::timeout(
            tuning::IPC_IO_TIMEOUT + std::time::Duration::from_secs(5),
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

#[cfg(test)]
mod chain_tests {
    use habilis_network_test_tracing::test;

    use super::IpcError;

    #[test]
    fn an_internal_cause_keeps_its_chain() {
        let io = std::io::Error::new(std::io::ErrorKind::AddrInUse, "Address already in use");
        let cause = anyhow::Error::new(io).context("bind the endpoint");
        let error = anyhow::Error::new(IpcError::internal(cause));
        let text = format!("{error:#}");
        assert!(
            text.contains("Address already in use"),
            "the io cause of IpcError is lost: {text}"
        );
    }
}
