//! The listener side of the IPC socket: bind, serve, and answer each connection.

use super::json_reply;
use crate::protocol::{MeshId, Nickname};
use crate::transport::IpcMessage;
use crate::util::consts::MAX_IPC_COMMAND_BYTES;

use std::time::Duration;

use anyhow::Result;
use interprocess::local_socket::tokio::{Listener, Stream};
use interprocess::local_socket::{ListenerOptions, Name};
use serde::de::DeserializeOwned;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::gossip::event;
use crate::util;
use crate::util::bounded_read::{self, LineRead};
use crate::util::clock;
use crate::util::tuning::{IPC_ACCEPT_BACKOFF_MAX, IPC_ACCEPT_BACKOFF_MIN, IPC_IO_TIMEOUT};
use tokio::sync::oneshot;

/// Returns the IPC endpoint identifier for a specific agent on a mesh —
/// a filesystem socket path (the project targets Unix only). Lives in the
/// mesh's runtime folder beside its `<nick>.tracing.log` / `<nick>.state.json`.
pub(crate) fn socket_path(base: &std::path::Path, mesh: &MeshId, nickname: &Nickname) -> String {
    format!(
        "{}/{nickname}.ipc.sock",
        util::mesh_runtime_dir(base, mesh.as_str()).display()
    )
}

pub(super) fn to_name(path: &str) -> Result<Name<'_>> {
    use interprocess::local_socket::{GenericFilePath, ToFsName};
    Ok(path.to_fs_name::<GenericFilePath>()?)
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
    util::ensure_mesh_runtime_dir(base, mesh.as_str())
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
pub(crate) async fn serve<Cmd>(
    listener: Listener,
    tx: mpsc::Sender<IpcMessage<Cmd>>,
    sink: std::sync::Arc<dyn event::NodeSink>,
) where
    Cmd: DeserializeOwned + Send + 'static,
{
    use interprocess::local_socket::traits::tokio::Listener as _;
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
                tokio::spawn(handle_connection::<Cmd>(stream, tx));
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
                    backoff_ms = clock::millis_saturating(backoff),
                    "IPC: accept error; retrying"
                );
                tokio::time::sleep(backoff).await;
                backoff = next_accept_backoff(backoff);
            }
        }
    }
}

/// Double the accept backoff up to its cap.
pub(super) fn next_accept_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(IPC_ACCEPT_BACKOFF_MAX)
}

async fn handle_connection<Cmd>(stream: Stream, tx: mpsc::Sender<IpcMessage<Cmd>>)
where
    Cmd: DeserializeOwned + Send + 'static,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // I/O deadline on both legs: a client that connects and goes silent
    // (or stops draining the response) would otherwise pin this task and
    // its fd for the daemon's lifetime.
    let io_deadline = IPC_IO_TIMEOUT;
    let line = match tokio::time::timeout(
        io_deadline,
        bounded_read::read_bounded_line(&mut reader, MAX_IPC_COMMAND_BYTES),
    )
    .await
    {
        Ok(Ok(LineRead::Line(line))) => line,
        Ok(Ok(LineRead::TooLong)) => {
            let error = json_reply::json_error("command too large");
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

    let response = match serde_json::from_str::<Cmd>(line.trim()) {
        Err(error) => json_reply::json_error(&format!("parse error: {error}")),
        Ok(command) => {
            let (resp_tx, resp_rx) = oneshot::channel();
            if tx.send((command, resp_tx)).await.is_err() {
                json_reply::json_error("server channel closed")
            } else {
                match resp_rx.await {
                    Ok(reply) => reply,
                    Err(_) => json_reply::json_error("response channel dropped"),
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
