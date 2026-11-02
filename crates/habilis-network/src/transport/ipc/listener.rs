//! The listener side of the IPC endpoint: bind, serve, and answer each connection.

use super::bound::Bound;
#[cfg(windows)]
use super::engine_control::{self, EngineCommand, EngineControl};
#[cfg(windows)]
use super::ipc_marker::{self, IpcMarker};
#[cfg(windows)]
use super::ipc_name::IpcName;
use super::json_reply;
use crate::protocol::{MeshId, Nickname};
use crate::transport::IpcMessage;
use crate::util::consts::MAX_IPC_COMMAND_BYTES;

use std::time::Duration;

use anyhow::Result;
use interprocess::local_socket::ListenerOptions;
#[cfg(unix)]
use interprocess::local_socket::Name;
use interprocess::local_socket::tokio::{Listener, Stream};
use serde::de::DeserializeOwned;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::gossip::event;
use crate::util;
use crate::util::clock;
use crate::util::line_read::{self, LineRead};
use crate::util::tuning::{IPC_ACCEPT_BACKOFF_MAX, IPC_ACCEPT_BACKOFF_MIN, IPC_IO_TIMEOUT};
use tokio::sync::oneshot;

#[cfg(unix)]
use std::fs;
use std::{path, sync};
use tokio::{io, time};

/// The start of the error text when a command line does not parse. A daemon
/// that does not know the engine `quit` answers a quit with it.
pub(super) const PARSE_ERROR: &str = "parse error";

/// The prefix of every pipe name of the engine, before the random part.
#[cfg(windows)]
pub(super) const PIPE_PREFIX: &str = r"\\.\pipe\habilis-";

/// Returns the IPC endpoint identifier for a specific agent on a mesh — a
/// filesystem socket path. Lives in the mesh's runtime folder beside its
/// `<nick>.tracing.log` / `<nick>.state.json`. Unix only: on Windows the
/// endpoint is a pipe, which the marker names.
#[cfg(unix)]
pub(crate) fn socket_path(base: &path::Path, mesh: &MeshId, nickname: &Nickname) -> String {
    format!(
        "{}/{nickname}.ipc.sock",
        util::mesh_runtime_dir(base, mesh.as_str()).display()
    )
}

#[cfg(unix)]
pub(super) fn to_name(path: &str) -> Result<Name<'_>> {
    use interprocess::local_socket::{GenericFilePath, PathNameType};
    use std::{borrow, ffi};
    Ok(GenericFilePath::map(borrow::Cow::Borrowed(
        ffi::OsStr::new(path),
    ))?)
}

/// Bind the local IPC socket synchronously, returning the listening
/// socket. Done *before* the daemon marks itself ready so that "ready"
/// can never precede an accepting socket: a `ready` gate that observes
/// the readiness flag is then guaranteed a subsequent `connect` succeeds.
///
/// # Errors
/// An invalid socket name, or the OS refusing the bind.
#[cfg(unix)]
pub(crate) fn bind(base: &path::Path, mesh: &MeshId, nickname: &Nickname) -> Result<Bound> {
    let path = socket_path(base, mesh, nickname);

    // The runtime base must exist and be private (0700) before the socket is
    // created inside it: this control socket has no in-band auth, so the base's
    // permissions are what keep another local user from reaching it. The choke
    // point validates the base (fails closed on a squat/symlink) and creates
    // the mesh folder in one step.
    util::ensure_mesh_runtime_dir(base, mesh.as_str())
        .map_err(|error| anyhow::anyhow!("failed to prepare runtime dir: {error}"))?;
    // Best-effort cleanup of a stale socket file.
    let _ = fs::remove_file(&path);

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
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
            tracing::warn!(?path, %error, "IPC socket: could not restrict to 0600");
        }
    }
    tracing::info!(?path, "IPC socket listening");
    Ok(Bound { listener })
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
#[cfg(windows)]
pub(crate) fn bind(base: &path::Path, mesh: &MeshId, nickname: &Nickname) -> Result<Bound> {
    util::ensure_mesh_runtime_dir(base, mesh.as_str())
        .map_err(|error| anyhow::anyhow!("failed to prepare runtime dir: {error}"))?;
    let (listener, name) = listen()?;
    let marker_at = ipc_marker::marker_path(base, mesh, nickname);
    let marker = match IpcMarker::write(marker_at.clone(), name.clone()) {
        Ok(marker) => marker,
        Err(error) => {
            drop(listener);
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
fn listen() -> Result<(Listener, IpcName)> {
    use interprocess::os::windows::local_socket::ListenerOptionsExt as _;
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;
    use rand::Rng as _;

    let random: u128 = rand::rng().random();
    let name = IpcName::new(format!("{PIPE_PREFIX}{random:032x}"))?;
    let sddl = util::win_security::user_sddl()
        .map_err(|error| anyhow::anyhow!("the security descriptor of the IPC pipe: {error}"))?;
    let sddl = widestring::U16CStr::from_slice(&sddl)
        .map_err(|error| anyhow::anyhow!("the security descriptor of the IPC pipe: {error}"))?;
    let descriptor = SecurityDescriptor::deserialize(sddl)
        .map_err(|error| anyhow::anyhow!("the security descriptor of the IPC pipe: {error}"))?;
    let options: ListenerOptions<'_> = ListenerOptions::new()
        .name(name.to_name()?)
        .security_descriptor(descriptor);
    let listener: Listener = options
        .create_tokio()
        .map_err(|error| anyhow::anyhow!("failed to bind IPC pipe {name}: {error}"))?;
    Ok((listener, name))
}

/// Server-side accept loop over an already-[`bind`]-ed endpoint: forward each
/// connection's command to the event loop, or on Windows answer an engine
/// command with `control`. Spawned after `bind` returns, so by the time this
/// runs the endpoint is already accepting.
pub(crate) async fn serve<Cmd>(
    listener: Listener,
    tx: mpsc::Sender<IpcMessage<Cmd>>,
    #[cfg(windows)] control: EngineControl,
    // trait object: the listener and its connections share the sink
    sink: sync::Arc<dyn event::NodeSink>,
) where
    Cmd: DeserializeOwned + Send + 'static,
{
    use interprocess::local_socket::traits::tokio::Listener as _;
    #[cfg(windows)]
    // shared by every connection task, each of which may answer a quit
    let control = sync::Arc::new(control);
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
                #[cfg(windows)]
                let control = sync::Arc::clone(&control);
                tokio::spawn(handle_connection(
                    stream,
                    tx,
                    #[cfg(windows)]
                    control,
                ));
            }
            Err(error) => {
                if !failing {
                    sink.emit(event::NodeEvent::Error(format!(
                        "IPC: accept error (retrying): {error}"
                    )));
                    failing = true;
                }
                #[cfg(unix)]
                tracing::warn!(
                    %error,
                    backoff_ms = clock::millis_saturating(backoff),
                    "IPC: accept error; retrying"
                );
                #[cfg(windows)]
                tracing::warn!(
                    target: "habilis_network::lifecycle",
                    %error,
                    backoff_ms = clock::millis_saturating(backoff),
                    "IPC: accept error; retrying"
                );
                time::sleep(backoff).await;
                backoff = next_accept_backoff(backoff);
            }
        }
    }
}

/// Double the accept backoff up to its cap.
pub(super) fn next_accept_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(IPC_ACCEPT_BACKOFF_MAX)
}

async fn handle_connection<Cmd>(
    stream: Stream,
    tx: mpsc::Sender<IpcMessage<Cmd>>,
    // the accept loop shares it with every connection
    #[cfg(windows)] control: sync::Arc<EngineControl>,
) where
    Cmd: DeserializeOwned + Send + 'static,
{
    let (read_half, mut write_half) = io::split(stream);
    let mut reader = BufReader::new(read_half);

    // I/O deadline on both legs: a client that connects and goes silent
    // (or stops draining the response) would otherwise pin this task and
    // its fd for the daemon's lifetime.
    let io_deadline = IPC_IO_TIMEOUT;
    let line = match time::timeout(
        io_deadline,
        line_read::read_bounded_line(&mut reader, MAX_IPC_COMMAND_BYTES),
    )
    .await
    {
        Ok(Ok(LineRead::Line(line))) => line,
        Ok(Ok(LineRead::TooLong)) => {
            let error = json_reply::json_error("command too large");
            let _ = time::timeout(
                io_deadline,
                write_half.write_all(format!("{error}\n").as_bytes()),
            )
            .await;
            return;
        }
        Ok(Ok(LineRead::Eof) | _) => return,
        Err(_idle) => {
            #[cfg(unix)]
            tracing::debug!("IPC: connection sent nothing within the read deadline; closing");
            #[cfg(windows)]
            tracing::debug!(
                target: "habilis_network::lifecycle",
                "IPC: connection sent nothing within the read deadline; closing"
            );
            return;
        }
    };

    // On Windows an engine command first. Any other line, also one that is no
    // JSON object, goes to the app's own parse, unchanged.
    #[cfg(windows)]
    let engine: serde_json::Result<EngineCommand> = serde_json::from_str(line.trim());
    #[cfg(windows)]
    if let Ok(EngineCommand::Quit { mesh }) = engine {
        engine_control::answer_quit(&mesh, &control, &mut write_half).await;
        return;
    }

    let parsed: serde_json::Result<Cmd> = serde_json::from_str(line.trim());
    let response = match parsed {
        Err(error) => json_reply::json_error(&format!("{PARSE_ERROR}: {error}")),
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

    let _ = time::timeout(
        io_deadline,
        write_half.write_all(format!("{response}\n").as_bytes()),
    )
    .await;
}
