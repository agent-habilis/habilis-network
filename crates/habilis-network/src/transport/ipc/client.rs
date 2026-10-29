//! The client side of the IPC socket: send a command and read its reply.

use super::addressed::Addressed;
use super::ipc_error::IpcError;
use super::listener;
use super::no_daemon::NoDaemon;
use crate::protocol::Nickname;
use crate::util::consts::MAX_IPC_RESPONSE_BYTES;
use interprocess::local_socket::tokio::Stream;

use anyhow::Result;
use serde::Serialize;
use tokio::io::{AsyncWriteExt, BufReader};

use crate::util::line_read::{self, LineRead};

/// Client-side: send an IPC command to the running server and return the raw JSON response.
///
/// # Panics
/// If called with a command that carries no mesh id — never: `Info` uses `send_to_path`.
/// # Errors
/// [`NoDaemon`] when no server is listening; otherwise an invalid socket name
/// or a failed request/response round trip.
pub async fn send<Cmd>(
    base: &std::path::Path,
    command: &Cmd,
    nickname: &Nickname,
) -> Result<String, IpcError>
where
    Cmd: Serialize + Addressed,
{
    use interprocess::local_socket::traits::tokio::Stream as _;
    let mesh = command
        .mesh_id()
        .expect("send() is only used for mesh-addressed commands; Info uses send_to_path");
    let path = listener::socket_path(base, mesh, nickname);
    let name = listener::to_name(&path)
        .map_err(|error| IpcError::internal(anyhow::anyhow!("invalid socket name: {error}")))?;
    let stream = Stream::connect(name).await.map_err(|_| {
        IpcError::NoDaemon(NoDaemon {
            nickname: nickname.clone(),
        })
    })?;
    round_trip(stream, command)
        .await
        .map_err(IpcError::internal)
}

/// Client-side: send an IPC command to a specific socket path. `doctor` uses
/// this to query each live daemon discovered under [`crate::util::runtime_base`] — a
/// missing/dead socket is a plain `Err` the caller can skip.
///
/// # Errors
/// The path is not valid UTF-8, the socket can't be connected (no live
/// daemon), or the request/response round trip fails.
pub async fn send_to_path<Cmd: Serialize>(
    path: &std::path::Path,
    command: &Cmd,
) -> Result<String, IpcError> {
    use anyhow::Context;
    use interprocess::local_socket::traits::tokio::Stream as _;
    let path_str = path
        .to_str()
        .context("socket path is not valid UTF-8")
        .map_err(IpcError::internal)?;
    let name = listener::to_name(path_str)
        .map_err(|error| IpcError::internal(anyhow::anyhow!("invalid socket name: {error}")))?;
    let stream = Stream::connect(name)
        .await
        .map_err(|error| IpcError::internal(anyhow::anyhow!("connect {path_str}: {error}")))?;
    round_trip(stream, command)
        .await
        .map_err(IpcError::internal)
}

/// Write `cmd`, half-close, and read back the single-line JSON response.
/// The shared body of [`send`] and [`send_to_path`].
async fn round_trip<Cmd: Serialize>(stream: Stream, command: &Cmd) -> Result<String> {
    let (read_half, mut write_half) = tokio::io::split(stream);

    let json = serde_json::to_string(command)?;
    write_half.write_all(format!("{json}\n").as_bytes()).await?;
    write_half.shutdown().await?;

    let mut reader = BufReader::new(read_half);
    match line_read::read_bounded_line(&mut reader, MAX_IPC_RESPONSE_BYTES).await? {
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
pub fn active_socket_paths(base: &std::path::Path) -> impl Iterator<Item = std::path::PathBuf> {
    let entries = std::fs::read_dir(base).into_iter().flatten().flatten();
    let dirs = entries
        .map(|entry| entry.path())
        .filter(|path| path.is_dir());
    let files = dirs.flat_map(|dir| std::fs::read_dir(dir).into_iter().flatten().flatten());
    let paths = files.map(|entry| entry.path());
    paths.filter(|path| path.extension().is_some_and(|ext| ext == "sock"))
}
