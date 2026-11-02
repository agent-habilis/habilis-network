//! The client side of the IPC endpoint: send a command and read its reply.

use super::addressed::Addressed;
use super::foreign_endpoint::ForeignEndpoint;
use super::ipc_error::IpcError;
#[cfg(windows)]
use super::ipc_marker;
use super::ipc_name::IpcName;
#[cfg(unix)]
use super::listener;
use super::no_daemon::NoDaemon;
use crate::protocol::Nickname;
use crate::util::consts::MAX_IPC_RESPONSE_BYTES;
use interprocess::local_socket::tokio::Stream;

use anyhow::Result;
use serde::Serialize;
use tokio::io::{AsyncWriteExt, BufReader};

use crate::util::line_read::{self, LineRead};

#[cfg(windows)]
use crate::util::win_security;
use std::io::Error as StdIoError;
#[cfg(any(windows, test))]
use std::time::Duration;
use std::{fs, path};
use tokio::io;

#[cfg(windows)]
use interprocess::os::windows::named_pipe::local_socket::tokio as pipe_tokio;
#[cfg(windows)]
use tokio::time;
/// Why a client could not reach an endpoint.
enum Unreached {
    /// Nothing accepts on the name: a stale marker, or a pipe whose DACL leaves
    /// us out, which is no endpoint of ours either.
    Absent(StdIoError),
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
pub(super) fn pipe_busy_retry(attempt: u32) -> Option<Duration> {
    const TRIES: u32 = 3;
    (attempt < TRIES).then_some(Duration::from_millis(50))
}

/// Connect to `name`. On Unix the socket sits in the private runtime folder, so
/// a connect is enough. On Windows the client opens the pipe itself with
/// `SECURITY_IDENTIFICATION`, so the server cannot act as the client, and checks
/// that `owner` owns the pipe before it sends a byte.
async fn connect(
    name: &IpcName,
    #[cfg(windows)] owner: &win_security::Sid,
) -> Result<Stream, Unreached> {
    #[cfg(unix)]
    {
        use interprocess::local_socket::traits::tokio::Stream as _;
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
            match win_security::open_pipe_identification(name.as_str()) {
                Ok(handle) => break handle,
                Err(error) if win_security::is_pipe_busy(&error) => {
                    let Some(wait) = pipe_busy_retry(attempt) else {
                        return Err(Unreached::Absent(error));
                    };
                    attempt += 1;
                    time::sleep(wait).await;
                }
                Err(error) => return Err(Unreached::Absent(error)),
            }
        };
        if !win_security::handle_owner_is(handle.as_handle(), owner) {
            tracing::warn!(
                target: "habilis_network::lifecycle",
                name = %name,
                "IPC: the pipe is not owned by this user; refusing it"
            );
            return Err(Unreached::Foreign);
        }
        let pipe = pipe_tokio::Stream::try_from(handle)
            .map_err(|error| Unreached::Other(anyhow::anyhow!("open IPC pipe {name}: {error}")))?;
        Ok(Stream::from(pipe))
    }
}

/// The owner that a client expects: the current user.
#[cfg(windows)]
fn current_owner() -> Result<win_security::Sid, IpcError> {
    win_security::current_user_sid().map_err(|error| {
        IpcError::internal(anyhow::anyhow!("read the SID of the current user: {error}"))
    })
}

/// Client-side: send an IPC command to the running server and return the raw JSON response.
///
/// # Panics
/// If called with a command that carries no mesh id — never: `Info` uses `send_to_path`.
/// # Errors
/// [`NoDaemon`] when no server is listening; otherwise an invalid socket name
/// or a failed request/response round trip.
///
/// # Examples
///
/// It sends a command to the daemon at the base path, and it returns the reply text. The doc test compiles it but does not run it.
///
/// ```no_run
/// use std::path::Path;
///
/// use habilis_network::protocol::Nickname;
/// use habilis_network::runtime::ipc::{Addressed, send};
/// use serde::Serialize;
///
/// # async fn demo<Cmd: Serialize + Addressed>(base: &Path, command: &Cmd, nickname: &Nickname) {
/// let _ = send(base, command, nickname).await;
/// # }
/// ```
#[cfg(unix)]
pub async fn send<Cmd>(
    base: &path::Path,
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

/// Client-side: send an IPC command to the running server and return the raw JSON response.
///
/// The server is found through its marker (`<mesh folder>/<nick>.ipc`).
/// Windows; on Unix the client derives the socket path.
///
/// # Panics
/// If called with a command that carries no mesh id — never: `Info` uses `send_to_endpoint`.
/// # Errors
/// [`NoDaemon`] when no marker exists or nothing accepts on its name;
/// [`ForeignEndpoint`] when the endpoint belongs to another account; otherwise
/// an unreadable or invalid marker, or a failed request/response round trip.
///
/// # Examples
///
/// It sends a command to the daemon at the base path, and it returns the reply text. The doc test compiles it but does not run it.
///
/// ```no_run
/// use std::path::Path;
///
/// use habilis_network::protocol::Nickname;
/// use habilis_network::runtime::ipc::{Addressed, send};
/// use serde::Serialize;
///
/// # async fn demo<Cmd: Serialize + Addressed>(base: &Path, command: &Cmd, nickname: &Nickname) {
/// let _ = send(base, command, nickname).await;
/// # }
/// ```
#[cfg(windows)]
pub async fn send<Cmd>(
    base: &path::Path,
    command: &Cmd,
    nickname: &Nickname,
) -> Result<String, IpcError>
where
    Cmd: Serialize + Addressed,
{
    let mesh = command
        .mesh_id()
        .expect("send() is only used for mesh-addressed commands; Info uses send_to_endpoint");
    let no_daemon = || {
        IpcError::NoDaemon(NoDaemon {
            nickname: nickname.clone(),
        })
    };
    let marker = ipc_marker::marker_path(base, mesh, nickname);
    let Some(name) = ipc_marker::read_marker(&marker).map_err(IpcError::internal)? else {
        return Err(no_daemon());
    };
    let reached = connect(&name, &current_owner()?).await;
    match reached {
        Ok(stream) => round_trip(stream, command)
            .await
            .map_err(IpcError::internal),
        Err(Unreached::Absent(_)) => Err(no_daemon()),
        Err(Unreached::Foreign) => Err(IpcError::ForeignEndpoint(ForeignEndpoint {
            nickname: Some(nickname.clone()),
            name,
        })),
        Err(Unreached::Other(error)) => Err(IpcError::internal(error)),
    }
}

/// Client-side: send an IPC command to a specific socket path. `doctor` uses
/// this to query each live daemon discovered under [`crate::util::runtime_base`] — a
/// missing/dead socket is a plain `Err` the caller can skip. Unix only; on
/// every OS [`send_to_endpoint`] takes the name of an endpoint.
///
/// # Errors
/// The path is not valid UTF-8, the socket can't be connected (no live
/// daemon), or the request/response round trip fails.
///
/// # Examples
///
/// It sends a command to the daemon socket at the given path. The doc test compiles it but does not run it.
///
/// ```no_run
/// use std::path::Path;
///
/// use habilis_network::runtime::ipc::send_to_path;
/// use serde::Serialize;
///
/// # async fn demo<Cmd: Serialize>(path: &Path, command: &Cmd) {
/// let _ = send_to_path(path, command).await;
/// # }
/// ```
#[cfg(unix)]
pub async fn send_to_path<Cmd: Serialize>(
    path: &path::Path,
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

/// Client-side: send an IPC command to the endpoint `name`. `doctor` uses this
/// to query each live daemon that [`active_endpoints`] found; a stale endpoint
/// is a plain `Err` that the caller can skip.
///
/// # Errors
/// Nothing accepts on `name` (no live daemon), [`ForeignEndpoint`] when the
/// endpoint belongs to another account, or the request/response round trip
/// fails.
///
/// # Examples
///
/// It sends a command to the endpoint of a live daemon. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::ipc::{IpcName, send_to_endpoint};
/// use serde::Serialize;
///
/// # async fn demo<Cmd: Serialize>(name: &IpcName, command: &Cmd) {
/// let _ = send_to_endpoint(name, command).await;
/// # }
/// ```
pub async fn send_to_endpoint<Cmd: Serialize>(
    name: &IpcName,
    command: &Cmd,
) -> Result<String, IpcError> {
    send_to_endpoint_owned_by(
        name,
        command,
        #[cfg(windows)]
        &current_owner()?,
    )
    .await
}

/// [`send_to_endpoint`] with the expected owner as a parameter, so a test can
/// expect another account and see the refusal.
pub(super) async fn send_to_endpoint_owned_by<Cmd: Serialize>(
    name: &IpcName,
    command: &Cmd,
    #[cfg(windows)] owner: &win_security::Sid,
) -> Result<String, IpcError> {
    let reached = connect(
        name,
        #[cfg(windows)]
        owner,
    )
    .await;
    match reached {
        Ok(stream) => round_trip(stream, command)
            .await
            .map_err(IpcError::internal),
        Err(Unreached::Absent(error)) => Err(IpcError::internal(anyhow::anyhow!(
            "connect {name}: {error}"
        ))),
        Err(Unreached::Foreign) => Err(IpcError::ForeignEndpoint(ForeignEndpoint {
            nickname: None,
            name: name.clone(),
        })),
        Err(Unreached::Other(error)) => Err(IpcError::internal(error)),
    }
}

/// Write `cmd`, half-close, and read back the single-line JSON response.
/// The shared body of [`send`], [`send_to_endpoint`] and, on Unix,
/// `send_to_path`.
async fn round_trip<Cmd: Serialize>(stream: Stream, command: &Cmd) -> Result<String> {
    let (read_half, mut write_half) = io::split(stream);

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

/// The files of every mesh folder under `base`, one level down. Best-effort: a
/// missing base yields none.
fn mesh_files(base: &path::Path) -> impl Iterator<Item = path::PathBuf> {
    let entries = fs::read_dir(base).into_iter().flatten().flatten();
    let dir_paths = entries.map(|entry| entry.path());
    let dirs = dir_paths.filter(|path| path.is_dir());
    let read_mesh = |dir: path::PathBuf| fs::read_dir(dir).into_iter().flatten().flatten();
    let files = dirs.flat_map(read_mesh);
    files.map(|entry| entry.path())
}

/// Every live daemon's IPC socket on this machine — one `<nick>.ipc.sock`
/// inside each mesh's folder (`<base>/<mesh-prefix>/`). Best-effort: a missing
/// base yields an empty list. Drives the consumer's active-mesh discovery, so it
/// walks the per-mesh subfolders. Unix only; on every OS
/// [`active_endpoints`] lists the endpoints.
///
/// # Examples
///
/// A base path with no daemon sockets lists none.
///
/// ```
/// use std::path::Path;
///
/// use habilis_network::runtime::ipc::active_socket_paths;
///
/// assert_eq!(active_socket_paths(Path::new("/nonexistent")).count(), 0);
/// ```
#[cfg(unix)]
pub fn active_socket_paths(base: &path::Path) -> impl Iterator<Item = path::PathBuf> {
    mesh_files(base).filter(|path| path.extension().is_some_and(|ext| ext == "sock"))
}

/// The endpoint of every daemon under `base`, as [`IpcName`]s. On Unix these
/// are the sockets of [`active_socket_paths`]; a path that is no valid name,
/// such as one that is not UTF-8, is skipped. The list is sorted, so its order
/// is stable.
///
/// # Examples
///
/// A base path with no daemon lists none.
///
/// ```
/// use std::path::Path;
///
/// use habilis_network::runtime::ipc::active_endpoints;
///
/// assert_eq!(active_endpoints(Path::new("/nonexistent")).count(), 0);
/// ```
#[cfg(unix)]
pub fn active_endpoints(base: &path::Path) -> impl Iterator<Item = IpcName> {
    let text_of = |path: path::PathBuf| path.into_os_string().into_string().ok();
    let texts: Vec<String> = active_socket_paths(base).filter_map(text_of).collect();
    let mut names: Vec<IpcName> = texts
        .into_iter()
        .filter_map(|text| IpcName::new(text).ok())
        .collect();
    names.sort();
    names.into_iter()
}

/// On Windows, the endpoint of every daemon that has a marker under `base`: one
/// `<nick>.ipc` inside each mesh folder (`<base>/<mesh-prefix>/`). Best-effort:
/// a missing base gives an empty list, and a marker that cannot be read or holds
/// no valid name is skipped with a warn. The tmp file of a marker write
/// (`<nick>.ipc.tmp.<pid>`) has another extension and is not read. A marker of
/// a daemon that died stays until a client fails to connect to it, as a stale
/// socket file did. The list is sorted, so its order is stable.
///
/// # Examples
///
/// A base path with no daemon lists none.
///
/// ```
/// use std::path::Path;
///
/// use habilis_network::runtime::ipc::active_endpoints;
///
/// assert_eq!(active_endpoints(Path::new("/nonexistent")).count(), 0);
/// ```
#[cfg(windows)]
pub fn active_endpoints(base: &path::Path) -> impl Iterator<Item = IpcName> {
    let files = mesh_files(base);
    let is_marker = |path: &path::PathBuf| path.extension().is_some_and(|ext| ext == "ipc");
    let markers: Vec<path::PathBuf> = files
        .filter(|path| is_marker(path) && path.is_file())
        .collect();
    let mut names: Vec<IpcName> = markers
        .into_iter()
        .filter_map(|path| match ipc_marker::read_marker(&path) {
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
    names.into_iter()
}
