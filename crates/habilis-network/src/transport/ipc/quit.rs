//! Stop a daemon: the IPC quit on Windows, `SIGTERM` on Unix.

use std::io;

#[cfg(windows)]
use super::client;
#[cfg(windows)]
use super::engine_control::EngineCommand;
#[cfg(windows)]
use super::listener::PARSE_ERROR;
use super::quit_error::QuitError;
use super::quit_target::QuitTarget;
#[cfg(unix)]
use crate::util::process;

/// Stop a daemon through its IPC endpoint: the engine's `quit` command. The
/// daemon answers, then takes the path of a signal: it removes its state file
/// and its marker, broadcasts `Left`, and exits. `Ok` means that the daemon
/// accepted the quit, not that it is gone already.
///
/// Windows only. On Unix it is [`QuitError::Unsupported`] and opens no
/// connection: a daemon there stops on `SIGTERM` ([`terminate`]).
///
/// # Errors
/// [`QuitError`]: the quit was not heard, the daemon is too old to know it, or
/// the daemon refused it; on Unix always `Unsupported`.
///
/// # Examples
///
/// It stops a running daemon, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::ipc::{QuitTarget, quit};
///
/// # async fn demo(target: &QuitTarget<'_>) {
/// let _ = quit(target).await;
/// # }
/// ```
#[cfg(windows)]
pub async fn quit(target: &QuitTarget<'_>) -> Result<(), QuitError> {
    let command = EngineCommand::Quit {
        mesh: target.mesh.clone(),
    };
    let reply = client::send(target.base, &command, target.nickname)
        .await
        .map_err(|error| QuitError::Unreached(error.into()))?;
    quit_outcome(&reply)
}

/// See the Windows version: on Unix the IPC quit does not exist.
///
/// # Errors
/// Always [`QuitError::Unsupported`].
///
/// # Examples
///
/// ```no_run
/// use habilis_network::runtime::ipc::{QuitTarget, quit};
///
/// # async fn demo(target: &QuitTarget<'_>) {
/// let _ = quit(target).await;
/// # }
/// ```
#[cfg(unix)]
pub async fn quit(target: &QuitTarget<'_>) -> Result<(), QuitError> {
    let _ = target;
    Err(QuitError::Unsupported)
}

/// What the answer to a quit means.
#[cfg(windows)]
pub(super) fn quit_outcome(reply: &str) -> Result<(), QuitError> {
    if reply.is_empty() {
        return Err(QuitError::Unreached(anyhow::anyhow!(
            "the daemon closed the connection with no answer"
        )));
    }
    let parsed: serde_json::Result<serde_json::Value> = serde_json::from_str(reply);
    let Ok(value) = parsed else {
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

/// Stop the daemon of `target`. On Windows it is [`quit`]. On Unix it sends
/// `SIGTERM` to `pid` ([`crate::util::process::terminate`]) and opens no
/// connection, as a client did before the port.
///
/// Not the same function as `util::process::terminate`: that one only signals
/// a pid, and on Windows it can do nothing. This one stops a daemon.
///
/// On Unix the caller must know that `pid` is the daemon of `target`, for
/// example from the `pid` of its `Info` answer, or the signal can reach a
/// process that took over the pid. `pid` is not used on Windows, and `target`
/// is not used on Unix.
///
/// # Errors
/// On Windows the [`QuitError`] of the quit, inside an [`io::Error`] of kind `Other`; on Unix
/// the error of the signal.
///
/// # Examples
///
/// It stops a running daemon, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::ipc::{QuitTarget, terminate};
///
/// # async fn demo(target: &QuitTarget<'_>, pid: u32) {
/// let _ = terminate(target, pid).await;
/// # }
/// ```
#[cfg(windows)]
pub async fn terminate(target: &QuitTarget<'_>, pid: u32) -> io::Result<()> {
    let _ = pid;
    quit(target).await.map_err(io::Error::other)
}

/// See the Windows version.
///
/// # Errors
/// The error of the signal: no such process, or no permission.
///
/// # Examples
///
/// ```no_run
/// use habilis_network::runtime::ipc::{QuitTarget, terminate};
///
/// # async fn demo(target: &QuitTarget<'_>, pid: u32) {
/// let _ = terminate(target, pid).await;
/// # }
/// ```
#[cfg(unix)]
pub async fn terminate(target: &QuitTarget<'_>, pid: u32) -> io::Result<()> {
    let _ = target;
    process::terminate(pid)
        .map_err(|signal| io::Error::new(signal.kind(), format!("SIGTERM to pid {pid}: {signal}")))
}
