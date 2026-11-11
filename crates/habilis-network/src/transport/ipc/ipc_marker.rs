//! The marker of a Windows daemon: the file that names its pipe.

use std::{fs, io, path};

use anyhow::Result;

use super::ipc_name::IpcName;
use crate::protocol::{MeshId, Nickname};
use crate::util;
use crate::util::file_retry;

use crate::daemon::state_file;
/// The path of the marker of `nickname` on `mesh`: `<mesh folder>/<nick>.ipc`.
/// Windows only: on Unix a client derives the socket path.
pub(super) fn marker_path(base: &path::Path, mesh: &MeshId, nickname: &Nickname) -> path::PathBuf {
    util::mesh_runtime_dir(base, mesh.as_str()).join(format!("{nickname}.ipc"))
}

/// Read a marker. `Ok(None)` when there is no marker: no daemon is bound.
///
/// # Errors
/// The marker exists but cannot be read, or its line is no valid [`IpcName`].
pub(super) fn read_marker(path: &path::Path) -> Result<Option<IpcName>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => anyhow::bail!("read the IPC marker {}: {error}", path.display()),
    };
    // We write LF only; a CRLF from a hand edit is read the same way.
    let line = text.trim_end_matches(['\r', '\n']);
    IpcName::new(line.to_owned())
        .map(Some)
        .map_err(|error| anyhow::anyhow!("the IPC marker {}: {error}", path.display()))
}

/// The marker that one daemon wrote, kept on the event-loop state so the
/// shutdown removes it. Windows only.
#[derive(Debug)]
pub(crate) struct IpcMarker {
    path: path::PathBuf,
    name: IpcName,
}

impl IpcMarker {
    /// Write `name` to the marker at `path`, atomically.
    pub(super) fn write(path: path::PathBuf, name: IpcName) -> io::Result<Self> {
        let line = format!("{name}\n");
        state_file::write_private_atomic(&path, line.as_bytes())?;
        Ok(Self { path, name })
    }

    /// Remove the marker only while it still names this daemon. The pipe name
    /// is per process, so a second daemon with the same nickname on the same
    /// mesh writes another name over ours, and an unconditional remove at our
    /// exit would hide that live daemon. The read and the remove are two steps,
    /// so a write between them is possible: then the marker of the live daemon
    /// goes, and no client finds it.
    pub(crate) fn remove_if_ours(&self) {
        match read_marker(&self.path) {
            Ok(Some(current)) if current == self.name => {
                // On Windows a reader without `FILE_SHARE_DELETE` blocks the
                // remove while it holds the marker (R8 of `docs/windows.md`).
                if let Err(error) = file_retry::retry_while_shared(|| fs::remove_file(&self.path)) {
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
