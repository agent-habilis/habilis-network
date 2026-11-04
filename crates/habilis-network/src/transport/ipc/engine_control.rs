//! The commands that the engine answers itself on Windows, before the app sees a line.

use interprocess::local_socket::tokio::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::{io, time};

use super::addressed::Addressed;
use super::json_reply;
use crate::protocol::MeshId;
use crate::util::tuning::IPC_IO_TIMEOUT;

/// The error text when a quit names another mesh.
pub(super) const QUIT_OF_ANOTHER_MESH: &str = "command mesh id does not match this daemon";

/// The commands that the engine answers itself, before the app sees a line.
/// A line that does not parse as one of them goes to the app as before.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command")]
pub(super) enum EngineCommand {
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
/// this session, and the sender of the quit channel that the console events
/// feed. Windows only.
pub(crate) struct EngineControl {
    pub(crate) mesh: MeshId,
    pub(crate) quit_tx: mpsc::Sender<()>,
}

/// Answer a quit, then feed the quit channel. The answer goes first, so the
/// client has it before the process exits: the shutdown still waits for the
/// `Left` broadcast before the exit. The channel is fed whatever the write
/// gave, so a client that does not read cannot keep the daemon up. A full
/// channel holds a quit already, and a closed one belongs to a loop that has
/// ended; the answer is right in both cases.
pub(super) async fn answer_quit(
    mesh: &MeshId,
    control: &EngineControl,
    write_half: &mut io::WriteHalf<Stream>,
) {
    use tokio::io::AsyncWriteExt as _;

    if *mesh != control.mesh {
        let error = json_reply::json_error(QUIT_OF_ANOTHER_MESH);
        let _ = time::timeout(
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
    let _ = time::timeout(
        IPC_IO_TIMEOUT,
        write_half.write_all(format!("{}\n", json_reply::json_ack()).as_bytes()),
    )
    .await;
    let _ = control.quit_tx.try_send(());
}
