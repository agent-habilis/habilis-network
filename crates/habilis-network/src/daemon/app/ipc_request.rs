use tokio::sync::oneshot;

use crate::protocol::mesh::MeshName;

/// One parsed IPC command bundled with its answer channel and this
/// session's mesh name — the value cluster [`NodeDriver::handle_ipc`](super::NodeDriver::handle_ipc) needs
/// beyond the loop state and handler context.
#[derive(Debug)]
#[non_exhaustive]
pub struct IpcRequest<'name, Cmd> {
    /// The parsed IPC command.
    pub command: Cmd,
    /// Gets the text of the answer.
    pub response: oneshot::Sender<String>,
    /// The name of the mesh.
    pub name: &'name MeshName,
}
