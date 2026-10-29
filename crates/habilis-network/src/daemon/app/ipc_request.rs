use tokio::sync::oneshot;

use crate::protocol::mesh::MeshName;

/// One parsed IPC command bundled with its answer channel and this
/// session's mesh name — the value cluster [`NodeDriver::handle_ipc`](super::NodeDriver::handle_ipc) needs
/// beyond the loop state and handler context.
///
/// # Examples
///
/// An IPC request is a command that a control client sends to the daemon. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::IpcRequest;
///
/// # fn demo<'name, Cmd>(request: IpcRequest<'name, Cmd>) {
/// let _ = request;
/// # }
/// ```
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
