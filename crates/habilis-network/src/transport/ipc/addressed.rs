//! The trait a peer's IPC command is addressed by.

use crate::protocol::MeshId;
/// A mesh-addressed IPC command. The engine derives the per-mesh socket path
/// from the mesh id in [`crate::transport::ipc::send`]; `None` means the command is addressed by
/// socket path directly (via [`crate::transport::ipc::send_to_path`]) and carries no mesh — the
/// concrete command type is defined app-side, the engine only needs the address.
///
/// # Examples
///
/// A command names the mesh it is for, or none.
///
/// ```
/// use habilis_network::protocol::MeshId;
/// use habilis_network::runtime::ipc::Addressed;
///
/// struct Command {
///     mesh: Option<MeshId>,
/// }
///
/// impl Addressed for Command {
///     fn mesh_id(&self) -> Option<&MeshId> {
///         self.mesh.as_ref()
///     }
/// }
///
/// let command = Command { mesh: None };
/// assert!(command.mesh_id().is_none());
/// ```
pub trait Addressed {
    /// The mesh this command is for, or `None` for a command that has none.
    fn mesh_id(&self) -> Option<&MeshId>;
}
