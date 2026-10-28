//! The trait a peer's IPC command is addressed by.

use crate::protocol::MeshId;
/// A mesh-addressed IPC command. The engine derives the per-mesh socket path
/// from the mesh id in [`crate::transport::ipc::send`]; `None` means the command is addressed by
/// socket path directly (via [`crate::transport::ipc::send_to_path`]) and carries no mesh — the
/// concrete command type is defined app-side, the engine only needs the address.
pub trait Addressed {
    /// The mesh this command is for, or `None` for a command that has none.
    fn mesh_id(&self) -> Option<&MeshId>;
}
