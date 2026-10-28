use std::ffi::CString;

use crate::mesh::Mesh;

/// The opaque handle behind `habilis_network_mesh *`. Holds the `Mesh` plus
/// NUL-terminated copies of the identity strings, so [`habilis_network_mesh_id`](super::habilis_network_mesh_id) /
/// [`habilis_network_mesh_nickname`](super::habilis_network_mesh_nickname) can hand out pointers that stay valid for the
/// handle's lifetime.
#[expect(
    missing_debug_implementations,
    reason = "wraps Mesh, which owns a tokio Runtime and so has no Debug impl"
)]
pub struct HabilisNetworkMesh {
    pub(super) mesh: Mesh,
    pub(super) id: CString,
    pub(super) nick: CString,
    pub(super) name: CString,
}
