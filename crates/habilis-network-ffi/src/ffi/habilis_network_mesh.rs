use std::ffi::CString;
use std::fmt;

use crate::mesh::Mesh;

/// The opaque handle behind `habilis_network_mesh *`. Holds the `Mesh` plus
/// NUL-terminated copies of the identity strings, so [`habilis_network_mesh_id`](super::habilis_network_mesh_id) /
/// [`habilis_network_mesh_nickname`](super::habilis_network_mesh_nickname) can hand out pointers that stay valid for the
/// handle's lifetime.
pub struct HabilisNetworkMesh {
    pub(super) mesh: Mesh,
    pub(super) id: CString,
    pub(super) nick: CString,
    pub(super) name: CString,
}

impl fmt::Debug for HabilisNetworkMesh {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HabilisNetworkMesh")
            .finish_non_exhaustive()
    }
}
