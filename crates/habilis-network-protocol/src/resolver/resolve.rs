//! The resolution of a join target to its locked mesh.

use super::{JoinTarget, ResolveError};
use crate::mesh::LockedMesh;

/// # Errors
/// [`ResolveError::InvalidId`] when the mesh id does not decode, or
/// [`ResolveError::InviteTarget`] for an invite, which the join redeems itself.
///
/// # Examples
///
/// A mesh id resolves to the mesh it names, without a network call.
///
/// ```
/// use habilis_network_protocol::mesh::MeshId;
/// use habilis_network_protocol::resolver::{JoinTarget, resolve};
///
/// use habilis_network_protocol::{Mesh, MeshConfig, MeshName, Seed};
///
/// let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
/// let mesh = Mesh::try_new(Seed::new([4u8; 32]), MeshName::try_new("chat").expect("a name"), config)
///     .expect("a mesh");
///
/// let id = MeshId::try_new(&mesh.to_string()).expect("a valid id");
/// let locked = resolve(&JoinTarget::Mesh(id)).expect("a mesh id resolves with no I/O");
/// assert_eq!(locked.name().as_str(), "chat");
/// ```
pub fn resolve(target: &JoinTarget) -> Result<LockedMesh, ResolveError> {
    match target {
        JoinTarget::Mesh(id) => {
            // Refusing an invite-only id is `LockedMesh::unlock`'s job, the one
            // place a bare hash can become a joinable mesh.
            let locked: Result<LockedMesh, _> = id.as_str().parse();
            locked.map_err(|error| ResolveError::InvalidId(error.to_string()))
        }
        // An invite carries the join key and needs the password to unwrap it, so
        // it is redeemed in `JoinParams::resolve`; `resolve` never sees it alone.
        JoinTarget::Invite(_) => Err(ResolveError::InviteTarget),
    }
}
