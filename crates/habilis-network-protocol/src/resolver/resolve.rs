//! The resolution of a join target to its locked mesh.

use super::{JoinTarget, ResolveError};
use crate::mesh::LockedMesh;

/// # Errors
/// [`ResolveError::InvalidId`] when the mesh id does not decode, or
/// [`ResolveError::InviteTarget`] for an invite, which the join redeems itself.
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
