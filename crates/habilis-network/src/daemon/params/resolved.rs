use crate::protocol::Nickname;
use crate::protocol::mesh::MeshName;

use crate::daemon::setup::SetupKind;

/// A resolved create/join, ready to hand to
/// [`setup_mesh`](crate::daemon::setup::setup_mesh). `advertise_directory` is the
/// directory to re-broadcast into (`create --advertise`), or `None`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Resolved {
    /// What the setup creates.
    pub kind: SetupKind,
    /// This member's nickname, the author of every message it sends.
    pub author: Nickname,
    /// The directory the mesh is advertised to, if any.
    pub advertise_directory: Option<MeshName>,
}
