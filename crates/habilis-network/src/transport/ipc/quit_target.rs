//! The address of the daemon of one session.

use std::path;

use crate::protocol::{MeshId, Nickname};

/// The daemon of one session, at the address that [`send`](super::send) takes:
/// the runtime base, the mesh, and the nickname.
///
/// # Examples
///
/// ```
/// use std::path::Path;
///
/// use habilis_network::protocol::{MeshId, Nickname};
/// use habilis_network::runtime::ipc::QuitTarget;
///
/// let mesh = MeshId::from("abc");
/// let nickname = Nickname::from("nick");
/// let target = QuitTarget::new(Path::new("/tmp/x"), &mesh, &nickname);
/// assert_eq!(target.nickname, &nickname);
/// ```
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct QuitTarget<'session> {
    /// The runtime base of the consumer.
    pub base: &'session path::Path,
    /// The mesh of the session.
    pub mesh: &'session MeshId,
    /// The nickname of the daemon on that mesh.
    pub nickname: &'session Nickname,
}

impl<'session> QuitTarget<'session> {
    /// The daemon of `nickname` on `mesh`, under `base`.
    #[must_use]
    pub const fn new(
        base: &'session path::Path,
        mesh: &'session MeshId,
        nickname: &'session Nickname,
    ) -> Self {
        Self {
            base,
            mesh,
            nickname,
        }
    }
}
