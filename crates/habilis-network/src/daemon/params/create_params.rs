use super::Resolved;

use crate::protocol::Nickname;
use crate::protocol::crypto::Password;
use crate::protocol::mesh::{
    AdvertiseRequiresReachable, DirectorySelection, MeshConfig, MeshName, validate_advertise,
};

use crate::daemon::setup::SetupKind;

/// The create intent, before resolution. Each frontend builds this from its
/// own input struct (the lookups are already resolved into `config`).
///
/// # Examples
///
/// A create request names the mesh, and it resolves when its advertising is allowed.
///
/// ```
/// use habilis_network::protocol::MeshName;
/// use habilis_network::protocol::mesh::{DirectorySelection, MeshConfig};
/// use habilis_network::runtime::CreateParams;
///
/// let name = MeshName::try_new("chat").expect("a name");
/// let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback config");
/// let params = CreateParams::new(name, None, config, DirectorySelection::Unset);
/// assert!(params.resolve().is_ok());
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CreateParams {
    /// The name of the mesh.
    pub name: MeshName,
    /// `None` ⇒ a random `word-word` nickname is minted in `resolve`.
    pub nickname: Option<Nickname>,
    /// The mesh configuration.
    pub config: MeshConfig,
    /// How the mesh is advertised.
    pub advertise: DirectorySelection,
    /// Password to protect the mesh with; the verifier is baked into the
    /// id at setup (the salt is the seed, minted there).
    pub password: Option<Password>,
    /// `--invite-only`: the mesh's issuer keypair + invite root are minted at
    /// setup and only creator-signed invites can join.
    pub invite_only: bool,
}

impl CreateParams {
    /// The name, nickname, config and advertisement of a new mesh. Set the password and the
    /// invite-only flag with their `with_` methods.
    #[must_use]
    pub fn new(
        name: MeshName,
        nickname: Option<Nickname>,
        config: MeshConfig,
        advertise: DirectorySelection,
    ) -> Self {
        Self {
            name,
            nickname,
            config,
            advertise,
            password: None,
            invite_only: false,
        }
    }

    /// The password that unlocks the mesh, when the mesh has one.
    #[must_use]
    pub fn password(mut self, password: Option<Password>) -> Self {
        self.password = password;
        self
    }

    /// Set whether the mesh is invite-only.
    #[must_use]
    pub fn invite_only(
        mut self,
        // true makes the mesh invite-only
        invite_only: bool,
    ) -> Self {
        self.invite_only = invite_only;
        self
    }
}

impl CreateParams {
    /// Validate the advertise request against the config, default the
    /// nickname, and build the create [`SetupKind`].
    ///
    /// # Errors
    /// Returns [`AdvertiseRequiresReachable`] if `advertise` is set on a
    /// loopback-only mesh.
    pub fn resolve(self) -> Result<Resolved, AdvertiseRequiresReachable> {
        validate_advertise(&self.advertise, &self.config.lookups)?;
        let advertise_directory = self.advertise.directory();
        Ok(Resolved {
            kind: SetupKind::Create {
                name: self.name,
                config: self.config,
                advertise: advertise_directory.clone(),
                password: self.password,
                invite_only: self.invite_only,
            },
            author: self.nickname.unwrap_or_else(Nickname::random),
            advertise_directory,
        })
    }
}
