use super::Resolved;
use crate::daemon::setup_error::SetupError;

use crate::protocol::Nickname;
use crate::protocol::crypto::Password;
use crate::protocol::meshes::UnlockError;
use crate::resolver::{self, JoinTarget};

use crate::daemon::setup::SetupKind;

/// The join intent, before resolution.
///
/// # Examples
///
/// A join request names the target to join, and an optional nickname and password. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::protocol::JoinTarget;
/// use habilis_network::runtime::JoinParams;
///
/// # fn demo(target: JoinTarget) {
/// let params = JoinParams::new(target, None, None);
/// let _ = params.resolve();
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JoinParams {
    /// The target to join.
    pub target: JoinTarget,
    /// The nickname of the member.
    pub nickname: Option<Nickname>,
    /// Password for a passworded id; verified against the id's verifier in
    /// `resolve` (before any network).
    pub password: Option<Password>,
}

impl JoinParams {
    /// The join target, the nickname and the password: every field a join sets.
    #[must_use]
    pub fn new(target: JoinTarget, nickname: Option<Nickname>, password: Option<Password>) -> Self {
        Self {
            target,
            nickname,
            password,
        }
    }
}

impl JoinParams {
    /// Resolve the mesh id target into a [`Mesh`], verify the password
    /// against the id's verifier (locally — a wrong password fails here,
    /// before any network), and default the nickname. `join` never
    /// advertises.
    ///
    /// # Errors
    /// The id cannot be decoded into a [`Mesh`]; the id requires a password
    /// and none was given (`PasswordRequired`, typed for the frontends);
    /// the password is wrong; or a password was given for a passwordless id.
    ///
    /// [`Mesh`]: crate::protocol::meshes::Mesh
    pub fn resolve(self) -> Result<Resolved, SetupError> {
        let mesh = match &self.target {
            JoinTarget::Mesh(_) => {
                let locked = resolver::resolve(&self.target).map_err(SetupError::Resolve)?;
                // ~100ms of Argon2id, accepted synchronously: this runs once
                // per join, before the daemon exists. `unlock` decides whether a
                // password is needed; only its typed reason is mapped here.
                locked.unlock(self.password.as_ref()).map_err(|error| {
                    if let UnlockError::PasswordRequired = error {
                        SetupError::PasswordRequired
                    } else {
                        SetupError::Unlock(error)
                    }
                })?
            }
            // Redeem the invite: verify the creator's signature + expiry and
            // unwrap the join root. An invite-only mesh carries no id-level
            // password verifier — the invite's own `password` flag drives the
            // prompt, and `redeem` unwraps the root with it.
            JoinTarget::Invite(invite) => {
                match (&self.password, invite.requires_password()) {
                    (None, true) => return Err(SetupError::PasswordRequired),
                    (Some(_), false) => return Err(SetupError::InviteNoPassword),
                    _ => {}
                }
                invite
                    .redeem(self.password.as_ref())
                    .map_err(SetupError::Invite)?
            }
            _ => {
                return Err(SetupError::internal(anyhow::anyhow!(
                    "this join target is not supported by this build"
                )));
            }
        };
        Ok(Resolved {
            kind: SetupKind::Join {
                mesh,
                // Retained so the daemon can key blob-ticket protection with the
                // same password (`None` for a passwordless id/invite).
                password: self.password,
            },
            author: self.nickname.unwrap_or_else(Nickname::random),
            advertise_directory: None,
        })
    }
}
