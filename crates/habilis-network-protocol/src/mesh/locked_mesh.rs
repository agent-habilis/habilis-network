//! A locked mesh id, and the error of unlocking it.

use std::fmt;
use std::str::FromStr;

use super::mesh::Mesh;
use super::mesh_secret::MeshSecret;
use super::{ConfigError, MeshConfig, MeshName, NAME_MAX_BYTES, SEED_LEN, VERSION};
use crate::base58check;
use crate::crypto::{self, Seed, SymmetricKey};

/// A decoded mesh id that has no secret yet.
///
/// Decoding an id (`FromStr`) yields this, not a [`Mesh`]: the id declares
/// what the mesh needs (a password verifier, an issuer key), but it cannot
/// derive anything, so there is no `topic_id` or `rendezvous_id` to call. The
/// secret is applied by [`LockedMesh::unlock`] (a password) or, for an
/// invite-only mesh, by redeeming an invite ticket.
///
/// A locked id has no derivation, so calling one does not compile:
///
/// ```compile_fail,E0599
/// fn derive(locked: habilis_network_protocol::mesh::LockedMesh) {
///     let _ = locked.topic_id();
/// }
/// ```
///
/// Unlocking it makes the same call compile:
///
/// ```
/// fn derive(locked: habilis_network_protocol::mesh::LockedMesh) {
///     let _ = locked.unlock(None).unwrap().topic_id();
/// }
/// ```
#[derive(Clone)]
pub struct LockedMesh {
    pub(super) name: MeshName,
    pub(super) seed: Seed,
    pub(super) config: MeshConfig,
}

/// Why a [`LockedMesh`] would not unlock. The messages are the operator's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum UnlockError {
    /// The id is invite-only: a bare hash never joins, redeem an invite.
    InviteOnly,
    /// The id carries a password verifier and none was given.
    PasswordRequired,
    /// The id carries no password verifier and one was given.
    NoPassword,
    /// The password does not match the id's verifier.
    WrongPassword,
}

impl fmt::Display for UnlockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InviteOnly => {
                "this mesh is invite-only — join with an invite ticket, not the bare hash"
            }
            Self::PasswordRequired => "this mesh requires a password",
            Self::NoPassword => "this mesh has no password — drop --password",
            Self::WrongPassword => "wrong password",
        })
    }
}

impl std::error::Error for UnlockError {}

impl fmt::Debug for LockedMesh {
    // The seed is the join capability, so it is redacted as it is on `Mesh`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("LockedMesh");
        debug
            .field("name", &self.name)
            .field("seed", &"***")
            .field("config", &self.config);
        debug.finish()
    }
}

impl LockedMesh {
    /// The wire seed (test-only, as on [`Mesh`]).
    #[cfg(test)]
    pub(crate) fn seed(&self) -> &Seed {
        &self.seed
    }

    /// The mesh's name.
    #[must_use]
    pub fn name(&self) -> &MeshName {
        &self.name
    }

    /// The config the id carries.
    #[must_use]
    pub fn config(&self) -> &MeshConfig {
        &self.config
    }

    /// Whether the id carries a password verifier, so a joiner must present
    /// the password.
    #[must_use]
    pub fn requires_password(&self) -> bool {
        self.config.password.is_some()
    }

    /// Whether the id carries an issuer key, so the bare id cannot join and an
    /// invite is required.
    #[must_use]
    pub fn requires_invite(&self) -> bool {
        self.config.issuer_pubkey.is_some()
    }

    /// True when the mesh is loopback-only (no off-machine lookups).
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.config.lookups.is_loopback()
    }

    /// `"private"`/`"public"` label for output, derived from the lookups.
    #[must_use]
    pub fn network_label(&self) -> &'static str {
        self.config.lookups.network_label()
    }

    /// The canonical config bytes mixed into the topic derivation (test-only:
    /// the derivation runs on an unlocked [`Mesh`]).
    #[cfg(test)]
    pub(crate) fn config_bytes(&self) -> Vec<u8> {
        self.config.to_bytes()
    }

    /// The id's canonical text (Base58Check), the same as `Display`.
    #[must_use]
    pub fn encode(&self) -> String {
        base58check::encode(&super::mesh::encode_id(
            &self.seed,
            &self.name,
            &self.config,
        ))
    }

    /// Join-side: apply the password the id asks for, and get the mesh that
    /// derives from it. Stretches `password` (salt = the wire seed), checks it
    /// against the verifier the id carries, and switches every derivation onto
    /// the stretched key. ~100ms of Argon2id by design.
    ///
    /// # Errors
    /// See [`UnlockError`]: the id is invite-only, the password is missing,
    /// unneeded or wrong.
    pub fn unlock(self, password: Option<&crypto::Password>) -> Result<Mesh, UnlockError> {
        if self.requires_invite() {
            return Err(UnlockError::InviteOnly);
        }
        let secret = match (&self.config.password, password) {
            (None, None) => MeshSecret::Open,
            (None, Some(_)) => return Err(UnlockError::NoPassword),
            (Some(_), None) => return Err(UnlockError::PasswordRequired),
            (Some(expected), Some(password)) => {
                let key = crypto::stretch_mesh_password(password, &self.seed);
                if crypto::password_verifier(&key) != *expected {
                    return Err(UnlockError::WrongPassword);
                }
                MeshSecret::Password(key)
            }
        };
        Ok(Mesh {
            name: self.name,
            seed: self.seed,
            secret,
            config: self.config,
        })
    }

    /// Redeem-side: the invite `root` a verified invite ticket carries becomes
    /// the derivation secret. The redeemer holds no issuer secret, so it can
    /// join but never mint.
    pub(crate) fn redeem_with(self, root: SymmetricKey) -> Mesh {
        Mesh {
            name: self.name,
            seed: self.seed,
            secret: MeshSecret::Invite { root, issuer: None },
            config: self.config,
        }
    }

    /// The issuer public key the id carries — a redeemer verifies each invite's
    /// signature against it.
    pub(crate) fn issuer_pubkey(&self) -> Option<&[u8; 32]> {
        self.config.issuer_pubkey.as_ref()
    }

    /// The public identity salt (the wire seed) an invite ticket wraps its root
    /// under when password-protected.
    pub(crate) fn wrap_salt(&self) -> &Seed {
        &self.seed
    }
}

impl LockedMesh {
    pub(super) fn decode_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        let mut position = 0usize;
        let version = *bytes
            .get(position)
            .ok_or(ConfigError::Truncated("mesh identifier too short"))?;
        position += 1;
        if version != VERSION {
            return Err(ConfigError::Invalid(format!(
                "unsupported mesh id version {version}, this build reads version {VERSION}: \
                 upgrade every member, then create the mesh again"
            )));
        }

        let seed_slice = bytes
            .get(position..position + SEED_LEN)
            .ok_or(ConfigError::Truncated("mesh identifier too short"))?;
        let mut seed_bytes = [0u8; SEED_LEN];
        seed_bytes.copy_from_slice(seed_slice);
        let seed = Seed::from_bytes(seed_bytes);
        position += SEED_LEN;

        let name_len = *bytes
            .get(position)
            .ok_or(ConfigError::Truncated("truncated mesh name length"))?
            as usize;
        position += 1;
        if name_len == 0 || name_len > NAME_MAX_BYTES {
            return Err(ConfigError::Invalid(format!(
                "invalid mesh name length: {name_len}"
            )));
        }
        let name_raw = bytes
            .get(position..position + name_len)
            .ok_or(ConfigError::Truncated("truncated mesh name"))?;
        position += name_len;
        let name_str = std::str::from_utf8(name_raw)
            .map_err(ConfigError::with_step("invalid mesh name UTF-8"))?;
        let name =
            MeshName::try_new(name_str).map_err(ConfigError::with_step("invalid mesh name"))?;

        let config_len = super::lookup::read_u16(bytes, &mut position)
            .map_err(ConfigError::with_step("truncated config length"))?
            as usize;
        let config_raw = bytes
            .get(position..position + config_len)
            .ok_or(ConfigError::Truncated("truncated mesh config"))?;
        position += config_len;
        if position != bytes.len() {
            return Err(ConfigError::Invalid(
                "trailing bytes in mesh identifier".to_owned(),
            ));
        }
        let config = MeshConfig::from_bytes(config_raw)?;

        Ok(LockedMesh { name, seed, config })
    }
}

impl fmt::Display for LockedMesh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl fmt::Display for Mesh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.encode_bytes();
        write!(f, "{}", base58check::encode(&bytes))
    }
}

impl FromStr for LockedMesh {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, ConfigError> {
        let bytes = base58check::decode(s, "mesh identifier")
            .map_err(|error| ConfigError::Invalid(error.to_string()))?;
        Self::decode_bytes(&bytes)
    }
}
