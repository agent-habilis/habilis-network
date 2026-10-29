//! The mesh: its seed, name and config, and the derivations of its identity.

use std::fmt;

use super::locked_mesh::LockedMesh;
use super::mesh_secret::MeshSecret;
use super::{ConfigError, LookupOpts, MeshConfig, MeshName, SEED_LEN, TransportPolicy, VERSION};
use iroh_base::{EndpointId, SecretKey};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::crypto::{self, Keying, Seed, SymmetricKey};

/// A mesh identifier — bare `Base58Check` payload.
///
/// The token carries the random `seed` plus the mesh's [`MeshConfig`]
/// (lookups); **no peer address is ever stored**. The
/// gossip topic, the well-known rendezvous identity (every joiner's
/// bootstrap target), and the loopback port ladder are all derived from
/// `seed` in memory, so the mesh is creator-independent and survives
/// the creator's death. The config is mixed into the topic derivation,
/// so every member of a mesh shares the same config.
///
/// Wire format (little-endian):
///
/// ```text
/// [1 byte version]
/// [32 bytes seed]
/// [1 byte name length in bytes, 1..=128]
/// [N bytes name (UTF-8, <=32 scalars, charset enforced by MeshName)]
/// [2 bytes config length] [config bytes (see MeshConfig::to_bytes)]
/// ```
#[derive(Clone)]
pub struct Mesh {
    pub(super) name: MeshName,
    pub(super) seed: Seed,
    /// What every derivation actually keys on. Never serialized —
    /// `encode_bytes` writes `seed`.
    pub(super) secret: MeshSecret,
    pub(super) config: MeshConfig,
}

impl fmt::Debug for Mesh {
    // Redact all secret material — the seed *is* the join capability, and the
    // invite root / issuer secret gate an invite-only mesh — so a stray `{:?}`
    // in a log can never leak them (mirrors `crypto::Password`).
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Mesh")
            .field("name", &self.name)
            .field("seed", &"***")
            .field("secret", &self.secret)
            .field("config", &self.config)
            .finish()
    }
}

/// Refuse a config that names a secret the caller does not hold. A password
/// verifier needs the password to unlock it, and an issuer needs the minting
/// session, so neither may arrive with a bare [`Mesh`].
pub(super) fn refuse_secret_config(config: &MeshConfig) -> Result<(), ConfigError> {
    if config.password.is_some() || config.issuer_pubkey.is_some() {
        return Err(ConfigError::Invalid(
            "a config with a password or an invite issuer is set by set_password or set_invite, \
             or unlocked from a LockedMesh"
                .to_owned(),
        ));
    }
    Ok(())
}

impl Mesh {
    /// A mesh with the wire `seed` of its id.
    ///
    /// # Errors
    /// # Errors
    /// A [`ConfigError::Invalid`] when the config carries a password verifier or an
    /// invite issuer. Such a mesh has a secret the caller does not hold, so it is set by
    /// [`Mesh::set_password`] or [`Mesh::set_invite`], or unlocked from a [`LockedMesh`].
    pub fn try_new(seed: Seed, name: MeshName, config: MeshConfig) -> Result<Self, ConfigError> {
        refuse_secret_config(&config)?;
        Ok(Mesh {
            name,
            seed,
            secret: MeshSecret::Open,
            config,
        })
    }

    /// Build a mesh deterministically from an arbitrary string (the `topic`
    /// command). The seed is `crypto::topic_seed` of the string; the name is
    /// the string itself sanitized into a [`MeshName`]
    /// (`MeshName::from_topic_string`). Both are deterministic functions of
    /// the string, so callers passing the same string + config converge on the
    /// same id with zero coordination.
    ///
    /// # Errors
    /// # Errors
    /// A [`ConfigError::Invalid`] when the config carries a password verifier or an
    /// invite issuer (see [`Mesh::try_new`]). A topic's secret is the string itself.
    pub fn from_topic(topic: &str, config: MeshConfig) -> Result<Self, ConfigError> {
        refuse_secret_config(&config)?;
        let seed = crypto::topic_seed(topic);
        let name = MeshName::from_topic_string(topic);
        Ok(Mesh {
            name,
            seed,
            secret: MeshSecret::Open,
            config,
        })
    }

    /// The wire seed (what the encoded id carries). Test-only: production
    /// derivations go through [`Mesh::effective_seed`] so the password mix
    /// can never be bypassed.
    #[cfg(test)]
    pub(crate) fn seed(&self) -> &Seed {
        &self.seed
    }

    /// The seed every derivation uses: the invite root for an invite-only
    /// mesh, the stretched password key when a password is applied, else the
    /// wire seed. (Invite-only and password are mutually exclusive in the id:
    /// an invite-only mesh's password, if any, only wraps its invite tickets —
    /// it never folds into the topic here.)
    ///
    /// Derivations reach a secret only through [`LockedMesh::unlock`],
    /// [`LockedMesh::redeem_with`], [`Mesh::set_password`] or [`Mesh::set_invite`],
    /// and a [`LockedMesh`] has no derivation methods at all.
    fn effective_seed(&self) -> Keying<'_> {
        match &self.secret {
            MeshSecret::Invite { root, .. } => Keying::Secret(root),
            MeshSecret::Password(key) => Keying::Secret(key),
            MeshSecret::Open => Keying::Wire(&self.seed),
        }
    }

    /// The mesh's name.
    #[must_use]
    pub fn name(&self) -> &MeshName {
        &self.name
    }

    /// The config the mesh was built with (or unlocked from).
    #[must_use]
    pub fn config(&self) -> &MeshConfig {
        &self.config
    }

    /// This mesh as a locked id, with its secret dropped. Round-trips through
    /// [`Display`](fmt::Display): `mesh.locked().encode()` is the id text.
    #[must_use]
    pub fn locked(&self) -> LockedMesh {
        LockedMesh {
            name: self.name.clone(),
            seed: self.seed,
            config: self.config.clone(),
        }
    }

    /// Whether the id carries a password verifier (joiners must present
    /// the password).
    #[must_use]
    pub fn requires_password(&self) -> bool {
        self.config.password.is_some()
    }

    /// The Argon2id-stretched password key, once a password has been applied
    /// (`set_password`, or `LockedMesh::unlock`) — `None` for a passwordless mesh. The
    /// daemon retains this to key the state/meta channel encryption; it is the
    /// same value every derivation switches onto, and it wipes itself on drop.
    #[must_use]
    pub fn mesh_key(&self) -> Option<SymmetricKey> {
        match &self.secret {
            MeshSecret::Password(key) => Some(key.clone()),
            MeshSecret::Open | MeshSecret::Invite { .. } => None,
        }
    }

    /// Create-side: stretch `password`, bake its verifier into the config
    /// (the encoded id must carry it), and switch every derivation onto
    /// the stretched key. ~100ms of Argon2id by design.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the secret moves in, so the caller keeps no copy of it"
    )]
    pub fn set_password(&mut self, password: crypto::Password) {
        let key = crypto::stretch_mesh_password(&password, &self.seed);
        self.config.password = Some(crypto::password_verifier(&key));
        self.secret = MeshSecret::Password(key);
    }

    /// Whether this mesh is invite-only (the id carries an issuer pubkey, so
    /// the bare hash cannot join — a creator-minted invite is required).
    #[must_use]
    pub fn requires_invite(&self) -> bool {
        self.config.issuer_pubkey.is_some()
    }

    /// Create-side: turn this into an invite-only mesh. Mints a random invite
    /// **root** (the derivation secret, held only in memory and in the invites
    /// this creator issues) and an Ed25519 **issuer** keypair (the mint
    /// authority), baking the issuer public key into the id. Both secrets stay
    /// in-memory only, so a creator restart ends minting.
    pub fn set_invite(&mut self) {
        let mut root = Zeroizing::new([0u8; SEED_LEN]);
        rand::rng().fill_bytes(&mut *root);
        let mut issuer_bytes = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(&mut *issuer_bytes);
        let issuer = SecretKey::from_bytes(&issuer_bytes);
        self.config.issuer_pubkey = Some(*issuer.public().as_bytes());
        self.secret = MeshSecret::Invite {
            root: SymmetricKey::from_zeroizing(root),
            issuer: Some(Box::new(issuer)),
        };
    }

    /// The issuer private key, for signing a minted invite (creator only).
    pub(crate) fn issuer_secret(&self) -> Option<&SecretKey> {
        match &self.secret {
            MeshSecret::Invite { issuer, .. } => issuer.as_deref(),
            MeshSecret::Open | MeshSecret::Password(_) => None,
        }
    }

    /// The invite root secret to embed in a minted invite (creator only).
    pub(crate) fn invite_key(&self) -> Option<&SymmetricKey> {
        match &self.secret {
            MeshSecret::Invite { root, .. } => Some(root),
            MeshSecret::Open | MeshSecret::Password(_) => None,
        }
    }

    /// The public identity salt (the wire seed) an invite ticket wraps its root
    /// under when password-protected — public and in the hash, so both minter
    /// and redeemer derive the same wrap key from the password alone.
    pub(crate) fn wrap_salt(&self) -> &Seed {
        &self.seed
    }

    /// The gossip `TopicId` — the one derivation entry point, so no caller
    /// can forget the password mix.
    #[must_use]
    pub fn topic_id(&self) -> crate::topic::TopicId {
        crypto::derive_topic_id(self.effective_seed(), &self.name, &self.config_bytes())
    }

    /// The shared rendezvous endpoint secret every co-host binds.
    #[must_use]
    pub fn rendezvous_secret(&self) -> SecretKey {
        crypto::rendezvous_secret(self.effective_seed())
    }

    /// The lookups that find the mesh.
    #[must_use]
    pub fn lookups(&self) -> &LookupOpts {
        &self.config.lookups
    }

    /// Which transports may carry payload on this mesh.
    #[must_use]
    pub fn transport(&self) -> &TransportPolicy {
        &self.config.transport
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

    /// The canonical config bytes mixed into the topic derivation (so a
    /// mesh's config is part of its identity).
    pub(crate) fn config_bytes(&self) -> Vec<u8> {
        self.config.to_bytes()
    }

    /// Well-known rendezvous `EndpointId`, derived from the effective seed.
    /// Every joiner computes this locally and bootstraps gossip from it; it
    /// is co-hosted by members rather than pinned to the creator.
    #[must_use]
    pub fn rendezvous_id(&self) -> EndpointId {
        crypto::rendezvous_id(self.effective_seed())
    }

    /// Deterministic loopback port *ladder* for loopback-only meshes (no
    /// pkarr/DNS to resolve `rendezvous_id`). Preference order; a beacon
    /// binds the first free rung, joiners try all rungs.
    #[must_use]
    pub fn rendezvous_ports(&self) -> [u16; crypto::RENDEZVOUS_LADDER] {
        crypto::rendezvous_ports(self.effective_seed())
    }

    pub(super) fn encode_bytes(&self) -> Vec<u8> {
        encode_id(&self.seed, &self.name, &self.config)
    }
}

/// The wire bytes of an id: version, seed, name, config. The secret is never
/// part of it.
pub(super) fn encode_id(seed: &Seed, name: &MeshName, config: &MeshConfig) -> Vec<u8> {
    let config = config.to_bytes();
    let mut buffer =
        Vec::with_capacity(1 + SEED_LEN + 1 + name.as_bytes().len() + 2 + config.len());
    buffer.push(VERSION);
    buffer.extend_from_slice(seed.as_bytes());
    // MeshName guarantees 1..=128 UTF-8 bytes, so a 1-byte length is safe.
    buffer.push(name.len_u8());
    buffer.extend_from_slice(name.as_bytes());
    let config_len =
        u16::try_from(config.len()).expect("MeshConfig encodes well within a u16 length");
    buffer.extend_from_slice(&config_len.to_le_bytes());
    buffer.extend_from_slice(&config);
    buffer
}
