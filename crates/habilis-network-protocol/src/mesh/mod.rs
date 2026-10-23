//! The mesh identifier, at two levels:
//!
//! - [`MeshId`] — the validated bare `Base58Check` string. Possession proves
//!   the checksum, version, and full payload structure. Code: `id`.
//! - [`Mesh`] — the *decoded* structure (32-byte seed + name +
//!   [`MeshConfig`]), with the `Base58Check` codec (this file). `MeshId`
//!   is what flows through the wire/CLI; `Mesh` is what `setup_mesh`
//!   derives identity and behavior from.
//!
//! See `docs/mesh-hash.md` for the full byte layout and rationale.
//!
//! Also home to [`MeshName`] (`name`), the lookup allowlist (`lookup`)
//! carried in the id, and the relay-ladder parsing.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use iroh_base::{EndpointId, SecretKey};
use rand::RngCore;
use zeroize::Zeroizing;

use super::crypto::{self, Keying, Seed, SymmetricKey};
use crate::base58check;

mod id;
mod lookup;
mod name;
mod transport;

pub use id::{MeshId, MeshIdError};
pub use lookup::{
    AdvertiseRequiresReachable, DEFAULT_DIRECTORY, DirectorySelection, Lookup, LookupOpts,
    LookupSet, MeshConfig, OptFlag, RelayChoice, RelayLadder, RelayLadderError, RelaySelection,
    resolve_lookups, validate_advertise,
};
pub use name::{MeshName, NameError};
pub use transport::{Transport, TransportPolicy};

/// A name that is not one of a list's choices — a `lookup` or `transport`
/// entry with a typo. Names the list and the choices, so the message stands
/// on its own wherever it surfaces (a CLI, a JSON error, a C error slot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChoiceError {
    list: &'static str,
    given: String,
    choices: &'static [&'static str],
}

impl ChoiceError {
    fn new(list: &'static str, given: &str, choices: &'static [&'static str]) -> Self {
        Self {
            list,
            given: given.to_owned(),
            choices,
        }
    }
}

impl fmt::Display for ChoiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unknown {} `{}`: expected one of {}",
            self.list,
            self.given,
            self.choices.join(", ")
        )
    }
}

impl std::error::Error for ChoiceError {}

/// Id format version. A single byte reserved so the encoding can evolve;
/// an unknown version is rejected.
const VERSION: u8 = 2;
const SEED_LEN: usize = 32;
/// Wire bound for the encoded name in bytes. `MeshName::new` caps the
/// name at `ident::MAX_CHARS` scalar values; each is at most 4 UTF-8
/// bytes, so the encoded form fits this many bytes (and inside the
/// 1-byte length field).
const NAME_MAX_BYTES: usize = super::ident::MAX_CHARS * 4;

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
    name: MeshName,
    seed: Seed,
    /// What every derivation actually keys on. Never serialized —
    /// `encode_bytes` writes `seed`.
    secret: MeshSecret,
    config: MeshConfig,
}

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
    name: MeshName,
    seed: Seed,
    config: MeshConfig,
}

/// Why a [`LockedMesh`] would not unlock. The messages are the operator's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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

/// The mesh's derivation secret.
///
/// One enum rather than three `Option` fields, because at most one of them was
/// ever meant to be set: an invite-only mesh's password wraps its tickets and
/// never folds into the topic, so "invite root" and "stretched password key"
/// are alternatives, not a pair. The old shape let a caller set both and left
/// [`Mesh::effective_seed`] to pick, which is a precedence rule nothing stated.
#[derive(Clone)]
enum MeshSecret {
    /// No password applied and no invite redeemed: derivations use the wire
    /// seed.
    Open,
    /// The Argon2id-stretched password key. Every derivation (topic,
    /// rendezvous, port ladder) switches onto it, so holding the id without
    /// the password computes nothing reachable.
    Password(SymmetricKey),
    /// The invite-only derivation secret, held only in memory: baked into no
    /// hash, carried only by creator-minted invites, so the bare invite-only
    /// hash reaches nothing.
    Invite {
        root: SymmetricKey,
        /// The Ed25519 issuer **private** key — the mint authority, held only
        /// by the creator's live session, so a restart ends minting. `None` on
        /// a redeemer, which can join but never mint.
        issuer: Option<Box<SecretKey>>,
    },
}

impl fmt::Debug for MeshSecret {
    // Redact every variant's payload: the invite root and the issuer secret
    // gate an invite-only mesh, and the stretched key is the password.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => formatter.write_str("Open"),
            Self::Password(_) => formatter.write_str("Password(***)"),
            Self::Invite { issuer, .. } => write!(
                formatter,
                "Invite {{ root: ***, issuer: {} }}",
                if issuer.is_some() { "***" } else { "None" }
            ),
        }
    }
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
fn refuse_secret_config(config: &MeshConfig) -> Result<()> {
    if config.password.is_some() || config.issuer_pubkey.is_some() {
        bail!(
            "a config with a password or an invite issuer is set by set_password or set_invite, \
             or unlocked from a LockedMesh"
        );
    }
    Ok(())
}

impl fmt::Debug for LockedMesh {
    // The seed is the join capability, so it is redacted as it is on `Mesh`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedMesh")
            .field("name", &self.name)
            .field("seed", &"***")
            .field("config", &self.config)
            .finish()
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
        base58check::encode(&encode_id(&self.seed, &self.name, &self.config))
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

impl Mesh {
    /// A mesh with the wire `seed` of its id.
    ///
    /// # Errors
    /// The config carries a password verifier or an invite issuer. Such a
    /// mesh has a secret the caller does not hold, so it is set by
    /// [`Mesh::set_password`] or [`Mesh::set_invite`], or unlocked from a
    /// [`LockedMesh`].
    pub fn new(seed: Seed, name: MeshName, config: MeshConfig) -> Result<Self> {
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
    /// The config carries a password verifier or an invite issuer (see
    /// [`Mesh::new`]). A topic's secret is the string itself.
    pub fn from_topic(topic: &str, config: MeshConfig) -> Result<Self> {
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
    pub fn set_password(&mut self, password: &crypto::Password) {
        let key = crypto::stretch_mesh_password(password, &self.seed);
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

    fn encode_bytes(&self) -> Vec<u8> {
        encode_id(&self.seed, &self.name, &self.config)
    }
}

/// The wire bytes of an id: version, seed, name, config. The secret is never
/// part of it.
fn encode_id(seed: &Seed, name: &MeshName, config: &MeshConfig) -> Vec<u8> {
    let config = config.to_bytes();
    let mut buf = Vec::with_capacity(1 + SEED_LEN + 1 + name.as_bytes().len() + 2 + config.len());
    buf.push(VERSION);
    buf.extend_from_slice(seed.as_bytes());
    // MeshName guarantees 1..=128 UTF-8 bytes, so a 1-byte length is safe.
    buf.push(name.len_u8());
    buf.extend_from_slice(name.as_bytes());
    let config_len =
        u16::try_from(config.len()).expect("MeshConfig encodes well within a u16 length");
    buf.extend_from_slice(&config_len.to_le_bytes());
    buf.extend_from_slice(&config);
    buf
}

impl LockedMesh {
    fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        let mut pos = 0usize;
        let version = *bytes.get(pos).context("Mesh identifier too short")?;
        pos += 1;
        if version != VERSION {
            bail!(
                "unsupported mesh id version {version}, this build reads version {VERSION}: \
                 upgrade every member, then create the mesh again"
            );
        }

        let seed_slice = bytes
            .get(pos..pos + SEED_LEN)
            .context("Mesh identifier too short")?;
        let mut seed_bytes = [0u8; SEED_LEN];
        seed_bytes.copy_from_slice(seed_slice);
        let seed = Seed::from_bytes(seed_bytes);
        pos += SEED_LEN;

        let name_len = *bytes.get(pos).context("Truncated mesh name length")? as usize;
        pos += 1;
        if name_len == 0 || name_len > NAME_MAX_BYTES {
            bail!("Invalid mesh name length: {name_len}");
        }
        let name_raw = bytes
            .get(pos..pos + name_len)
            .context("Truncated mesh name")?;
        pos += name_len;
        let name_str = std::str::from_utf8(name_raw).context("Invalid mesh name UTF-8")?;
        let name = MeshName::new(name_str).context("Invalid mesh name")?;

        let config_len =
            lookup::read_u16(bytes, &mut pos).context("Truncated config length")? as usize;
        let config_raw = bytes
            .get(pos..pos + config_len)
            .context("Truncated mesh config")?;
        pos += config_len;
        if pos != bytes.len() {
            bail!("Trailing bytes in mesh identifier");
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
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = base58check::decode(s, "mesh identifier")?;
        Self::decode_bytes(&bytes)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod mesh_tests;
