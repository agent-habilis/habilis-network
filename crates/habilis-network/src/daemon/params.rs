//! The shared create/join intent, resolved once for every frontend.
//!
//! The CLI (`clap`), the in-process driver (public API), and the MCP server
//! (`serde`) each have their own native input struct, but they all want the
//! same thing: turn a name + config + nickname (create) or a target +
//! nickname (join) into a [`SetupKind`] plus the resolved author and the
//! directory to advertise into. [`CreateParams`]/[`JoinParams`] are that
//! common shape; `resolve` is the single place the nickname default, the
//! advertise validation, and the target resolution live — instead of three
//! near-identical copies in `cli`, `api`, and `mcp`.

use super::setup_error::SetupError;

use crate::protocol::Nickname;
use crate::protocol::crypto::Password;
use crate::protocol::mesh::{
    AdvertiseRequiresReachable, DirectorySelection, LookupOpts, Mesh, MeshConfig, MeshName,
    TransportPolicy, UnlockError, validate_advertise,
};
use crate::resolver::{self, JoinTarget};

use super::setup::SetupKind;

use crate::protocol::mesh::RelayChoice;
use crate::util::tuning;
/// The create intent, before resolution. Each frontend builds this from its
/// own input struct (the lookups are already resolved into `config`).
#[derive(Debug)]
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
    pub const fn new(
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

    /// Set the password.
    #[must_use]
    pub fn with_password(mut self, password: Option<Password>) -> Self {
        self.password = password;
        self
    }

    /// Set whether the mesh is invite-only.
    #[must_use]
    pub fn with_invite_only(mut self, invite_only: bool) -> Self {
        self.invite_only = invite_only;
        self
    }
}

/// The join intent, before resolution.
#[derive(Debug)]
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
    pub const fn new(
        target: JoinTarget,
        nickname: Option<Nickname>,
        password: Option<Password>,
    ) -> Self {
        Self {
            target,
            nickname,
            password,
        }
    }
}

/// The topic intent: a mesh derived deterministically from a shared string,
/// always public. Name + config are derived, not supplied — the string alone
/// determines the mesh.
#[derive(Debug)]
#[non_exhaustive]
pub struct TopicParams {
    /// The shared string that fixes the mesh. Every peer that passes the same string meets in the same mesh.
    pub string: String,
    /// `None` ⇒ a random `word-word` nickname is minted in `resolve`.
    pub nickname: Option<Nickname>,
}

/// A resolved create/join, ready to hand to
/// [`setup_mesh`](super::setup::setup_mesh). `advertise_directory` is the
/// directory to re-broadcast into (`create --advertise`), or `None`.
#[derive(Debug)]
#[non_exhaustive]
pub struct Resolved {
    /// What the setup creates.
    pub kind: SetupKind,
    /// This member's nickname, the author of every message it sends.
    pub author: Nickname,
    /// The directory the mesh is advertised to, if any.
    pub advertise_directory: Option<MeshName>,
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
    /// [`Mesh`]: crate::protocol::mesh::Mesh
    pub fn resolve(self) -> Result<Resolved, SetupError> {
        let mesh = match &self.target {
            JoinTarget::Mesh(_) => {
                let locked = resolver::resolve(&self.target).map_err(SetupError::Resolve)?;
                // ~100ms of Argon2id, accepted synchronously: this runs once
                // per join, before the daemon exists. `unlock` decides whether a
                // password is needed; only its typed reason is mapped here.
                #[expect(
                    clippy::wildcard_enum_match_arm,
                    reason = "foreign non_exhaustive enum: the compiler needs a wildcard arm; the named variants are listed before it"
                )]
                let unlocked =
                    locked
                        .unlock(self.password.as_ref())
                        .map_err(|error| match error {
                            UnlockError::PasswordRequired => SetupError::PasswordRequired,
                            error @ (UnlockError::InviteOnly
                            | UnlockError::NoPassword
                            | UnlockError::WrongPassword) => SetupError::Unlock(error),
                            other => SetupError::Unlock(other),
                        })?;
                unlocked
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

/// The canonical [`Mesh`] a topic string derives — always the public preset.
/// The single source of that derivation *and* of the empty/whitespace-string
/// guard, shared by [`TopicParams::resolve`] and the MCP idempotency check so
/// neither can drift — an empty string would otherwise silently derive one
/// globally-fixed mesh that every empty-string caller lands in. (The clap
/// A consumer's own arg `value_parser` may re-check emptiness only to surface it as a
/// parse-time usage error.)
/// # Errors
/// The topic string sanitizes to an empty mesh name.
pub fn derive_topic_mesh(string: &str) -> Result<Mesh, SetupError> {
    // `--topic-mdns-only` (test-only): keep the mesh *public-shaped* (an
    // ephemeral, address-lookup-discoverable rendezvous — the beacon-claim
    // race under test lives on that path, not the loopback ladder) while
    // reaching no further than the LAN — CI has no public relay, and the
    // narrowed config bytes also derive a topic id no production peer on
    // the same string can land in. Same rationale as `--directory-private`.
    //
    // Deliberately applied here and not in `derive_topic_mesh_with`: a caller
    // that states its own reach must not have it silently rewritten.
    let lookups = if tuning::topic_mdns_only_for_test() {
        LookupOpts::new(RelayChoice::Disabled).with_mdns(true)
    } else {
        LookupOpts::public_preset()
    };
    derive_topic_mesh_with(string, lookups)
}

/// The canonical [`Mesh`] a topic string derives **at a stated reach**.
///
/// The lookups are part of the mesh id — `MeshConfig` is mixed into the topic
/// derivation and encoded into the id payload — so they are also part of
/// what the peers on this mesh agree to. A loopback caller derives a loopback
/// mesh: a rendezvous on the seed-derived port ladder, and no external network
/// call.
///
/// Use this whenever the caller already knows its reach, and pass the *same*
/// lookups the endpoint was built with. [`derive_topic_mesh`] hardcoded the
/// public preset, so a share served with `--swarm <loopback-id>` — bound with
/// relays disabled and no mDNS or DHT, the documented "zero external network
/// calls" branch — still stood up a second endpoint doing real multicast, real
/// DHT, and a publicly published rendezvous. It accomplished nothing either:
/// the rendezvous went to a relay the loopback endpoint had no transport to
/// dial, so two loopback peers of one share never found each other.
///
/// An injected endpoint makes this a hard requirement rather than a nicety —
/// see [`crate::runtime::InjectedEndpoint`].
///
/// # Errors
/// The string is empty or whitespace.
pub fn derive_topic_mesh_with(string: &str, lookups: LookupOpts) -> Result<Mesh, SetupError> {
    derive_topic_mesh_config(
        string,
        MeshConfig::new(lookups, None, None, TransportPolicy::default()),
    )
}

/// [`derive_topic_mesh_with`] for a caller with a whole [`MeshConfig`] to bake
/// in — a topic mesh whose relay is lookup only, say. Password and invite
/// fields are meaningless on a topic mesh (its secret is the string) and are
/// dropped.
///
/// # Errors
/// The string is empty or whitespace, or `config` fails
/// [`MeshConfig::validate`].
pub fn derive_topic_mesh_config(string: &str, config: MeshConfig) -> Result<Mesh, SetupError> {
    if string.trim().is_empty() {
        return Err(SetupError::EmptyTopic);
    }
    config.validate().map_err(SetupError::Config)?;
    Mesh::from_topic(
        string,
        MeshConfig::new(config.lookups, None, None, config.transport),
    )
    .map_err(SetupError::Config)
}

impl TopicParams {
    /// Derive the mesh from the string (always the public preset) and default
    /// the nickname. A topic never advertises. The empty/whitespace-string
    /// guard lives in [`derive_topic_mesh`], which every frontend (CLI,
    /// in-process) funnels through.
    ///
    /// # Errors
    /// Fails if the string is empty or whitespace-only.
    pub fn resolve(self) -> Result<Resolved, SetupError> {
        let mesh = derive_topic_mesh(&self.string)?;
        Ok(Resolved {
            kind: SetupKind::Topic {
                mesh,
                topic_string: self.string,
            },
            author: self.nickname.unwrap_or_else(Nickname::random),
            advertise_directory: None,
        })
    }
}

#[cfg(test)]
mod topic_derivation_tests {
    use super::{
        LookupOpts, MeshConfig, TransportPolicy, derive_topic_mesh, derive_topic_mesh_config,
        derive_topic_mesh_with,
    };
    use habilis_network_test_tracing::test;

    /// The no-argument form must stay exactly what it always was, because the
    /// `--topic` id it derives is public API for every frontend that calls it.
    #[test]
    fn the_bare_form_is_the_public_preset_form() {
        let bare = derive_topic_mesh("standup").expect("derive");
        let explicit =
            derive_topic_mesh_with("standup", LookupOpts::public_preset()).expect("derive");
        assert_eq!(bare.to_string(), explicit.to_string());
    }

    /// Reach is part of the mesh id, and that is the point: peers on one mesh
    /// have provably agreed where to rendezvous. It is also the deliberate wire
    /// change — a share served with narrowed lookups now derives a different
    /// mesh than it did when the derivation hardcoded the public preset.
    ///
    /// The default share is unaffected: `serve` with no flags resolves to
    /// `public_preset()`, which is byte-identical to the old behaviour.
    #[test]
    fn stating_a_narrower_reach_changes_the_id() {
        let public =
            derive_topic_mesh_with("standup", LookupOpts::public_preset()).expect("derive");
        let private = derive_topic_mesh_with("standup", LookupOpts::loopback()).expect("derive");
        assert_ne!(
            public.to_string(),
            private.to_string(),
            "lookups are mixed into the id, so two reaches cannot collide"
        );
    }

    /// The whole point of threading the lookups: a private share gets a mesh
    /// that stays on the box, rather than one that publishes a rendezvous it
    /// has no transport to reach.
    #[test]
    fn a_loopback_reach_derives_a_loopback_mesh() {
        let mesh = derive_topic_mesh_with("standup", LookupOpts::loopback()).expect("derive");
        assert!(mesh.is_loopback());
        assert!(
            !derive_topic_mesh_with("standup", LookupOpts::public_preset())
                .expect("derive")
                .is_loopback()
        );
    }

    /// The empty-string guard is shared, not duplicated: an empty topic would
    /// otherwise derive one globally-fixed mesh every empty-string caller lands
    /// in.
    #[test]
    fn both_forms_reject_an_empty_string() {
        assert!(derive_topic_mesh("   ").is_err());
        assert!(derive_topic_mesh_with("   ", LookupOpts::loopback()).is_err());
    }

    /// The relay's transport role is part of the id: two meshes that differ
    /// only in it are different meshes, so members provably agree on it.
    #[test]
    fn relay_transport_changes_the_id() {
        let lookup_only =
            derive_topic_mesh_with("standup", LookupOpts::public_preset()).expect("derive");
        let relayed = derive_topic_mesh_config(
            "standup",
            MeshConfig::new(
                LookupOpts::public_preset(),
                None,
                None,
                TransportPolicy::default().with_relay_transport(true),
            ),
        )
        .expect("derive");
        assert_ne!(lookup_only.to_string(), relayed.to_string());
        assert!(!lookup_only.transport().relay_transport);
        assert!(relayed.transport().relay_transport);
    }

    /// A minted config gets the same cross-field check a decoded id gets;
    /// otherwise the creator would run a mesh whose id every joiner rejects.
    #[test]
    fn a_relay_transport_without_a_relay_lookup_is_rejected_on_mint() {
        let config = MeshConfig::new(
            LookupOpts::loopback(),
            None,
            None,
            TransportPolicy::default().with_relay_transport(true),
        );
        assert!(derive_topic_mesh_config("standup", config).is_err());
    }
}

#[cfg(test)]
mod join_password_tests {
    use super::{JoinParams, Password, SetupError};
    use crate::protocol::Seed;
    use crate::protocol::mesh::{Mesh, MeshConfig, MeshName};

    /// A passworded id, as a joiner is handed it.
    fn passworded_id() -> String {
        let mut mesh = Mesh::try_new(
            Seed::from_bytes([9u8; 32]),
            MeshName::try_new("pw").unwrap(),
            MeshConfig::loopback(),
        )
        .unwrap();
        mesh.set_password(&Password::new("hunter2".to_owned()));
        mesh.to_string()
    }

    #[test]
    fn a_passworded_id_without_a_password_is_password_required() {
        let params = JoinParams::new(passworded_id().parse().unwrap(), None, None);
        let error = params.resolve().unwrap_err();
        assert!(
            matches!(error, SetupError::PasswordRequired),
            "got: {error}"
        );
    }
}
