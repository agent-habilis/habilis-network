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

mod create_params;
mod join_params;
mod resolved;
mod topic_params;

use super::setup_error::SetupError;

use crate::protocol::mesh::{LookupOpts, Mesh, MeshConfig, TransportPolicy};

use crate::protocol::mesh::RelayChoice;
use crate::util::tuning;

pub use create_params::CreateParams;
pub use join_params::JoinParams;
pub use resolved::Resolved;
pub use topic_params::TopicParams;
/// The canonical [`Mesh`] a topic string derives — always the public preset.
/// The single source of that derivation *and* of the empty/whitespace-string
/// guard, shared by [`TopicParams::resolve`] and the MCP idempotency check so
/// neither can drift — an empty string would otherwise silently derive one
/// globally-fixed mesh that every empty-string caller lands in. (The clap
/// A consumer's own arg `value_parser` may re-check emptiness only to surface it as a
/// parse-time usage error.)
/// # Errors
/// The topic string sanitizes to an empty mesh name.
///
/// # Examples
///
/// The same topic string always derives the same mesh.
///
/// ```
/// use habilis_network::runtime::derive_topic_mesh;
///
/// let mesh = derive_topic_mesh("chat").expect("a topic mesh");
/// assert_eq!(derive_topic_mesh("chat").expect("a topic mesh").to_string(), mesh.to_string());
/// ```
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
///
/// # Examples
///
/// A topic mesh can be derived with the lookups the caller gives.
///
/// ```
/// use habilis_network::protocol::mesh::LookupOpts;
/// use habilis_network::runtime::derive_topic_mesh_with;
///
/// assert!(derive_topic_mesh_with("chat", LookupOpts::loopback()).is_ok());
/// ```
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
///
/// # Examples
///
/// A topic mesh can be derived with a whole config the caller gives.
///
/// ```
/// use habilis_network::protocol::mesh::MeshConfig;
/// use habilis_network::runtime::derive_topic_mesh_config;
///
/// let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback config");
/// assert!(derive_topic_mesh_config("chat", config).is_ok());
/// ```
pub fn derive_topic_mesh_config(string: &str, config: MeshConfig) -> Result<Mesh, SetupError> {
    if string.trim().is_empty() {
        return Err(SetupError::EmptyTopic);
    }
    config.validate().map_err(SetupError::Config)?;
    Mesh::for_topic(
        string,
        MeshConfig::new(config.lookups, None, None, config.transport),
    )
    .map_err(SetupError::Config)
}

#[cfg(test)]
mod topic_derivation_tests {
    use super::{
        LookupOpts, MeshConfig, TransportPolicy, derive_topic_mesh, derive_topic_mesh_config,
        derive_topic_mesh_with,
    };

    /// The no-argument form must stay exactly what it always was, because the
    /// `--topic` id it derives is public API for every frontend that calls it.
    #[test]
    fn the_bare_form_is_the_public_preset_form() {
        let _guard = ::habilis_network_test_tracing::init();
        let bare = derive_topic_mesh("standup").expect("derive");
        let explicit =
            derive_topic_mesh_with("standup", LookupOpts::public_preset()).expect("derive");
        assert_eq!(
            bare.to_string(),
            explicit.to_string(),
            "the bare form and the explicit public form give the same string"
        );
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
        let _guard = ::habilis_network_test_tracing::init();
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
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = derive_topic_mesh_with("standup", LookupOpts::loopback()).expect("derive");
        assert!(
            mesh.is_loopback(),
            "a loopback reach derives a loopback mesh"
        );
        assert!(
            !derive_topic_mesh_with("standup", LookupOpts::public_preset())
                .expect("derive")
                .is_loopback(),
            "a loopback reach does not derive a public mesh"
        );
    }

    /// The empty-string guard is shared, not duplicated: an empty topic would
    /// otherwise derive one globally-fixed mesh every empty-string caller lands
    /// in.
    #[test]
    fn both_forms_reject_an_empty_string() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            derive_topic_mesh("   ").is_err(),
            "an empty topic is refused in the public form"
        );
        assert!(
            derive_topic_mesh_with("   ", LookupOpts::loopback()).is_err(),
            "an empty topic is refused in the loopback form"
        );
    }

    /// The relay's transport role is part of the id: two meshes that differ
    /// only in it are different meshes, so members provably agree on it.
    #[test]
    fn relay_transport_changes_the_id() {
        let _guard = ::habilis_network_test_tracing::init();
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
        assert_ne!(
            lookup_only.to_string(),
            relayed.to_string(),
            "the relay transport changes the id"
        );
        assert!(
            !lookup_only.transport().relay_transport,
            "the lookup-only mesh has the relay transport off"
        );
        assert!(
            relayed.transport().relay_transport,
            "the relayed mesh has the relay transport on"
        );
    }

    /// A minted config gets the same cross-field check a decoded id gets;
    /// otherwise the creator would run a mesh whose id every joiner rejects.
    #[test]
    fn a_relay_transport_without_a_relay_lookup_is_rejected_on_mint() {
        let _guard = ::habilis_network_test_tracing::init();
        let config = MeshConfig::new(
            LookupOpts::loopback(),
            None,
            None,
            TransportPolicy::default().with_relay_transport(true),
        );
        assert!(
            derive_topic_mesh_config("standup", config).is_err(),
            "a relay transport without a relay lookup is rejected on mint"
        );
    }
}

#[cfg(test)]
mod join_password_tests {
    use super::{JoinParams, SetupError};
    use crate::protocol::Seed;
    use crate::protocol::crypto::Password;
    use crate::protocol::mesh::{Mesh, MeshConfig, MeshName};

    /// A passworded id, as a joiner is handed it.
    fn passworded_id() -> String {
        let mut mesh = Mesh::try_new(
            Seed::new([9u8; 32]),
            MeshName::try_new("pw").unwrap(),
            MeshConfig::loopback(),
        )
        .unwrap();
        mesh.set_password(Password::new("hunter2".to_owned()));
        mesh.to_string()
    }

    #[test]
    fn a_passworded_id_without_a_password_is_password_required() {
        let _guard = ::habilis_network_test_tracing::init();
        let params = JoinParams::new(passworded_id().parse().unwrap(), None, None);
        let error = params.resolve().unwrap_err();
        assert!(
            matches!(error, SetupError::PasswordRequired),
            "got: {error}"
        );
    }
}
