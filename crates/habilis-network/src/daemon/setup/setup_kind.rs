use crate::protocol::crypto::Password;
use crate::protocol::meshes::{Mesh, MeshConfig, MeshName};

/// What kind of mesh we're setting up — either minting a new one
/// (create) or attaching to an existing one (join).
///
/// # Examples
///
/// A setup kind says whether the node creates a mesh, joins one, or follows a topic. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::SetupKind;
///
/// # fn demo(kind: SetupKind) -> bool {
/// matches!(kind, SetupKind::Create { .. })
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SetupKind {
    /// Create a mesh.
    Create {
        /// The name of the mesh.
        name: MeshName,
        /// The mesh-wide config (lookups) baked into the minted id and
        /// mixed into the topic.
        config: MeshConfig,
        /// The directory this mesh advertises into, if any. Drives the
        /// `advertising on #<directory>` startup line; the re-broadcast
        /// task itself is spawned by the caller post-setup.
        advertise: Option<MeshName>,
        /// Password to protect the mesh with. Stretched *here* rather than
        /// by the frontend: the verifier's salt is the seed, which is
        /// minted below.
        password: Option<Password>,
        /// `--invite-only`: mint an invite root + issuer keypair here (the
        /// issuer pubkey is baked into the id) so the bare hash can't join —
        /// only creator-minted invites can.
        invite_only: bool,
    },
    /// Join a mesh.
    Join {
        /// The unlocked mesh to join.
        mesh: Mesh,
        /// The password the joiner presented (already verified + applied to
        /// `mesh`), retained so the daemon can key blob-ticket protection with
        /// it. `None` for a passwordless id.
        password: Option<Password>,
    },
    /// A `topic` mesh derived from a shared string. Identical to `Join`
    /// except the first peer must beacon: there is no distinguished creator,
    /// so it co-hosts the shared rendezvous eagerly-but-probed
    /// ([`CoHostPolicy::EagerProbed`](crate::daemon::CoHostPolicy::EagerProbed)) rather than deferring.
    Topic {
        /// The mesh derived from `topic_string`.
        mesh: Mesh,
        /// The raw string the mesh was derived from. The derived name is
        /// lossy (URL scheme and query stripped, truncated), so the string
        /// is carried whole for every user-facing joined/left surface.
        topic_string: String,
    },
}
