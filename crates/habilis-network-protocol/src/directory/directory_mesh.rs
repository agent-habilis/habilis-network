//! The directory mesh and the seed of its derivation.

use crate::crypto::{Seed, derive_secret};
use crate::mesh::{LookupOpts, Mesh, MeshConfig, MeshName, TransportPolicy};

/// Domain-separation seed for every directory. The directory name is
/// the `derive_secret` *label*; this is the *seed*, so a directory's
/// derived mesh seed (`derive_secret(DIRECTORY_BASE_SEED, directory)`) is a
/// SHA-256 output that can never collide with a user mesh's random
/// 32-byte seed. Bumping this
/// orphans every existing directory (a wire-incompatible directory change).
/// The literal must be exactly 32 bytes to fit `[u8; 32]` (the `derive_secret`
/// seed width) — keep any future rename to that length.
const DIRECTORY_BASE_SEED: Seed = Seed::new(*b"habilis-mesh/directory/domain/v1");

/// The well-known [`Mesh`] for a directory, reached over `lookups`. Both
/// The advertise and discover paths both call this; the
/// seed + rendezvous are name-derived (so they're identical regardless of
/// `lookups`), but the **topic** mixes in the config bytes — which include the
/// lookups — so an advertiser and a discoverer meet only when they pass the
/// **same** `lookups`. That is deliberate: the directory's lookups are the
/// advertiser's own mesh lookups (so an mDNS-only mesh advertises over mDNS
/// only) and the discoverer's `--mdns/--dht/--relay` choice, and the two must
/// align to see each other. A different name still yields a fully independent
/// directory.
///
/// # Panics
/// Never. The directory config carries no password or invite issuer, which
/// [`Mesh::try_new`] refuses, so the constructor cannot fail here.
///
/// # Examples
///
/// The same directory name always gives the same directory mesh.
///
/// ```
/// use habilis_network_protocol::MeshName;
/// use habilis_network_protocol::directory::directory_mesh;
/// use habilis_network_protocol::mesh::{LookupOpts, RelayChoice};
///
/// let name = MeshName::try_new("directory-chat").expect("a name");
/// let first = directory_mesh(&name, LookupOpts::new(RelayChoice::Disabled));
/// let again = directory_mesh(&name, LookupOpts::new(RelayChoice::Disabled));
/// assert_eq!(first.to_string(), again.to_string());
/// ```
#[must_use]
pub fn directory_mesh(directory: &MeshName, lookups: LookupOpts) -> Mesh {
    Mesh::try_new(
        Seed::new(*derive_secret(
            DIRECTORY_BASE_SEED.as_bytes(),
            directory.as_bytes(),
        )),
        directory.clone(),
        directory_config(lookups),
    )
    .expect("the directory config carries no secret")
}

/// The config a directory mesh uses for `lookups`: the caller's chosen
/// lookups. The lookups become the directory session's lookups, so a member
/// reaches the directory over exactly those mechanisms — a disabled leg issues
/// no network requests for the directory at all.
///
/// # Examples
///
/// A directory config builds a mesh that carries the directory name.
///
/// ```
/// use habilis_network_protocol::directory::directory_config;
/// use habilis_network_protocol::mesh::{LookupOpts, RelayChoice};
/// use habilis_network_protocol::{Mesh, MeshName, Seed};
///
/// let config = directory_config(LookupOpts::new(RelayChoice::Disabled));
/// let name = MeshName::try_new("directory-chat").expect("a name");
/// let mesh = Mesh::try_new(Seed::new([6u8; 32]), name, config).expect("a mesh");
/// assert_eq!(mesh.name().as_str(), "directory-chat");
/// ```
#[must_use]
pub fn directory_config(lookups: LookupOpts) -> MeshConfig {
    MeshConfig {
        lookups,
        password: None,
        issuer_pubkey: None,
        // Lookup only, whatever the advertised mesh chose: the directory is
        // a separate rendezvous mesh that carries advertisements, not data.
        transport: TransportPolicy::default(),
        // The directory rendezvous always uses gossip — it is how advertisers
        // and discoverers meet.
    }
}
