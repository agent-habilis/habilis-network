//! One listed mesh, as a discoverer sees it.

use crate::MeshId;
use crate::mesh::MeshName;

use habilis_network_util::clock::Instant;
use habilis_network_util::unix_secs::UnixSecs;

/// One live directory entry, decoded from an [`super::Ad`].
///
/// # Examples
///
/// A listing holds the mesh id and the member count from the latest ad.
///
/// ```
/// use std::time::Instant;
///
/// use habilis_network_protocol::directory::Listings;
/// use habilis_network_protocol::mesh::MeshId;
///
/// use habilis_network_protocol::{Mesh, MeshConfig, MeshName, Seed};
///
/// let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
/// let mesh = Mesh::try_new(Seed::new([4u8; 32]), MeshName::try_new("chat").expect("a name"), config)
///     .expect("a mesh");
///
/// let text = mesh.to_string();
/// let mut listings = Listings::new();
/// listings.note(&format!(r#"{{"id":"{text}","peers":3}}"#), Instant::now());
/// let id = MeshId::try_new(&text).expect("a valid id");
/// let listing = listings.get(&id).expect("the listed mesh");
/// assert_eq!(listing.peers, 3);
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Listing {
    /// The id of the listed mesh.
    pub mesh: MeshId,
    /// The name of the listed mesh.
    pub name: MeshName,
    /// `true` if the advertised mesh's id decodes to the public
    /// network (the norm — `--advertise` requires `--public`).
    pub public: bool,
    /// `true` if the advertised id carries a password verifier — joining
    /// needs the password, so the ad alone does not admit.
    pub password: bool,
    /// How many members the mesh has, this advertiser included.
    pub peers: usize,
    /// Local instant of the most recent ad; drives expiry.
    pub last_seen: Instant,
    /// When this mesh was *first* seen in the directory (preserved across
    /// re-ads). Read by the directory API of a consumer, to order or age the
    /// listing.
    pub first_seen_unix: UnixSecs,
}
