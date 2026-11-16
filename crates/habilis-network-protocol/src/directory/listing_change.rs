//! A change to the listings of a directory: an arrival or a departure.

use crate::MeshId;

/// The change one [`super::Listings::note`] made: a newly seen mesh or a
/// refreshed peer count. Departures aren't here — they come from
/// [`super::Listings::expire`], which returns the aged-out ids directly. A consumer
/// maps this onto its own public directory-event type.
///
/// # Examples
///
/// A mesh seen first is found, and a later ad with a new member count is an update.
///
/// ```
/// use std::time::Instant;
///
/// use habilis_network_protocol::directory::{ListingChange, Listings};
///
/// use habilis_network_protocol::{Mesh, MeshConfig, MeshName, Seed};
///
/// let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
/// let mesh = Mesh::try_new(Seed::new([4u8; 32]), MeshName::try_new("chat").expect("a name"), config)
///     .expect("a mesh");
///
/// let text = mesh.to_string();
/// let ad = |peers: usize| format!(r#"{{"id":"{text}","peers":{peers}}}"#);
/// let mut listings = Listings::new();
/// let now = Instant::now();
/// assert!(matches!(listings.note(&ad(3), now), Some(ListingChange::Found(_))));
/// assert!(matches!(listings.note(&ad(4), now), Some(ListingChange::Updated(_))));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListingChange {
    /// A mesh seen for the first time.
    Found(MeshId),
    /// A re-ad whose visible data (peer count) changed. A re-ad with an
    /// unchanged count produces no event — see [`super::Listings::note`].
    Updated(MeshId),
}
