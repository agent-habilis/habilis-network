//! A change to the listings of a directory: an arrival or a departure.

use crate::MeshId;

/// The change one [`super::Listings::note`] made: a newly seen mesh or a
/// refreshed peer count. Departures aren't here — they come from
/// [`super::Listings::expire`], which returns the aged-out ids directly. A consumer
/// maps this onto its own public directory-event type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListingChange {
    /// A mesh seen for the first time.
    Found(MeshId),
    /// A re-ad whose visible data (peer count) changed. A re-ad with an
    /// unchanged count produces no event — see [`super::Listings::note`].
    Updated(MeshId),
}
