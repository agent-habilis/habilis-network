//! The directory — opt-in mesh discovery ("meshes all the way
//! down").
//!
//! Folded in from its own crate: it isolated no dependency of its own — every
//! name it used was already one of this crate's — so the split bought a
//! manifest, two feature sets and a cross-crate public API where a module
//! does.
//!
//! A mesh created with `--advertise[=<name>]` re-broadcasts its own
//! mesh id into a **directory**; a consumer's discovery command browses it. A directory
//! is not a server — it is itself a well-known public [`crate::meshes::Mesh`] derived
//! deterministically from its name, so a publisher and a discoverer that
//! name the same directory derive the same mesh and mesh over the
//! ordinary gossip + relay/DHT/mDNS stack. Ads are plain gossip messages
//! ([`Ad`] in the body) on that mesh's topic — there is no stored list,
//! so an ad lives only while its publisher keeps re-broadcasting (see
//! [`habilis_network_util::tuning`]'s `ADVERTISE_INTERVAL` /
//! `DIRECTORY_EXPIRY`).
//!
//! This module is **pure**: directory derivation, the [`Ad`] codec, and the
//! [`Listings`] collector. The advertise *task* (a live session on the
//! directory) and the discover UI are consumer-side concerns that drive the
//! primitives here.

mod ad;
pub use ad::Ad;
mod directory_mesh;
pub use directory_mesh::{directory_config, directory_mesh};
mod listing;
pub use listing::Listing;
mod listing_change;
pub use listing_change::ListingChange;
mod listings;
pub use listings::Listings;

#[cfg(test)]
mod tests;
