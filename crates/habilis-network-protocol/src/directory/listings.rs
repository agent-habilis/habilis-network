//! The listings a discoverer has collected, bounded.

use std::collections::HashMap;
use std::time::Duration;

use habilis_network_util::clock::Instant;
use habilis_network_util::unix_secs::UnixSecs;

use super::{Ad, Listing, ListingChange};

use crate::MeshId;
use crate::mesh::LockedMesh;

/// Upper bound on tracked listings. The directory is an open public mesh
/// (anyone can mint and broadcast valid mesh ids), so the map is
/// capped — a new id past the cap evicts the stalest entry — mirroring
/// the bounded-set discipline the rest of the daemon follows for
/// adversary-reachable collections.
const MAX_LISTINGS: usize = 256;

/// The live directory: a set of [`Listing`]s keyed by mesh id, fed by
/// directory messages and aged out by [`Listings::expire`]. Pure +
/// deterministic (the caller supplies `now`), so it unit-tests without
/// a clock or a network. Shared by the CLI `discover` stream and the
/// in-process directory watcher.
#[derive(Debug, Clone, Default)]
pub struct Listings {
    entries: HashMap<MeshId, Listing>,
}

impl Listings {
    /// An empty set of listings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Process one directory message body. A valid [`Ad`] whose id
    /// decodes to a [`crate::mesh::Mesh`] refreshes the listing's liveness; the
    /// returned event is `Found` for a new mesh, `Updated` only when a
    /// visible field (the peer count) changed, and `None` for an
    /// unchanged re-ad or an unparseable body. Suppressing the no-op
    /// `Updated` matters because every advertiser re-ads on a fixed
    /// interval — surfacing each would spam the JSON stream every tick
    /// with identical data.
    pub fn note(&mut self, body: &str, now: Instant) -> Option<ListingChange> {
        let ad = Ad::parse(body)?;
        // `ad.id` is a `MeshId` (shallow charset check only); the
        // structural `LockedMesh` decode below is the real validity gate, so
        // an id that doesn't decode is dropped here.
        let mesh: LockedMesh = ad.id.as_str().parse().ok()?;
        let mesh_id = ad.id;

        if let Some(listing) = self.entries.get_mut(&mesh_id) {
            listing.last_seen = now;
            if listing.peers == ad.peers {
                return None;
            }
            listing.peers = ad.peers;
            return Some(ListingChange::Updated(mesh_id));
        }

        // New mesh. Bound the map by evicting the stalest entry.
        if self.entries.len() >= MAX_LISTINGS
            && let Some(stalest) = self
                .entries
                .iter()
                .min_by_key(|(_, listing)| listing.last_seen)
                .map(|(id, _)| id.clone())
        {
            self.entries.remove(&stalest);
        }
        self.entries.insert(
            mesh_id.clone(),
            Listing {
                mesh: mesh_id.clone(),
                public: !mesh.is_loopback(),
                password: mesh.requires_password(),
                name: mesh.name().clone(),
                peers: ad.peers,
                last_seen: now,
                first_seen_unix: UnixSecs::now(),
            },
        );
        Some(ListingChange::Found(mesh_id))
    }

    /// Drop every listing whose last ad is older than `ttl`, returning
    /// the ids removed (so the caller can surface a `Lost` event each).
    pub fn expire(&mut self, ttl: Duration, now: Instant) -> impl Iterator<Item = MeshId> {
        let mut expired = Vec::new();
        self.entries.retain(|id, listing| {
            let alive = now.duration_since(listing.last_seen) <= ttl;
            if !alive {
                expired.push(id.clone());
            }
            alive
        });
        expired.into_iter()
    }

    /// The current listings, sorted by mesh name then id — a stable
    /// order for the picker and for `snapshot()` callers.
    pub fn snapshot(&self) -> impl Iterator<Item = Listing> {
        let mut listings: Vec<Listing> = self.entries.values().cloned().collect();
        listings.sort_by(|left, right| {
            left.name
                .as_str()
                .cmp(right.name.as_str())
                .then_with(|| left.mesh.as_str().cmp(right.mesh.as_str()))
        });
        listings.into_iter()
    }

    /// Look up a single listing by id (used to attach data to an event).
    #[must_use]
    pub fn get(&self, id: &MeshId) -> Option<&Listing> {
        self.entries.get(id)
    }
}
