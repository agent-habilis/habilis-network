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
//! is not a server — it is itself a well-known public [`Mesh`] derived
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

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crypto::{Seed, derive_secret};
use crate::mesh::{LockedMesh, LookupOpts, Mesh, MeshConfig, MeshName, TransportPolicy};
use crate::{MeshId, MessageBody};
use habilis_network_util::clock::{Instant, UnixSecs};

/// Domain-separation seed for every directory. The directory name is
/// the `derive_secret` *label*; this is the *seed*, so a directory's
/// derived mesh seed (`derive_secret(DIRECTORY_BASE_SEED, directory)`) is a
/// SHA-256 output that can never collide with a user mesh's random
/// 32-byte seed. Bumping this
/// orphans every existing directory (a wire-incompatible directory change).
/// The literal must be exactly 32 bytes to fit `[u8; 32]` (the `derive_secret`
/// seed width) — keep any future rename to that length.
const DIRECTORY_BASE_SEED: Seed = Seed::from_bytes(*b"habilis-mesh/directory/domain/v1");

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
#[must_use]
pub fn directory_mesh(directory: &MeshName, lookups: LookupOpts) -> Mesh {
    Mesh::try_new(
        Seed::from_bytes(*derive_secret(
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

/// A directory advertisement: the advertised mesh's id plus its
/// live peer count. The id already encodes the mesh name and
/// network mode, so a discoverer decodes those locally — nothing else need
/// be on the wire. Serialized as a JSON object (room for future fields;
/// discoverers ignore unknown keys via serde's default behaviour and
/// ignore unparseable bodies entirely).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Ad {
    /// The mesh that this ad advertises.
    pub id: MeshId,
    /// How many members the mesh has, this advertiser included.
    pub peers: usize,
}

impl Ad {
    /// Render this ad as a [`MessageBody`] for broadcast on the directory.
    /// Infallible: the JSON of an `{id, peers}` object contains no
    /// control characters.
    ///
    /// # Panics
    /// If `Ad` fails to serialize, or its JSON somehow carries a control
    /// character. Neither is reachable for an `{id, peers}` object.
    #[must_use]
    pub fn to_body(&self) -> MessageBody {
        let json = serde_json::to_string(self).expect("Ad always serializes to JSON");
        MessageBody::try_new(json).expect("Ad JSON contains no control characters")
    }

    /// Parse a directory message body as an ad. Returns `None` for any
    /// non-ad body (presence, digests, junk) so the collector can feed
    /// every directory message through without pre-filtering.
    #[must_use]
    pub fn parse(body: &str) -> Option<Self> {
        serde_json::from_str(body).ok()
    }
}

/// One live directory entry, decoded from an [`Ad`].
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

/// The change one [`Listings::note`] made: a newly seen mesh or a
/// refreshed peer count. Departures aren't here — they come from
/// [`Listings::expire`], which returns the aged-out ids directly. A consumer
/// maps this onto its own public directory-event type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListingChange {
    /// A mesh seen for the first time.
    Found(MeshId),
    /// A re-ad whose visible data (peer count) changed. A re-ad with an
    /// unchanged count produces no event — see [`Listings::note`].
    Updated(MeshId),
}

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
    /// decodes to a [`Mesh`] refreshes the listing's liveness; the
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

#[cfg(test)]
mod tests {
    use habilis_network_test_tracing::test;
    use habilis_network_util::clock::Instant;
    use std::time::Duration;

    use super::{Ad, ListingChange, Listings, directory_mesh};
    use crate::MeshId;
    use crate::mesh::{LookupOpts, MeshName};

    fn directory(name: &str) -> MeshName {
        MeshName::try_new(name).unwrap()
    }

    /// The advertised mesh's id for a directory of the given name.
    fn advertised_id(name: &str) -> MeshId {
        MeshId::try_new(directory_mesh(&directory(name), LookupOpts::public_preset()).to_string())
            .expect("directory mesh id is valid")
    }

    // The golden id, topic and rendezvous of the `global` directory. They equal what the code
    // before the newtype refactor (795c4f88) gives. The rendezvous holds for both lookups, and the
    // topic differs, because only the topic mixes in the config.
    #[test]
    fn golden_global_directory_is_pinned() {
        let name = directory("global");
        let public = directory_mesh(&name, LookupOpts::public_preset());
        let loopback = directory_mesh(&name, LookupOpts::loopback());
        assert_eq!(
            public.to_string(),
            "6V2BWDBYyzZ2JSgSeNnSuaDLLyeWXYsCMx51Rrx6uAahPifGmAhw4oGrZ7X4fAAoK"
        );
        assert_eq!(
            format!("{:?}", public.topic_id()),
            "TopicId(0ac3690b9968f8fd7f2183337984af2629df292a94165f0405135ed001db0dc7)"
        );
        assert_eq!(
            loopback.to_string(),
            "6V2BWDBYyzZ2JSgSeNnSuaDLLyeWXYsCMx51Rrx6uAahPifGmAhw4oGrZ42xQmkfY"
        );
        assert_eq!(
            format!("{:?}", loopback.topic_id()),
            "TopicId(14a8001b57bb1cbcc7b94f936c71cb94c2ab39a8c9b0423dbad0da809f93db8f)"
        );
        for mesh in [&public, &loopback] {
            assert_eq!(
                mesh.rendezvous_id().to_string(),
                "947e089a2d95674c53b0c9fd4b3a4abd2d58480bda7fd18e268438d4c56d7cbc"
            );
        }
    }

    #[test]
    fn directory_is_deterministic_per_name() {
        let one = directory_mesh(&directory("global"), LookupOpts::public_preset());
        let two = directory_mesh(&directory("global"), LookupOpts::public_preset());
        assert_eq!(
            one.to_string(),
            two.to_string(),
            "same directory + same lookups ⇒ same mesh"
        );
    }

    #[test]
    fn distinct_names_are_distinct_directories() {
        assert_ne!(
            directory_mesh(&directory("global"), LookupOpts::public_preset()).to_string(),
            directory_mesh(&directory("gamedev"), LookupOpts::public_preset()).to_string(),
            "different names ⇒ independent directories"
        );
    }

    #[test]
    fn directory_is_public_with_public_lookups() {
        assert!(!directory_mesh(&directory("global"), LookupOpts::public_preset()).is_loopback());
    }

    #[test]
    fn directory_topic_couples_to_lookups() {
        // The symmetry rule: same name but different lookups ⇒ a different
        // directory mesh (id encodes config_bytes, and the topic derives
        // from those same bytes), so an advertiser and a discoverer meet only
        // when their lookups match. Equal lookups ⇒ identical mesh.
        let name = directory("global");
        let all_on = directory_mesh(&name, LookupOpts::public_preset()).to_string();
        let all_on_again = directory_mesh(&name, LookupOpts::public_preset()).to_string();
        let loopback = directory_mesh(&name, LookupOpts::loopback()).to_string();
        assert_eq!(
            all_on, all_on_again,
            "same name + same lookups ⇒ same directory"
        );
        assert_ne!(
            all_on, loopback,
            "same name, different lookups ⇒ different directory (they won't meet)"
        );
    }

    #[test]
    fn ad_round_trips_through_body() {
        // Build a real advertised id so `observe` can decode it.
        let advertised = advertised_id("demo");
        let ad = Ad {
            id: advertised.clone(),
            peers: 4,
        };
        let body = ad.to_body();
        let parsed = Ad::parse(body.as_str()).expect("ad parses");
        assert_eq!(parsed.id, advertised);
        assert_eq!(parsed.peers, 4);
    }

    #[test]
    fn parse_rejects_non_ad_bodies() {
        assert!(Ad::parse("").is_none());
        assert!(Ad::parse("not json").is_none());
        assert!(
            Ad::parse(r#"["a","b"]"#).is_none(),
            "digest array isn't an ad"
        );
        assert!(Ad::parse(r#"{"peers":1}"#).is_none(), "missing id");
    }

    #[test]
    fn note_found_then_updated_then_expire_lost() {
        let advertised = advertised_id("demo");
        let body = Ad {
            id: advertised.clone(),
            peers: 2,
        }
        .to_body();

        let mut dir = Listings::new();
        let start = Instant::now();

        // First sighting ⇒ Found.
        let first_event = dir.note(body.as_str(), start);
        assert!(matches!(first_event, Some(ListingChange::Found(_))));
        let listing = dir.snapshot().next().expect("one listing");
        assert_eq!(listing.name.as_str(), "demo");
        assert_eq!(listing.peers, 2);
        assert!(listing.public);

        // Re-ad with a changed peer count ⇒ Updated.
        let refreshed = Ad {
            id: advertised,
            peers: 5,
        }
        .to_body();
        let second_event = dir.note(refreshed.as_str(), start + Duration::from_secs(20));
        assert!(matches!(second_event, Some(ListingChange::Updated(_))));
        assert_eq!(dir.snapshot().next().expect("one listing").peers, 5);

        // No fresh ad past the ttl ⇒ expired/Lost.
        let lost = dir
            .expire(Duration::from_mins(1), start + Duration::from_secs(200))
            .collect::<Vec<_>>();
        assert_eq!(lost.len(), 1);
        assert!(dir.snapshot().next().is_none());
    }

    #[test]
    fn unchanged_re_ad_refreshes_liveness_without_an_event() {
        let body = Ad {
            id: advertised_id("demo"),
            peers: 3,
        }
        .to_body();
        let mut dir = Listings::new();
        let start = Instant::now();

        assert!(matches!(
            dir.note(body.as_str(), start),
            Some(ListingChange::Found(_))
        ));
        // Same peer count ⇒ no event, but liveness is refreshed so the
        // entry survives an expiry sweep past the original timestamp.
        let later = start + Duration::from_secs(50);
        assert!(dir.note(body.as_str(), later).is_none());
        assert!(
            dir.expire(Duration::from_mins(1), start + Duration::from_secs(70))
                .next()
                .is_none(),
            "the re-ad refreshed last_seen, so the entry is still alive"
        );
        assert_eq!(dir.snapshot().count(), 1);
    }

    #[test]
    fn junk_directory_traffic_is_ignored() {
        let mut dir = Listings::new();
        assert!(dir.note("", Instant::now()).is_none());
        assert!(dir.note("hello peers", Instant::now()).is_none());
        assert!(dir.snapshot().next().is_none());
    }
}
