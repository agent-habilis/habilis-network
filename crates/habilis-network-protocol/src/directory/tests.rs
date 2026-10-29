//! Tests of the directory.

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
    let lost: Vec<_> = dir
        .expire(Duration::from_mins(1), start + Duration::from_secs(200))
        .collect();
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
