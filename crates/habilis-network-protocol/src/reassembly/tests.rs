//! Tests of the multipart reassembly.

use habilis_network_util::clock::Instant;
use std::time::Duration;

use super::{ReassemblyStore, ShardIngest};
use crate::message::Verified;
use crate::{AppFrameParams, AuthorKey, MeshId, Message, MessageBody, Nickname, Shard, ShardGroup};
use habilis_network_util::consts::{
    REASSEMBLY_AUTHOR_BUDGET_BYTES, REASSEMBLY_GROUP_MAX_BYTES, REASSEMBLY_STALE,
    REASSEMBLY_TOTAL_BUDGET_BYTES,
};

use crate::message;
fn group(uuid: &str) -> ShardGroup {
    ShardGroup::parse_uuid(uuid).expect("valid group")
}

fn group_a() -> ShardGroup {
    group("550e8400-e29b-41d4-a716-446655440000")
}

/// The key of the test author `name`: its bytes, zero-padded.
fn author_of(name: &str) -> AuthorKey {
    let mut bytes = [0u8; 32];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    AuthorKey::from(bytes)
}

/// A shard frame notionally signed by the author `name`.
fn shard_msg(body: &str, name: &str, shard: Shard) -> Verified {
    let mut message = Message::new_app(
        &MeshId::from("test"),
        &Nickname::from("author"),
        AppFrameParams {
            tag: crate::AppTag::try_new("app_msg").expect("a valid app tag"),
            to: None,
            corr: None,
            body: MessageBody::from(body),
        },
    );
    message.shard = Some(shard);
    Verified::fixture_unchecked(message, author_of(name))
}

fn ingest(store: &mut ReassemblyStore, message: &Verified, now: Instant) -> ShardIngest {
    store.ingest(message, now)
}

#[test]
fn isolates_by_author() {
    let _guard = ::habilis_network_test_tracing::init();
    // Two authors reuse the SAME group id. Each forms its own set; one
    // author's shard never fills another's slot, so a crafted cross-author
    // shard can't inject a slice into the victim's reassembled body.
    let now = Instant::now();
    let mut store = ReassemblyStore::default();
    assert!(
        matches!(
            ingest(
                &mut store,
                &shard_msg(
                    "alice-0",
                    "alice",
                    Shard {
                        group: group_a(),
                        index: 0,
                        total: 2
                    }
                ),
                now
            ),
            ShardIngest::Buffered
        ),
        "a shard from one author is kept apart from another author's"
    );
    assert!(
        matches!(
            ingest(
                &mut store,
                &shard_msg(
                    "mallory-1",
                    "mallory",
                    Shard {
                        group: group_a(),
                        index: 1,
                        total: 2
                    }
                ),
                now
            ),
            ShardIngest::Buffered
        ),
        "mallory's same-group shard forms a separate set, never completes alice's"
    );
    // Alice's own second shard completes with alice's bodies only.
    let ShardIngest::Complete(logical) = ingest(
        &mut store,
        &shard_msg(
            "alice-1",
            "alice",
            Shard {
                group: group_a(),
                index: 1,
                total: 2,
            },
        ),
        now,
    ) else {
        panic!("alice's set completes");
    };
    assert_eq!(
        logical.body.as_str(),
        "alice-0alice-1",
        "the two alice shards reassemble in order"
    );
}

#[test]
fn slots_by_idx_not_arrival() {
    let _guard = ::habilis_network_test_tracing::init();
    let now = Instant::now();
    let mut store = ReassemblyStore::default();
    ingest(
        &mut store,
        &shard_msg(
            "b",
            "a",
            Shard {
                group: group_a(),
                index: 1,
                total: 3,
            },
        ),
        now,
    );
    ingest(
        &mut store,
        &shard_msg(
            "a",
            "a",
            Shard {
                group: group_a(),
                index: 0,
                total: 3,
            },
        ),
        now,
    );
    let ShardIngest::Complete(logical) = ingest(
        &mut store,
        &shard_msg(
            "c",
            "a",
            Shard {
                group: group_a(),
                index: 2,
                total: 3,
            },
        ),
        now,
    ) else {
        panic!("third shard completes the group");
    };
    assert_eq!(logical.body.as_str(), "abc", "slotted by idx, not arrival");
    assert_eq!(logical.id.as_str(), group_a().as_str(), "id is the group");
    assert!(logical.shard.is_none(), "the view carries no shard header");
}

#[test]
fn header_mismatch_is_dropped() {
    let _guard = ::habilis_network_test_tracing::init();
    let now = Instant::now();
    let mut store = ReassemblyStore::default();
    ingest(
        &mut store,
        &shard_msg(
            "x",
            "a",
            Shard {
                group: group_a(),
                index: 0,
                total: 3,
            },
        ),
        now,
    );
    // Same signer contradicting its own advertised total: crafted stream.
    assert!(
        matches!(
            ingest(
                &mut store,
                &shard_msg(
                    "y",
                    "a",
                    Shard {
                        group: group_a(),
                        index: 1,
                        total: 4
                    }
                ),
                now
            ),
            ShardIngest::Dropped
        ),
        "a shard whose header mismatches is dropped"
    );
    // A different kind under the same group is equally crafted.
    let mut wrong_kind = shard_msg(
        "z",
        "a",
        Shard {
            group: group_a(),
            index: 1,
            total: 3,
        },
    )
    .into_message();
    wrong_kind.kind = crate::MessageKind::Presence {
        subtype: crate::PresenceSubtype::Joined,
    };
    let wrong_kind = Verified::fixture_unchecked(wrong_kind, author_of("a"));
    assert!(
        matches!(ingest(&mut store, &wrong_kind, now), ShardIngest::Dropped),
        "a shard of the wrong kind is dropped"
    );
}

#[test]
fn duplicate_idx_is_dropped_first_seen_wins() {
    let _guard = ::habilis_network_test_tracing::init();
    let now = Instant::now();
    let mut store = ReassemblyStore::default();
    ingest(
        &mut store,
        &shard_msg(
            "first",
            "a",
            Shard {
                group: group_a(),
                index: 0,
                total: 2,
            },
        ),
        now,
    );
    assert!(
        matches!(
            ingest(
                &mut store,
                &shard_msg(
                    "second",
                    "a",
                    Shard {
                        group: group_a(),
                        index: 0,
                        total: 2
                    }
                ),
                now
            ),
            ShardIngest::Dropped
        ),
        "the first copy of a duplicate index wins"
    );
    let ShardIngest::Complete(logical) = ingest(
        &mut store,
        &shard_msg(
            "!",
            "a",
            Shard {
                group: group_a(),
                index: 1,
                total: 2,
            },
        ),
        now,
    ) else {
        panic!("completes");
    };
    assert_eq!(logical.body.as_str(), "first!", "first-seen wins per idx");
}

#[test]
fn group_budget_breach_drops_the_group() {
    let _guard = ::habilis_network_test_tracing::init();
    ::habilis_network_test_tracing::expect_warn(
        "habilis_network::gossip",
        "partial shard group exceeded its byte budget; dropped",
    );
    let now = Instant::now();
    let mut store = ReassemblyStore::default();
    let big = "x".repeat(REASSEMBLY_GROUP_MAX_BYTES / 2 + 1);
    ingest(
        &mut store,
        &shard_msg(
            &big,
            "a",
            Shard {
                group: group_a(),
                index: 0,
                total: 3,
            },
        ),
        now,
    );
    // The second shard pushes the group past its byte ceiling: the whole
    // group is dropped, and its budget released.
    assert!(
        matches!(
            ingest(
                &mut store,
                &shard_msg(
                    &big,
                    "a",
                    Shard {
                        group: group_a(),
                        index: 1,
                        total: 3
                    }
                ),
                now
            ),
            ShardIngest::Dropped
        ),
        "a group over the budget is dropped"
    );
    assert_eq!(store.total_bytes, 0, "dropped group released its budget");
    assert!(
        store.groups.is_empty(),
        "a dropped group leaves no groups behind"
    );
}

#[test]
fn author_budget_evicts_the_stalest_group() {
    let _guard = ::habilis_network_test_tracing::init();
    ::habilis_network_test_tracing::expect_warn(
        "habilis_network::gossip",
        "author reassembly budget breached; stalest partial group evicted",
    );
    let start = Instant::now();
    let mut store = ReassemblyStore::default();
    // Sized so two groups fit the author budget but three overflow it.
    let chunk = "x".repeat(REASSEMBLY_GROUP_MAX_BYTES / 2 + 64);
    // Two half-budget groups from one author fill its allowance...
    let stale = group("00000000-0000-4000-8000-000000000001");
    let fresh = group("00000000-0000-4000-8000-000000000002");
    ingest(
        &mut store,
        &shard_msg(
            &chunk,
            "a",
            Shard {
                group: stale.clone(),
                index: 0,
                total: 2,
            },
        ),
        start,
    );
    ingest(
        &mut store,
        &shard_msg(
            &chunk,
            "a",
            Shard {
                group: fresh.clone(),
                index: 0,
                total: 2,
            },
        ),
        start + Duration::from_secs(1),
    );
    // ...so a third group evicts the stalest (the first), not the freshest.
    let newcomer = group("00000000-0000-4000-8000-000000000003");
    assert!(
        matches!(
            ingest(
                &mut store,
                &shard_msg(
                    &chunk,
                    "a",
                    Shard {
                        group: newcomer.clone(),
                        index: 0,
                        total: 2
                    }
                ),
                start + Duration::from_secs(2)
            ),
            ShardIngest::Buffered
        ),
        "the author budget evicts the stalest group"
    );
    assert!(
        !store.groups.contains_key(&(author_of("a"), stale)),
        "stalest group evicted"
    );
    assert!(
        store.groups.contains_key(&(author_of("a"), fresh)),
        "the fresh group stays after the author budget eviction"
    );
    assert!(
        store.groups.contains_key(&(author_of("a"), newcomer)),
        "the newcomer group is kept after the author budget eviction"
    );
}

#[test]
fn global_budget_refuses_the_newcomer() {
    let _guard = ::habilis_network_test_tracing::init();
    ::habilis_network_test_tracing::expect_warn(
        "habilis_network::gossip",
        "global reassembly budget breached; incoming shard group dropped",
    );
    let now = Instant::now();
    let mut store = ReassemblyStore::default();
    let chunk = "x".repeat(REASSEMBLY_GROUP_MAX_BYTES / 2);
    // Sybil authors each stay under their own budget until the global
    // backstop bites; the newcomer is refused rather than evicting an
    // honest author's transfer.
    let mut fitted = 0usize;
    for author in 0..64u32 {
        let sybil_group = group(&format!("00000000-0000-4000-8000-0000000000{author:02x}"));
        match ingest(
            &mut store,
            &shard_msg(
                &chunk,
                &format!("sybil-{author}"),
                Shard {
                    group: sybil_group,
                    index: 0,
                    total: 2,
                },
            ),
            now,
        ) {
            ShardIngest::Buffered => fitted += 1,
            ShardIngest::Dropped => break,
            ShardIngest::Complete(_) => panic!("nothing completes here"),
        }
    }
    assert!(
        fitted <= REASSEMBLY_TOTAL_BUDGET_BYTES / (REASSEMBLY_GROUP_MAX_BYTES / 2),
        "global backstop caps buffered bytes across Sybil authors"
    );
    assert!(
        store.total_bytes <= REASSEMBLY_TOTAL_BUDGET_BYTES,
        "the global budget refuses the newcomer"
    );
}

/// The Sybil property, and the reason the budget is per author at all: a
/// flooder exhausts its own allowance and leaves everyone else's alone.
///
/// `author_budget_evicts_the_stalest_group` above drives a single author,
/// so it pins *which* group goes without pinning *whose*. Named to match
/// `habilis_network_doc`'s `a_floods_orphans_do_not_evict_another_authors`, which
/// states the same rule over the other store.
#[test]
fn a_floods_groups_do_not_evict_another_authors() {
    let _guard = ::habilis_network_test_tracing::init();
    ::habilis_network_test_tracing::expect_warn(
        "habilis_network::gossip",
        "author reassembly budget breached; stalest partial group evicted",
    );
    let now = Instant::now();
    let mut store = ReassemblyStore::default();
    let chunk = "x".repeat(REASSEMBLY_GROUP_MAX_BYTES / 2 + 64);

    // One honest partial transfer, parked.
    let honest = group("00000000-0000-4000-8000-0000000000aa");
    assert!(
        matches!(
            ingest(
                &mut store,
                &shard_msg(
                    &chunk,
                    "honest",
                    Shard {
                        group: honest.clone(),
                        index: 0,
                        total: 2,
                    },
                ),
                now,
            ),
            ShardIngest::Buffered
        ),
        "one author's flood does not evict another author's groups"
    );

    // A flooder then burns through its own allowance several times over.
    for round in 0..8u32 {
        let flood = group(&format!("00000000-0000-4000-8000-0000000000{round:02x}"));
        let _ = ingest(
            &mut store,
            &shard_msg(
                &chunk,
                "flooder",
                Shard {
                    group: flood,
                    index: 0,
                    total: 2,
                },
            ),
            now,
        );
    }

    let flooder_groups = store
        .groups
        .keys()
        .filter(|key| key.0 == author_of("flooder"))
        .count();
    assert!(
        flooder_groups < 8,
        "the flood must actually breach its own budget, or this proves nothing"
    );
    assert!(
        store.groups.keys().any(|key| key.1 == honest),
        "the honest author's partial transfer survived the flood"
    );
}

#[test]
fn stale_groups_are_swept_and_release_budget() {
    let _guard = ::habilis_network_test_tracing::init();
    let start = Instant::now();
    let mut store = ReassemblyStore::default();
    ingest(
        &mut store,
        &shard_msg(
            "x",
            "a",
            Shard {
                group: group_a(),
                index: 0,
                total: 3,
            },
        ),
        start,
    );
    // Progress (a NEW slot) refreshes the group's clock...
    let touched = start + REASSEMBLY_STALE.saturating_sub(Duration::from_secs(1));
    assert!(
        matches!(
            ingest(
                &mut store,
                &shard_msg(
                    "y",
                    "a",
                    Shard {
                        group: group_a(),
                        index: 1,
                        total: 3
                    }
                ),
                touched
            ),
            ShardIngest::Buffered
        ),
        "a stale group is swept on the next shard"
    );
    // ...but a duplicate slot does NOT — no attacker keepalive via resends.
    let dup_at = touched + REASSEMBLY_STALE.saturating_sub(Duration::from_secs(1));
    assert!(
        matches!(
            ingest(
                &mut store,
                &shard_msg(
                    "x",
                    "a",
                    Shard {
                        group: group_a(),
                        index: 0,
                        total: 3
                    }
                ),
                dup_at
            ),
            ShardIngest::Dropped
        ),
        "a fresh shard after the sweep is accepted"
    );
    assert_eq!(
        store.sweep_stale(touched + REASSEMBLY_STALE.saturating_sub(Duration::from_secs(1))),
        0,
        "a progressing group survives the sweep"
    );
    assert_eq!(
        store.sweep_stale(touched + REASSEMBLY_STALE),
        1,
        "a group with no new slots is reaped at the idle TTL (the dup did not refresh)"
    );
    assert_eq!(
        store.total_bytes, 0,
        "a sweep returns the total budget to zero"
    );
    assert!(
        store.author_bytes.is_empty(),
        "a sweep leaves no author bytes"
    );
}

#[test]
fn a_trickling_group_is_reaped_at_the_lifetime_ceiling() {
    use habilis_network_util::consts::REASSEMBLY_MAX_GROUP_LIFETIME;
    let _guard = ::habilis_network_test_tracing::init();
    let start = Instant::now();
    let mut store = ReassemblyStore::default();
    // One new shard per idle window keeps the group alive under the idle
    // TTL alone — feed progress right up to the lifetime ceiling.
    let total = 64u32;
    let mut at = start;
    let mut index = 0u32;
    while at.duration_since(start) < REASSEMBLY_MAX_GROUP_LIFETIME {
        ingest(
            &mut store,
            &shard_msg(
                "x",
                "a",
                Shard {
                    group: group_a(),
                    index: index % total,
                    total,
                },
            ),
            at,
        );
        index += 1;
        at += REASSEMBLY_STALE.saturating_sub(Duration::from_secs(1));
    }
    assert_eq!(store.groups.len(), 1, "the trickle kept the group alive");
    assert_eq!(
        store.sweep_stale(start + REASSEMBLY_MAX_GROUP_LIFETIME),
        1,
        "the lifetime ceiling reaps it regardless of progress"
    );
    assert_eq!(
        store.total_bytes, 0,
        "a reaped trickling group releases its bytes"
    );
}

#[test]
fn completion_releases_the_budget() {
    let _guard = ::habilis_network_test_tracing::init();
    let now = Instant::now();
    let mut store = ReassemblyStore::default();
    ingest(
        &mut store,
        &shard_msg(
            "a",
            "a",
            Shard {
                group: group_a(),
                index: 0,
                total: 2,
            },
        ),
        now,
    );
    assert!(
        store.total_bytes > 0,
        "a partial group holds budget before completion"
    );
    assert!(
        matches!(
            ingest(
                &mut store,
                &shard_msg(
                    "b",
                    "a",
                    Shard {
                        group: group_a(),
                        index: 1,
                        total: 2
                    }
                ),
                now
            ),
            ShardIngest::Complete(_)
        ),
        "the completing shard is accepted"
    );
    assert_eq!(store.total_bytes, 0, "completion releases the total budget");
    assert!(
        store.author_bytes.is_empty(),
        "completion releases the author budget"
    );
    assert!(
        store.groups.is_empty(),
        "completion leaves no groups behind"
    );
}

#[test]
fn repair_tickets_target_stalled_big_groups_once_per_window() {
    use habilis_network_util::consts::{LOGGED_SHARD_GROUP_MAX_TOTAL, REASSEMBLY_REPAIR_IDLE};
    let _guard = ::habilis_network_test_tracing::init();
    let start = Instant::now();
    let mut store = ReassemblyStore::default();
    // A small group (logged, heals via anti-entropy) and a big one.
    let small = group("00000000-0000-4000-8000-00000000000a");
    let big = group("00000000-0000-4000-8000-00000000000b");
    ingest(
        &mut store,
        &shard_msg(
            "s",
            "a",
            Shard {
                group: small,
                index: 0,
                total: 2,
            },
        ),
        start,
    );
    ingest(
        &mut store,
        &shard_msg(
            "b",
            "a",
            Shard {
                group: big.clone(),
                index: 0,
                total: LOGGED_SHARD_GROUP_MAX_TOTAL + 4,
            },
        ),
        start,
    );
    ingest(
        &mut store,
        &shard_msg(
            "b",
            "a",
            Shard {
                group: big.clone(),
                index: 2,
                total: LOGGED_SHARD_GROUP_MAX_TOTAL + 4,
            },
        ),
        start,
    );

    // Not stalled yet — no tickets.
    let early: Vec<_> = store.repair_tickets(start).collect();
    assert!(
        early.is_empty(),
        "no repair ticket is due before the window"
    );

    // Stalled: only the big group is ticketed, with exactly its gaps.
    let stalled = start + REASSEMBLY_REPAIR_IDLE;
    let tickets: Vec<_> = store.repair_tickets(stalled).collect();
    assert_eq!(tickets.len(), 1, "small groups heal via anti-entropy");
    assert_eq!(
        tickets[0].group, big,
        "the repair ticket targets the stalled big group"
    );
    assert_eq!(
        tickets[0].author.as_str(),
        "author",
        "the repair ticket names the author"
    );
    assert!(
        !tickets[0].missing.contains(&0),
        "the repair ticket does not ask for shard 0, which is held"
    );
    assert!(
        !tickets[0].missing.contains(&2),
        "the repair ticket does not ask for shard 2, which is held"
    );
    assert!(
        tickets[0].missing.contains(&1),
        "the repair ticket asks for the missing shard 1"
    );

    // Asked once per window — the immediate re-check yields nothing.
    let asked_again: Vec<_> = store.repair_tickets(stalled).collect();
    assert!(
        asked_again.is_empty(),
        "the repair ticket is not asked again inside the window"
    );
    // The next window asks again.
    let next = stalled + REASSEMBLY_REPAIR_IDLE;
    let next_tickets: Vec<_> = store.repair_tickets(next).collect();
    assert_eq!(
        next_tickets.len(),
        1,
        "the next window issues one repair ticket"
    );
}

#[test]
fn shard_cache_serves_requested_frames_and_evicts_whole_groups() {
    use habilis_network_util::consts::SHARD_CACHE_BUDGET_BYTES;
    let _guard = ::habilis_network_test_tracing::init();
    let mut cache = super::ShardCache::default();
    let first = group("00000000-0000-4000-8000-0000000000c1");
    let frame = |tag: u8, len: usize| message::WireFrame::new(bytes::Bytes::from(vec![tag; len]));
    cache.insert(first.clone(), vec![frame(1, 10), frame(2, 10)]);
    let served: Vec<_> = cache.frames(&first, &[1, 7]).collect();
    assert_eq!(served.len(), 1, "out-of-range idx skipped");
    assert_eq!(
        served[0].as_bytes()[0],
        2,
        "the shard cache serves the requested frame"
    );

    // A budget-filling newcomer evicts the oldest group whole.
    let second = group("00000000-0000-4000-8000-0000000000c2");
    cache.insert(second.clone(), vec![frame(3, SHARD_CACHE_BUDGET_BYTES)]);
    let evicted: Vec<_> = cache.frames(&first, &[0]).collect();
    assert!(evicted.is_empty(), "old group evicted");
    let kept: Vec<_> = cache.frames(&second, &[0]).collect();
    assert_eq!(kept.len(), 1, "the newest group always stays");
}

#[test]
fn author_budget_never_exceeded_under_random_streams() {
    let _guard = ::habilis_network_test_tracing::init();
    // Property-ish sweep: many interleaved groups from two authors, with
    // crafted totals; whatever the interleaving, the store's accounting
    // never exceeds the budgets.
    let now = Instant::now();
    let mut store = ReassemblyStore::default();
    let chunk = "x".repeat(4096);
    for round in 0..2048u32 {
        let author = if round % 3 == 0 { "a" } else { "b" };
        let group = group(&format!(
            "00000000-0000-4000-8000-0000000{:05x}",
            round % 37
        ));
        let _ = ingest(
            &mut store,
            &shard_msg(
                &chunk,
                author,
                Shard {
                    group,
                    index: round % 5,
                    total: u32::MAX,
                },
            ),
            now,
        );
        assert!(
            store.total_bytes <= REASSEMBLY_TOTAL_BUDGET_BYTES,
            "the total budget is never exceeded under random streams"
        );
        assert!(
            store
                .author_bytes
                .values()
                .all(|bytes| *bytes <= REASSEMBLY_AUTHOR_BUDGET_BYTES),
            "the author budget is never exceeded under random streams"
        );
    }
}
