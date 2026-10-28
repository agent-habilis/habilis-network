//! Tests of the multipart reassembly.

use habilis_network_test_tracing::{expect_warn, test};
use habilis_network_util::clock::Instant;
use std::time::Duration;

use super::{ReassemblyStore, ShardIngest};
use crate::message::Verified;
use crate::{AppFrameParams, AuthorKey, MeshId, Message, MessageBody, Nickname, Shard, ShardGroup};
use habilis_network_util::consts::{
    REASSEMBLY_AUTHOR_BUDGET_BYTES, REASSEMBLY_GROUP_MAX_BYTES, REASSEMBLY_STALE,
    REASSEMBLY_TOTAL_BUDGET_BYTES,
};

fn group(uuid: &str) -> ShardGroup {
    ShardGroup::from_uuid_str(uuid).expect("valid group")
}

fn group_a() -> ShardGroup {
    group("550e8400-e29b-41d4-a716-446655440000")
}

/// The key of the test author `name`: its bytes, zero-padded.
fn author_of(name: &str) -> AuthorKey {
    let mut bytes = [0u8; 32];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    AuthorKey::from_bytes(bytes)
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
    // Two authors reuse the SAME group id. Each forms its own set; one
    // author's shard never fills another's slot, so a crafted cross-author
    // shard can't inject a slice into the victim's reassembled body.
    let now = Instant::now();
    let mut store = ReassemblyStore::default();
    assert!(matches!(
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
    ));
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
    assert_eq!(logical.body.as_str(), "alice-0alice-1");
}

#[test]
fn slots_by_idx_not_arrival() {
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
    assert!(matches!(
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
    ));
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
    assert!(matches!(
        ingest(&mut store, &wrong_kind, now),
        ShardIngest::Dropped
    ));
}

#[test]
fn duplicate_idx_is_dropped_first_seen_wins() {
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
    assert!(matches!(
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
    ));
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
    expect_warn(
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
    assert!(matches!(
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
    ));
    assert_eq!(store.total_bytes, 0, "dropped group released its budget");
    assert!(store.groups.is_empty());
}

#[test]
fn author_budget_evicts_the_stalest_group() {
    expect_warn(
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
    assert!(matches!(
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
    ));
    assert!(
        !store.groups.contains_key(&(author_of("a"), stale)),
        "stalest group evicted"
    );
    assert!(store.groups.contains_key(&(author_of("a"), fresh)));
    assert!(store.groups.contains_key(&(author_of("a"), newcomer)));
}

#[test]
fn global_budget_refuses_the_newcomer() {
    expect_warn(
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
    assert!(store.total_bytes <= REASSEMBLY_TOTAL_BUDGET_BYTES);
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
    expect_warn(
        "habilis_network::gossip",
        "author reassembly budget breached; stalest partial group evicted",
    );
    let now = Instant::now();
    let mut store = ReassemblyStore::default();
    let chunk = "x".repeat(REASSEMBLY_GROUP_MAX_BYTES / 2 + 64);

    // One honest partial transfer, parked.
    let honest = group("00000000-0000-4000-8000-0000000000aa");
    assert!(matches!(
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
    ));

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
    assert!(matches!(
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
    ));
    // ...but a duplicate slot does NOT — no attacker keepalive via resends.
    let dup_at = touched + REASSEMBLY_STALE.saturating_sub(Duration::from_secs(1));
    assert!(matches!(
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
    ));
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
    assert_eq!(store.total_bytes, 0);
    assert!(store.author_bytes.is_empty());
}

#[test]
fn a_trickling_group_is_reaped_at_the_lifetime_ceiling() {
    use habilis_network_util::consts::REASSEMBLY_MAX_GROUP_LIFETIME;
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
    assert_eq!(store.total_bytes, 0);
}

#[test]
fn completion_releases_the_budget() {
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
    assert!(store.total_bytes > 0);
    assert!(matches!(
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
    ));
    assert_eq!(store.total_bytes, 0);
    assert!(store.author_bytes.is_empty());
    assert!(store.groups.is_empty());
}

#[test]
fn repair_tickets_target_stalled_big_groups_once_per_window() {
    use habilis_network_util::consts::{LOGGED_SHARD_GROUP_MAX_TOTAL, REASSEMBLY_REPAIR_IDLE};
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
    assert!(store.repair_tickets(start).collect::<Vec<_>>().is_empty());

    // Stalled: only the big group is ticketed, with exactly its gaps.
    let stalled = start + REASSEMBLY_REPAIR_IDLE;
    let tickets = store.repair_tickets(stalled).collect::<Vec<_>>();
    assert_eq!(tickets.len(), 1, "small groups heal via anti-entropy");
    assert_eq!(tickets[0].group, big);
    assert_eq!(tickets[0].author.as_str(), "author");
    assert!(!tickets[0].missing.contains(&0));
    assert!(!tickets[0].missing.contains(&2));
    assert!(tickets[0].missing.contains(&1));

    // Asked once per window — the immediate re-check yields nothing.
    assert!(store.repair_tickets(stalled).collect::<Vec<_>>().is_empty());
    // The next window asks again.
    let next = stalled + REASSEMBLY_REPAIR_IDLE;
    assert_eq!(store.repair_tickets(next).collect::<Vec<_>>().len(), 1);
}

#[test]
fn shard_cache_serves_requested_frames_and_evicts_whole_groups() {
    use habilis_network_util::consts::SHARD_CACHE_BUDGET_BYTES;
    let mut cache = super::ShardCache::default();
    let first = group("00000000-0000-4000-8000-0000000000c1");
    let frame =
        |tag: u8, len: usize| crate::message::WireFrame::new(bytes::Bytes::from(vec![tag; len]));
    cache.insert(first.clone(), vec![frame(1, 10), frame(2, 10)]);
    let served = cache.frames(&first, &[1, 7]).collect::<Vec<_>>();
    assert_eq!(served.len(), 1, "out-of-range idx skipped");
    assert_eq!(served[0].as_bytes()[0], 2);

    // A budget-filling newcomer evicts the oldest group whole.
    let second = group("00000000-0000-4000-8000-0000000000c2");
    cache.insert(second.clone(), vec![frame(3, SHARD_CACHE_BUDGET_BYTES)]);
    assert!(
        cache.frames(&first, &[0]).collect::<Vec<_>>().is_empty(),
        "old group evicted"
    );
    assert_eq!(
        cache.frames(&second, &[0]).collect::<Vec<_>>().len(),
        1,
        "the newest group always stays"
    );
}

#[test]
fn author_budget_never_exceeded_under_random_streams() {
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
        assert!(store.total_bytes <= REASSEMBLY_TOTAL_BUDGET_BYTES);
        assert!(
            store
                .author_bytes
                .values()
                .all(|bytes| *bytes <= REASSEMBLY_AUTHOR_BUDGET_BYTES)
        );
    }
}
