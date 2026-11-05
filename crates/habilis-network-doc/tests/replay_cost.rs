//! The cost of a replay frame, as a measurement and not as a check: wall time and bytes allocated
//! to apply one replay frame of 127 leaves and an object, and to apply 96 of them, in a state
//! document of N live leaves. It is ignored by default. Run it in release mode:
//!
//! `REPLAY_COST_LEAVES=1000,10000 cargo test --release -p habilis-network-doc --test replay_cost -- --ignored --nocapture`.
//!
//! Filling a document through normal writes costs a hydration of the whole document for each
//! frame (the gate check of every ingest), so the fill takes minutes at 100000 leaves.

#![allow(
    unsafe_code,
    clippy::allow_attributes,
    clippy::allow_attributes_without_reason,
    clippy::undocumented_unsafe_blocks,
    missing_docs
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use habilis_network_doc::{MeshDoc, Stamp, wire};
use habilis_network_protocol::messages::{MessageBody, Verified};
use habilis_network_protocol::{AuthorKey, Channel, MeshId, Message, Nickname};
use serde_json::{Map, Value, json};

/// Counts the bytes that the process allocates, so a measurement can say how many a step took.
struct Counting;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call goes to the system allocator unchanged; the counter is the only addition.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller upholds the contract of `alloc` for this layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the caller upholds the contract of `dealloc` for this pointer and layout.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

fn nick(name: &str) -> Nickname {
    Nickname::try_new(name).expect("a nickname")
}

fn pad(name: &str) -> [u8; 32] {
    let mut padded = [0u8; 32];
    padded[..name.len()].copy_from_slice(name.as_bytes());
    padded
}

fn signed(who: &Nickname, body: MessageBody) -> Verified {
    let key = AuthorKey::from(pad(who.as_str()));
    let message = Message::new_channel_event(&MeshId::from("test"), who, body, Channel::State);
    Verified::fixture_unchecked(message.unverified_key(key), key)
}

/// The time and the bytes allocated that `step` took.
fn measured<Out>(step: impl FnOnce() -> Out) -> (Out, Duration, usize) {
    let before = ALLOCATED.load(Ordering::Relaxed);
    let started = Instant::now();
    let out = step();
    (
        out,
        started.elapsed(),
        ALLOCATED.load(Ordering::Relaxed) - before,
    )
}

/// A replay frame of 127 leaves under `rep{index}`, written by a node whose actor is above all
/// the others, so it wins the conflicts, as the worst case.
fn replay_frame(index: usize) -> Verified {
    let who = nick("zzz");
    let replayer = MeshDoc::new_ungated().state_epochs();
    let mut leaves = Map::new();
    let mut stamps: Vec<(Vec<String>, Stamp)> = Vec::new();
    let object = format!("rep{index:03}");
    for leaf in 0..127 {
        leaves.insert(format!("r{leaf:03}"), json!(leaf));
        stamps.push((
            vec![object.clone(), format!("r{leaf:03}")],
            Stamp::new(5, "7a7a7a7a00000000".to_owned()),
        ));
    }
    let merge = json!({ object: Value::Object(leaves) });
    let change = replayer
        .build_change(&merge, &pad(who.as_str()))
        .expect("applies")
        .expect("a change");
    let body = replayer
        .compose_replay_body(&change, &stamps)
        .expect("a replay body");
    signed(&who, body)
}

/// The same change as a plain frame, for a document with no state epochs.
fn plain_frame(index: usize) -> Verified {
    let who = nick("zzz");
    let replayer = MeshDoc::new_ungated();
    let mut leaves = Map::new();
    let object = format!("rep{index:03}");
    for leaf in 0..127 {
        leaves.insert(format!("r{leaf:03}"), json!(leaf));
    }
    let merge = json!({ object: Value::Object(leaves) });
    let change = replayer
        .build_change(&merge, &pad(who.as_str()))
        .expect("applies")
        .expect("a change");
    signed(
        &who,
        wire::change_body_at(&change, None, 0).expect("a plain body"),
    )
}

fn fill(doc: &mut MeshDoc, base: &mut MeshDoc, leaves: usize) {
    let me = nick("me");
    let chunk = 100;
    for round in 0..leaves / chunk {
        let mut part = Map::new();
        for leaf in 0..chunk {
            part.insert(format!("k{round:05}x{leaf:03}"), json!(leaf));
        }
        let merge = json!({ "live": Value::Object(part) });
        let change = doc
            .build_change(&merge, &pad(me.as_str()))
            .expect("applies")
            .expect("a change");
        let (wire_body, _) = doc.compose_wire_body(&change, None).expect("a body");
        let frame = signed(&me, wire_body);
        doc.ingest(&frame);
        // The same history in a document with no state epochs, for the plain baseline.
        let plain = wire::change_body_at(&change, None, 0).expect("a plain body");
        base.ingest(&signed(&me, plain));
    }
}

#[test]
#[ignore = "a measurement: run it in release mode with --ignored"]
fn the_cost_of_a_replay_frame_and_of_a_burst() {
    let sizes: Vec<usize> = env::var("REPLAY_COST_LEAVES")
        .unwrap_or_else(|_| "1000,10000".to_owned())
        .split(',')
        .filter_map(|text| text.trim().parse().ok())
        .collect();
    for leaves in sizes {
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let mut base = MeshDoc::new_ungated();
        let ((), fill_time, fill_bytes) = measured(|| fill(&mut doc, &mut base, leaves));
        let replay = replay_frame(0);
        let plain = plain_frame(0);
        let (_, replay_time, replay_bytes) = measured(|| doc.ingest(&replay));
        let (_, plain_time, plain_bytes) = measured(|| base.ingest(&plain));
        eprintln!(
            "COST leaves={leaves} fill={fill_time:?}/{fill_bytes}B one replay frame: {replay_time:?}/{replay_bytes}B, the same change as a plain frame: {plain_time:?}/{plain_bytes}B"
        );
        // The burst: 96 replay frames of 96 writers, one after the other.
        let replays: Vec<Verified> = (1..=96).map(replay_frame).collect();
        let plains: Vec<Verified> = (1..=96).map(plain_frame).collect();
        let ((), burst_time, burst_bytes) = measured(|| {
            for frame in &replays {
                doc.ingest(frame);
            }
        });
        let ((), plain_burst_time, plain_burst_bytes) = measured(|| {
            for frame in &plains {
                base.ingest(frame);
            }
        });
        eprintln!(
            "COST leaves={leaves} burst of 96 replay frames: {burst_time:?}/{burst_bytes}B, the same as plain frames: {plain_burst_time:?}/{plain_burst_bytes}B"
        );
    }
}
