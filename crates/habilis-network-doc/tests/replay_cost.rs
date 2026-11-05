//! The cost of a replay frame, as a measurement and not as a check: wall time and bytes allocated
//! to apply one replay frame of 127 leaves and an object, and to apply 96 of them, in a state
//! document of N live leaves. It is ignored by default. Run it in release mode:
//!
//! `REPLAY_COST_LEAVES=1000,10000 cargo test --release -p habilis-network-doc --test replay_cost -- --ignored --nocapture`.
//!
//! Filling a document through normal writes costs a hydration of the whole document for each
//! frame (the gate check of every ingest), so the fill takes minutes at 100000 leaves.

#![expect(
    unsafe_code,
    reason = "a counting allocator needs an unsafe GlobalAlloc impl that only forwards to the system allocator"
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

/// The change that `doc` builds for `merge`, written by the node `who`.
fn change_of(doc: &MeshDoc, merge: &Value, who: &str) -> Vec<u8> {
    let built = doc.build_change(merge, &pad(who)).expect("applies");
    built.expect("a change")
}

/// The leaf count that `text` names, if it names one.
fn parse_size(text: &str) -> Option<usize> {
    text.trim().parse().ok()
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
    frame_of("zzz", &format!("rep{index:03}"), 5, true)
}

/// The same change as a plain frame, for a document with no state epochs.
fn plain_frame(index: usize) -> Verified {
    frame_of("zzz", &format!("rep{index:03}"), 5, false)
}

/// The frame of one writer for the object `object` with 127 leaves: a replay frame with the stamp
/// time `time`, or the same change as a plain frame.
fn frame_of(writer: &str, object: &str, time: u64, replay: bool) -> Verified {
    let who = nick(writer);
    let author = MeshDoc::new_ungated();
    let mut leaves = Map::new();
    let mut stamps: Vec<(Vec<String>, Stamp)> = Vec::new();
    for leaf in 0..127 {
        leaves.insert(format!("r{leaf:03}"), json!(leaf));
        stamps.push((
            vec![object.to_owned(), format!("r{leaf:03}")],
            Stamp::new(time, "7a7a7a7a00000000".to_owned()),
        ));
    }
    let merge = json!({ object: Value::Object(leaves) });
    let change = change_of(&author, &merge, who.as_str());
    let body: MessageBody = if replay {
        MeshDoc::new_ungated()
            .state_epochs()
            .compose_replay_body(&change, &stamps)
            .expect("a replay body")
    } else {
        wire::change_body_at(&change, None, 0).expect("a plain body")
    };
    signed(&who, body)
}

/// The frames of the same-leaf burst: 96 writers, and every frame names the same object and the
/// same 127 leaves, with a stamp time that rises with the writer.
fn same_leaf_burst(replay: bool) -> Vec<Verified> {
    (1..=96u64)
        .map(|writer| frame_of(&format!("w{writer:03}"), "shared", 5 + writer, replay))
        .collect()
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
        let change = change_of(doc, &merge, me.as_str());
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
    let spec: String = env::var("REPLAY_COST_LEAVES").unwrap_or_else(|_| "1000,10000".to_owned());
    let sizes: Vec<usize> = spec.split(',').filter_map(parse_size).collect();
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
        // The same-leaf burst: the real switch with 96 writers, where every frame names the same
        // object, so every frame hides the leaves of the frames before it.
        let same = same_leaf_burst(true);
        let same_plain = same_leaf_burst(false);
        let ((), same_time, same_bytes) = measured(|| {
            for frame in &same {
                doc.ingest(frame);
            }
        });
        let ((), same_plain_time, same_plain_bytes) = measured(|| {
            for frame in &same_plain {
                base.ingest(frame);
            }
        });
        eprintln!(
            "COST leaves={leaves} same-leaf burst of 96 replay frames: {same_time:?}/{same_bytes}B, the same as plain frames: {same_plain_time:?}/{same_plain_bytes}B"
        );
    }
}

/// `part` as a share of `whole`, in tenths of a percent, as text.
fn percent(part: usize, whole: usize) -> String {
    let tenths = part * 1000 / whole;
    format!("{}.{} percent", tenths / 10, tenths % 10)
}

/// The bytes that the time and the stamps add to the frame bodies on the wire.
#[test]
#[ignore = "a measurement: run it with --ignored --nocapture"]
fn the_bytes_that_the_stamps_add_to_a_frame() {
    let me = nick("me");
    let doc = MeshDoc::new_ungated().state_epochs();
    for (label, merge) in [
        ("smallest write {a:1}", json!({ "a": 1 })),
        (
            "one nested leaf",
            json!({ "board": { "title": "a title of 20 chars" } }),
        ),
        ("a text of 200 chars", json!({ "note": "x".repeat(200) })),
    ] {
        let change = change_of(&doc, &merge, me.as_str());
        let plain = wire::change_body_at(&change, None, 0).expect("a plain body");
        let (timed, _) = doc.compose_wire_body(&change, None).expect("a timed body");
        let (plain_len, timed_len) = (plain.as_str().len(), timed.as_str().len());
        let added = timed_len - plain_len;
        eprintln!(
            "BYTES {label}: plain {plain_len} B, with the time {timed_len} B, +{added} B = {}",
            percent(added, plain_len)
        );
    }
    let plain = plain_frame(0);
    let replay = replay_frame(0);
    let (plain_len, replay_len) = (plain.body.as_str().len(), replay.body.as_str().len());
    let added = replay_len - plain_len;
    eprintln!(
        "BYTES replay frame of 127 leaves: plain {plain_len} B, with the stamps {replay_len} B, +{added} B = {} B per leaf, {}",
        added / 127,
        percent(added, plain_len)
    );
}
