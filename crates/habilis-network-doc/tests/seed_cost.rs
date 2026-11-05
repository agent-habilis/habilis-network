//! The cost of a seed (the cut of the state document), as a measurement and not as a check: the
//! wall time to build a seed and to adopt it, and the bytes that a seed takes for each path against
//! the bytes of the history that made it. It is ignored by default. Run it in release mode:
//! `SEED_COST_LEAVES=1000,10000 cargo test --release -p habilis-network-doc --test seed_cost -- --ignored --nocapture`.

use std::env;
use std::time::{Duration, Instant};

use habilis_network_doc::{Ingested, MeshDoc, SeedChain, Stamp, wire};
use habilis_network_protocol::messages::{MessageBody, Verified};
use habilis_network_protocol::{AuthorKey, Channel, MeshId, Message, Nickname};
use serde_json::{Map, Value, json};

/// The largest body of a frame: the message size of 3840 bytes less the margin of the envelope.
const BODY_MAX: usize = 3712;
/// The room that the seed mark of the root takes, which the `fits` of a merge leaves free.
const MARK_ROOM: usize = 64;
/// The Lamport clock at the start, so the times have 7 digits, as in a mesh that has run a while.
const CLOCK_START: u64 = 5_000_000;
const TAG: &str = "7a7a7a7a00000000";

#[derive(Clone, Copy)]
enum Shape {
    /// A number of 1 to 3 digits.
    Tiny,
    /// A string of 16 bytes.
    Small,
    /// A string of 100 bytes.
    Large,
}

impl Shape {
    fn name(self) -> &'static str {
        match self {
            Self::Tiny => "tiny number",
            Self::Small => "string of 16 B",
            Self::Large => "string of 100 B",
        }
    }

    fn value(self, index: usize) -> Value {
        match self {
            Self::Tiny => json!(index % 1000),
            Self::Small => json!(format!("{index:016}")),
            Self::Large => json!(format!("{index:0>100}")),
        }
    }
}

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

/// The merge `{ live: { k<index>: value, ... } }` for `count` leaves from `first`.
fn merge_of(shape: Shape, first: usize, count: usize) -> Value {
    let mut leaves = Map::new();
    for index in first..first + count {
        leaves.insert(format!("k{index:06}"), shape.value(index));
    }
    json!({ "live": Value::Object(leaves) })
}

fn leaf_count(value: &Value) -> usize {
    match value {
        Value::Object(fields) if !fields.is_empty() => fields.values().map(leaf_count).sum(),
        Value::Object(_)
        | Value::Null
        | Value::Bool(_)
        | Value::Number(_)
        | Value::String(_)
        | Value::Array(_) => 1,
    }
}

/// Whether the real frame of `merge`, with the stamps of a seed, is inside a frame.
fn frame_fits(merge: &Value) -> bool {
    let timeless = MeshDoc::new_ungated();
    let built = timeless.build_change(merge, &pad("seed"));
    let Ok(Some(change)) = built else {
        return true;
    };
    let mut stamps: Vec<Stamp> = Vec::new();
    for position in 0..leaf_count(merge) {
        let time = CLOCK_START + u64::try_from(position).expect("a small number");
        stamps.push(Stamp::new(time, TAG.to_owned()));
    }
    let body =
        wire::change_body_tombstoned(&change, None, 1, None, Some(CLOCK_START), &stamps, &[]);
    body.is_ok_and(|body| body.as_str().len() + MARK_ROOM <= BODY_MAX)
}

/// Move the clock of `doc` to `CLOCK_START`, with a frame of another node that carries that time.
fn move_clock(doc: &mut MeshDoc) {
    let who = nick("clock");
    let timeless = MeshDoc::new_ungated();
    let change = change_of(&timeless, &json!({ "clock": 1 }), who.as_str());
    let body = wire::change_body_timed(&change, None, 0, None, Some(CLOCK_START)).expect("a body");
    let outcome = doc.ingest(&signed(&who, body));
    assert!(
        matches!(outcome, Ingested::Applied { .. }),
        "the clock frame applies: {outcome:?}"
    );
}

/// Fill `doc` with `leaves` leaves of `shape`, in plain frames that hold as many leaves as fit.
/// Returns the number of frames.
fn fill(doc: &mut MeshDoc, shape: Shape, leaves: usize) -> usize {
    let me = nick("me");
    let mut chunk: usize = 400;
    let mut index: usize = 0;
    let mut frames: usize = 0;
    while index < leaves {
        let take = chunk.min(leaves - index);
        let merge = merge_of(shape, index, take);
        let change = change_of(doc, &merge, me.as_str());
        let composed = doc.compose_wire_body(&change, None);
        let fitting: bool = composed
            .as_ref()
            .is_ok_and(|(body, _)| body.as_str().len() <= BODY_MAX);
        if !fitting {
            assert!(chunk > 1, "one leaf does not fit a frame");
            chunk = (chunk * 3 / 4).max(1);
            continue;
        }
        let (body, _) = composed.expect("a body");
        let outcome = doc.ingest(&signed(&me, body));
        assert!(
            matches!(outcome, Ingested::Applied { .. }),
            "the frame applies: {outcome:?}"
        );
        index += take;
        frames += 1;
    }
    frames
}

/// The real frames of a seed chain, and the bytes of their bodies.
fn seed_frames(chain: &SeedChain, epoch: u64, who: &Nickname) -> (Vec<Verified>, usize, usize) {
    let mut frames: Vec<Verified> = Vec::new();
    let mut total: usize = 0;
    let mut longest: usize = 0;
    let numbered = chain.changes.iter().enumerate();
    for (position, bytes) in numbered {
        let mark = (position == 0).then_some(&chain.mark);
        let body = wire::change_body_tombstoned(
            bytes,
            None,
            epoch,
            mark,
            Some(chain.time),
            &chain.origins[position],
            &chain.tombstones[position],
        )
        .expect("a body");
        total += body.as_str().len();
        longest = longest.max(body.as_str().len());
        frames.push(signed(who, body));
    }
    (frames, total, longest)
}

/// The time that the adopter takes to adopt the seed in `frames`, at the tick that adopts it.
fn adoption_time(frames: &[Verified], epoch: u64) -> Duration {
    let me = nick("adopter");
    let mut adopter = MeshDoc::new_ungated().state_epochs();
    for frame in frames {
        adopter.ingest(frame);
    }
    let mut took = Duration::ZERO;
    for _ in 0..6 {
        let started = Instant::now();
        let switch = adopter.tick_epoch(&me);
        if switch.is_some() {
            took = started.elapsed();
        }
    }
    assert_eq!(
        adopter.epoch(),
        epoch,
        "the adopter is in the epoch of the seed"
    );
    took
}

#[test]
#[ignore = "a measurement: run it in release mode with --ignored"]
fn the_cost_of_a_seed_by_shape_and_size() {
    let spec: String = env::var("SEED_COST_LEAVES").unwrap_or_else(|_| "1000,10000".to_owned());
    let big: usize = env::var("SEED_COST_BIG").map_or(0, |text| text.parse().unwrap_or(0));
    let mut sizes: Vec<usize> = spec.split(',').filter_map(parse_size).collect();
    if big > 0 {
        sizes.push(big);
    }
    for shape in [Shape::Tiny, Shape::Small, Shape::Large] {
        for leaves in &sizes {
            let leaves = *leaves;
            if leaves > 20_000 && !matches!(shape, Shape::Tiny) {
                continue;
            }
            measure(shape, leaves);
        }
    }
}

/// The leaf count that `text` names, if it names one.
fn parse_size(text: &str) -> Option<usize> {
    text.trim().parse().ok()
}

/// `part` over `whole`, with 2 decimals, as text.
fn ratio(part: usize, whole: usize) -> String {
    let hundredths = part * 100 / whole;
    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

fn measure(shape: Shape, leaves: usize) {
    let me = nick("me");
    let mut doc = MeshDoc::new_ungated().state_epochs();
    move_clock(&mut doc);
    let started = Instant::now();
    let history_frames = fill(&mut doc, shape, leaves);
    let fill_time = started.elapsed();
    let history_bytes = doc.census(false).frame_bytes;
    let paths = leaves + 1;
    let cut_started = Instant::now();
    let built = doc.build_seed(1, &pad(me.as_str()), frame_fits);
    let build_time = cut_started.elapsed();
    let chain = built.expect("the live values split");
    let (frames, seed_bytes, longest) = seed_frames(&chain, 1, &me);
    let adopt_time = adoption_time(&frames, 1);
    eprintln!(
        "SEED shape={} leaves={leaves} history: {history_frames} frames {history_bytes} B ({} B/path) seed: {} frames {seed_bytes} B ({} B/path, longest body {longest}) seed/history={} fill={fill_time:?} build={build_time:?} adopt={adopt_time:?}",
        shape.name(),
        ratio(history_bytes, paths),
        frames.len(),
        ratio(seed_bytes, paths),
        ratio(seed_bytes, history_bytes),
    );
}
