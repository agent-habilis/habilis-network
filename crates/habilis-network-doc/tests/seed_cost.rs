//! The cost of a seed (the cut of the state document), as a measurement and not as a check: the
//! wall time to build a seed and to adopt it, and the bytes that a seed takes for each path against
//! the bytes of the history that made it. It is ignored by default. Run it in release mode:
//! `SEED_COST_LEAVES=1000,10000 cargo test --release -p habilis-network-doc --test seed_cost -- --ignored --nocapture`.

use std::env;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use habilis_network_doc::{Ingested, MeshDoc, SeedChain, Stamp, wire};
use habilis_network_protocol::messages::{MessageBody, Verified};
use habilis_network_protocol::{AuthorKey, Channel, Identity, MeshId, Message, Nickname};
use habilis_network_util::consts::{DOC_EPOCH_FRAME_MARGIN, MAX_MESSAGE_SIZE};
use serde_json::{Map, Value, json};

/// The room that the seed mark of the root takes, which the `fits` of a merge leaves free.
const MARK_ROOM: usize = 64;
/// The Lamport clock at the start, so the times have 7 digits, as in a mesh that has run a while.
const CLOCK_START: u64 = 5_000_000;
/// The writers that take turns to write the plain frames, so a seed frame carries many tags.
const WRITERS: usize = 128;
/// How many times the seed is built for one document, for the spread of the time.
const BUILDS: usize = 5;

#[derive(Clone, Copy)]
enum Shape {
    /// A number of 1 to 3 digits.
    Tiny,
    /// A string of 16 bytes.
    Small,
    /// A string of 100 bytes.
    Large,
    /// A number at the end of a path of 8 keys.
    Nested,
}

impl Shape {
    fn name(self) -> &'static str {
        match self {
            Self::Tiny => "tiny number",
            Self::Small => "string of 16 B",
            Self::Large => "string of 100 B",
            Self::Nested => "number at depth 8",
        }
    }

    /// The paths above the leaves: the keys of the levels that all the leaves share.
    fn prefix_paths(self) -> usize {
        match self {
            Self::Nested => 7,
            Self::Tiny | Self::Small | Self::Large => 1,
        }
    }

    fn value(self, index: usize) -> Value {
        match self {
            Self::Tiny | Self::Nested => json!(index % 1000),
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
    let mut level = Value::Object(leaves);
    if matches!(shape, Shape::Nested) {
        for depth in (1..=7).rev() {
            level = json!({ format!("n{depth}"): level });
        }
        return level;
    }
    json!({ "live": level })
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

/// The key that signs the frames of this measurement.
fn identity() -> &'static Identity {
    static IDENTITY: OnceLock<Identity> = OnceLock::new();
    IDENTITY.get_or_init(Identity::generate)
}

/// Whether the frame of `body`, signed and serialized as a node sends it, is inside a message
/// with the margin of the envelope that the daemon keeps.
fn wire_fits(body: MessageBody) -> bool {
    let message =
        Message::new_channel_event(&MeshId::from("test"), &nick("me"), body, Channel::State);
    let frame = message.sign(identity());
    frame
        .serialize()
        .is_ok_and(|wire| wire.as_bytes().len() + DOC_EPOCH_FRAME_MARGIN <= MAX_MESSAGE_SIZE)
}

/// The tag of the writer number `position`, 16 hexadecimal digits.
fn tag_of(position: usize) -> String {
    let number = u64::try_from(position).expect("a number");
    format!("{:016x}", 0x7a7a_0000_0000_0000_u64 + number)
}

/// Whether the real frame of `merge`, with the stamps of a seed, is inside a frame. The stamps
/// are those of a mesh that has run a while: a time of 7 digits, and a tag of any of the writers.
fn frame_fits(merge: &Value) -> bool {
    let call_started = Instant::now();
    let answer = frame_fits_inner(merge);
    FITS_CALLS.fetch_add(1, Ordering::Relaxed);
    let nanos = u64::try_from(call_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    FITS_NANOS.fetch_add(nanos, Ordering::Relaxed);
    answer
}

/// How many times `frame_fits` was asked, and the nanoseconds that it took, since the last reset.
static FITS_CALLS: AtomicUsize = AtomicUsize::new(0);
static FITS_NANOS: AtomicU64 = AtomicU64::new(0);

fn frame_fits_inner(merge: &Value) -> bool {
    let timeless = MeshDoc::new_ungated();
    let built = timeless.build_change(merge, &pad("seed"));
    let Ok(Some(change)) = built else {
        return true;
    };
    let mut stamps: Vec<Stamp> = Vec::new();
    for position in 0..leaf_count(merge) {
        let time = CLOCK_START + u64::try_from(position).expect("a small number");
        stamps.push(Stamp::new(time, tag_of(position % WRITERS)));
    }
    let root = Some(CLOCK_START);
    let body = wire::change_body_tombstoned(&change, None, 1, None, root, &stamps, &[]);
    let Ok(body) = body else {
        return false;
    };
    body.as_str().len() + MARK_ROOM + DOC_EPOCH_FRAME_MARGIN <= MAX_MESSAGE_SIZE && wire_fits(body)
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
    let mut chunk: usize = 400;
    let mut index: usize = 0;
    let mut frames: usize = 0;
    while index < leaves {
        let take = chunk.min(leaves - index);
        let merge = merge_of(shape, index, take);
        let me = nick(&format!("w{:03}", frames % WRITERS));
        let change = change_of(doc, &merge, me.as_str());
        let composed = doc.compose_wire_body(&change, None);
        let fitting: bool = composed
            .as_ref()
            .is_ok_and(|(body, _)| wire_fits(body.clone()));
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

/// The real frames of a seed chain and what they weigh.
struct SeedFrames {
    frames: Vec<Verified>,
    /// The bytes of all the bodies.
    total: usize,
    /// The bytes of the same bodies with no stamp and no tombstone: the content of the seed.
    plain: usize,
    /// The longest body.
    longest: usize,
    /// The most bytes of stamps for one path in one frame.
    worst_stamp: usize,
}

fn seed_frames(chain: &SeedChain, epoch: u64, who: &Nickname) -> SeedFrames {
    let mut weighed = SeedFrames {
        frames: Vec::new(),
        total: 0,
        plain: 0,
        longest: 0,
        worst_stamp: 0,
    };
    let numbered = chain.changes.iter().enumerate();
    for (position, bytes) in numbered {
        let mark = (position == 0).then_some(&chain.mark);
        let origins = &chain.origins[position];
        let body = wire::change_body_tombstoned(
            bytes,
            None,
            epoch,
            mark,
            Some(chain.time),
            origins,
            &chain.tombstones[position],
        )
        .expect("a body");
        let bare =
            wire::change_body_tombstoned(bytes, None, epoch, mark, Some(chain.time), &[], &[])
                .expect("a body");
        let with_stamps = body.as_str().len();
        let without = bare.as_str().len();
        weighed.total += with_stamps;
        weighed.plain += without;
        weighed.longest = weighed.longest.max(with_stamps);
        let stamp_bytes = with_stamps.saturating_sub(without);
        let per_path: usize = stamp_bytes / origins.len().max(1);
        weighed.worst_stamp = weighed.worst_stamp.max(per_path);
        weighed.frames.push(signed(who, body));
    }
    weighed
}

/// The time to sign and serialize the frames of the chain as a node does to send them: the root
/// alone, and all of them. The network time is not in it.
fn send_cpu(chain: &SeedChain, epoch: u64) -> (Duration, Duration) {
    let identity = Identity::generate();
    let who = nick("me");
    let mut root_time = Duration::ZERO;
    let started = Instant::now();
    let numbered = chain.changes.iter().enumerate();
    for (position, bytes) in numbered {
        let frame_started = Instant::now();
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
        let message = Message::new_channel_event(&MeshId::from("test"), &who, body, Channel::State);
        let signed_frame = message.sign(&identity);
        signed_frame.serialize().expect("a wire frame");
        if position == 0 {
            root_time = frame_started.elapsed();
        }
    }
    (root_time, started.elapsed())
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
    for shape in [Shape::Tiny, Shape::Small, Shape::Large, Shape::Nested] {
        for leaves in &sizes {
            let leaves = *leaves;
            if leaves > 4_000 && matches!(shape, Shape::Large) {
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
    let paths = leaves + shape.prefix_paths();
    let mut builds: Vec<Duration> = Vec::new();
    let mut last: Option<SeedChain> = None;
    for _ in 0..BUILDS {
        FITS_CALLS.store(0, Ordering::Relaxed);
        FITS_NANOS.store(0, Ordering::Relaxed);
        let cut_started = Instant::now();
        let built = doc.build_seed(1, &pad(me.as_str()), frame_fits);
        builds.push(cut_started.elapsed());
        last = Some(built.expect("the live values split"));
    }
    let fits_calls = FITS_CALLS.load(Ordering::Relaxed);
    let fits_time = Duration::from_nanos(FITS_NANOS.load(Ordering::Relaxed));
    builds.sort();
    let chain = last.expect("a chain");
    let weighed = seed_frames(&chain, 1, &me);
    let (root_send, chain_send) = send_cpu(&chain, 1);
    let adopt_time = adoption_time(&weighed.frames, 1);
    eprintln!(
        "SEED shape={} paths={paths} history: {history_frames} frames {history_bytes} B ({} B/path) seed: {} frames {} B ({} B/path, content {} B/path, longest body {}) S_avg={} B/path S_worst={} B/path a={} seed/history={} fill={fill_time:?} build min={:?} median={:?} max={:?} sign+serialize root={root_send:?} chain={chain_send:?} adopt={adopt_time:?} fits calls={fits_calls} in {fits_time:?}",
        shape.name(),
        ratio(history_bytes, paths),
        weighed.frames.len(),
        weighed.total,
        ratio(weighed.total, paths),
        ratio(weighed.plain, paths),
        weighed.longest,
        ratio(weighed.total - weighed.plain, paths),
        weighed.worst_stamp,
        ratio(weighed.plain, history_bytes),
        ratio(weighed.total, history_bytes),
        builds[0],
        builds[builds.len() / 2],
        builds[builds.len() - 1],
    );
}
