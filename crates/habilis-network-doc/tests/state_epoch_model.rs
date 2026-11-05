//! A model of the state channel across epoch resets.
//!
//! Three nodes hold an ungated document each. Each node writes only inside its own key (`n0`, `n1`,
//! `n2`), so the value of every key has one writer, and the model is the plain sum of the writes of
//! each node in order. A node cuts a seed, and every node, the cutter too, adopts it after the
//! wait. Frames travel with random delay, and a sync round (the answer to a digest) gives every
//! node the frames of the others that it lacks. When all is quiet, every node must hold the model.
//!
//! The quiet scenario cuts only when no write is in flight. The free scenario writes while a cut
//! is in the wait: a write of the old epoch that the seed lacks is written again by its author
//! after the switch, from the cut vector of the seed. The cut gate is free: a node cuts at random,
//! so a wait can hold several epochs and two cutters of one epoch.

use std::{env, mem};

use habilis_network_doc::{DocError, MeshDoc, wire};
use habilis_network_protocol::messages::{MessageBody, Verified};
use habilis_network_protocol::{AuthorKey, Channel, MeshId, Message, Nickname};
use serde_json::{Map, Value, json};

const NODES: usize = 3;
/// How many ticks a node waits before it adopts a seed. The same as `DOC_EPOCH_ADOPT_WAIT_TICKS`.
const WAIT: u32 = 5;
/// The largest merge of one seed frame, in bytes of JSON text. The live values of the model are a
/// few hundred bytes, so this small bound gives a seed of several frames, and the chain is tested.
const FRAME_FITS: usize = 60;
const KEYS: [&str; 3] = ["a", "b", "c"];

fn nick(name: &str) -> Nickname {
    Nickname::try_new(name).expect("a nickname")
}

fn pad(name: &str) -> [u8; 32] {
    let mut padded = [0u8; 32];
    padded[..name.len()].copy_from_slice(name.as_bytes());
    padded
}

/// A small deterministic generator, so a failing seed can be run again.
struct Dice(u64);

impl Dice {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, bound: usize) -> usize {
        let wide = u64::try_from(bound).expect("a bound");
        usize::try_from(self.next() % wide).expect("a small number")
    }
}

struct Node {
    name: Nickname,
    doc: MeshDoc,
}

struct Sim {
    nodes: Vec<Node>,
    dice: Dice,
    /// Frames on the way: the target node, the step at which it arrives, the frame.
    wire: Vec<(usize, u64, Verified)>,
    step: u64,
    /// The values of every node, written in order.
    model: Map<String, Value>,
}

fn signed(who: &Nickname, body: MessageBody) -> Verified {
    let key = AuthorKey::from(pad(who.as_str()));
    let message = Message::new_channel_event(&MeshId::from("test"), who, body, Channel::State);
    Verified::fixture_unchecked(message.unverified_key(key), key)
}

impl Sim {
    fn new(seed: u64) -> Self {
        let mut nodes: Vec<Node> = Vec::new();
        for index in 0..NODES {
            nodes.push(Node {
                name: nick(&format!("n{index}")),
                doc: MeshDoc::new_ungated()
                    .state_epochs()
                    .owner(AuthorKey::from(pad(&format!("n{index}")))),
            });
        }
        Self {
            nodes,
            dice: Dice(seed),
            wire: Vec::new(),
            step: 0,
            model: Map::new(),
        }
    }

    fn send_to_others(&mut self, from: usize, frame: &Verified) {
        for target in 0..NODES {
            if target != from {
                let delay = u64::try_from(self.dice.below(4)).expect("a delay");
                self.wire.push((target, self.step + delay, frame.clone()));
            }
        }
    }

    /// Node `index` writes `merge`, and sends the frame. `false` when the merge changes nothing.
    fn commit(&mut self, index: usize, merge: &Value) -> bool {
        let node = &mut self.nodes[index];
        let actor = pad(node.name.as_str());
        let built = node
            .doc
            .build_change(merge, &actor)
            .expect("the merge applies");
        let Some(change) = built else {
            return false;
        };
        let (wire, _plain) = node.doc.compose_wire_body(&change, None).expect("compose");
        let frame = signed(&node.name, wire);
        node.doc.ingest(&frame);
        self.send_to_others(index, &frame);
        true
    }

    /// Node `index` sets (`Some`) or deletes (`None`) `key` inside its own key, and the model
    /// follows.
    fn write_exact(&mut self, index: usize, key: &str, value: Option<Value>) {
        let own = format!("n{index}");
        let leaf: Value = value.clone().unwrap_or(Value::Null);
        let merge: Value = json!({ own.clone(): { key: leaf } });
        if !self.commit(index, &merge) {
            // A delete of a key that is not there changes nothing, and neither does the model.
            return;
        }
        let namespace = self.model.entry(own).or_insert_with(|| json!({}));
        if let Value::Object(fields) = namespace {
            match value {
                Some(present) => {
                    fields.insert(key.to_owned(), present);
                }
                None => {
                    fields.remove(key);
                }
            }
        }
    }

    /// Node `index` sets or deletes one random key inside its own key.
    fn write(&mut self, index: usize) {
        let key: &str = KEYS[self.dice.below(KEYS.len())];
        let kind = self.dice.below(4);
        let value: Option<Value> = match kind {
            0 => None,
            1 => Some(json!(self.dice.below(1000))),
            2 => Some(json!(vec![self.dice.below(10), self.dice.below(10)])),
            _ => Some(json!(format!("v{}", self.dice.below(1000)))),
        };
        self.write_exact(index, key, value);
    }

    /// Node `index` cuts the next epoch: it builds the seed of its live values and sends it to
    /// every node, itself included.
    fn cut(&mut self, index: usize) -> usize {
        let epoch = self.nodes[index].doc.epoch() + 1;
        let name = self.nodes[index].name.clone();
        let actor = pad(name.as_str());
        let fits = |merge: &Value| merge.to_string().len() <= FRAME_FITS;
        // A node that holds a candidate adopts it and cuts no epoch: the document says so.
        let built = self.nodes[index].doc.build_seed(epoch, &actor, fits);
        if matches!(built, Err(DocError::CandidateHeld)) {
            return 0;
        }
        let chain = built.expect("the live values split");
        let mut frames: Vec<Verified> = Vec::new();
        let numbered: Vec<(usize, &Vec<u8>)> = chain.changes.iter().enumerate().collect();
        for (position, bytes) in numbered {
            let mark = (position == 0).then_some(&chain.mark);
            let body = wire::change_body_seed(bytes, None, epoch, mark).expect("a body");
            frames.push(signed(&name, body));
        }
        for frame in &frames {
            self.nodes[index].doc.ingest(frame);
            self.send_to_others(index, frame);
        }
        frames.len()
    }

    fn deliver_due(&mut self) {
        let due_at = self.step;
        let mut waiting: Vec<(usize, u64, Verified)> = Vec::new();
        for (target, at, frame) in mem::take(&mut self.wire) {
            if at <= due_at {
                self.nodes[target].doc.ingest(&frame);
            } else {
                waiting.push((target, at, frame));
            }
        }
        self.wire = waiting;
    }

    /// Deliver every frame that waits for `target`, so that the third node stays behind.
    fn deliver_to(&mut self, from: usize, target: usize) {
        let _ = from;
        let mut waiting: Vec<(usize, u64, Verified)> = Vec::new();
        for (to, at, frame) in mem::take(&mut self.wire) {
            if to == target {
                self.nodes[to].doc.ingest(&frame);
            } else {
                waiting.push((to, at, frame));
            }
        }
        self.wire = waiting;
    }

    fn tick_all(&mut self) {
        let mut replays: Vec<(usize, Value)> = Vec::new();
        for (index, node) in self.nodes.iter_mut().enumerate() {
            let me = node.name.clone();
            let switched = node.doc.tick_epoch(&me);
            if let Some(patch) = switched.and_then(|switch| switch.replay) {
                replays.push((index, patch));
            }
        }
        for (index, patch) in replays {
            self.commit(index, &patch);
        }
    }

    /// The answer to a digest: every node gives every other node the frames that it lacks.
    fn sync_all(&mut self) {
        for from in 0..NODES {
            for to in 0..NODES {
                if from == to {
                    continue;
                }
                let have: Vec<String> = self.nodes[to].doc.heads().collect();
                let missing: Vec<Verified> =
                    self.nodes[from].doc.changes_since(&have, 100_000).collect();
                for frame in &missing {
                    self.nodes[to].doc.ingest(frame);
                }
            }
        }
    }

    fn deliver_everything(&mut self) {
        self.step += 100;
        self.deliver_due();
    }

    /// Run until every node holds the same epoch and values, or give up.
    fn settle(&mut self) {
        for _ in 0..30 {
            self.deliver_everything();
            for _ in 0..=WAIT {
                self.tick_all();
            }
            self.sync_all();
            let first: Value = self.nodes[0].doc.to_json();
            let epoch = self.nodes[0].doc.epoch();
            let mut same = true;
            for node in &self.nodes {
                if node.doc.to_json() != first || node.doc.epoch() != epoch {
                    same = false;
                }
            }
            if same {
                return;
            }
        }
    }

    fn assert_model(&self, label: &str) {
        let expected = Value::Object(self.model.clone());
        for node in &self.nodes {
            assert_eq!(
                node.doc.to_json(),
                expected,
                "{label}: node {} does not hold the model (epoch {})",
                node.name.as_str(),
                node.doc.epoch()
            );
        }
    }
}

/// A write that a node makes after the cut and before it adopts the seed must survive the switch.
#[test]
fn model_writes_during_the_wait_are_replayed() {
    let _guard = habilis_network_test_tracing::init();
    let mut sim = Sim::new(7);
    sim.write_exact(0, "a", Some(json!(1)));
    sim.settle();
    sim.cut(0);
    sim.write_exact(1, "b", Some(json!(2)));
    sim.write_exact(2, "c", Some(json!([3, 4])));
    sim.settle();
    sim.assert_model("writes during the wait");
}

/// A delete that a node makes while the cut waits must not come back with the seed.
#[test]
fn model_a_delete_in_flight_stays_deleted() {
    let _guard = habilis_network_test_tracing::init();
    let mut sim = Sim::new(8);
    sim.write_exact(1, "x", Some(json!("keep me not")));
    sim.write_exact(1, "y", Some(json!("keep me")));
    sim.settle();
    sim.cut(0);
    sim.write_exact(1, "x", None);
    sim.settle();
    sim.assert_model("a delete in the wait");
}

/// A node that lacks the newer value of a key at the cut must not write its older value again.
#[test]
fn model_a_stale_node_does_not_revert_a_newer_value() {
    let _guard = habilis_network_test_tracing::init();
    let mut sim = Sim::new(9);
    sim.write_exact(0, "a", Some(json!("old")));
    sim.settle();
    sim.write_exact(0, "a", Some(json!("new")));
    sim.deliver_to(0, 1);
    sim.cut(0);
    sim.settle();
    sim.assert_model("a stale node");
}

/// Two nodes cut the same epoch from different views. The seed of the lower key wins on every node,
/// the other seed is dropped, and no write is lost: node n1 wrote `b` twice, and only the cutter
/// that saw the second write has it in its seed.
#[test]
fn model_two_cutters_converge_to_one_seed_and_lose_no_write() {
    let _guard = habilis_network_test_tracing::init();
    for first in 0..NODES {
        for second in 0..NODES {
            if first == second {
                continue;
            }
            let mut sim = Sim::new(31);
            sim.write_exact(1, "b", Some(json!(0)));
            sim.write_exact(0, "a", Some(json!("x")));
            sim.settle();
            sim.write_exact(1, "b", Some(json!(1)));
            sim.deliver_to(1, first);
            let _ = sim.cut(first);
            let _ = sim.cut(second);
            sim.write_exact(second, "c", Some(json!([1, 2])));
            sim.settle();
            sim.assert_model(&format!("cutters n{first} and n{second}"));
        }
    }
}

/// A node that adopted a seed and then rewrote an object keeps the newer object when a lower rival
/// seed of the same epoch wins. The carried value of an inner leaf must not come back above the
/// newer write of its outer leaf.
#[test]
fn model_a_rival_seed_keeps_the_newer_object_of_a_node() {
    let _guard = habilis_network_test_tracing::init();
    let mut sim = Sim::new(5);
    // The seed of epoch 1 holds `obj`, so a later write of `obj.k` is an inner leaf.
    sim.write_exact(0, "obj", Some(json!({ "x": 0 })));
    sim.settle();
    let _ = sim.cut(2);
    sim.settle();
    // No other node holds this write of `k`.
    sim.write_exact(0, "obj", Some(json!({ "k": 1 })));
    // Only the seed of n2 reaches n0 first, so n0 adopts it and carries `k = 1`.
    let _ = sim.cut(2);
    sim.deliver_to(2, 0);
    for _ in 0..=WAIT {
        sim.tick_all();
    }
    sim.write_exact(0, "obj", None);
    sim.write_exact(0, "obj", Some(json!({ "k": 2 })));
    // The lower rival of n1 comes after, and wins on every node.
    let _ = sim.cut(1);
    sim.settle();
    sim.assert_model("a rival seed after a rewrite of an object");
}

/// The cut vector of a rival seed counts the sequence numbers of the epoch before the seed, and the
/// node holds the numbers of the epoch of the seed that it adopted. A write of the node with a low
/// number must not read as covered by the vector of the rival.
#[test]
fn model_a_rival_seed_does_not_cover_a_write_by_its_cut_vector() {
    let _guard = habilis_network_test_tracing::init();
    let mut sim = Sim::new(6);
    // n0 has written 3 changes in epoch 0, and every node holds them: the vector of any seed of
    // epoch 1 names n0 with 3.
    for round in 1..=3 {
        sim.write_exact(0, "a", Some(json!(round)));
    }
    sim.settle();
    // Only the seed of n2 reaches n0 first. n0 adopts it, and writes once in epoch 1.
    let _ = sim.cut(2);
    sim.deliver_to(2, 0);
    for _ in 0..=WAIT {
        sim.tick_all();
    }
    sim.write_exact(0, "z", Some(json!(9)));
    // The lower rival of n1 does not hold `z`, and its vector says that n0 is covered up to 3.
    let _ = sim.cut(1);
    sim.settle();
    sim.assert_model("a rival seed with a vector above the writes of the node");
}

/// Seeds for the run in CI: 500 take about 25 s of a debug build. The environment variable
/// `STATE_EPOCH_MODEL_SEEDS` sets the count, for a long run by hand.
fn seed_count(default: u64) -> u64 {
    let text: Option<String> = env::var("STATE_EPOCH_MODEL_SEEDS").ok();
    text.and_then(|count| count.parse().ok()).unwrap_or(default)
}

#[test]
fn model_cuts_with_no_write_in_flight_converge_to_the_model() {
    let _guard = habilis_network_test_tracing::init();
    let mut longest = 0;
    for seed in 0..seed_count(500) {
        let mut sim = Sim::new(seed);
        for round in 0..6 {
            let writes = 3 + sim.dice.below(6);
            for _ in 0..writes {
                let index = sim.dice.below(NODES);
                sim.write(index);
            }
            sim.settle();
            sim.assert_model(&format!("seed {seed} round {round} before the cut"));
            let cutter = sim.dice.below(NODES);
            longest = longest.max(sim.cut(cutter));
            sim.settle();
            sim.assert_model(&format!("seed {seed} round {round} after the cut"));
        }
    }
    assert!(
        longest > 2,
        "the seeds were too short to test a chain: the longest had {longest} frames"
    );
}

#[test]
fn model_random_writes_cuts_and_adopts_converge_to_the_model() {
    let _guard = habilis_network_test_tracing::init();
    // A seed that is not whole when the wait ends is dropped, and a node says so. With random delay
    // that happens, and the sync rounds bring the frames again.
    habilis_network_test_tracing::expect_warn(
        "habilis_network::gossip",
        "the seed of the candidate epoch was not complete",
    );
    for seed in 0..seed_count(300) {
        let mut sim = Sim::new(seed);
        // Cuts are free: a node cuts at random, so several epochs and two cutters of one epoch
        // happen in one wait. A node that holds a candidate does not cut, as in `tick_epoch`.
        let mut cut_pending: Option<u64> = None;
        for _ in 0..60 {
            sim.step += 1;
            match sim.dice.below(8) {
                0..=3 => {
                    let index = sim.dice.below(NODES);
                    sim.write(index);
                }
                4 => {
                    if cut_pending.is_none() || sim.dice.below(2) == 0 {
                        let cutter = sim.dice.below(NODES);
                        let epoch = sim.nodes[cutter].doc.epoch() + 1;
                        let _ = sim.cut(cutter);
                        cut_pending = Some(epoch);
                    }
                }
                5 => sim.tick_all(),
                6 => sim.sync_all(),
                _ => {}
            }
            sim.deliver_due();
            if let Some(epoch) = cut_pending
                && sim.nodes.iter().all(|node| node.doc.epoch() >= epoch)
            {
                cut_pending = None;
            }
        }
        sim.settle();
        sim.assert_model(&format!("seed {seed}"));
    }
}
