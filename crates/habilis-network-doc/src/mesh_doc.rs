use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use automerge::transaction::Transactable;
use automerge::{
    AutoSerde, Automerge, Change, ChangeHash, ObjId, ObjType, ROOT, ReadDoc, Value as AmValue,
};
use serde_json::{Map, Value};

use habilis_network_protocol::messages::Verified;
use habilis_network_protocol::{AuthorKey, DedupKey, Message, Nickname, SymmetricKey};
use habilis_network_util::bounded_fifo_set::BoundedFifoSet;
use habilis_network_util::consts::{
    DOC_CUT_BACKOFF_FIRST, DOC_CUT_BACKOFF_MAX, DOC_CUT_RANKS_SLOTTED, DOC_CUT_SLOT_TICKS,
    DOC_CUT_SPREAD_TICKS, DOC_EPOCH_ADOPT_WAIT_TICKS, DOC_EPOCH_FRAME_CAP_BYTES,
    DOC_EPOCH_FRAME_MARGIN, DOC_EPOCH_JUMP_MAX, DOC_PENDING_AUTHOR_MAX, DOC_PENDING_TOTAL_MAX,
    DOC_REPLAY_ENTRIES_MAX, DOC_RESTORES_MAX, DOC_SEED_FRAMES_MAX, DOC_SEED_TOMBSTONE_FRAME_BYTES,
    DOC_SEED_TOMBSTONES_MAX, DOC_STATE_DEPTH_MAX, DOC_STATE_ENVELOPE_BYTES,
    DOC_STATE_EPOCH_FRAME_CAP_BYTES, DOC_TOMBSTONE_PATH_BYTES_MAX, MAX_MESSAGE_SIZE,
};

use crate::wire::SeedMark;
use crate::{DocError, Limits, Stamp, pack_entry, wire};

use automerge::transaction;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{mem, vec};
/// Matches the receive path these drops happen on, so a reader filtering the
/// gossip target sees the orphan buffer alongside the frames feeding it.
const LOG_TARGET: &str = "habilis_network::gossip";

/// A refusal that the WARN reports is logged for the first one of its kind and then for every
/// `WARN_EVERY`th, with the number of refusals since the last WARN of that kind. An author who
/// floods a channel would otherwise log one line per frame. This crate keeps no clock, because it
/// runs in a browser, so the window is a count of refusals.
const WARN_EVERY: u64 = 16;

/// How many refusals of one kind the doc has seen, and how many of them a WARN has reported.
#[derive(Debug, Default, Clone, Copy)]
struct Refusals {
    seen: u64,
    reported: u64,
}

/// The outcome of ingesting one frame into a [`MeshDoc`].
///
/// # Examples
///
/// A change that cannot apply yet is buffered until its parents arrive.
///
/// ```
/// use habilis_network_doc::Ingested;
///
/// assert!(matches!(Ingested::Buffered, Ingested::Buffered));
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Ingested {
    /// Applied to the live doc. `changed` is whether the derived document moved
    /// (a no-op change surfaces nothing); `doc` is the document after applying
    /// this change and draining anything it unblocked.
    Applied {
        /// Whether the derived document moved.
        changed: bool,
        /// The document after applying this change and draining anything it unblocked.
        doc: Value,
    },
    /// A change we already hold — dropped.
    Duplicate,
    /// Held pending its causal dependencies; not yet applied.
    Buffered,
    /// Refused: it would write another peer's gated field. Never applied.
    Rejected,
    /// The frame body is not a decodable automerge change (a legacy/foreign
    /// body) — a no-op.
    Ignored,
    /// The frame starts a higher epoch and passed every check. The document keeps it as the
    /// candidate and does not apply it yet: [`MeshDoc::adopt_if_alone`] and
    /// [`MeshDoc::tick_epoch`] switch to it.
    NewEpoch {
        /// The epoch that the frame starts.
        epoch: u64,
    },
}

impl EpochSwitch {
    /// A switch to `epoch` of the per-peer map `map`, with the entry of this node as it was.
    #[must_use]
    pub fn new(epoch: u64, map: String, own_entry: Option<Value>) -> Self {
        Self {
            epoch,
            map,
            own_entry,
            replay: None,
            replay_stamps: Vec::new(),
        }
    }
}

/// A switch of the document to a new epoch: every frame of the old epoch is gone.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct EpochSwitch {
    /// The epoch that the document is in now.
    pub epoch: u64,
    /// The root key of the per-peer map.
    pub map: String,
    /// The entry of this node in that map, as it was before the switch. The caller writes it
    /// again, because only its owner can.
    pub own_entry: Option<Value>,
    /// A merge of the values that this node wrote, or that it holds from the old epoch with no
    /// seed behind them, and that the seed of the new epoch lacks. The caller writes it on top of
    /// the seed. `None` for a gated channel and when nothing is lacking.
    pub replay: Option<Value>,
    /// The stamp of each leaf that `replay` writes again, where the leaf has one: the stamp of the
    /// write that made the value in the old epoch. The caller passes them to
    /// [`MeshDoc::compose_replay_body`], so the frame of the replay names them.
    pub replay_stamps: Vec<(Vec<String>, Stamp)>,
}

/// Declares that a channel holds a **per-peer map** at the document root — one
/// entry per nickname — in which a single field belongs to the peer that entry
/// names, and may be written by no one else.
///
/// The engine needs two things from this and nothing more: the map's key, so it
/// can plant a shared genesis change and every replica agrees on that map's
/// object identity; and the field's key, so [`MeshDoc::ingest`] can refuse a
/// change that touches somebody else's. What the field *means* — an agent card,
/// a public key, a capability set — is the application's business.
///
/// # Compatibility
///
/// Both keys reach the wire: `map` determines the genesis change's bytes (hence
/// the map's object id), so **every replica of a channel must configure the same
/// gate**. Two peers with different `map` values vivify different maps, automerge
/// discards one, and a peer's entry is silently erased. Changing either key on a
/// live mesh is a format break.
///
/// # Examples
///
/// A gate names the map and the field whose own writes it skips.
///
/// ```
/// use habilis_network_doc::SelfWriteGate;
///
/// let _gate = SelfWriteGate::new("state".to_owned(), "field");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SelfWriteGate {
    /// Root key of the per-peer map, keyed by nickname.
    pub map: String,
    /// The field inside `<map>/<nick>/` that only `<nick>` may write.
    pub field: String,
}

impl SelfWriteGate {
    /// The gate for the per-peer map `map`, where only `<nick>` writes `<map>/<nick>/<field>`.
    /// The map is a `String` and the field a `&str`, so a call with the two swapped does not compile.
    #[must_use]
    pub fn new(map: String, field: &str) -> Self {
        Self {
            map,
            field: field.to_owned(),
        }
    }
}

/// One buffered orphan: the frame that carried it, and the change already
/// decoded.
///
/// The decoded change is kept rather than re-derived because readiness is
/// checked on every drain pass. Re-deriving means a ChaCha20-Poly1305 open, a
/// Base58 decode and an automerge decode per buffered frame per pass, so one
/// arriving change that unblocks a chain of depth *d* over *p* orphans costs
/// *p×d* of them. Held once, the same check is a hash-set lookup.
#[derive(Debug)]
struct Pending {
    frame: Verified,
    change: Change,
    arrival: u64,
}

/// The changes of a state seed, in order, and the mark that its root carries. The first change
/// depends on the genesis of the epoch, and each later one on the change before it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SeedChain {
    /// The automerge changes, root first.
    pub changes: Vec<Vec<u8>>,
    /// The mark for the body of the root.
    pub mark: SeedMark,
    /// The Lamport time of the frames of the chain: the cutter takes one time for the whole seed.
    pub time: u64,
    /// For each change of the chain, the stamps of the paths that it writes, in the order of
    /// those paths: the stamp of the write that made the value in the document of the cutter.
    pub origins: Vec<Vec<Stamp>>,
    /// For each change of the chain, the tombstones of the cutter that its frame carries, in the
    /// order of the paths: all of them together are the tombstones of the cutter, and each list
    /// stays inside `DOC_SEED_TOMBSTONE_FRAME_BYTES` bytes.
    pub tombstones: Vec<StampedPaths>,
    /// The paths of the chain that got the stamp 0 for want of a time: the cutter adds them to its
    /// count with [`MeshDoc::note_seed_built`].
    pub unstamped: u64,
}

/// What a seed names: the stamps of its changes, and the tombstones of its root.
type SeedRead = (SeedStamps, StampedPaths);

/// What a cut needs from a document, copied out of it: the live JSON, the stamp of each live leaf,
/// the tombstones and the time of the seed. A cut that is large takes seconds, so the node takes
/// this plan on its event loop (a read of the document, in proportion to its size) and builds the
/// chain from it on another thread (see [`SeedPlan::build`]), while the document goes on taking
/// frames. The chain is the seed of the document as it was when the plan was taken.
#[derive(Debug)]
pub struct SeedPlan {
    live: Value,
    stamps: HashMap<Vec<String>, Stamp>,
    tombstones: Vec<(Vec<String>, Stamp)>,
    time: u64,
}

impl SeedPlan {
    /// The stamps that a frame of this seed would carry for `merge`: one for each leaf and each
    /// object that the merge writes, as the plan holds them (the stamp 0 for a path that it holds
    /// none for). A caller that measures the frames of a seed uses them, so the frames come out as
    /// full as they can be and not as full as the worst stamp lets them be.
    #[must_use]
    pub fn stamps_for(&self, merge: &Value) -> Vec<Stamp> {
        let mut leaves: Vec<(Vec<String>, Value)> = Vec::new();
        collect_leaves(merge, &mut Vec::new(), &mut leaves);
        let mut objects: Vec<(Vec<String>, Value)> = Vec::new();
        collect_objects(merge, &mut Vec::new(), &mut objects);
        let none = Stamp::new(0, "0000000000000000".to_owned());
        let mut stamps: Vec<Stamp> = Vec::with_capacity(leaves.len() + objects.len());
        for (path, _) in &leaves {
            stamps.push(self.stamps.get(path).unwrap_or(&none).clone());
        }
        for (path, _) in &objects {
            stamps.push(self.stamps.get(path).unwrap_or(&none).clone());
        }
        stamps
    }

    /// Build the chain of the seed of `epoch` from this plan: the live JSON cut by leaf path into
    /// merges that each fit one frame, written as a chain of changes on the genesis of `epoch`.
    /// `fits` takes one merge and says whether its frame is small enough, as [`pack_entry`] does.
    /// `actor_seed` is the actor of the chain, the signing key of the cutter. An empty document
    /// gives a chain of 1 change that writes a key and deletes it, so a seed always has a root.
    /// The plan reads nothing from the document, so this runs on any thread.
    ///
    /// # Errors
    /// [`DocError::TooLarge`] when one leaf does not fit a frame, [`DocError::SeedTooLong`] when
    /// the seed needs more frames than a node accepts, and [`DocError::Encode`] when a merge does
    /// not encode.
    pub fn build(
        &self,
        epoch: u64,
        actor_seed: &[u8],
        fits: impl FnMut(&Value) -> bool,
    ) -> Result<SeedChain, DocError> {
        let mut within_frame = fits;
        let cuts: Result<Vec<Value>, DocError> = pack_entry(&self.live, |merge| {
            count_paths(merge) <= DOC_REPLAY_ENTRIES_MAX && within_frame(merge)
        })
        .collect();
        let mut merges: Vec<Value> = cuts?;
        merges.retain(|merge| !matches!(merge, Value::Object(map) if map.is_empty()));
        if merges.len() > DOC_SEED_FRAMES_MAX {
            // A node refuses the root of such a seed, so the cutter does not send it. The live
            // state is then over what a reset can carry: the bound of the channel is its live size.
            return Err(DocError::SeedTooLong {
                frames: merges.len(),
            });
        }
        let mut fork = Automerge::new();
        fork.apply_changes([state_genesis(epoch)])
            .map_err(DocError::encode)?;
        fork.set_actor(actor_for(actor_seed));
        let mut changes: Vec<Vec<u8>> = Vec::new();
        if merges.is_empty() {
            let mut tx = fork.transaction();
            tx.put(&ROOT, "seed", epoch).map_err(DocError::encode)?;
            tx.delete(&ROOT, "seed").map_err(DocError::encode)?;
            tx.commit();
            let all: Vec<Vec<u8>> = raw_changes(&fork, &[]);
            changes.extend(all.into_iter().skip(1));
        }
        for merge in &merges {
            let heads: Vec<ChangeHash> = fork.get_heads();
            let mut tx = fork.transaction();
            write_map(&mut tx, &ROOT, merge).map_err(DocError::encode)?;
            tx.commit();
            changes.extend(raw_changes(&fork, &heads));
        }
        let (mut origins, unstamped) = seed_origins_from(&self.stamps, &fork, &changes)?;
        // The tombstones go on the frames in the order of their paths, as many as a frame holds
        // inside its byte budget and its entry cap. If the frames of the seed are not enough,
        // carrier changes (a key written and deleted, as for an empty seed) take the rest.
        let mut queue: VecDeque<(Vec<String>, Stamp)> = VecDeque::new();
        for (path, stamp) in &self.tombstones {
            queue.push_back((path.clone(), stamp.clone()));
        }
        let mut carried: Vec<StampedPaths> = Vec::with_capacity(changes.len());
        for stamps in &origins {
            carried.push(take_tombstones(
                &mut queue,
                DOC_REPLAY_ENTRIES_MAX - stamps.len(),
            ));
        }
        while !queue.is_empty() {
            let heads: Vec<ChangeHash> = fork.get_heads();
            let mut tx = fork.transaction();
            tx.put(&ROOT, "seed", epoch).map_err(DocError::encode)?;
            tx.delete(&ROOT, "seed").map_err(DocError::encode)?;
            tx.commit();
            changes.extend(raw_changes(&fork, &heads));
            origins.push(Vec::new());
            carried.push(take_tombstones(&mut queue, DOC_REPLAY_ENTRIES_MAX));
            if changes.len() > DOC_SEED_FRAMES_MAX {
                return Err(DocError::SeedTooLong {
                    frames: changes.len(),
                });
            }
        }
        let tip: Vec<u8> = changes.last().cloned().unwrap_or_default();
        let tip_change: Change = Change::from_bytes(tip).map_err(DocError::encode)?;
        let last: String = tip_change.hash().to_string();
        let frames = u32::try_from(changes.len()).unwrap_or(u32::MAX);
        Ok(SeedChain {
            changes,
            mark: SeedMark::new(frames, last),
            time: self.time,
            origins,
            tombstones: carried,
            unstamped,
        })
    }
}

/// What a restore asks the glue to write: a merge and a stamp for each path.
pub type Restores = (Value, StampedPaths);

/// Take tombstones from the front of `queue` for one frame: at most `entries`, and as many as fit
/// `DOC_SEED_TOMBSTONE_FRAME_BYTES` (the bytes of the paths and 32 for each entry). One entry is
/// always taken when there is one, since a path is at most `DOC_TOMBSTONE_PATH_BYTES_MAX` bytes.
fn take_tombstones(queue: &mut VecDeque<(Vec<String>, Stamp)>, entries: usize) -> StampedPaths {
    let mut taken: StampedPaths = Vec::new();
    let mut bytes: usize = 0;
    while let Some((path, _)) = queue.front() {
        let path_bytes: usize = path.iter().map(String::len).sum();
        let cost = path_bytes + 32;
        let full = taken.len() >= entries
            || (!taken.is_empty() && bytes + cost > DOC_SEED_TOMBSTONE_FRAME_BYTES);
        if full {
            break;
        }
        bytes += cost;
        if let Some(entry) = queue.pop_front() {
            taken.push(entry);
        }
    }
    taken
}

/// A path with a stamp each.
pub type StampedPaths = Vec<(Vec<String>, Stamp)>;

/// The merges of a split replay, in the order to send them: one frame for each merge.
#[derive(Debug)]
#[must_use]
pub struct ReplayMerges(Vec<Value>);

impl IntoIterator for ReplayMerges {
    type Item = Value;
    type IntoIter = vec::IntoIter<Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// The stamps that the changes of a seed name: for each change, its paths with a stamp each.
type SeedStamps = HashMap<ChangeHash, StampedPaths>;

/// A leaf that a replay frame changes, hides or names: its value before (`None` when the leaf had
/// none), the stamp that this node held for it, and the stamp that the replay leaves on it (`None`
/// when the leaf is hidden).
struct Lowered {
    path: Vec<String>,
    value: Option<Value>,
    before: Option<Stamp>,
    after: Option<Stamp>,
}

/// The stamps that stored frames name, read once for each call of `stamps_of`.
type RebuiltStamps = HashMap<ChangeHash, Option<Vec<(Vec<String>, Stamp)>>>;

/// The time that a stored frame carries, for each change that was asked about in one call. A frame
/// is parsed once for each call and not once for each path that it holds (the parse decodes the
/// change, which costs about 3 ms for a full frame).
type FrameTimes = HashMap<ChangeHash, Option<u64>>;

/// The ops that one change holds: which actor wrote them, the counter of the first, and how many.
/// A scan of the history makes one per change, so an op id finds its change.
struct OpSpan {
    start: u64,
    len: u64,
    hash: ChangeHash,
}

/// The spans of every actor, each list sorted by the counter of its first op, so an op id finds its
/// change by binary search.
type OpIndex = HashMap<Vec<u8>, Vec<OpSpan>>;

/// The object that each parent path names, read once for each call of `stamps_of`: the paths of
/// one call mostly share a few parents, so the walk from the root is made once for each of them.
type ParentObjects = HashMap<Vec<String>, Option<ObjId>>;

/// The bound of the Lamport time of a state change: 2^53, the largest whole number that a JSON
/// number keeps exact. A change with a time at or above it is refused, so the clock stays below it
/// and `next_time` never saturates in practice. This does not stop a signed member from writing a
/// time far below the bound that is still far above the clock of the others: that member wins
/// the conflicts of the leaves that it writes, which any member of an ungated channel can already
/// do by overwriting them.
const DOC_TIME_MAX: u64 = 1 << 53;

/// The root frame of a higher epoch that the document keeps until it adopts the epoch.
#[derive(Debug)]
struct Candidate {
    epoch: u64,
    /// The root frame.
    frame: Verified,
    /// The hash of the change of the root frame.
    root_hash: ChangeHash,
    /// The sequence number of the change of the root frame. The changes of a chain have the
    /// sequence numbers that follow it, one each.
    root_seq: u64,
    /// The mark of a state seed root, `None` for the one frame candidate of a gated channel.
    mark: Option<SeedMark>,
    /// The later frames of a seed chain, by the hash of their change.
    tail: HashMap<ChangeHash, TailFrame>,
}

impl Candidate {
    fn new(epoch: u64, frame: Verified, root: &Change, mark: Option<SeedMark>) -> Self {
        Self {
            epoch,
            frame,
            root_hash: root.hash(),
            root_seq: root.seq(),
            mark,
            tail: HashMap::new(),
        }
    }
}

impl Candidate {
    /// The tail frames by the change that they follow.
    fn by_parent(&self) -> HashMap<ChangeHash, (ChangeHash, &TailFrame)> {
        let mut by_parent: HashMap<ChangeHash, (ChangeHash, &TailFrame)> = HashMap::new();
        for (hash, tail) in &self.tail {
            by_parent.insert(tail.parent, (*hash, tail));
        }
        by_parent
    }

    /// The path from the root through the tail frames that follow each other, as far as the mark
    /// allows: the frames in order, root first, and the change at the end of the path.
    fn path(&self) -> (Vec<&Verified>, ChangeHash) {
        let named = self.mark.as_ref().map_or(1, |mark| mark.frames as usize);
        let by_parent = self.by_parent();
        let mut ordered: Vec<&Verified> = vec![&self.frame];
        let mut tip: ChangeHash = self.root_hash;
        while ordered.len() < named {
            let Some((hash, tail)) = by_parent.get(&tip) else {
                break;
            };
            ordered.push(&tail.frame);
            tip = *hash;
        }
        (ordered, tip)
    }

    /// The frames of the chain in order, root first, when the candidate holds all of them and the
    /// last change is the one that the mark names. A candidate with no mark is its root alone.
    fn chain(&self) -> Option<Vec<&Verified>> {
        let Some(mark) = self.mark.as_ref() else {
            return Some(vec![&self.frame]);
        };
        let (ordered, tip) = self.path();
        let whole = ordered.len() == mark.frames as usize && tip.to_string() == mark.last;
        whole.then_some(ordered)
    }

    /// The hashes of the tail frames that lie on the path from the root.
    fn on_path(&self) -> HashSet<ChangeHash> {
        let by_parent = self.by_parent();
        let mut hashes: HashSet<ChangeHash> = HashSet::new();
        let mut tip: ChangeHash = self.root_hash;
        while let Some((hash, _)) = by_parent.get(&tip) {
            if !hashes.insert(*hash) {
                break;
            }
            tip = *hash;
        }
        hashes
    }

    /// The tail frame that is not in `on_path` and has the lowest hash, if there is one. The order
    /// is fixed, so every node gives way to the same frame.
    fn first_off_path(&self, on_path: &HashSet<ChangeHash>) -> Option<ChangeHash> {
        let mut found: Option<ChangeHash> = None;
        for hash in self.tail.keys() {
            let lower = found.is_none_or(|best| hash.0 < best.0);
            if !on_path.contains(hash) && lower {
                found = Some(*hash);
            }
        }
        found
    }

    /// The dedup keys of every frame that the candidate holds.
    fn keys(&self) -> Vec<DedupKey> {
        let mut keys: Vec<DedupKey> = vec![self.frame.dedup_key()];
        for tail in self.tail.values() {
            keys.push(tail.frame.dedup_key());
        }
        keys
    }
}

/// A frame of a seed chain after its root, and the change that it follows.
#[derive(Debug)]
struct TailFrame {
    frame: Verified,
    parent: ChangeHash,
}

/// What a [`MeshDoc`] holds, as [`MeshDoc::census`] reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DocCensus {
    /// The epoch of the history that the document holds. It counts the resets that this mesh went through.
    pub epoch: u64,
    /// The changes applied, the genesis included.
    pub changes: usize,
    /// The signed frames kept to serve the changes again.
    pub frames: usize,
    /// The wire bytes of those frames.
    pub frame_bytes: usize,
    /// The bytes of the whole document as Automerge saves it, when the caller asked for the
    /// heavy census.
    pub save_bytes: Option<usize>,
    /// The bytes of the document as JSON, when the caller asked for the heavy census.
    pub json_bytes: Option<usize>,
    /// The nicknames that have an entry in the per-peer map, when the caller asked for the heavy
    /// census. Empty for a document with no gate.
    pub peer_nicks: Option<Vec<String>>,
    /// The state changes that were refused for want of a valid time, since the document began.
    pub refused_time: u64,
    /// The paths of a seed that got the stamp 0 for want of a time, since the document began.
    pub unstamped_paths: u64,
    /// The restores that were dropped because the map of restores was full, since the document
    /// began.
    pub dropped_restores: u64,
    /// The values that wait to be written again (see [`MeshDoc::take_restores`]): after a switch
    /// it is 0 again within 3 ticks, so a value that stays means a write that did not settle.
    pub replay_unsettled: u64,
    /// The frames that the document refused over its remote line, since it began.
    pub refused_remote: u64,
}

/// The bytes of a frame on the wire, 0 for a frame that does not serialize.
fn wire_len(frame: &Verified) -> usize {
    frame.serialize().map_or(0, |wire| wire.as_bytes().len())
}

/// One channel's automerge document plus the bookkeeping to apply changes in
/// causal order and re-serve them.
///
/// # Examples
///
/// A new document holds no change.
///
/// ```
/// use habilis_network_doc::MeshDoc;
///
/// let doc = MeshDoc::new_ungated();
/// assert_eq!(doc.change_count(), 0);
/// ```
#[derive(Debug)]
pub struct MeshDoc {
    // Boxed: an `Automerge` is large inline, and two `MeshDoc`s live in the
    // event-loop state that several CLI futures capture — keeping it off the
    // stack holds those futures under clippy's `large_futures` size threshold.
    doc: Box<Automerge>,
    /// Hashes of every change applied to `doc` — the "deps satisfied?" oracle
    /// (includes the internal genesis change, which has no frame).
    applied: HashSet<ChangeHash>,
    /// The signed frame that carried each applied change, keyed by change hash —
    /// the re-serve store (a peer forwards another author's change with its
    /// original signature intact). Replaces the old `StateLog`.
    frames: HashMap<ChangeHash, Verified>,
    /// The wire bytes of every frame in `frames`, kept as a running sum so that the census does
    /// not serialize them all again.
    frame_bytes: usize,
    /// Orphan frames awaiting their change's deps, keyed by change hash.
    ///
    /// Bounded per author and overall: the frames arriving here have passed
    /// signature, mesh-id and dedup checks, but nothing about them proves their
    /// dependencies will ever arrive. An author who gossips a chain while
    /// withholding its first link parks every later one here for good.
    pending: HashMap<ChangeHash, Pending>,
    /// Insertion order for `pending`, so the per-author ceiling picks the same
    /// victim among equal seqs on every run. A counter rather than a clock:
    /// this crate runs in a browser too, where `Instant` is not available.
    pending_arrivals: u64,
    /// The refusals by kind (the WARN text), for the rate limit of the WARNs.
    refusals: HashMap<&'static str, Refusals>,
    /// Dedup keys of orphan frames dropped from `pending` since the last
    /// [`Self::take_dropped`]. The receive path marked them seen on arrival, so
    /// unless it forgets them the author's re-send is discarded as a repeat and
    /// the change can never land.
    ///
    /// Unbounded, so every caller that ingests other authors' frames must drain
    /// it after each ingest, as the receive path does. A local write cannot
    /// orphan and never adds to it.
    dropped: Vec<DedupKey>,
    /// The epoch of the history that the document holds. Epoch 0 is the history from before
    /// epochs. A gated channel moves to a higher epoch to drop its frames: see
    /// [`Self::tick_epoch`].
    epoch: u64,
    /// The best root frame of a higher epoch that passed every check, and the document has not
    /// adopted. One frame at most, so it is bounded; a frame that does not take the place is
    /// forgotten by the receive path.
    candidate: Option<Box<Candidate>>,
    /// The ticks since the candidate took its place.
    candidate_ticks: u32,
    /// The ticks since the epoch began.
    epoch_ticks: u32,
    /// The tick of the epoch before which `take_restores` gives nothing: a node that is not the
    /// author of a write that a seed lacks waits 1 to 3 ticks, so the author writes it first.
    restores_due: u32,
    /// The tag of the actor that this node wrote its last change with (the first 8 bytes), `0`
    /// before its first write. A stamp with this tag is a write of this node.
    own_tag: AtomicU64,
    /// The operations of the changes that this document holds in this epoch: an upper bound of its
    /// live paths, because every live key has at least the operation that made it.
    ops_held: usize,
    /// The frame bytes and the operations right after the seed that this node adopted was applied,
    /// 0 in an epoch that began with no seed. What the document grew by since is the growth that
    /// the lines of `Limits` measure.
    seed_bytes: usize,
    seed_ops: usize,
    /// The lines of this document.
    limits: Limits,
    /// The hashes of the frames that this document refused over its remote line, so that anti-
    /// entropy that offers one again finds it dropped at once. Bounded by `Limits::refused_max`:
    /// when it is full the oldest hash leaves. Cleared at a cut.
    refused: BoundedFifoSet<ChangeHash>,
    /// The frames refused over the remote line since the document began.
    refused_remote: u64,
    /// The ticks since the size of this document first crossed the cut ceiling, `None` while it
    /// is below it.
    crossed_ticks: Option<u32>,
    /// The ticks that the document still holds its cut after a failed cut, and the wait that the
    /// next failure sets.
    cut_wait: u32,
    cut_backoff: u32,
    /// The frame bytes of the epoch when it settled, 0 before. The live entries are back by then.
    settled_bytes: usize,
    /// The frame bytes that start a reset, before the settled size is known.
    frame_cap: usize,
    /// Whether the document is applying the frames of the seed that it adopts, which the rule for
    /// a rival seed must not see.
    adopting: bool,
    /// The Lamport clock of a state channel with state epochs: the highest time that this node
    /// wrote or saw. A change takes the time `clock + 1`, so it is above every change that its
    /// author saw. It never goes down and it does not restart at an epoch. At most `DOC_TIME_MAX`:
    /// a change with a higher time is refused, so one integer is all the memory it needs.
    clock: AtomicU64,
    /// The state changes that were refused for want of a valid time: one integer, which saturates.
    refused_time: u64,
    /// The paths of a seed that got the stamp 0 (see [`Self::unstamped_paths`]).
    unstamped: AtomicU64,
    /// The values that this node holds with a stamp above the live stamp that a replay of another
    /// node just set: the replay won in automerge but has the lower stamp, so this node writes its
    /// value again (see [`Self::take_restores`]). At most `DOC_RESTORES_MAX` paths.
    restores: BTreeMap<Vec<String>, (Value, Stamp)>,
    /// The restores that were dropped because the map was full (see [`Self::dropped_restores`]).
    restores_dropped: u64,
    /// Whether local writes wait for the end of the first sync (see [`Self::awaiting_first_sync`]).
    awaiting_sync: bool,
    /// The stamps that the changes of the adopted seed name, for each change and each path that it
    /// writes. They tell who wrote the value of a leaf and when, where the change is the seed of
    /// another node. Dropped at the next epoch, and at most the paths of the seed.
    origins: SeedStamps,
    /// The paths that were deleted, with the stamp of the delete: a leaf that a seed lacks because
    /// it was deleted must not be written again from an older value. It survives the epochs (a
    /// seed carries it), holds at most `DOC_SEED_TOMBSTONES_MAX` entries, and drops the one with
    /// the lowest stamp when it is full.
    tombstones: BTreeMap<Vec<String>, Stamp>,
    /// The deletes of a path longer than `DOC_TOMBSTONE_PATH_BYTES_MAX` bytes, which have no
    /// tombstone.
    tombstone_paths_long: u64,
    /// The author of the root of the seed that this document adopted for its epoch, `None` when
    /// it holds no seed. A rival root of the same epoch with a lower key replaces that seed.
    seed_author: Option<AuthorKey>,
    /// The hashes of the changes of that seed. They are no write of the node, so a replay skips
    /// them. At most `DOC_SEED_FRAMES_MAX`.
    seed_hashes: HashSet<ChangeHash>,
    /// The authors of rival roots that lost, so that the rest of their chains is refused at once.
    /// At most 8, the oldest gives way.
    refused_rivals: Vec<AuthorKey>,
    /// Whether an ungated document keeps the root of a higher epoch as a candidate. Off by
    /// default, so a state channel refuses such a frame, as it did before the state epochs, until
    /// the node ticks the state channel (see [`Self::state_epochs`]).
    state_epochs: bool,
    /// This channel's per-peer write gate, when it has one (`meta` does; `state`
    /// is free-form and carries no per-peer identity, so it does not).
    gate: Option<SelfWriteGate>,
    /// This channel's symmetric encryption key, on a password-protected mesh.
    /// `Some` ⇒ change bodies are sealed on the wire (`enc` envelope) and
    /// decrypted here before applying; `None` ⇒ plaintext, exactly as before.
    /// Wiped on drop.
    key: Option<SymmetricKey>,
}

impl MeshDoc {
    /// A channel with no per-peer gate: free-form, every author may write
    /// anywhere. This is the `state` channel.
    #[must_use]
    pub fn new_ungated() -> Self {
        Self::assemble(Automerge::new(), HashSet::new(), None)
    }

    /// A channel whose per-peer map is gated by `gate` — the `meta` channel.
    ///
    /// The gated map must have ONE object identity across every replica, or two
    /// peers each vivifying it would create conflicting maps and automerge would
    /// discard one, silently erasing a peer's entry (its identity). A
    /// byte-identical genesis change (fixed actor, fixed time) gives the map a
    /// shared id everywhere; per-peer writes then land in the same map as
    /// distinct keys and merge cleanly.
    ///
    /// That is also why the genesis is planted by the *gate* config rather than
    /// unconditionally: an ungated channel has no per-peer map, so planting one
    /// would put an empty map on its wire for no reason.
    #[must_use]
    pub fn new_gated(gate: SelfWriteGate) -> Self {
        let mut doc = Automerge::new();
        let mut applied = HashSet::new();
        let genesis = peers_genesis(&gate.map, 0);
        let hash = genesis.hash();
        let _ = doc.apply_changes([genesis]);
        applied.insert(hash);
        Self::assemble(doc, applied, Some(gate))
    }

    fn assemble(doc: Automerge, applied: HashSet<ChangeHash>, gate: Option<SelfWriteGate>) -> Self {
        Self {
            doc: Box::new(doc),
            applied,
            frames: HashMap::new(),
            frame_bytes: 0,
            pending: HashMap::new(),
            pending_arrivals: 0,
            refusals: HashMap::new(),
            dropped: Vec::new(),
            epoch: 0,
            candidate: None,
            candidate_ticks: 0,
            epoch_ticks: 0,
            restores_due: 0,
            own_tag: AtomicU64::new(0),
            ops_held: 0,
            seed_bytes: 0,
            seed_ops: 0,
            limits: Limits::real(),
            refused: BoundedFifoSet::new(Limits::real().refused_max),
            refused_remote: 0,
            crossed_ticks: None,
            cut_wait: 0,
            cut_backoff: DOC_CUT_BACKOFF_FIRST,
            settled_bytes: 0,
            frame_cap: DOC_EPOCH_FRAME_CAP_BYTES,
            state_epochs: false,
            adopting: false,
            clock: AtomicU64::new(0),
            refused_time: 0,
            unstamped: AtomicU64::new(0),
            restores: BTreeMap::new(),
            restores_dropped: 0,
            awaiting_sync: false,
            origins: HashMap::new(),
            tombstones: BTreeMap::new(),
            tombstone_paths_long: 0,
            seed_author: None,
            seed_hashes: HashSet::new(),
            refused_rivals: Vec::new(),
            gate,
            key: None,
        }
    }

    /// Drop the gate but keep the document shape — the state of a replica that
    /// has **synced** a gated channel but enforces no policy of its own.
    ///
    /// Test-only, and the honest way to model an attacker: a forge has to be
    /// authored somewhere, and authoring it on a genuinely gated replica is
    /// impossible by construction. Building it on a bare [`Self::new_ungated`]
    /// would be a *different* document — no genesis, so a different map object
    /// id — and then whether the victim's gate fires at all depends on which of
    /// the two conflicting maps automerge happens to keep. Two of these tests
    /// passed on exactly that coincidence until the genesis actor was rebranded
    /// and the hash ordering flipped.
    #[cfg(test)]
    #[must_use]
    fn synced_but_ungated(mut self) -> Self {
        self.gate = None;
        self
    }

    /// Would applying `change` (authored by `author`) write any peer's gated
    /// field other than the author's own? Applied to a throwaway fork so the live
    /// doc is never touched by an unauthorized change. Always `false` on an
    /// ungated channel — there is no field to guard.
    /// `hydrated` lets a caller that already holds `self.to_json()` for this
    /// same, still-unmutated document hand it over instead of paying for a
    /// second one. `None` when there is none to reuse — `drain_pending` applies
    /// between checks, so each pass there needs its own.
    fn forges_foreign_entry(
        &self,
        change: &Change,
        author: &Nickname,
        hydrated: Option<&Value>,
    ) -> bool {
        let Some(gate) = self.gate.as_ref() else {
            return false;
        };
        let mut fork = self.doc.fork();
        if fork.apply_changes([change.clone()]).is_err() {
            return true;
        }
        let before = match hydrated {
            Some(json) => gated_entries(json, gate),
            None => peer_entries(&self.doc, gate),
        };
        let after = peer_entries(&fork, gate);
        let author_name = author.as_str();
        let mut nicks = before.keys().chain(after.keys());
        nicks.any(|nick| nick.as_str() != author_name && before.get(nick) != after.get(nick))
    }

    /// Let this ungated document keep the root of a higher epoch as a candidate. Call it only on a
    /// node that ticks the state channel, because a candidate that no tick adopts or drops holds
    /// its frames for ever. This is a development guard and no runtime switch: nodes that
    /// disagree on it would diverge. Step 4 removes it, and every node of frame version 13.0 has
    /// state epochs.
    #[must_use]
    pub fn state_epochs(mut self) -> Self {
        self.state_epochs = true;
        self
    }

    /// Set this channel's encryption key (the daemon's per-channel
    /// mesh-password-derived key). `None` leaves the channel in plaintext.
    #[must_use]
    pub fn key(mut self, key: Option<SymmetricKey>) -> Self {
        self.key = key;
        self
    }

    /// The plaintext automerge change bytes carried by `frame`, decrypting an
    /// `enc` body with this channel's key first. `None` for an opaque/foreign
    /// body (or, on a passworded mesh, an unsealed or unopenable body) — a
    /// no-op on the doc.
    fn change_bytes(&self, frame: &Message) -> Option<wire::ParsedChange> {
        match self.key.as_ref() {
            // Passwordless: parse directly — no decrypt indirection, no clone.
            None => wire::parse_change_full(frame.body.as_str()),
            Some(key) => {
                let plain = wire::decrypt_body(frame.body.as_str(), Some(key))?;
                wire::parse_change_full(&plain)
            }
        }
    }

    /// Compose the wire body for a locally-built change: the plaintext
    /// `change`/`merge` envelope, sealed under this channel's key when set.
    /// Returns `(wire, plain)` — `wire` is signed + gossiped + retained for
    /// re-serve; `plain` surfaces the author's own human-readable delta locally.
    ///
    /// # Errors
    /// # Errors
    /// [`DocError::NotAnObject`] when the merge is not a JSON object, [`DocError::Body`]
    /// when the change body is not a valid message body, or [`DocError::Encode`] when
    /// the change does not encode, and [`DocError::ClockNotReady`] when a state document waits for
    /// its first sync (see [`Self::awaiting_first_sync`]).
    pub fn compose_wire_body(
        &self,
        change: &[u8],
        merge: Option<&Value>,
    ) -> Result<
        (
            habilis_network_protocol::MessageBody,
            habilis_network_protocol::MessageBody,
        ),
        DocError,
    > {
        let timed: bool = self.state_epochs && self.gate.is_none();
        if timed && self.awaiting_sync {
            return Err(DocError::ClockNotReady);
        }
        let time: Option<u64> = timed.then(|| self.next_time());
        let plain = wire::change_body_timed(change, merge, self.epoch, None, time)?;
        let wire = match self.key.as_ref() {
            Some(key) => wire::encrypt_body(&plain, key)?,
            None => plain.clone(),
        };
        Ok((wire, plain))
    }

    /// Compose the wire body for a replay change: like [`Self::compose_wire_body`], and the body
    /// names, for each path that the change writes, the stamp from `stamps` (the stamp that the
    /// write had in the old epoch), or a fresh stamp of this change for a path with none. The
    /// change is checked on a fork, so the paths it lists are those that a receiver lists.
    ///
    /// # Errors
    /// As [`Self::compose_wire_body`], and [`DocError::TooLarge`] when the change writes more than
    /// `DOC_REPLAY_ENTRIES_MAX` paths: split the replay with [`Self::split_replay`] first.
    pub fn compose_replay_body(
        &self,
        change: &[u8],
        stamps: &[(Vec<String>, Stamp)],
    ) -> Result<habilis_network_protocol::MessageBody, DocError> {
        if self.awaiting_sync {
            return Err(DocError::ClockNotReady);
        }
        let parsed = Change::from_bytes(change.to_vec()).map_err(DocError::encode)?;
        let mut fork = self.doc.fork();
        fork.apply_changes([parsed.clone()])
            .map_err(DocError::encode)?;
        let paths = change_leaves(&fork, &parsed);
        if paths.len() > DOC_REPLAY_ENTRIES_MAX {
            return Err(DocError::TooLarge { bytes: paths.len() });
        }
        let time = self.next_time();
        let fresh = Stamp::new(time, actor_tag(parsed.actor_id()));
        let named: HashMap<&Vec<String>, &Stamp> =
            stamps.iter().map(|(path, stamp)| (path, stamp)).collect();
        // An object that the replay makes only because a leaf below it needs a place has no write
        // of its own, so it gets the stamp 0: a stamp from now would cover the newer leaves that
        // other nodes write below it.
        let written: Value = doc_json(&fork);
        let none = Stamp::new(0, "0000000000000000".to_owned());
        let origins: Vec<Stamp> = paths
            .iter()
            .map(|path| match named.get(path) {
                Some(stamp) => (*stamp).clone(),
                None if lookup(&written, path).is_some_and(Value::is_object) => none.clone(),
                None => fresh.clone(),
            })
            .collect();
        let plain =
            wire::change_body_stamped(change, None, self.epoch, None, Some(time), &origins)?;
        match self.key.as_ref() {
            Some(key) => wire::encrypt_body(&plain, key),
            None => Ok(plain),
        }
    }

    /// Split a replay merge into merges of at most `DOC_REPLAY_ENTRIES_MAX` paths that each fit a
    /// frame (`fits` measures the real frame, as for [`Self::build_seed`]). A sender that has more
    /// leaves to write again than one frame names sends one frame for each merge.
    ///
    /// # Errors
    /// [`DocError::TooLarge`] when one leaf does not fit a frame. No merge comes out then, so the
    /// caller never sends a part of the replay.
    pub fn split_replay(
        &self,
        replay: &Value,
        fits: impl FnMut(&Value) -> bool,
    ) -> Result<ReplayMerges, DocError> {
        let mut within_frame = fits;
        let cuts: Result<Vec<Value>, DocError> = pack_entry(replay, |merge| {
            count_paths(merge) <= DOC_REPLAY_ENTRIES_MAX && within_frame(merge)
        })
        .collect();
        Ok(ReplayMerges(cuts?))
    }

    /// The plaintext body string to surface for `frame`, decrypting an `enc`
    /// body so the `m` delta renders. `None` when it can't be opened; the caller
    /// then surfaces the original (opaque) frame.
    #[must_use]
    pub fn surface_body(&self, frame: &Message) -> Option<String> {
        wire::decrypt_body(frame.body.as_str(), self.key.as_ref())
    }

    /// This channel's automerge heads, Base58-encoded — the compact frontier a
    /// peer advertises so others can compute exactly what it is missing.
    pub fn heads(&self) -> impl Iterator<Item = String> {
        self.doc
            .get_heads()
            .into_iter()
            .map(|hash| encode_hash(&hash))
    }

    /// What the document holds, for the census: the sizes that a keyframe scheme would shrink.
    /// The counts and the frame bytes are O(1). `heavy` also hydrates the JSON, lists the
    /// per-peer map and encodes the whole document, which costs CPU in proportion to the
    /// document, so a caller asks for it only now and then.
    #[must_use]
    pub fn census(
        &mut self,
        // True also hydrates the JSON and encodes the whole document.
        heavy: bool,
    ) -> DocCensus {
        let json = heavy.then(|| doc_json(&self.doc));
        let save_bytes = heavy.then(|| self.doc.save().len());
        let json_bytes: Option<usize> = json
            .as_ref()
            .map(|json| serde_json::to_vec(json).map_or(0, |bytes| bytes.len()));
        let peer_nicks = json.as_ref().map(|json| self.gated_nicks(json));
        let unstamped_paths: u64 = self.unstamped.load(Ordering::Relaxed);
        let replay_unsettled: u64 = u64::try_from(self.restores.len()).unwrap_or(u64::MAX);
        DocCensus {
            epoch: self.epoch,
            changes: self.applied.len(),
            frames: self.frames.len(),
            frame_bytes: self.frame_bytes,
            save_bytes,
            json_bytes,
            peer_nicks,
            refused_time: self.refused_time,
            unstamped_paths,
            dropped_restores: self.restores_dropped,
            replay_unsettled,
            refused_remote: self.refused_remote,
        }
    }

    /// The nicknames with an entry in the gated map of `json`. Empty for a document with no gate.
    fn gated_nicks(&self, json: &Value) -> Vec<String> {
        let Some(gate) = self.gate.as_ref() else {
            return Vec::new();
        };
        let entries = gated_entries(json, gate);
        entries.keys().cloned().collect()
    }

    /// The operations of the changes that this document holds in this epoch.
    #[must_use]
    pub fn ops_held(&self) -> usize {
        self.ops_held
    }

    /// The frame bytes right after the seed of this epoch was applied.
    #[must_use]
    pub fn seed_bytes(&self) -> usize {
        self.seed_bytes
    }

    /// The operations right after the seed of this epoch was applied.
    #[must_use]
    pub fn seed_ops(&self) -> usize {
        self.seed_ops
    }

    /// A state document for the daemon: epochs on, no gate, the cap of the state channel, and a
    /// clock that waits for the first sync (see [`Self::awaiting_first_sync`]).
    #[must_use]
    pub fn new_state(key: Option<SymmetricKey>) -> Self {
        Self::new_ungated()
            .state_epochs()
            .key(key)
            .epoch_cap(DOC_STATE_EPOCH_FRAME_CAP_BYTES)
            .awaiting_first_sync()
    }

    /// Whether this document has state epochs.
    #[must_use]
    pub fn has_state_epochs(&self) -> bool {
        self.state_epochs
    }

    /// Whether a cut of the state document is due for a node of `rank` among the nodes that it
    /// sees alive. The size of the document must have crossed the cut ceiling (see [`Limits`]) and
    /// grown by the growth of a cut since its seed, and the node must have waited the slot of its
    /// rank: rank 0 at once, rank `r` for `2 x r` ticks, and a node of rank 16 or more for 32
    /// ticks and a spread that its tag chooses. A node that holds a candidate does not cut, and a
    /// node that a failed cut holds does not cut until the hold ends. The ticks are those of
    /// [`Self::tick_epoch`]. The rank is soft: a wrong view of the nodes delays or doubles a cut and
    /// never blocks it, because the higher ranks cut after the spread.
    #[must_use]
    pub fn cut_due(&self, rank: usize) -> bool {
        if !self.state_epochs
            || self.gate.is_some()
            || self.candidate.is_some()
            || self.cut_wait > 0
        {
            return false;
        }
        self.crossed_ticks
            .is_some_and(|waited| waited >= self.cut_delay(rank))
    }

    /// The ticks that a node of `rank` waits after it sees the size cross the ceiling.
    fn cut_delay(&self, rank: usize) -> u32 {
        if rank < DOC_CUT_RANKS_SLOTTED {
            let slot = u32::try_from(rank).unwrap_or(u32::MAX);
            return DOC_CUT_SLOT_TICKS.saturating_mul(slot);
        }
        let slotted = u32::try_from(DOC_CUT_RANKS_SLOTTED).unwrap_or(u32::MAX);
        let tag = self.own_tag.load(Ordering::Relaxed) ^ self.epoch;
        let spread = u32::try_from(tag % u64::from(DOC_CUT_SPREAD_TICKS)).unwrap_or(0);
        DOC_CUT_SLOT_TICKS.saturating_mul(slotted) + spread
    }

    /// Tell the document that the cut that it asked for failed: it holds the next cut for a wait
    /// that doubles at each failure, from `DOC_CUT_BACKOFF_FIRST` ticks to `DOC_CUT_BACKOFF_MAX`.
    pub fn note_cut_failed(&mut self) {
        self.cut_wait = self.cut_backoff;
        self.cut_backoff = self.cut_backoff.saturating_mul(2).min(DOC_CUT_BACKOFF_MAX);
    }

    /// Whether the size of this document is at the cut ceiling, on the bytes of the next seed or on
    /// the operations, and has grown by the growth of a cut since its seed.
    fn size_crossed(&self) -> bool {
        let growth_bytes = self.frame_bytes.saturating_sub(self.seed_bytes);
        let growth_ops = self.ops_held.saturating_sub(self.seed_ops);
        let clock = self.clock.load(Ordering::Relaxed);
        let projected = Limits::projected_bytes(self.seed_bytes, growth_bytes, growth_ops, clock);
        let bytes = &self.limits.bytes;
        let ops = &self.limits.ops;
        (projected >= bytes.ceiling && growth_bytes >= bytes.growth)
            || (self.ops_held >= ops.ceiling && growth_ops >= ops.growth)
    }

    /// One tick of the size of a free-form state document: count the ticks since it crossed the
    /// ceiling, and let the hold of a failed cut run down.
    fn watch_size(&mut self) {
        self.cut_wait = self.cut_wait.saturating_sub(1);
        self.crossed_ticks = if self.size_crossed() {
            Some(
                self.crossed_ticks
                    .map_or(0, |waited| waited.saturating_add(1)),
            )
        } else {
            None
        };
    }

    /// Set the lines of this document, for a test that wants a small seed.
    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self.refused = BoundedFifoSet::new(limits.refused_max);
        self
    }

    /// The frames that this document refused over its remote line, since it began.
    #[must_use]
    pub fn refused_remote(&self) -> u64 {
        self.refused_remote
    }

    /// The hashes of refused frames that the document holds now.
    #[must_use]
    pub fn refused_held(&self) -> usize {
        self.refused.len()
    }

    /// The epoch of the history that this document holds.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The Lamport clock of this document: the highest time that it wrote or saw.
    #[must_use]
    pub fn clock(&self) -> u64 {
        self.clock.load(Ordering::Relaxed)
    }

    /// The stamp of the value that the document holds at each of `paths`: the Lamport time and the
    /// actor of the change that wrote the value that automerge kept. `None` for a path that holds
    /// no value, and for a value whose change has no time (a change of a channel with no state
    /// epochs, or the genesis). One scan of the history builds the index for all the paths.
    #[must_use]
    pub(crate) fn stamps_of(&self, paths: &[Vec<String>]) -> Vec<Option<Stamp>> {
        let mut index: OpIndex = HashMap::new();
        for change in self.doc.get_changes(&[]) {
            let start: u64 = change.start_op().get();
            let len: u64 = u64::try_from(change.len()).unwrap_or(u64::MAX);
            let span = OpSpan {
                start,
                len,
                hash: change.hash(),
            };
            let actor: Vec<u8> = change.actor_id().to_bytes().to_vec();
            index.entry(actor).or_default().push(span);
        }
        for spans in index.values_mut() {
            spans.sort_by_key(|span| span.start);
        }
        let mut rebuilt: RebuiltStamps = HashMap::new();
        let mut times: FrameTimes = HashMap::new();
        let mut parents: ParentObjects = HashMap::new();
        paths
            .iter()
            .map(|path| self.stamp_at(path, &index, (&mut rebuilt, &mut times), &mut parents))
            .collect()
    }

    /// The stamps that the stored frame of the change `hash` names, for each path that the change
    /// writes. `None` when the frame is not stored, names none, or names a different number of stamps
    /// than the change has leaves.
    fn stamps_of_frame(&self, hash: &ChangeHash) -> Option<Vec<(Vec<String>, Stamp)>> {
        let frame = self.frames.get(hash)?;
        let parsed = self.change_bytes(frame)?;
        if parsed.origins.is_empty() {
            return None;
        }
        let change = Change::from_bytes(parsed.bytes).ok()?;
        let paths = change_leaves(&self.doc, &change);
        if paths.len() != parsed.origins.len() {
            return None;
        }
        Some(paths.into_iter().zip(parsed.origins).collect())
    }

    /// The stamp of the value at `path`, from the op that holds it.
    fn stamp_at(
        &self,
        path: &[String],
        index: &OpIndex,
        (rebuilt, times): (&mut RebuiltStamps, &mut FrameTimes),
        parents: &mut ParentObjects,
    ) -> Option<Stamp> {
        let (leaf_key, parent_path) = path.split_last()?;
        if !parents.contains_key(parent_path) {
            parents.insert(parent_path.to_vec(), self.object_at(parent_path));
        }
        let parent: ObjId = parents.get(parent_path)?.clone()?;
        let (_, id) = self.doc.get(&parent, leaf_key.as_str()).ok()??;
        let holder = Some(id);
        let ObjId::Id(counter, actor, _) = holder? else {
            return None;
        };
        let spans = index.get(actor.to_bytes())?;
        let after = spans.partition_point(|span| span.start <= counter);
        let span = spans[..after]
            .last()
            .filter(|span| counter - span.start < span.len)?;
        // The record of the stamps lives in memory only. A frame of a seed or a replay that is
        // stored carries them, so a node that lost the record reads them from the frame.
        // One frame names many paths, so the list that a frame gives is read once for each call.
        let named: Option<&Vec<(Vec<String>, Stamp)>> = match self.origins.get(&span.hash) {
            Some(list) => Some(list),
            None => rebuilt
                .entry(span.hash)
                .or_insert_with(|| self.stamps_of_frame(&span.hash))
                .as_ref(),
        };
        if let Some(stamp) = named.and_then(|list| list.iter().find(|(held, _)| held == path)) {
            return Some(stamp.1.clone());
        }
        let known = times
            .entry(span.hash)
            .or_insert_with(|| self.frame_time(&span.hash));
        let time: u64 = (*known)?;
        Some(Stamp::new(time, actor_tag(&actor)))
    }

    /// The Lamport time that the stored frame of the change `hash` carries.
    fn frame_time(&self, hash: &ChangeHash) -> Option<u64> {
        let frame = self.frames.get(hash)?;
        self.change_bytes(frame)?.time
    }

    /// The object that `path` names, `None` when the path holds no object.
    fn object_at(&self, path: &[String]) -> Option<ObjId> {
        let mut object: ObjId = ROOT;
        for key in path {
            let (value, id) = self.doc.get(&object, key.as_str()).ok()??;
            if !matches!(value, automerge::Value::Object(_)) {
                return None;
            }
            object = id;
        }
        Some(object)
    }

    /// How many paths of a seed got the stamp 0 for want of a time, since the document began. A
    /// value that gets 0 loses to every replay, so the count says that a cut read a value with no
    /// time.
    #[must_use]
    pub fn unstamped_paths(&self) -> u64 {
        self.unstamped.load(Ordering::Relaxed)
    }

    /// How many state changes this document refused for want of a valid time: none, or above `DOC_TIME_MAX`. A caller reads it
    /// for a gauge, so a refusal is never silent.
    #[must_use]
    pub fn refused_time(&self) -> u64 {
        self.refused_time
    }

    /// Take the time of the next change of this node: one above the clock, which then holds it.
    /// [`Self::compose_wire_body`] and [`Self::build_seed`] call it.
    pub(crate) fn next_time(&self) -> u64 {
        let taken = self
            .clock
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                Some(held.saturating_add(1).min(DOC_TIME_MAX))
            });
        taken.map_or(DOC_TIME_MAX, |held| {
            held.saturating_add(1).min(DOC_TIME_MAX)
        })
    }

    /// Whether a candidate seed waits to be adopted. A node that holds one adopts it after the wait
    /// and does not cut an epoch of its own, so the glue and the model ask before they cut.
    #[must_use]
    pub fn has_candidate(&self) -> bool {
        self.candidate.is_some()
    }

    /// Whether the local writes of this document still wait for the end of the first sync (see
    /// [`Self::awaiting_first_sync`]).
    #[must_use]
    pub fn is_awaiting_first_sync(&self) -> bool {
        self.awaiting_sync
    }

    /// Whether the candidate seed that this document waits to adopt holds every frame of its chain,
    /// so that the node can adopt it after the wait. False when there is no candidate.
    #[must_use]
    pub fn candidate_whole(&self) -> bool {
        self.candidate
            .as_ref()
            .is_some_and(|candidate| candidate.chain().is_some())
    }

    /// Hold the local writes of a state document until it has heard of another write. A node that
    /// restarts has a clock of 0, so a write now would get a time below the writes that the node
    /// made before, and lose to them. [`Self::compose_wire_body`] returns
    /// [`DocError::ClockNotReady`] until [`Self::finish_sync`]. A frame does not end the wait,
    /// because the first one that sync brings can be an old one with a low time.
    #[must_use]
    pub fn awaiting_first_sync(mut self) -> Self {
        self.awaiting_sync = true;
        self
    }

    /// Say that the first sync is over, so the local writes go on. The glue calls it after the
    /// first full answer to the digest, when that answer is empty, and when no peer answers within
    /// a time limit: without the last two a mesh where every node restarts at once never writes.
    pub fn finish_sync(&mut self) {
        self.awaiting_sync = false;
    }

    /// Set the frame bytes that start a reset, before the size of a settled epoch is known (the
    /// default is `DOC_EPOCH_FRAME_CAP_BYTES`).
    #[must_use]
    pub fn epoch_cap(mut self, cap: usize) -> Self {
        self.frame_cap = cap;
        self
    }

    /// Adopt the candidate epoch at once when this node holds no frame of another author: it has
    /// nothing to lose, so it need not wait. `None` when there is no candidate or the node holds
    /// the frames of others.
    ///
    /// A fresh joiner holds nothing, so one frame can move it up to `DOC_EPOCH_JUMP_MAX` epochs. The
    /// mesh then follows it within one wait, because that jump is inside the bound of the mesh, and
    /// the joiner holds frames of others after that, so it waits the next time.
    pub fn adopt_if_alone(&mut self, me: &Nickname, own: &AuthorKey) -> Option<EpochSwitch> {
        let held = self.candidate.as_ref()?;
        let alone = self.frames.values().all(|frame| frame.key() == *own);
        let whole = held.chain().is_some();
        if alone && whole { self.adopt(me) } else { None }
    }

    /// One tick of 1 minute. Adopts the candidate epoch when it has waited for
    /// `DOC_EPOCH_ADOPT_WAIT_TICKS`, jumping to the highest epoch that it saw. Else starts a new epoch
    /// when the frame bytes reach the threshold: the larger of the cap and twice the bytes that the
    /// epoch held when it settled. Until it settled, the threshold is twice the cap, so the live
    /// entries that come back after a reset cannot start another one. Either way the frames of the
    /// old epoch are dropped, and the caller writes the entry in the returned switch again.
    ///
    /// A node that holds the frames of others adopts after the wait, so for up to
    /// `DOC_EPOCH_ADOPT_WAIT_TICKS` minutes after a reset the writes of the two epochs do not cross,
    /// and a reader can see a peer with no entry. An entry comes back smallest field first, so the
    /// capabilities of a card can land after its other fields. The size of the epoch is taken one
    /// tick after the wait: a node adopts at the end of the wait and writes its entry on the next
    /// sweep, so the entries are back in that margin, whatever the phase of the two timers. Only a
    /// gated channel has epochs today: the free-form `state` channel keeps every frame until the
    /// state epoch work lands (`state-epoch-design.md`).
    pub fn tick_epoch(&mut self, me: &Nickname) -> Option<EpochSwitch> {
        self.epoch_ticks = self.epoch_ticks.saturating_add(1);
        if self.state_epochs && self.gate.is_none() {
            self.watch_size();
        }

        if self.candidate.is_some() {
            self.candidate_ticks = self.candidate_ticks.saturating_add(1);
            if self.candidate_ticks >= DOC_EPOCH_ADOPT_WAIT_TICKS {
                return self.adopt(me);
            }
        }
        if self.epoch_ticks == DOC_EPOCH_ADOPT_WAIT_TICKS + 2 {
            self.settled_bytes = self.frame_bytes;
        }
        let settled = self.epoch_ticks > DOC_EPOCH_ADOPT_WAIT_TICKS + 1;
        let threshold = if settled {
            self.frame_cap.max(self.settled_bytes.saturating_mul(2))
        } else {
            self.frame_cap.saturating_mul(2)
        };
        if self.gate.is_some() && self.frame_bytes >= threshold {
            if self.candidate.is_some() {
                return self.adopt(me);
            }
            return Some(self.switch_to(self.epoch.saturating_add(1), me));
        }
        None
    }

    /// Switch to the epoch of the candidate and apply its root frame. The candidate is a root of its
    /// epoch, and a peer sent it once, so a switch that dropped it would leave its dedup key seen
    /// with no frame behind it. A node that crosses the threshold with a candidate adopts it for
    /// that reason, and does not start an epoch of its own.
    fn adopt(&mut self, me: &Nickname) -> Option<EpochSwitch> {
        let candidate = self.candidate.take()?;
        let frames: Option<Vec<Verified>> = candidate.chain().map(|chain| {
            let mut owned: Vec<Verified> = Vec::with_capacity(chain.len());
            for frame in chain {
                owned.push(frame.clone());
            }
            owned
        });
        let Some(frames) = frames else {
            // The chain is not whole: the cutter left, or frames were lost. Adopting it would leave
            // the state with a part of its values, so the node keeps its epoch and forgets the
            // frames, and a later digest brings them again.
            self.dropped.extend(candidate.keys());
            if let Some(held) = self.warn_due("the seed of the candidate epoch was not complete") {
                tracing::warn!(target: LOG_TARGET, held, author = %candidate.frame.author, "the seed of the candidate epoch was not complete");
            }
            return None;
        };
        // A state seed names the stamp of each path that each of its changes writes. A seed whose
        // stamps do not match its changes is dropped before the switch, as an incomplete one is.
        let recorded: Option<SeedRead> = if candidate.mark.is_some() {
            let Some(found) = self.read_seed_stamps(candidate.epoch, &frames) else {
                self.dropped.extend(candidate.keys());
                if let Some(held) =
                    self.warn_due("the stamps of the candidate seed do not match it")
                {
                    tracing::warn!(target: LOG_TARGET, held, author = %candidate.frame.author, "the stamps of the candidate seed do not match it");
                }
                return None;
            };
            Some(found)
        } else {
            None
        };
        // A state seed names the stamp of each path. A leaf that this node holds with a stamp above
        // the stamp that the seed holds for it (or for an object that holds it) is a write that the
        // seed lacks, and the node writes it again with its stamp. A leaf that the seed holds with
        // a higher stamp stays as the seed has it. No cut is needed: the rule is the same for the
        // next epoch, a jump, and a rival seed.
        let theirs: HashMap<Vec<String>, Stamp> = match recorded.as_ref() {
            Some((found, dead)) => seed_stamp_map(found, dead),
            None => HashMap::new(),
        };
        let mut pending: Vec<(Vec<String>, Value, Stamp)> = match recorded.as_ref() {
            Some(_) => self.pending_writes(&theirs),
            None => Vec::new(),
        };
        // A delete of this node that the seed does not know of is written again as well, if the
        // seed holds the value: its tombstone has the higher stamp. A value that the document
        // still holds at that path is older than the delete (a newer write would have removed the
        // tombstone), so what is written is the delete.
        if let Some((found, _)) = recorded.as_ref() {
            // Whether the seed holds a value that the delete outranks is a question about the
            // values of the seed, not about its tombstones: a seed can hold a value and a tombstone
            // of a higher stamp for it (its cutter had not yet written the delete again).
            let held_by_seed = seed_stamp_map(found, &[]);
            for (path, stamp) in &self.tombstones {
                let bar: Option<&Stamp> = (1..=path.len())
                    .filter_map(|depth| held_by_seed.get(&path[..depth]))
                    .max();
                if bar.is_none_or(|held| stamp > held) {
                    pending.push((path.clone(), Value::Null, stamp.clone()));
                }
            }
        }
        let mut seed_hashes: HashSet<ChangeHash> = candidate.tail.keys().copied().collect();
        seed_hashes.insert(candidate.root_hash);
        let mut switch = self.switch_to(candidate.epoch, me);
        self.adopting = true;
        for frame in &frames {
            if !matches!(self.ingest(frame), Ingested::Applied { .. }) {
                // Automerge can still refuse the change in `apply`, which only a crafted frame reaches.
                self.dropped.push(frame.dedup_key());
                if let Some(refused) =
                    self.warn_due("the candidate of the new epoch was not applied")
                {
                    tracing::warn!(target: LOG_TARGET, refused, author = %frame.author, "the candidate of the new epoch was not applied");
                }
            }
        }
        self.adopting = false;
        self.seed_bytes = self.frame_bytes;
        self.seed_ops = self.ops_held;
        if let Some((found, dead)) = recorded {
            self.origins = found;
            // The tombstones of the seed join ours. A tombstone that the seed beats with a live
            // value of a higher stamp is of no use any more.
            for (path, stamp) in dead {
                self.add_tombstone(path, stamp);
            }
            let live = seed_stamp_map(&self.origins, &[]);
            self.tombstones
                .retain(|path, stamp| live.get(path).is_none_or(|held| &*stamp >= held));
        }
        if candidate.mark.is_some() {
            self.seed_author = Some(candidate.frame.key());
            self.seed_hashes = seed_hashes;
        }
        // The author of a write writes it again at once. A node that holds a write of another node
        // keeps it for 1 to 3 ticks: if the author's replay arrives first, the stamp that it
        // names is the stamp that this node holds, and there is nothing left to write.
        let own_tag = format!("{:016x}", self.own_tag.load(Ordering::Relaxed));
        let (own, others): (Vec<_>, Vec<_>) = pending
            .into_iter()
            .partition(|(_, _, stamp)| stamp.tag == own_tag);
        let mut own_writes = own;
        // The value of an object of this node holds the children that other nodes wrote. A child
        // is written again with its own stamp when its wait is over, and not here, where it would
        // get a fresh stamp that outranks a delete of the child.
        for (path, value, _) in &mut own_writes {
            for (child, _, _) in &others {
                if child.len() > path.len() && child.starts_with(path) {
                    remove_path(value, &child[path.len()..]);
                }
            }
        }
        // Only the leaves and the deletes wait: an object as a whole replaces the keys below it,
        // and the leaves below it that have a write of another node are named on their own.
        for (path, value, stamp) in others {
            if !is_full_object(&value) {
                self.keep_restore(path, (value, stamp));
            }
        }
        let jitter = 1 + (self.own_tag.load(Ordering::Relaxed) ^ candidate.epoch) % 3;
        self.restores_due = u32::try_from(jitter).unwrap_or(3);
        let mut leaves: Vec<(Vec<String>, Value)> = Vec::new();
        let mut stamped: StampedPaths = Vec::new();
        for (path, value, stamp) in &own_writes {
            leaves.push((path.clone(), value.clone()));
            stamped.push((path.clone(), stamp.clone()));
        }
        switch.replay = self.replay_patch(leaves);
        if switch.replay.is_some() {
            switch.replay_stamps = stamped;
        }
        Some(switch)
    }

    /// The leaves and the objects that this document holds with a stamp above the one that the
    /// seed holds for them (`theirs`): the writes that the seed lacks. The stamp of an object is
    /// the stamp of the write that made it, so an object that was deleted and made again is a
    /// write of the whole object, which replaces the keys that the seed holds below it. A path
    /// with no stamp is not a write of anyone. The shorter paths come first.
    fn pending_writes(
        &self,
        theirs: &HashMap<Vec<String>, Stamp>,
    ) -> Vec<(Vec<String>, Value, Stamp)> {
        let now: Value = self.to_json();
        let mut leaves: Vec<(Vec<String>, Value)> = Vec::new();
        collect_leaves(&now, &mut Vec::new(), &mut leaves);
        let mut objects: Vec<(Vec<String>, Value)> = Vec::new();
        collect_objects(&now, &mut Vec::new(), &mut objects);
        objects.extend(leaves);
        let paths: Vec<Vec<String>> = objects.iter().map(|(path, _)| path.clone()).collect();
        let mine = self.stamps_of(&paths);
        let floors = self.tombstone_floors(&paths);
        let mut pending: Vec<(Vec<String>, Value, Stamp)> = Vec::new();
        let rows = objects.into_iter().zip(mine).zip(floors);
        for (((path, value), stamp), floor) in rows {
            let Some(stamp) = stamp else { continue };
            // A value below a delete of a higher stamp is dead: the delete is what is written.
            if floor.is_some_and(|dead| dead >= stamp) {
                continue;
            }
            let bar: Option<&Stamp> = (1..=path.len())
                .filter_map(|depth| theirs.get(&path[..depth]))
                .max();
            if bar.is_none_or(|held| stamp > *held) {
                pending.push((path, value, stamp));
            }
        }
        pending.sort_by_key(|(path, _, _)| path.len());
        pending
    }

    /// The merge that writes again the `leaves` that the document does not hold yet. A leaf that
    /// the new epoch already holds with the same value is left out, so a write that every node
    /// holds is not sent again by every node.
    fn replay_patch(&self, leaves: Vec<(Vec<String>, Value)>) -> Option<Value> {
        let now: Value = self.to_json();
        let mut merge: Map<String, Value> = Map::new();
        let mut lacking = false;
        for (path, value) in leaves {
            let holds: Option<&Value> = lookup(&now, &path);
            let same = match holds {
                Some(held) => *held == value,
                None => value.is_null(),
            };
            if !same {
                set_path(&mut merge, &path, replace_with(&value, holds));
                lacking = true;
            }
        }
        lacking.then_some(Value::Object(merge))
    }

    /// Drop every frame and start `epoch`, and hand back the entry of `me`, which only `me` can
    /// write again.
    fn switch_to(&mut self, epoch: u64, me: &Nickname) -> EpochSwitch {
        let gate_map = self.gate.as_ref().map(|gate| gate.map.clone());
        let map: String = gate_map.unwrap_or_default();
        let json = self.to_json();
        let peers = json.get(&map);
        let own_entry: Option<Value> = peers.and_then(|peers| peers.get(me.as_str())).cloned();
        self.restart(epoch);
        EpochSwitch::new(epoch, map, own_entry)
    }

    /// Forget the history: a document of `epoch` that holds its genesis and nothing else. The
    /// orphans go with it, and their dedup keys stay seen, because an old epoch is dead.
    fn restart(&mut self, epoch: u64) {
        let mut doc = Automerge::new();
        let mut applied = HashSet::new();
        if let Some(genesis) = self.genesis(epoch) {
            applied.insert(genesis.hash());
            let _ = doc.apply_changes([genesis]);
        }
        *self.doc = doc;
        self.applied = applied;
        self.frames = HashMap::new();
        self.frame_bytes = 0;
        self.ops_held = 0;
        self.seed_bytes = 0;
        self.seed_ops = 0;
        self.crossed_ticks = None;
        self.cut_wait = 0;
        self.cut_backoff = DOC_CUT_BACKOFF_FIRST;
        self.refused = BoundedFifoSet::new(self.limits.refused_max);
        self.pending = HashMap::new();
        self.candidate = None;
        self.candidate_ticks = 0;
        self.epoch = epoch;
        self.epoch_ticks = 0;
        self.restores_due = 0;
        self.settled_bytes = 0;
        self.seed_author = None;
        self.seed_hashes = HashSet::new();
        self.refused_rivals = Vec::new();
        self.origins = HashMap::new();
    }

    /// The plan of a cut of this document: its live JSON, the stamp of each live leaf, its
    /// tombstones and the time of the seed (it takes one from the clock). The read costs in
    /// proportion to the size of the document; the chain is built from the plan with
    /// [`SeedPlan::build`], on another thread if the caller wants the loop free, and the cutter
    /// calls [`Self::note_seed_built`] with the chain.
    ///
    /// # Errors
    /// [`DocError::CandidateHeld`] when the document waits to adopt a candidate seed.
    pub fn seed_plan(&self) -> Result<SeedPlan, DocError> {
        if self.candidate.is_some() {
            return Err(DocError::CandidateHeld);
        }
        let live = self.without_dead_values();
        // The paths that a change of the seed writes are its leaves and the objects that it makes,
        // so the plan holds the stamp of both.
        let mut leaves: Vec<(Vec<String>, Value)> = Vec::new();
        collect_leaves(&live, &mut Vec::new(), &mut leaves);
        let mut objects: Vec<(Vec<String>, Value)> = Vec::new();
        collect_objects(&live, &mut Vec::new(), &mut objects);
        let mut paths: Vec<Vec<String>> = Vec::with_capacity(leaves.len() + objects.len());
        for (path, _) in leaves {
            paths.push(path);
        }
        for (path, _) in objects {
            paths.push(path);
        }
        let found = self.stamps_of(&paths);
        let mut stamps: HashMap<Vec<String>, Stamp> = HashMap::with_capacity(paths.len());
        let named = paths.into_iter().zip(found);
        for (path, stamp) in named {
            if let Some(stamp) = stamp {
                stamps.insert(path, stamp);
            }
        }
        let mut tombstones: Vec<(Vec<String>, Stamp)> = Vec::with_capacity(self.tombstones.len());
        for (path, stamp) in &self.tombstones {
            tombstones.push((path.clone(), stamp.clone()));
        }
        Ok(SeedPlan {
            live,
            stamps,
            tombstones,
            time: self.next_time(),
        })
    }

    /// Count the paths of a built seed that got the stamp 0 for want of a time, and warn: a value
    /// that gets 0 loses to every replay.
    pub fn note_seed_built(&self, chain: &SeedChain) {
        if chain.unstamped > 0 {
            self.unstamped.fetch_add(chain.unstamped, Ordering::Relaxed);
            let zeros = chain.unstamped;
            tracing::warn!(target: LOG_TARGET, zeros, "a seed path got the stamp 0 for want of a time");
        }
    }

    /// The seed of `epoch`: the live JSON of this document, cut by leaf path into merges that each
    /// fit one frame, written as a chain of changes on the genesis of `epoch`. A node that starts
    /// the epoch sends the chain, and a node that adopts it holds the same live values, with no
    /// history. `fits` takes one merge and says whether its frame is small enough, as
    /// [`pack_entry`] does: the caller measures the real frame, signed and sealed.
    /// `actor_seed` is the actor of the chain, the signing key of the cutter, as for
    /// [`Self::build_change`]. An empty document gives a chain of 1 change that writes a key and
    /// deletes it, so a seed always has a root. This is [`Self::seed_plan`], [`SeedPlan::build`]
    /// and [`Self::note_seed_built`] on the calling thread.
    ///
    /// # Errors
    /// [`DocError::TooLarge`] when one leaf does not fit a frame, [`DocError::Encode`] when a
    /// merge does not encode, and [`DocError::CandidateHeld`] when the document waits to adopt a
    /// candidate seed.
    pub fn build_seed(
        &self,
        epoch: u64,
        actor_seed: &[u8],
        fits: impl FnMut(&Value) -> bool,
    ) -> Result<SeedChain, DocError> {
        let plan = self.seed_plan()?;
        let chain = plan.build(epoch, actor_seed, fits)?;
        self.note_seed_built(&chain);
        Ok(chain)
    }

    /// The JSON of this document without the values that a tombstone of a higher stamp governs. A
    /// replay of another node can bring such a value back for a while (the restore removes it
    /// again), and a seed must not carry it: a node that adopts it would hold a value that the
    /// seed itself says was deleted.
    fn without_dead_values(&self) -> Value {
        let mut live: Value = self.to_json();
        if self.tombstones.is_empty() {
            return live;
        }
        let mut leaves: Vec<(Vec<String>, Value)> = Vec::new();
        collect_leaves(&live, &mut Vec::new(), &mut leaves);
        let paths: Vec<Vec<String>> = leaves.into_iter().map(|(path, _)| path).collect();
        let stamps = self.stamps_of(&paths);
        let floors = self.tombstone_floors(&paths);
        let rows = paths.iter().zip(stamps).zip(floors);
        for ((path, stamp), floor) in rows {
            let dead = match (stamp, floor) {
                (Some(held), Some(floor)) => held < floor,
                (None, Some(_)) => true,
                (_, None) => false,
            };
            if dead {
                remove_path(&mut live, path);
            }
        }
        live
    }

    /// The stamps that the frames of a seed name, checked against the changes: a scratch document
    /// of `epoch` applies the changes in order, and each frame must carry one stamp for each path
    /// that its change writes, and the tombstones of the root. `None` when a frame carries a number of
    /// stamps that does not match, more than `DOC_REPLAY_ENTRIES_MAX`, tombstones outside the root
    /// or more than `DOC_SEED_TOMBSTONES_MAX`, or no body.
    fn read_seed_stamps(&self, epoch: u64, frames: &[Verified]) -> Option<SeedRead> {
        let mut scratch = Automerge::new();
        scratch.apply_changes([state_genesis(epoch)]).ok()?;
        let mut found: SeedStamps = HashMap::new();
        let mut dead: Vec<(Vec<String>, Stamp)> = Vec::new();
        for frame in frames {
            let parsed = self.change_bytes(frame)?;
            // The tombstones of the chain, frame after frame, are in the order of their paths with
            // none twice, and no more than a node keeps.
            for entry in parsed.tombstones {
                if dead.last().is_some_and(|last| last.0 >= entry.0) {
                    return None;
                }
                dead.push(entry);
            }
            if dead.len() > DOC_SEED_TOMBSTONES_MAX {
                return None;
            }
            let change = Change::from_bytes(parsed.bytes).ok()?;
            scratch.apply_changes([change.clone()]).ok()?;
            let paths = change_leaves(&scratch, &change);
            if paths.len() != parsed.origins.len() || paths.len() > DOC_REPLAY_ENTRIES_MAX {
                return None;
            }
            let named: StampedPaths = paths.into_iter().zip(parsed.origins).collect();
            found.insert(change.hash(), named);
        }
        Some((found, dead))
    }

    /// The genesis of `epoch` for this channel: the per-peer map of a gated channel (meta), the
    /// empty genesis of a state channel above epoch 0, and nothing for epoch 0 of a state channel.
    fn genesis(&self, epoch: u64) -> Option<Change> {
        match self.gate.as_ref() {
            Some(gate) => Some(peers_genesis(&gate.map, epoch)),
            None if epoch == 0 => None,
            None => Some(state_genesis(epoch)),
        }
    }

    /// The same document in `epoch`, with no change but its genesis.
    #[must_use]
    fn at_epoch(mut self, epoch: u64) -> Self {
        self.restart(epoch);
        self
    }

    /// How many changes this document holds, the internal genesis included.
    #[must_use]
    pub fn change_count(&self) -> usize {
        self.applied.len()
    }

    /// The signed frames for changes a peer with heads `have` is missing, oldest
    /// first (the roots of a history come first, so a capped answer can start a
    /// peer that holds none of it), capped at `max`. Undecodable heads are ignored (we
    /// then over-serve, never under-serve). The genesis change has no frame and
    /// is never sent — every replica constructs it locally.
    pub fn changes_since(&self, have: &[String], max: usize) -> impl Iterator<Item = Verified> {
        self.changes_since_not_by(have, None, max)
    }

    /// [`Self::changes_since`] without the frames signed by `author`: a peer
    /// holds every change it signed, since a change's actor is its signer's
    /// key and a session key lives no longer than its document. Skipped
    /// before the cap, so the budget goes to what the peer can lack. `None`
    /// skips nothing.
    pub fn changes_since_not_by(
        &self,
        have: &[String],
        author: Option<&AuthorKey>,
        max: usize,
    ) -> impl Iterator<Item = Verified> {
        let have: Vec<ChangeHash> = have
            .iter()
            .filter_map(|encoded| decode_hash(encoded))
            .collect();
        let changes = self.doc.get_changes(&have).into_iter();
        let frames = changes.filter_map(|change| self.frames.get(&change.hash()));
        let kept = frames.filter(move |frame| author.is_none_or(|skipped| &frame.key() != skipped));
        kept.take(max).cloned()
    }

    /// Whether this document holds every change in `heads`, Base58-encoded as
    /// [`Self::heads`] gives them: a peer that advertises these heads is not
    /// ahead of us. A head that does not decode counts as not held.
    #[must_use]
    pub fn holds_heads(&self, heads: &[String]) -> bool {
        heads.iter().all(|encoded| {
            decode_hash(encoded).is_some_and(|hash| self.doc.get_change_by_hash(&hash).is_some())
        })
    }

    /// The derived document as JSON — the shape a consumer's `state`/`meta` read returns.
    #[must_use]
    pub fn to_json(&self) -> Value {
        doc_json(&self.doc)
    }

    /// Translate an RFC 7386 merge document into a single automerge change,
    /// computed against current heads **without mutating the live doc**. `None`
    /// when the merge produced no ops. The caller size-gates the resulting frame
    /// before feeding the bytes back through [`MeshDoc::ingest`] to apply them,
    /// so an oversize change never lands in the doc it could not be gossiped for.
    ///
    /// `actor_seed` must be unique per session — the daemon passes its signing
    /// public key (see `actor_for`).
    ///
    /// # Errors
    /// # Errors
    /// [`DocError::Encode`] when the change does not encode, or [`DocError::Body`] when
    /// it is not a valid message body.
    pub fn build_change(
        &self,
        merge: &Value,
        actor_seed: &[u8],
    ) -> Result<Option<Vec<u8>>, DocError> {
        let Value::Object(_) = merge else {
            return Err(DocError::NotAnObject);
        };
        let mut fork = self.doc.fork();
        let actor = actor_for(actor_seed);
        self.own_tag
            .store(actor_tag_number(&actor), Ordering::Relaxed);
        fork.set_actor(actor);
        let heads = fork.get_heads();
        {
            let mut tx = fork.transaction();
            write_map(&mut tx, &ROOT, merge).map_err(DocError::encode)?;
            tx.commit();
        }
        let mut changes = fork.get_changes(&heads);
        let Some(change) = changes.pop() else {
            return Ok(None);
        };
        self.check_lines(merge, &change, false)?;
        Ok(Some(change.raw_bytes().to_vec()))
    }

    /// [`Self::build_change`] for a write that puts back a value that this node held (a replay of
    /// its own writes, or a restore). It is not refused at the refusal line or for its depth,
    /// because it adds nothing that the document did not hold, but it is refused over the memory
    /// line.
    ///
    /// # Errors
    /// As [`Self::build_change`].
    pub fn build_restore(
        &self,
        merge: &Value,
        actor_seed: &[u8],
    ) -> Result<Option<Vec<u8>>, DocError> {
        let mut fork = self.doc.fork();
        let actor = actor_for(actor_seed);
        self.own_tag
            .store(actor_tag_number(&actor), Ordering::Relaxed);
        fork.set_actor(actor);
        let heads = fork.get_heads();
        {
            let mut tx = fork.transaction();
            write_map(&mut tx, &ROOT, merge).map_err(DocError::encode)?;
            tx.commit();
        }
        let mut changes = fork.get_changes(&heads);
        let Some(change) = changes.pop() else {
            return Ok(None);
        };
        self.check_lines(merge, &change, true)?;
        Ok(Some(change.raw_bytes().to_vec()))
    }

    /// Whether applying `change` (in `frame`) would take this document over its remote line: the
    /// memory line of a local write (the frames, or the operations) and the room of a remote flood
    /// above it. It is a bound on memory, not a policy: a node that refuses a frame holds less than
    /// the nodes that took it, and the next seed brings the difference.
    fn over_remote_line(&self, change: &Change, frame: &Verified) -> bool {
        let bytes = &self.limits.bytes;
        let ops = &self.limits.ops;
        let frames_after = self.frame_bytes + wire_len(frame);
        let ops_after = self.ops_held + change.len();
        let line_bytes =
            bytes.memory.max(self.seed_bytes + bytes.break_even / 10) + bytes.remote_extra;
        let line_ops = ops.memory.max(self.seed_ops + ops.break_even / 10) + ops.remote_extra;
        frames_after > line_bytes || ops_after > line_ops
    }

    /// A leaf that this write adds must fit a frame of a seed, with the largest stamp, the margin
    /// of the envelope and the envelope itself. If one did not, the write would pass the frame of
    /// the write (which has no stamp) and every later cut would fail on it. Only a leaf of
    /// `SEED_LEAF_CHECK_MIN` bytes or more is built and measured: a smaller one always fits.
    fn check_seed_frames(merge: &Value) -> Result<(), DocError> {
        let mut leaves: Vec<(Vec<String>, Value)> = Vec::new();
        collect_leaves(merge, &mut Vec::new(), &mut leaves);
        for (path, value) in &leaves {
            if value.is_null() {
                continue;
            }
            let path_bytes: usize = path.iter().map(String::len).sum();
            let json_bytes: usize = serde_json::to_vec(value).map_or(0, |bytes| bytes.len());
            if path_bytes + json_bytes < SEED_LEAF_CHECK_MIN {
                continue;
            }
            let body = seed_frame_body_len(path, value);
            if body + DOC_EPOCH_FRAME_MARGIN + DOC_STATE_ENVELOPE_BYTES > MAX_MESSAGE_SIZE {
                return Err(DocError::TooLarge {
                    bytes: path_bytes + json_bytes,
                });
            }
        }
        Ok(())
    }

    /// The lines of a free-form state document, for a local write whose `change` was built from
    /// `merge`. A merge nested deeper than `DOC_STATE_DEPTH_MAX` that adds a value is refused. Any
    /// write is refused over the memory line, and a write that adds a value (a leaf that is not
    /// `null`, or an empty object) is refused when the next seed would pass the refusal line, on
    /// the bytes or on the operations. A delete is exempt from the refusal line and from the depth.
    fn check_lines(&self, merge: &Value, change: &Change, restoring: bool) -> Result<(), DocError> {
        if !self.state_epochs || self.gate.is_some() {
            return Ok(());
        }
        let adds = adds_value(merge) && !restoring;
        if adds {
            Self::check_seed_frames(merge)?;
            let depth = merge_depth(merge);
            if depth > DOC_STATE_DEPTH_MAX {
                return Err(DocError::StateTooDeep {
                    depth,
                    limit: DOC_STATE_DEPTH_MAX,
                });
            }
        }
        let bytes = &self.limits.bytes;
        let ops = &self.limits.ops;
        // The frame of a change is its bytes in base58 (a factor of 1.37) and the margin of the
        // envelope.
        let frame = change.raw_bytes().len() * 137 / 100 + DOC_EPOCH_FRAME_MARGIN;
        let frames_after = self.frame_bytes + frame;
        let ops_after = self.ops_held + change.len();
        let memory_bytes = bytes.memory.max(self.seed_bytes + bytes.break_even / 10);
        let memory_ops = ops.memory.max(self.seed_ops + ops.break_even / 10);
        if frames_after > memory_bytes {
            return Err(full(frames_after, memory_bytes, "bytes"));
        }
        if ops_after > memory_ops {
            return Err(full(ops_after, memory_ops, "operations"));
        }
        if !adds {
            return Ok(());
        }
        let growth_bytes = frames_after.saturating_sub(self.seed_bytes);
        let growth_ops = ops_after.saturating_sub(self.seed_ops);
        let clock = self.clock.load(Ordering::Relaxed);
        let projected = Limits::projected_bytes(self.seed_bytes, growth_bytes, growth_ops, clock);
        if projected > bytes.refuse_add {
            return Err(full(projected, bytes.refuse_add, "bytes"));
        }
        if ops_after > ops.refuse_add {
            return Err(full(ops_after, ops.refuse_add, "operations"));
        }
        Ok(())
    }

    /// Ingest one verified frame carrying an automerge change. Verifies causal
    /// readiness and card authorization before applying; buffers orphans (as
    /// frames, so re-serve and the gate both see the original signed frame). The
    /// `Verified` proof means the signature was checked before the frame got here,
    /// so the signer is `frame.key()`, never a field of the body.
    pub fn ingest(&mut self, frame: &Verified) -> Ingested {
        let Some(parsed) = self.change_bytes(frame) else {
            return Ingested::Ignored;
        };
        let (epoch, mark, time) = (parsed.epoch, parsed.seed, parsed.time);
        if parsed.origins.len() + parsed.tombstones.len() > DOC_REPLAY_ENTRIES_MAX {
            if let Some(refused) = self.warn_due("a frame carries more stamps than the cap") {
                tracing::warn!(target: LOG_TARGET, refused, author = %frame.author, "a frame carries more stamps than the cap");
            }
            return Ingested::Ignored;
        }
        let Ok(change) = Change::from_bytes(parsed.bytes) else {
            return Ingested::Ignored;
        };
        let author = frame.key();
        if change.actor_id().to_bytes() != author.as_bytes().as_slice() {
            if let Some(changes) =
                self.warn_due("dropping a channel change whose actor is not its signer's key")
            {
                tracing::warn!(target: LOG_TARGET, changes, author = %frame.author, "dropping a channel change whose actor is not its signer's key");
            }
            return Ingested::Ignored;
        }
        if self.state_epochs && self.gate.is_none() {
            // A state change names its Lamport time, and a node that cannot place it before or
            // after its own writes would break the order of the replay rule.
            let Some(stamped) = time.filter(|stamped| *stamped < DOC_TIME_MAX) else {
                self.refused_time = self.refused_time.saturating_add(1);
                if let Some(refused) =
                    self.warn_due("a state change with no valid time was refused")
                {
                    tracing::warn!(target: LOG_TARGET, refused, author = %frame.author, "a state change with no valid time was refused");
                }
                return Ingested::Ignored;
            };
            self.clock.fetch_max(stamped, Ordering::Relaxed);
        }
        if epoch != self.epoch {
            return self.ingest_other_epoch(epoch, &change, frame, mark);
        }
        if self.state_epochs
            && !self.adopting
            && self.gate.is_none()
            && self.epoch > 0
            && let Some(taken) = self.rival_seed_frame(&change, frame, mark)
        {
            return taken;
        }
        let hash = change.hash();
        if self.applied.contains(&hash) {
            return Ingested::Duplicate;
        }
        if !self.deps_satisfied(change.deps()) {
            return self.buffer_orphan(author, hash, change, frame);
        }
        if self.state_epochs && self.gate.is_none() && !self.adopting {
            if self.refused.contains(&hash) {
                return Ingested::Ignored;
            }
            if self.over_remote_line(&change, frame) {
                self.refused.insert(hash);
                self.refused_remote = self.refused_remote.saturating_add(1);
                if let Some(refused) =
                    self.warn_due("a frame was refused: the state document is over its remote line")
                {
                    tracing::warn!(target: LOG_TARGET, refused, held = self.refused_remote, author = %frame.author, "a frame was refused: the state document is over its remote line");
                }
                return Ingested::Ignored;
            }
        }
        // Hoisted above the gate so the two share one hydration: nothing
        // mutates the document between them, and `doc_json` over the whole
        // `meta` map was the dominant cost of ingesting a frame. On the
        // rejection path this pays for a hydration it does not use, which is
        // the rare adversarial case rather than the steady-state one.
        if self.adopting && self.gate.is_none() {
            // The frames of a seed that a free-form channel adopts: nobody reads the JSON of the
            // document after each one, and the channel has no gate that needs `before`. Two
            // hydrations of the whole document for each frame made an adoption cost the square of
            // the size of the state. A gated channel keeps the full path: its gate needs `before`.
            if !self.apply(change, hash, frame.clone()) {
                return Ingested::Ignored;
            }
            self.drain_pending();
            return Ingested::Applied {
                changed: true,
                doc: Value::Null,
            };
        }
        let before = self.to_json();
        if self.forges_foreign_entry(&change, &frame.author, Some(&before)) {
            return Ingested::Rejected;
        }
        if !self.apply(change, hash, frame.clone()) {
            // Refused by automerge, so nothing was recorded and nothing it
            // could have unblocked has changed. `apply` has already said why.
            return Ingested::Ignored;
        }
        self.drain_pending();
        let after = self.to_json();
        Ingested::Applied {
            changed: before != after,
            doc: after,
        }
    }

    /// A frame of another epoch than the one that the document holds.
    ///
    /// A lower epoch is dead: ignored, and its dedup key stays seen, because it can never be of use
    /// again. A higher epoch is never applied here. It becomes the candidate only if the frame is a
    /// root of that epoch (its only dependency is the genesis of the epoch), is no further than
    /// `DOC_EPOCH_JUMP_MAX` above, and passes the gate on a fresh document of that epoch. Every
    /// other refusal forgets the dedup key, so the re-send of the frame is not dropped as a repeat
    /// when it can be taken later.
    fn ingest_other_epoch(
        &mut self,
        epoch: u64,
        change: &Change,
        frame: &Verified,
        mark: Option<SeedMark>,
    ) -> Ingested {
        if epoch < self.epoch {
            return Ingested::Ignored;
        }
        if epoch - self.epoch > DOC_EPOCH_JUMP_MAX {
            return self.refuse_frame(frame);
        }
        let Some(genesis) = self.genesis(epoch) else {
            return self.refuse_frame(frame);
        };
        if change.deps() != [genesis.hash()] {
            return self.take_tail_frame(epoch, change, frame);
        }
        let mark: Option<SeedMark> = if let Some(gate) = self.gate.clone() {
            let fresh = Self::new_gated(gate).at_epoch(epoch);
            if fresh.forges_foreign_entry(change, &frame.author, None) {
                return Ingested::Rejected;
            }
            None
        } else {
            if !self.state_epochs {
                return self.refuse_frame(frame);
            }
            let named: usize = mark.as_ref().map_or(0, |named| named.frames as usize);
            if named == 0 || named > DOC_SEED_FRAMES_MAX {
                return self.refuse_frame(frame);
            }
            mark
        };
        match self.candidate.as_ref() {
            Some(held) if held.epoch == epoch && held.frame.dedup_key() == frame.dedup_key() => {
                return Ingested::Duplicate;
            }
            // Two seeds of one epoch: the root with the lowest key wins on every node.
            Some(held)
                if held.epoch == epoch
                    && mark.is_some()
                    && beats(&frame.key(), &held.frame.key()) => {}
            Some(held) if held.epoch >= epoch => return self.refuse_frame(frame),
            _ => {}
        }
        let kept = Candidate::new(epoch, frame.clone(), change, mark);
        match self.candidate.replace(Box::new(kept)) {
            Some(beaten) => self.dropped.extend(beaten.keys()),
            None => self.candidate_ticks = 0,
        }
        Ingested::NewEpoch { epoch }
    }

    /// A frame of the epoch that the document holds that belongs to a rival seed: another node cut
    /// the same epoch from another view. `None` when the frame is no part of a rival seed.
    fn rival_seed_frame(
        &mut self,
        change: &Change,
        frame: &Verified,
        mark: Option<SeedMark>,
    ) -> Option<Ingested> {
        let genesis: Change = state_genesis(self.epoch);
        let is_root = change.deps() == [genesis.hash()];
        if is_root && mark.is_some() {
            if self.applied.contains(&change.hash()) {
                return Some(Ingested::Duplicate);
            }
            return Some(self.take_rival_root(change, frame, mark));
        }
        if self.deps_satisfied(change.deps()) {
            return None;
        }
        let rival_chain = self
            .candidate
            .as_ref()
            .is_some_and(|held| held.epoch == self.epoch);
        if rival_chain {
            return Some(self.take_tail_frame(self.epoch, change, frame));
        }
        if self.refused_rivals.contains(&frame.key()) {
            return Some(self.refuse_frame(frame));
        }
        None
    }

    /// The root of a rival seed of the epoch that the document holds. The seed whose root has the
    /// lowest key wins on every node, so all nodes end in one seed. A lower root becomes the
    /// candidate and the document switches to it after the wait, as for a higher epoch.
    fn take_rival_root(
        &mut self,
        change: &Change,
        frame: &Verified,
        mark: Option<SeedMark>,
    ) -> Ingested {
        let named: usize = mark.as_ref().map_or(0, |mark| mark.frames as usize);
        let Some(adopted) = self.seed_author else {
            return self.refuse_frame(frame);
        };
        if named == 0 || named > DOC_SEED_FRAMES_MAX {
            return self.refuse_frame(frame);
        }
        if let Some(held) = self.candidate.as_ref()
            && held.epoch == self.epoch
            && held.frame.dedup_key() == frame.dedup_key()
        {
            return Ingested::Duplicate;
        }
        let standing: AuthorKey = match self.candidate.as_ref() {
            Some(held) if held.epoch == self.epoch => held.frame.key(),
            _ => adopted,
        };
        if !beats(&frame.key(), &standing) {
            if self.refused_rivals.len() >= 8 {
                self.refused_rivals.remove(0);
            }
            self.refused_rivals.push(frame.key());
            return self.refuse_frame(frame);
        }
        let kept = Candidate::new(self.epoch, frame.clone(), change, mark);
        match self.candidate.replace(Box::new(kept)) {
            Some(beaten) => self.dropped.extend(beaten.keys()),
            None => self.candidate_ticks = 0,
        }
        Ingested::NewEpoch { epoch: self.epoch }
    }

    /// Forget the dedup key of a frame that the document does not take, so its re-send is not
    /// dropped as a repeat when it can be taken later.
    fn refuse_frame(&mut self, frame: &Verified) -> Ingested {
        self.dropped.push(frame.dedup_key());
        Ingested::Ignored
    }

    /// A frame of a higher epoch that is not a root: a later frame of the seed chain that the
    /// candidate holds. Only the author of the root sends the chain, and the candidate holds as
    /// many frames as the mark of its root names, so a flood of tail frames cannot grow it.
    fn take_tail_frame(&mut self, epoch: u64, change: &Change, frame: &Verified) -> Ingested {
        let hash = change.hash();
        let Some(held) = self.candidate.as_mut() else {
            return self.refuse_frame(frame);
        };
        let named = held.mark.as_ref().map_or(0, |mark| mark.frames as usize);
        let [parent] = change.deps() else {
            return self.refuse_frame(frame);
        };
        if held.epoch != epoch || named < 2 || frame.key() != held.frame.key() {
            return self.refuse_frame(frame);
        }
        if hash == held.root_hash || held.tail.contains_key(&hash) {
            return Ingested::Duplicate;
        }
        // The changes of the chain are one actor's, so their sequence numbers follow the root one
        // by one. A write of the cutter after the seed, and every write that follows it, has a
        // number above them. A second frame that follows one change is a fork.
        let last_seq: u64 = held.root_seq + u64::try_from(named).unwrap_or(u64::MAX) - 1;
        let outside = change.seq() <= held.root_seq || change.seq() > last_seq;
        let forked = held.tail.values().any(|kept| kept.parent == *parent);
        if outside || forked {
            return self.refuse_frame(frame);
        }
        if held.tail.len() + 1 >= named {
            // The slots are full. A frame that is off the path from the root has no place that a
            // frame of the chain needs, so one of them gives way.
            let on_path = held.on_path();
            let off_path: Option<ChangeHash> = held.first_off_path(&on_path);
            let Some(victim) = off_path else {
                return self.refuse_frame(frame);
            };
            if let Some(gone) = held.tail.remove(&victim) {
                self.dropped.push(gone.frame.dedup_key());
            }
        }
        let Some(slots) = self.candidate.as_mut() else {
            return self.refuse_frame(frame);
        };
        let kept = TailFrame {
            frame: frame.clone(),
            parent: *parent,
        };
        slots.tail.insert(hash, kept);
        Ingested::NewEpoch { epoch }
    }

    /// Apply a change and record it, or record nothing.
    ///
    /// Returns whether the document took it. The two must not come apart: a
    /// hash in `applied` that the document does not hold makes every descendant
    /// pass `deps_satisfied`, so those land in automerge's own queue instead of
    /// the document and are recorded as applied in turn. Anti-entropy cannot
    /// repair it either — a re-served frame is answered `Duplicate` by the very
    /// bookkeeping that is wrong.
    ///
    /// The refusal this actually sees is a repeated `(actor, seq)` carrying
    /// different content, which automerge rejects before it looks at deps.
    /// Missing deps are not an error there at all; they are queued. An earlier
    /// comment here had both backwards and dropped the error on that basis.
    /// Two processes sharing a signing key reach it without any malice, since
    /// the actor id is derived from the key.
    fn apply(&mut self, change: Change, hash: ChangeHash, frame: Verified) -> bool {
        // A frame of a replay names the stamp of each path that its change writes. The stamps are
        // checked on a fork before the change is applied, so a frame that names them wrongly is
        // refused as a whole, and the node records them after it is applied.
        let stamped: Option<(StampedPaths, Automerge)> = if self.state_epochs && !self.adopting {
            let Ok(stamped) = self.stamped_paths(&change, &frame) else {
                if let Some(refused) = self.warn_due("the stamps of a frame do not match it") {
                    tracing::warn!(target: LOG_TARGET, refused, author = %frame.author, "the stamps of a frame do not match it");
                }
                return false;
            };
            stamped
        } else {
            None
        };
        // A frame of a replay names stamps. Before it is applied, the node finds the leaves that
        // it holds with a stamp, and that the replay changes or hides (the fork that checked the
        // stamps shows how the document will look). If the replay won in automerge with a lower
        // stamp than the value that this node held, the node writes its value again.
        let watch: Option<Vec<Lowered>> = stamped
            .as_ref()
            .map(|(named, after)| self.lowered_leaves(after, named));
        let named: Option<StampedPaths> = stamped.map(|(named, _)| named);
        let seen: Option<Change> = (self.state_epochs && !self.adopting).then(|| change.clone());
        let ops = change.len();
        if let Err(error) = self.doc.apply_changes([change]) {
            if let Some(changes) = self.warn_due("dropping a channel change automerge refused") {
                tracing::warn!(target: LOG_TARGET, changes, %error, author = %frame.author, "dropping a channel change automerge refused");
            }
            return false;
        }
        self.applied.insert(hash);
        if let Some(applied) = seen.as_ref() {
            self.note_deletes(applied, &frame, named.as_deref());
        }
        if let Some(named) = named {
            self.origins.insert(hash, named);
        }
        if let Some(lowered) = watch {
            self.note_lowered(&lowered);
        }
        self.frame_bytes += wire_len(&frame);
        match self.frames.insert(hash, frame) {
            Some(replaced) => self.frame_bytes -= wire_len(&replaced),
            None => self.ops_held += ops,
        }
        true
    }

    /// The highest tombstone at each of `paths` or above it: the stamp of the delete that governs
    /// the path, if a value there would be a value that the delete should have removed.
    fn tombstone_floors(&self, paths: &[Vec<String>]) -> Vec<Option<Stamp>> {
        paths
            .iter()
            .map(|path| self.tombstone_floor(path))
            .collect()
    }

    /// The highest tombstone at `path` or above it.
    fn tombstone_floor(&self, path: &[String]) -> Option<Stamp> {
        let governing = (1..=path.len()).filter_map(|depth| self.tombstones.get(&path[..depth]));
        governing.max().cloned()
    }

    /// The leaves that a replay frame changes or hides, that this node holds with a stamp, and the
    /// leaves that the frame names (for a delete that the frame undoes). `after` is the document as
    /// it will look once the frame is applied. Only the leaves below the objects that the frame
    /// names are compared, and a stamp is read only for a leaf that differs, so the work follows what
    /// the replay changes and not the size of the document. A leaf differs when its value is not the
    /// same after the frame (the replay wrote another value), when the document held it and the
    /// frame hides it (the replay made its object again), or when the frame names it and the document
    /// had no value there (a delete that the frame undoes).
    fn lowered_leaves(&self, after: &Automerge, named: &[(Vec<String>, Stamp)]) -> Vec<Lowered> {
        let named_stamps: HashMap<&Vec<String>, &Stamp> =
            named.iter().map(|(path, stamp)| (path, stamp)).collect();
        let paths: Vec<&[String]> = named.iter().map(|(path, _)| path.as_slice()).collect();
        let mut before_reader = PathReader::new(&self.doc, &paths);
        let mut after_reader = PathReader::new(after, &paths);
        // For each leaf that differs: the value that this node held (`None` for a leaf that the
        // frame names with no value held), and whether the document has a value there after the frame.
        let mut held: BTreeMap<Vec<String>, (Option<Value>, bool)> = BTreeMap::new();
        for (path, _) in named {
            let before = before_reader.value_at(path);
            let now = after_reader.value_at(path);
            if let Some(object) = &before {
                let mut leaves: Vec<(Vec<String>, Value)> = Vec::new();
                collect_leaves(object, &mut path.clone(), &mut leaves);
                for (leaf, value) in leaves {
                    let there = now
                        .as_ref()
                        .and_then(|after_value| lookup(after_value, &leaf[path.len()..]));
                    if there != Some(&value) {
                        held.insert(leaf, (Some(value), there.is_some()));
                    }
                }
            }
            // A leaf that the frame names: a delete that the frame undoes shows here.
            if now.as_ref().is_some_and(|value| !is_full_object(value)) {
                held.entry(path.clone()).or_insert((None, true));
            }
        }
        let leaf_paths: Vec<Vec<String>> = held.keys().cloned().collect();
        let before = self.stamps_of(&leaf_paths);
        leaf_paths
            .into_iter()
            .zip(before)
            .map(|(path, before_stamp)| {
                let (value, present) = held.remove(&path).unwrap_or((None, false));
                let after_stamp: Option<Stamp> = match named_stamps.get(&path) {
                    Some(stamp) if present => Some((*stamp).clone()),
                    _ => None,
                };
                Lowered {
                    path,
                    value,
                    before: before_stamp,
                    after: after_stamp,
                }
            })
            .collect()
    }

    /// Keep what this node must write again after a replay was applied: a value that it held with
    /// a stamp above the stamp that the replay left (or with the leaf hidden), and a delete that
    /// governed a path (a tombstone above the stamp of a value that the replay brought back). The
    /// deletes are kept as `null`.
    fn note_lowered(&mut self, lowered: &[Lowered]) {
        let paths: Vec<Vec<String>> = lowered.iter().map(|leaf| leaf.path.clone()).collect();
        let floors = self.tombstone_floors(&paths);
        let rows = lowered.iter().zip(floors);
        for (leaf, floor) in rows {
            let value_lowered = match (&leaf.before, &leaf.after, &leaf.value) {
                (Some(held), Some(now), Some(_)) => now < held,
                (Some(held), None, Some(_)) => floor.as_ref() < Some(held),
                _ => false,
            };
            let delete_lost = match (&leaf.value, &leaf.after, &floor) {
                (None, Some(now), Some(dead)) => now < dead,
                _ => false,
            };
            let kept: Option<(Value, Stamp)> = if value_lowered {
                leaf.value.clone().zip(leaf.before.clone())
            } else if delete_lost {
                floor.map(|dead| (Value::Null, dead))
            } else {
                None
            };
            if let Some(kept) = kept {
                self.keep_restore(leaf.path.clone(), kept);
            }
        }
    }

    /// Keep a restore for `path`, unless one with a higher stamp waits. A restore that finds the map
    /// full (`DOC_RESTORES_MAX` paths) is dropped, which is a newer write that the node
    /// cannot write again: it is counted and warned, never silent.
    fn keep_restore(&mut self, path: Vec<String>, kept: (Value, Stamp)) {
        if self.restores.len() >= DOC_RESTORES_MAX && !self.restores.contains_key(&path) {
            self.restores_dropped = self.restores_dropped.saturating_add(1);
            if let Some(dropped) =
                self.warn_due("a restore was dropped: the map of restores is full")
            {
                tracing::warn!(target: LOG_TARGET, dropped, "a restore was dropped: the map of restores is full");
            }
            return;
        }
        match self.restores.get(&path) {
            Some(held) if held.1 >= kept.1 => {}
            _ => {
                self.restores.insert(path, kept);
            }
        }
    }

    /// How many restores were dropped because the map of restores was full, since the document
    /// began. Each one is a newer write that this node could not write again.
    #[must_use]
    pub fn dropped_restores(&self) -> u64 {
        self.restores_dropped
    }

    /// Whether a value waits to be written again (see [`Self::take_restores`]).
    #[must_use]
    pub fn has_restores(&self) -> bool {
        !self.restores.is_empty()
    }

    /// The values that this node must write again because a replay of another node set a lower
    /// stamp on them, and the deletes that a replay undid: a merge and the stamp of each path, for
    /// [`Self::compose_replay_body`]. The live stamps are read again here, so a value that a
    /// newer write, or a delete of a higher stamp, has overtaken in the meantime is not written.
    /// That read saves writes and is not needed for convergence: a node that writes an overtaken
    /// value anyway lowers the stamp of the newer value on the nodes that hold it, and they restore it.
    /// `None` when there is nothing to write. The glue calls it on each tick.
    pub fn take_restores(&mut self) -> Option<Restores> {
        if self.epoch_ticks < self.restores_due {
            return None;
        }
        let held: Vec<(Vec<String>, (Value, Stamp))> =
            mem::take(&mut self.restores).into_iter().collect();
        let paths: Vec<Vec<String>> = held.iter().map(|(path, _)| path.clone()).collect();
        let live = self.stamps_of(&paths);
        let floors = self.tombstone_floors(&paths);
        let mut leaves: Vec<(Vec<String>, Value)> = Vec::new();
        let mut stamps: Vec<(Vec<String>, Stamp)> = Vec::new();
        let rows = held.into_iter().zip(live).zip(floors);
        for (((path, (value, stamp)), now), floor) in rows {
            // A delete of a higher stamp governs the path: a value is not written over it.
            let deleted = !value.is_null() && floor.is_some_and(|dead| dead >= stamp);
            // An empty object over an object that the document holds only wipes its keys.
            let wipes = matches!(&value, Value::Object(fields) if fields.is_empty())
                && json_at(&self.doc, &path).is_some_and(|there| there.is_object());
            let stale = deleted
                || wipes
                || match &now {
                    Some(current) => *current >= stamp,
                    None => value.is_null(),
                };
            if !stale {
                leaves.push((path.clone(), value));
                stamps.push((path, stamp));
            }
        }
        let patch = self.replay_patch(leaves)?;
        Some((patch, stamps))
    }

    /// Record the deletes of a change that was just applied, and forget the tombstone of a path
    /// that the change writes again with a higher stamp. Only a state document with state epochs
    /// keeps tombstones. The stamp of a path is the stamp that the frame names for it, or the time
    /// of the change with the tag of its actor.
    fn note_deletes(
        &mut self,
        change: &Change,
        frame: &Verified,
        named: Option<&[(Vec<String>, Stamp)]>,
    ) {
        if self.gate.is_some() {
            return;
        }
        let Some(time) = self.change_bytes(frame).and_then(|parsed| parsed.time) else {
            return;
        };
        let own = Stamp::new(time, actor_tag(change.actor_id()));
        let deps: Vec<ChangeHash> = change.deps().to_vec();
        let patches = self.doc.diff(&deps, &[change.hash()]);
        for patch in patches {
            let path = leaf_path(&patch);
            if path.is_empty() {
                continue;
            }
            let named_here = named.and_then(|list| list.iter().find(|(held, _)| *held == path));
            let stamp: Stamp = named_here.map_or_else(|| own.clone(), |(_, stamp)| stamp.clone());
            match patch.action {
                automerge::PatchAction::DeleteMap { .. } => self.add_tombstone(path, stamp),
                automerge::PatchAction::PutMap { .. } => {
                    if self.tombstones.get(&path).is_some_and(|held| *held < stamp) {
                        self.tombstones.remove(&path);
                    }
                }
                automerge::PatchAction::PutSeq { .. }
                | automerge::PatchAction::Insert { .. }
                | automerge::PatchAction::SpliceText { .. }
                | automerge::PatchAction::Increment { .. }
                | automerge::PatchAction::Conflict { .. }
                | automerge::PatchAction::DeleteSeq { .. }
                | automerge::PatchAction::Mark { .. } => {}
            }
        }
    }

    /// Keep the tombstone of `path`, unless the path is too long, and drop the one with the lowest
    /// stamp when there are more than `DOC_SEED_TOMBSTONES_MAX`. A tombstone with a higher stamp
    /// already there stays.
    fn add_tombstone(&mut self, path: Vec<String>, stamp: Stamp) {
        let bytes: usize = path.iter().map(String::len).sum();
        if bytes > DOC_TOMBSTONE_PATH_BYTES_MAX {
            self.tombstone_paths_long = self.tombstone_paths_long.saturating_add(1);
            return;
        }
        match self.tombstones.get(&path) {
            Some(held) if *held >= stamp => return,
            _ => {}
        }
        self.tombstones.insert(path, stamp);
        if self.tombstones.len() > DOC_SEED_TOMBSTONES_MAX {
            let entries = self.tombstones.iter();
            let lowest: Option<Vec<String>> = entries
                .min_by(|left, right| left.1.cmp(right.1))
                .map(|(held, _)| held.clone());
            if let Some(oldest) = lowest {
                self.tombstones.remove(&oldest);
            }
        }
    }

    /// The paths of `change` with the stamps that its `frame` names, and the document as it will
    /// look when the change is applied (a fork that has applied it). `None` when the frame names no
    /// stamps, and `Err` when they do not match the paths of the change.
    fn stamped_paths(
        &self,
        change: &Change,
        frame: &Verified,
    ) -> Result<Option<(StampedPaths, Automerge)>, ()> {
        let Some(parsed) = self.change_bytes(frame) else {
            return Ok(None);
        };
        // The tombstones belong to the frames of a seed, which an adoption applies and which do not
        // come here. A normal write or a replay that carries some is refused.
        if !parsed.tombstones.is_empty() {
            return Err(());
        }
        if parsed.origins.is_empty() {
            return Ok(None);
        }
        let mut fork = self.doc.fork();
        fork.apply_changes([change.clone()]).map_err(|_| ())?;
        let paths = change_leaves(&fork, change);
        if paths.len() != parsed.origins.len() {
            return Err(());
        }
        Ok(Some((
            paths.into_iter().zip(parsed.origins).collect(),
            fork,
        )))
    }

    fn deps_satisfied(&self, deps: &[ChangeHash]) -> bool {
        deps.iter().all(|dep| self.applied.contains(dep))
    }

    /// Buffer an orphan under the per-author and global ceilings.
    ///
    /// The author ceiling keeps *that author's* lowest seqs, so a peer flooding
    /// orphans exhausts only itself. The lowest seqs are the links next to what
    /// this doc holds, so they drain first; a kept tail waits on every link
    /// below it. A global breach refuses the newcomer instead: evicting across
    /// authors would let one hostile stream push a joiner's honest backfill out
    /// of the buffer, which is the failure the ceiling exists to prevent. Both
    /// mirror the reassembly store. A refused newcomer is recovered: its frame is
    /// forgotten (see [`Self::take_dropped`]), so the author's re-send lands once
    /// the lower seqs drain. The refusal is logged at debug, not as a warning.
    fn buffer_orphan(
        &mut self,
        author: AuthorKey,
        hash: ChangeHash,
        change: Change,
        frame: &Verified,
    ) -> Ingested {
        if self.pending.contains_key(&hash) {
            return Ingested::Buffered;
        }
        if self.pending_by(&author) >= DOC_PENDING_AUTHOR_MAX
            && let Some((victim, victim_seq)) = self.highest_of(&author)
        {
            if change.seq() >= victim_seq {
                // Back-pressure, not a fault: the frame is forgotten below, so the author's
                // re-send lands once the lower seqs have drained.
                tracing::debug!(target: LOG_TARGET, author = %frame.author, "channel orphan buffer full for this author; incoming higher-seq orphan refused, recovered by the re-send");
                self.dropped.push(frame.dedup_key());
                return Ingested::Ignored;
            }
            if let Some(evicted) = self.pending.remove(&victim) {
                self.dropped.push(evicted.frame.dedup_key());
            }
            if let Some(changes) = self
                .warn_due("channel orphan buffer full for this author; highest-seq orphan evicted")
            {
                tracing::warn!(target: LOG_TARGET, changes, author = %frame.author, "channel orphan buffer full for this author; highest-seq orphan evicted");
            }
        }
        if self.pending.len() >= DOC_PENDING_TOTAL_MAX {
            if let Some(changes) =
                self.warn_due("channel orphan buffer full; incoming orphan dropped")
            {
                tracing::warn!(target: LOG_TARGET, changes, author = %frame.author, "channel orphan buffer full; incoming orphan dropped");
            }
            self.dropped.push(frame.dedup_key());
            return Ingested::Ignored;
        }
        self.pending_arrivals += 1;
        self.pending.insert(
            hash,
            Pending {
                frame: frame.clone(),
                change,
                arrival: self.pending_arrivals,
            },
        );
        Ingested::Buffered
    }

    /// The dedup keys of the orphan frames dropped since the last call, for the
    /// receive path to forget.
    pub fn take_dropped(&mut self) -> impl Iterator<Item = DedupKey> + use<> {
        mem::take(&mut self.dropped).into_iter()
    }

    /// How many orphans this author key has buffered. Scanned rather than counted
    /// in a second map: `pending` is bounded, and one source of truth cannot
    /// drift from itself.
    fn pending_by(&self, author: &AuthorKey) -> usize {
        self.pending
            .values()
            .filter(|entry| entry.frame.key() == *author)
            .count()
    }

    /// This author key's highest-seq orphan and its seq, the latest arrival among
    /// equals. Keyed on the key rather than the nickname, which an author
    /// picks freely.
    fn highest_of(&self, author: &AuthorKey) -> Option<(ChangeHash, u64)> {
        let mine = self
            .pending
            .iter()
            .filter(|(_, entry)| entry.frame.key() == *author);
        mine.max_by_key(|(_, entry)| (entry.change.seq(), entry.arrival))
            .map(|(hash, entry)| (*hash, entry.change.seq()))
    }

    /// Counts one refusal of `kind` and returns the number of refusals the WARN must report, when
    /// one is due: the first of a kind, then every `WARN_EVERY`th.
    fn warn_due(&mut self, kind: &'static str) -> Option<u64> {
        let refusals = self.refusals.entry(kind).or_default();
        refusals.seen += 1;
        let since = refusals.seen - refusals.reported;
        if refusals.reported == 0 || since >= WARN_EVERY {
            refusals.reported = refusals.seen;
            Some(since)
        } else {
            None
        }
    }

    /// Accounting snapshot `(pending, max_author_pending)` for the adversarial
    /// suite's orphan-buffer tripwires.
    #[cfg(any(test, feature = "adversarial"))]
    #[must_use]
    pub fn pending_stats(&self) -> (usize, usize) {
        let mut per_author: HashMap<AuthorKey, usize> = HashMap::new();
        for entry in self.pending.values() {
            *per_author.entry(entry.frame.key()).or_default() += 1;
        }
        let longest: usize = per_author.values().copied().max().unwrap_or(0);
        (self.pending.len(), longest)
    }

    /// Apply every buffered frame whose change's deps are now met — through the
    /// gate — repeating until a full pass unblocks nothing.
    ///
    /// Each pass reads the deps already decoded at buffer time, so a pass costs
    /// a hash-set lookup per orphan rather than a decrypt and two decodes. That
    /// matters because this runs to completion on the event-loop thread with no
    /// await in it: every pass is time the whole daemon is not doing anything
    /// else.
    fn drain_pending(&mut self) {
        loop {
            let entries = self.pending.iter();
            let waiting = entries.filter(|(_, entry)| self.deps_satisfied(entry.change.deps()));
            let ready: Vec<ChangeHash> = waiting.map(|(hash, _)| *hash).collect();
            if ready.is_empty() {
                return;
            }
            for hash in ready {
                self.try_apply_pending(hash);
            }
        }
    }

    /// Apply one now-ready buffered frame through the gate, dropping it
    /// silently if it's no longer pending or forges a card — same handling as
    /// the equivalent direct-ingest failure modes.
    fn try_apply_pending(&mut self, hash: ChangeHash) {
        let Some(entry) = self.pending.remove(&hash) else {
            return;
        };
        if self.forges_foreign_entry(&entry.change, &entry.frame.author, None) {
            return; // dropped, same as a directly-rejected change
        }
        self.apply(entry.change, hash, entry.frame);
    }
}

/// Base58-encode an automerge change hash for a `MessageBody`-safe wire form.
fn encode_hash(hash: &ChangeHash) -> String {
    bs58::encode(hash.0).into_string()
}

/// Decode a Base58 change hash; `None` if it isn't 32 valid Base58 bytes.
fn decode_hash(encoded: &str) -> Option<ChangeHash> {
    let bytes = bs58::decode(encoded).into_vec().ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok().map(ChangeHash)
}

/// Each peer's gated field, keyed by nick (absent → no entry). Derived from the
/// hydrated JSON so it captures the field whatever its shape.
fn peer_entries(doc: &Automerge, gate: &SelfWriteGate) -> Map<String, Value> {
    gated_entries(&doc_json(doc), gate)
}

/// Each peer's gated field, picked out of an already-hydrated document.
///
/// Split from [`peer_entries`] so a caller holding a hydration can reuse it
/// rather than paying for a second one of the same document.
fn gated_entries(json: &Value, gate: &SelfWriteGate) -> Map<String, Value> {
    let mut entries = Map::new();
    if let Some(peers) = json.get(&gate.map).and_then(Value::as_object) {
        for (nick, entry) in peers {
            if let Some(guarded) = entry.get(&gate.field) {
                entries.insert(nick.clone(), guarded.clone());
            }
        }
    }
    entries
}

fn doc_json(doc: &Automerge) -> Value {
    serde_json::to_value(AutoSerde::from(doc)).unwrap_or(Value::Null)
}

/// The deterministic genesis of a state epoch above 0, built from constants (fixed actor,
/// `time = 0`, the epoch in the message) so every replica gets the same hash. It leaves no key in
/// the document. A change with no operation is no change, so the genesis writes a key and deletes
/// it. The hash depends on how automerge encodes that pair, so a bump of automerge must keep the
/// pinned hashes: if it does not, the bump is a wire break and needs a frame version bump.
fn state_genesis(epoch: u64) -> Change {
    let mut doc = Automerge::new();
    doc.set_actor(automerge::ActorId::from(
        b"habilis-state/genesis".as_slice(),
    ));
    {
        let mut tx = doc.transaction();
        tx.put(&ROOT, "epoch", epoch).expect("root is a map");
        tx.delete(&ROOT, "epoch").expect("the key was just put");
        let options = transaction::CommitOptions::default()
            .with_time(0)
            .with_message(format!("epoch {epoch}"));
        tx.commit_with(options);
    }
    doc.get_changes(&[])
        .pop()
        .expect("genesis produced exactly one change")
}

/// The deterministic genesis change that creates the shared per-peer `map`. Built
/// from constants (fixed actor, `time = 0`) so its hash — and thus the map's
/// object id — is identical on every replica configured with the same gate.
fn peers_genesis(map: &str, epoch: u64) -> Change {
    let mut doc = Automerge::new();
    doc.set_actor(automerge::ActorId::from(b"habilis-mesh/genesis".as_slice()));
    {
        let mut tx = doc.transaction();
        tx.put_object(&ROOT, map, ObjType::Map)
            .expect("root is a map");
        let options = transaction::CommitOptions::default().with_time(0);
        // Epoch 0 has no message, so its genesis is the one from before epochs.
        let options = if epoch == 0 {
            options
        } else {
            options.with_message(format!("epoch {epoch}"))
        };
        tx.commit_with(options);
    }
    doc.get_changes(&[])
        .pop()
        .expect("genesis produced exactly one change")
}

/// Whether the root of a seed from `rival` wins over the one from `held`: the lowest key wins on
/// every node, so all nodes end in one seed.
fn beats(rival: &AuthorKey, held: &AuthorKey) -> bool {
    rival.as_bytes() < held.as_bytes()
}

/// The merge that makes the value `held` into `desired`. A merge of an object only adds and
/// changes keys, so a key that `held` has and `desired` lacks is deleted with a `null`.
fn replace_with(desired: &Value, held: Option<&Value>) -> Value {
    let (Value::Object(wanted), Some(Value::Object(present))) = (desired, held) else {
        return desired.clone();
    };
    let mut merge: Map<String, Value> = Map::new();
    for (key, value) in wanted {
        merge.insert(key.clone(), replace_with(value, present.get(key)));
    }
    for key in present.keys() {
        if !wanted.contains_key(key) {
            merge.insert(key.clone(), Value::Null);
        }
    }
    Value::Object(merge)
}

/// A tag of the actor of a change for the cut vector: the first 8 bytes, in hex.
/// The tag of `actor` as a number: the first 8 bytes, as [`actor_tag`] writes them in hex.
fn actor_tag_number(actor: &automerge::ActorId) -> u64 {
    let mut bytes = [0u8; 8];
    let first = actor.to_bytes();
    let len = first.len().min(8);
    bytes[..len].copy_from_slice(&first[..len]);
    u64::from_be_bytes(bytes)
}

fn actor_tag(actor: &automerge::ActorId) -> String {
    use std::fmt::Write as _;

    let bytes: &[u8] = actor.to_bytes();
    let first: &[u8] = &bytes[..bytes.len().min(8)];
    let mut tag = String::with_capacity(16);
    for byte in first {
        let _ = write!(tag, "{byte:02x}");
    }
    tag
}

/// The value at `path` in `json`, `None` when a key on the way is missing.
fn lookup<'json>(json: &'json Value, path: &[String]) -> Option<&'json Value> {
    let mut here: &Value = json;
    for key in path {
        here = here.get(key.as_str())?;
    }
    Some(here)
}

/// Put `value` at `path` inside the nested merge `root`.
fn set_path(root: &mut Map<String, Value>, path: &[String], value: Value) {
    let Some((first, rest)) = path.split_first() else {
        return;
    };
    if rest.is_empty() {
        root.insert(first.clone(), value);
        return;
    }
    let child = root
        .entry(first.clone())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(fields) = child {
        set_path(fields, rest, value);
    }
}

/// The path of the leaf that a patch of one change touched. A patch inside a list gives the path
/// of the list, because a list is written whole. A counter or a conflict patch gives the path of
/// its parent: the state JSON has no counters, so no value of it is a counter.
fn leaf_path(patch: &automerge::Patch) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    for (_, prop) in &patch.path {
        match prop {
            automerge::Prop::Map(key) => keys.push(key.clone()),
            automerge::Prop::Seq(_) => return keys,
        }
    }
    match &patch.action {
        automerge::PatchAction::PutMap { key, .. } | automerge::PatchAction::DeleteMap { key } => {
            keys.push(key.clone());
        }
        automerge::PatchAction::PutSeq { .. }
        | automerge::PatchAction::Insert { .. }
        | automerge::PatchAction::SpliceText { .. }
        | automerge::PatchAction::Increment { .. }
        | automerge::PatchAction::Conflict { .. }
        | automerge::PatchAction::DeleteSeq { .. }
        | automerge::PatchAction::Mark { .. } => {}
    }
    keys
}

/// The paths that `change` writes in `doc`, which already holds it: the leaves, and the objects
/// that it makes, once each. They come from the patches of the change, in the order of the paths
/// (the lists of keys compared key by key, each key by its bytes), so two nodes that hold the same
/// change list the same paths in the same order. The `o` of a frame follows this order.
fn change_leaves(doc: &Automerge, change: &Change) -> Vec<Vec<String>> {
    let deps: Vec<ChangeHash> = change.deps().to_vec();
    let mut paths: Vec<Vec<String>> = Vec::new();
    for patch in doc.diff(&deps, &[change.hash()]) {
        let path = leaf_path(&patch);
        if !path.is_empty() {
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

/// The stamp of each path that the changes of a seed name, and the tombstones of its root, in one
/// map: a path with both keeps the higher stamp.
fn seed_stamp_map(
    found: &SeedStamps,
    dead: &[(Vec<String>, Stamp)],
) -> HashMap<Vec<String>, Stamp> {
    let mut map: HashMap<Vec<String>, Stamp> = HashMap::new();
    for list in found.values() {
        for (path, stamp) in list {
            raise_stamp(&mut map, path, stamp);
        }
    }
    for (path, stamp) in dead {
        raise_stamp(&mut map, path, stamp);
    }
    map
}

/// Whether a JSON value is an object with keys: a leaf is anything else.
fn is_full_object(value: &Value) -> bool {
    matches!(value, Value::Object(fields) if !fields.is_empty())
}

/// Reads values of one document by path. A parent object that several of the paths share is read
/// once as JSON, because a read of each path walks the parent again; a path with no sibling is read
/// by its walk, so a leaf in a large object costs no pass over it.
struct PathReader<'doc> {
    doc: &'doc Automerge,
    /// The parents that at least `PATH_READER_SHARED_MIN` of the paths share.
    shared: HashSet<Vec<String>>,
    read: HashMap<Vec<String>, Option<Value>>,
}

/// The number of paths with one parent from which the parent is read once.
const PATH_READER_SHARED_MIN: usize = 4;

impl<'doc> PathReader<'doc> {
    fn new(doc: &'doc Automerge, paths: &[&[String]]) -> Self {
        let mut counts: HashMap<&[String], usize> = HashMap::new();
        for path in paths {
            if let Some((_, parent)) = path.split_last() {
                *counts.entry(parent).or_default() += 1;
            }
        }
        let crowded = counts
            .into_iter()
            .filter(|(_, count)| *count >= PATH_READER_SHARED_MIN);
        let shared = crowded.map(|(parent, _)| parent.to_vec()).collect();
        Self {
            doc,
            shared,
            read: HashMap::new(),
        }
    }

    fn value_at(&mut self, path: &[String]) -> Option<Value> {
        let doc = self.doc;
        let (key, parent) = path.split_last()?;
        if !self.shared.contains(parent) {
            return json_at(doc, path);
        }
        let read = self
            .read
            .entry(parent.to_vec())
            .or_insert_with(|| json_at(doc, parent));
        let field: Option<&Value> = read.as_ref().and_then(|object| object.get(key.as_str()));
        field.cloned()
    }
}

/// The value at `path` in `doc`: a walk down the path, and one pass over the subtree below it. The
/// empty path is the whole document.
fn json_at(doc: &Automerge, path: &[String]) -> Option<Value> {
    let mut object: ObjId = ROOT;
    if path.is_empty() {
        return Some(subtree_json(
            doc,
            &automerge::Value::Object(ObjType::Map),
            &object,
        ));
    }
    let steps = path.iter().enumerate();
    for (position, key) in steps {
        let (value, id) = doc.get(&object, key.as_str()).ok()??;
        if position + 1 == path.len() {
            return Some(subtree_json(doc, &value, &id));
        }
        if !matches!(value, automerge::Value::Object(_)) {
            return None;
        }
        object = id;
    }
    None
}

/// The JSON of one value of `doc` and of everything below it, in one pass over each object. The
/// state JSON holds numbers, strings, booleans, `null`, lists and objects, so any other scalar
/// reads as `null`.
fn subtree_json(doc: &Automerge, value: &automerge::Value<'_>, id: &ObjId) -> Value {
    match value {
        automerge::Value::Object(ObjType::List) => list_json(doc, id),
        automerge::Value::Object(ObjType::Text) => Value::String(doc.text(id).unwrap_or_default()),
        automerge::Value::Object(ObjType::Map | ObjType::Table) => map_json(doc, id),
        automerge::Value::Scalar(scalar) => scalar_json(scalar),
    }
}

/// The JSON array of the list `id` of `doc`.
fn list_json(doc: &Automerge, id: &ObjId) -> Value {
    let items = doc.list_range(id, ..).map(|item| {
        let child = item.id();
        subtree_json(doc, &item.value.into_value(), &child)
    });
    Value::Array(items.collect())
}

/// The JSON object of the map or table `id` of `doc`.
fn map_json(doc: &Automerge, id: &ObjId) -> Value {
    let fields = doc.map_range(id, ..).map(|item| {
        let child = item.id();
        let json = subtree_json(doc, &item.value.into_value(), &child);
        (item.key.into_owned(), json)
    });
    Value::Object(fields.collect())
}

/// Set the stamp of `path` in `map` to `stamp`, unless the map holds a higher one.
fn raise_stamp(map: &mut HashMap<Vec<String>, Stamp>, path: &[String], stamp: &Stamp) {
    match map.get_mut(path) {
        Some(held) if *held >= *stamp => {}
        Some(held) => *held = stamp.clone(),
        None => {
            map.insert(path.to_vec(), stamp.clone());
        }
    }
}

/// The JSON of a scalar of the state document.
fn scalar_json(scalar: &automerge::ScalarValue) -> Value {
    match scalar {
        automerge::ScalarValue::Str(text) => Value::String(text.to_string()),
        automerge::ScalarValue::Int(number) => Value::from(*number),
        automerge::ScalarValue::Uint(number) => Value::from(*number),
        automerge::ScalarValue::F64(number) => {
            serde_json::Number::from_f64(*number).map_or(Value::Null, Value::Number)
        }
        automerge::ScalarValue::Boolean(flag) => Value::Bool(*flag),
        automerge::ScalarValue::Bytes(_)
        | automerge::ScalarValue::Counter(_)
        | automerge::ScalarValue::Timestamp(_)
        | automerge::ScalarValue::Null
        | automerge::ScalarValue::Unknown { .. } => Value::Null,
    }
}

/// Remove the value at `path` from a JSON value, and the objects that this leaves empty.
fn remove_path(value: &mut Value, path: &[String]) {
    let Some((key, rest)) = path.split_first() else {
        return;
    };
    let Value::Object(fields) = value else {
        return;
    };
    if rest.is_empty() {
        fields.remove(key);
        return;
    }
    if let Some(inner) = fields.get_mut(key) {
        remove_path(inner, rest);
        if matches!(inner, Value::Object(left) if left.is_empty()) {
            fields.remove(key);
        }
    }
}

/// The leaves of a JSON value with their paths: a scalar, a list, or an empty object is one leaf.
fn collect_leaves(value: &Value, prefix: &mut Vec<String>, out: &mut Vec<(Vec<String>, Value)>) {
    match value {
        Value::Object(fields) if !fields.is_empty() => {
            for (key, inner) in fields {
                prefix.push(key.clone());
                collect_leaves(inner, prefix, out);
                prefix.pop();
            }
        }
        Value::Object(_)
        | Value::Null
        | Value::Bool(_)
        | Value::Number(_)
        | Value::String(_)
        | Value::Array(_) => {
            if !prefix.is_empty() {
                out.push((prefix.clone(), value.clone()));
            }
        }
    }
}

/// The objects of a JSON value with their paths, the root left out, each with its whole value.
fn collect_objects(value: &Value, prefix: &mut Vec<String>, out: &mut Vec<(Vec<String>, Value)>) {
    if let Value::Object(fields) = value {
        if !prefix.is_empty() {
            out.push((prefix.clone(), value.clone()));
        }
        for (key, inner) in fields {
            prefix.push(key.clone());
            collect_objects(inner, prefix, out);
            prefix.pop();
        }
    }
}

/// The bytes of a leaf (its keys and its value) from which `check_seed_frames` builds the frame that
/// a seed would carry it in. A leaf of 1 500 bytes is about 2 100 bytes of body, which fits.
const SEED_LEAF_CHECK_MIN: usize = 1_500;

/// The bytes of the body of the frame of a seed that holds only the leaf `value` at `path`, with the
/// largest stamp. The change is built on an empty document, so it holds the keys above the leaf as
/// well, which is more than a later frame of the seed needs: the figure is an upper bound.
fn seed_frame_body_len(path: &[String], value: &Value) -> usize {
    let mut merge = value.clone();
    let innermost_first = path.iter().rev();
    for key in innermost_first {
        merge = Value::Object(Map::from_iter([(key.clone(), merge)]));
    }
    let mut doc = Automerge::new();
    let mut tx = doc.transaction();
    if write_map(&mut tx, &ROOT, &merge).is_err() {
        return usize::MAX;
    }
    tx.commit();
    let mut changes = doc.get_changes(&[]);
    let Some(change) = changes.pop() else {
        return usize::MAX;
    };
    let time = DOC_TIME_MAX - 1;
    let worst = [Stamp::new(time, "ffffffffffffffff".to_owned())];
    let bytes = change.raw_bytes();
    let body = wire::change_body_tombstoned(bytes, None, 1, None, Some(time), &worst, &[]);
    body.map_or(usize::MAX, |body| body.as_str().len())
}

/// The stamps for the changes of a seed that `fork` holds: for each change, one stamp for each path
/// that it writes, in the order of the paths. The stamp is the one that the cutter's document holds
/// for the path (`stamps`), so a node that adopts the seed learns who wrote each value and when. A
/// path that the document holds no stamp for (a change with no time) gets the stamp 0, and the
/// count of those paths comes back with the stamps.
fn seed_origins_from(
    stamps: &HashMap<Vec<String>, Stamp>,
    fork: &Automerge,
    changes: &[Vec<u8>],
) -> Result<(Vec<Vec<Stamp>>, u64), DocError> {
    let none = Stamp::new(0, "0000000000000000".to_owned());
    let mut zeros: u64 = 0;
    let mut origins: Vec<Vec<Stamp>> = Vec::with_capacity(changes.len());
    for bytes in changes {
        let change = Change::from_bytes(bytes.clone()).map_err(DocError::encode)?;
        let paths = change_leaves(fork, &change);
        let mut named: Vec<Stamp> = Vec::with_capacity(paths.len());
        for path in &paths {
            named.push(stamps.get(path).cloned().unwrap_or_else(|| {
                zeros += 1;
                none.clone()
            }));
        }
        origins.push(named);
    }
    Ok((origins, zeros))
}

/// The error of a state document that is over a line.
fn full(used: usize, limit: usize, what: &'static str) -> DocError {
    DocError::StateFull { used, limit, what }
}

/// Whether `merge` adds a value: it has a leaf that is not `null`. An empty object is a leaf that
/// adds a map. A merge of nulls only deletes.
fn adds_value(merge: &Value) -> bool {
    match merge {
        Value::Object(fields) if !fields.is_empty() => {
            let mut adds = false;
            for field in fields.values() {
                adds = adds || adds_value(field);
            }
            adds
        }
        Value::Null => false,
        Value::Object(_)
        | Value::Bool(_)
        | Value::Number(_)
        | Value::String(_)
        | Value::Array(_) => true,
    }
}

/// The keys on the way to the deepest value that `merge` adds, counting the key of the value.
fn merge_depth(merge: &Value) -> usize {
    let Value::Object(fields) = merge else {
        return 0;
    };
    let mut deepest = 0;
    for field in fields.values() {
        if adds_value(field) {
            deepest = deepest.max(merge_depth(field));
        }
    }
    if fields.is_empty() { 0 } else { 1 + deepest }
}

/// How many paths a merge writes: each key of each object counts once, and a list is one leaf. A
/// frame stays inside `DOC_REPLAY_ENTRIES_MAX` paths, which also bounds its stamps.
fn count_paths(merge: &Value) -> usize {
    match merge {
        Value::Object(fields) => fields.values().map(|value| 1 + count_paths(value)).sum(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_) => 0,
    }
}

/// The raw bytes of every change of `doc` that comes after `since`, in order.
fn raw_changes(doc: &Automerge, since: &[ChangeHash]) -> Vec<Vec<u8>> {
    let changes = doc.get_changes(since);
    let mut raw: Vec<Vec<u8>> = Vec::with_capacity(changes.len());
    for change in changes {
        raw.push(change.raw_bytes().to_vec());
    }
    raw
}

/// Derive a stable automerge [`ActorId`](automerge::ActorId) from a
/// per-session seed (the daemon passes its signing public key) so a member's
/// concurrent same-key writes resolve deterministically. Authenticity is the
/// signed envelope's job, not the actor id — this only stabilizes automerge's
/// own conflict tie-break.
///
/// The seed must NOT be the nickname: automerge numbers each actor's changes
/// sequentially, so a rejoined session (fresh doc, seq restarting at 1) under
/// a nickname-derived actor collides with its predecessor's history and every
/// replica rejects its writes as `DuplicateSeqNumber` equivocation. The
/// session identity is minted fresh per run, which makes it exactly
/// session-unique. (If identity ever persists across restarts, the seed must
/// grow a per-run component, since the docs start empty each run.)
fn actor_for(seed: &[u8]) -> automerge::ActorId {
    automerge::ActorId::from(seed)
}

/// Apply an RFC 7386 object merge into the map `obj`: recurse into object
/// members (vivifying missing maps), delete on `null`, and replace on any
/// scalar or array.
fn write_map(
    tx: &mut transaction::Transaction<'_>,
    obj: &ObjId,
    merge: &Value,
) -> anyhow::Result<()> {
    let Value::Object(map) = merge else {
        // Non-object nested merge is handled by the caller (write_value); the
        // root is guaranteed an object by build_change.
        return Ok(());
    };
    for (key, value) in map {
        match value {
            Value::Null => {
                let _ = tx.delete(obj, key.as_str());
            }
            Value::Object(_) => {
                let child = ensure_map(tx, obj, key)?;
                write_map(tx, &child, value)?;
            }
            Value::Bool(_) | Value::String(_) | Value::Number(_) | Value::Array(_) => {
                write_value(tx, obj, key, value)?;
            }
        }
    }
    Ok(())
}

/// The map object at `obj[key]`, reusing an existing map or creating one.
fn ensure_map(
    tx: &mut transaction::Transaction<'_>,
    obj: &ObjId,
    key: &str,
) -> anyhow::Result<ObjId> {
    if let Some((AmValue::Object(ObjType::Map), id)) = tx.get(obj, key)? {
        return Ok(id);
    }
    Ok(tx.put_object(obj, key, ObjType::Map)?)
}

/// Write a scalar or array as `obj[key]`, replacing whatever is there (RFC 7386
/// semantics for non-object values).
fn write_value(
    tx: &mut transaction::Transaction<'_>,
    obj: &ObjId,
    key: &str,
    value: &Value,
) -> anyhow::Result<()> {
    match value {
        Value::Array(items) => {
            let list = tx.put_object(obj, key, ObjType::List)?;
            let indexed: Vec<(usize, &Value)> = items.iter().enumerate().collect();
            for (index, item) in indexed {
                append_item(tx, &list, index, item)?;
            }
        }
        Value::Object(_) | Value::Null => unreachable!("handled by write_map"),
        Value::Bool(_) | Value::String(_) | Value::Number(_) => put_scalar(tx, obj, key, value)?,
    }
    Ok(())
}

fn append_item(
    tx: &mut transaction::Transaction<'_>,
    list: &ObjId,
    index: usize,
    item: &Value,
) -> anyhow::Result<()> {
    match item {
        Value::Object(_) => {
            let child = tx.insert_object(list, index, ObjType::Map)?;
            write_map(tx, &child, item)?;
        }
        Value::Array(inner) => {
            let child = tx.insert_object(list, index, ObjType::List)?;
            let indexed: Vec<(usize, &Value)> = inner.iter().enumerate().collect();
            for (inner_index, inner_item) in indexed {
                append_item(tx, &child, inner_index, inner_item)?;
            }
        }
        Value::Bool(_) | Value::String(_) | Value::Number(_) | Value::Null => {
            insert_scalar(tx, list, index, item)?;
        }
    }
    Ok(())
}

fn put_scalar(
    tx: &mut transaction::Transaction<'_>,
    obj: &ObjId,
    key: &str,
    scalar: &Value,
) -> anyhow::Result<()> {
    match scalar {
        Value::Bool(bool_value) => tx.put(obj, key, *bool_value)?,
        Value::String(string_value) => tx.put(obj, key, string_value.as_str())?,
        Value::Number(number) => put_number(tx, obj, key, number)?,
        Value::Null | Value::Array(_) | Value::Object(_) => {
            unreachable!("non-scalar handled elsewhere")
        }
    }
    Ok(())
}

fn insert_scalar(
    tx: &mut transaction::Transaction<'_>,
    list: &ObjId,
    index: usize,
    scalar: &Value,
) -> anyhow::Result<()> {
    match scalar {
        Value::Bool(bool_value) => tx.insert(list, index, *bool_value)?,
        Value::String(string_value) => tx.insert(list, index, string_value.as_str())?,
        Value::Number(number) => {
            if let Some(int_value) = number.as_i64() {
                tx.insert(list, index, int_value)?;
            } else if let Some(uint_value) = number.as_u64() {
                tx.insert(list, index, uint_value)?;
            } else if let Some(float_value) = number.as_f64() {
                tx.insert(list, index, float_value)?;
            }
        }
        // A JSON array element may be `null` (unlike a map, where `null` means
        // delete and is handled upstream), so a list preserves it as a null.
        Value::Null => tx.insert(list, index, automerge::ScalarValue::Null)?,
        Value::Array(_) | Value::Object(_) => unreachable!("non-scalar handled elsewhere"),
    }
    Ok(())
}

fn put_number(
    tx: &mut transaction::Transaction<'_>,
    obj: &ObjId,
    key: &str,
    number: &serde_json::Number,
) -> anyhow::Result<()> {
    if let Some(int_value) = number.as_i64() {
        tx.put(obj, key, int_value)?;
    } else if let Some(uint_value) = number.as_u64() {
        tx.put(obj, key, uint_value)?;
    } else if let Some(float_value) = number.as_f64() {
        tx.put(obj, key, float_value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DOC_CUT_BACKOFF_FIRST, DOC_CUT_BACKOFF_MAX, DOC_CUT_RANKS_SLOTTED, DOC_CUT_SLOT_TICKS,
        DOC_CUT_SPREAD_TICKS, DOC_PENDING_AUTHOR_MAX, DOC_PENDING_TOTAL_MAX, DOC_SEED_FRAMES_MAX,
        Ingested, Limits, MeshDoc, SeedChain, SelfWriteGate,
    };
    use crate::wire::{
        SeedMark, change_body_stamped, change_body_timed, change_body_tombstoned, encrypt_body,
        parse_change_full,
    };
    use crate::{DocError, Stamp, StampedPaths};
    use automerge::Change;
    use automerge::transaction::Transactable;
    use habilis_network_protocol::messages::Verified;
    use habilis_network_protocol::{
        AuthorKey, Channel, DedupKey, MeshId, Message, Nickname, SymmetricKey,
    };
    use serde_json::{Map, Value, json};
    use std::collections::{HashMap, HashSet};

    fn nick(name: &str) -> Nickname {
        Nickname::from(name)
    }

    /// Wrap change bytes in a signed-frame stand-in, signed by the change's
    /// actor. The doc layer reads `author`, `pubkey` and `body`; a valid
    /// signature is `gossip::ingest`'s job.
    fn frame(who: &Nickname, bytes: &[u8]) -> Verified {
        let change = Change::from_bytes(bytes.to_vec()).expect("a change");
        let actor = AuthorKey::decode_hex(&change.actor_id().to_hex_string())
            .expect("a test actor is 32 bytes");
        frame_as(who, bytes, actor)
    }

    /// [`frame`] claiming `key` as its signer, which need not be the change's actor.
    fn frame_as(who: &Nickname, bytes: &[u8], key: AuthorKey) -> Verified {
        Verified::fixture_unchecked(
            Message::new_channel_event(
                &MeshId::from("test"),
                who,
                super::wire::change_body(bytes, None).expect("body"),
                Channel::State,
            )
            .unverified_key(key),
            key,
        )
    }

    /// Author a merge on `doc` (build + ingest, as the daemon does) and return
    /// the signed frame to hand to a peer. The actor seed is the nickname —
    /// fine for single-session tests; a test spanning two sessions of one
    /// nickname must use [`author_as`] with distinct seeds.
    /// The genesis change is what makes every replica agree on the gated map's
    /// object identity, so its bytes are a compatibility surface: if this hash
    /// moves, replicas built from different versions vivify different maps,
    /// automerge discards one, and a peer's entry is silently erased. Pinned so
    /// that can only ever happen on purpose.
    ///
    /// It last moved when the byte-domains dropped the product name for the
    /// engine's, which moved `messages::VERSION` to `12.0`.
    #[test]
    fn genesis_bytes_are_pinned() {
        let _guard = ::habilis_network_test_tracing::init();
        let genesis = super::peers_genesis("peers", 0);
        assert_eq!(
            format!("{:?}", genesis.hash()),
            "ChangeHash(\"faf84e310070f1127948a680064551304e36a70d14ccff86f7ece64caf82908b\")",
            "the genesis change hash is pinned"
        );
    }

    /// Golden: the hash and the bytes of one change, built with a fixed actor seed on an empty
    /// document. Documents persist, so a change of either breaks replicas that hold the old
    /// change. The values were captured at the base commit.
    #[test]
    fn a_fixed_change_keeps_its_hash_and_bytes() {
        let _guard = ::habilis_network_test_tracing::init();
        let doc = MeshDoc::new_ungated();
        let bytes = doc
            .build_change(&json!({"board": "x", "n": 1}), b"alice")
            .expect("the merge applies")
            .expect("the merge is not a no-op");
        assert_eq!(
            bs58::encode(&bytes).into_string(),
            "BkyumvZ6ckpDpEVTTzvrfqoyymBWzN1qTVn2sqCJYU4TC7HQkarE1DSR52uEx1vZg2n6LotbD9",
            "a fixed change keeps its bytes"
        );
        let change = Change::from_bytes(bytes).expect("a change");
        assert_eq!(
            format!("{:?}", change.hash()),
            "ChangeHash(\"c979bd7ef18f904ebbef0fb8fc381516074bbf9a68cdf28227661f35c7239cb6\")",
            "a fixed change keeps its hash"
        );
    }

    /// Golden: an `enc` envelope captured at the base commit opens with its key to the plaintext
    /// `change` body, and that body carries its change bytes. The nonce is random on encrypt, so
    /// this pins the open path and the envelope shape, and there is no golden for the encrypt path.
    #[test]
    fn a_fixed_enc_body_opens_to_its_plaintext_change() {
        use super::wire::{decrypt_body, parse_change_body};

        let _guard = ::habilis_network_test_tracing::init();
        let plain = r#"{"k":"change","c":"2VfUX","m":{"board":"x"}}"#;
        assert_eq!(
            super::wire::change_body(&[1, 2, 3, 4], Some(&json!({"board": "x"})))
                .expect("compose")
                .as_str(),
            plain,
            "a fixed enc body opens to the expected change body"
        );
        let enc = concat!(
            r#"{"k":"enc","d":"418rHy72Zv4wKRPXd4ff7MKEgNVoG1qe7RD94gp7a97VTVc5B4bEXa"#,
            r#"qCBUwXKpBHZmAAM8zFEEiGKEzMZY7dcnQnuXjCcerUr3F"}"#,
        );
        let key = SymmetricKey::from([3u8; 32]);
        let recovered = decrypt_body(enc, Some(&key)).expect("the key opens the body");
        assert_eq!(
            recovered, plain,
            "a fixed enc body decrypts to its plaintext"
        );
        assert_eq!(
            parse_change_body(&recovered),
            Some(vec![1u8, 2, 3, 4]),
            "the decrypted body parses to the plaintext change"
        );
    }

    /// The gate the application configures on its `meta` channel. Any
    /// per-peer map/field pair would do; this one is what production uses.
    fn card_gate() -> SelfWriteGate {
        SelfWriteGate {
            map: "peers".to_owned(),
            field: "card".to_owned(),
        }
    }

    fn author(doc: &mut MeshDoc, who: &Nickname, merge: &Value) -> Verified {
        author_as(doc, who, who.as_str().as_bytes(), merge)
    }

    /// A test actor seed as the 32 bytes of a signer's key: the seed, zero-padded. Zero padding
    /// keeps the byte order of any two seeds that are not a prefix of each other, so the order
    /// automerge settles conflicts by is the one the unpadded seeds had.
    fn pad_seed(seed: &[u8]) -> [u8; 32] {
        let mut padded = [0u8; 32];
        padded[..seed.len()].copy_from_slice(seed);
        padded
    }

    /// [`author`] with an explicit per-session actor seed, as the daemon
    /// derives from its signing key.
    fn author_as(doc: &mut MeshDoc, who: &Nickname, seed: &[u8], merge: &Value) -> Verified {
        let bytes = doc
            .build_change(merge, &pad_seed(seed))
            .expect("merge applies")
            .expect("merge is not a no-op");
        let carrier = frame(who, &bytes);
        let outcome = doc.ingest(&carrier);
        assert!(
            matches!(outcome, Ingested::Applied { .. }),
            "expected applied, got {outcome:?}"
        );
        carrier
    }

    /// The bytes that one fixture frame takes on the wire, counted by hand from its JSON, on the
    /// mesh `test`: 103 bytes of fixed text (the keys, the quotes, the commas and `{"v":"13.0"`
    /// through `"ext":{}}`), a 36 byte id, a 62 byte mesh id, a 10 digit timestamp, a 64 byte hex
    /// key and a 128 byte hex signature, which is 300 bytes, and then the author and the body. The
    /// body is written as a JSON string, so each of its quotes costs one more byte for the
    /// backslash.
    fn hand_counted_wire_len(frame: &Verified) -> usize {
        let body = frame.body.as_str();
        let quotes = body.matches('"').count();
        403 + frame.author.as_str().len() + body.len() + quotes
    }

    /// The census counts what the document keeps: the changes with the genesis, the frames
    /// without it, their bytes, the JSON, the save on request, and the owners of the peer map. The
    /// sizes are counted by hand, not read back with the code that makes them.
    #[test]
    fn a_census_counts_changes_frames_and_sizes() {
        let mut doc = MeshDoc::new_gated(card_gate());
        let (alice, bob) = (nick("alice"), nick("bob"));
        let first = author(
            &mut doc,
            &alice,
            &json!({ "peers": { "alice": { "card": 1 } } }),
        );
        let second = author(
            &mut doc,
            &bob,
            &json!({ "peers": { "bob": { "card": 2 } } }),
        );
        assert_eq!(
            hand_counted_wire_len(&first),
            639,
            "the hand count of the first frame matches the frame as it serializes"
        );
        let wire_bytes = hand_counted_wire_len(&first) + hand_counted_wire_len(&second);

        let light = doc.census(false);

        assert_eq!(light.changes, 3, "the genesis and two changes");
        assert_eq!(light.frames, 2, "the genesis has no frame");
        assert_eq!(
            light.frame_bytes, wire_bytes,
            "the wire bytes of the frames"
        );
        assert_eq!(
            (light.json_bytes, light.save_bytes, light.peer_nicks),
            (None, None, None),
            "the light census reads nothing that costs in proportion to the document"
        );

        let heavy = doc.census(true);

        assert_eq!(heavy.frame_bytes, wire_bytes, "the same sum");
        assert_eq!(
            heavy.json_bytes,
            Some(47),
            "the 47 bytes of the two-entry document, counted by hand"
        );
        let mut nicks = heavy.peer_nicks.expect("the heavy census lists the owners");
        nicks.sort();
        assert_eq!(nicks, ["alice", "bob"], "the owners of the peer map");
        assert!(
            heavy.save_bytes.expect("a save was asked for") > 0,
            "the save has bytes"
        );
    }

    #[test]
    fn distinct_top_level_keys_converge_either_order() {
        let _guard = ::habilis_network_test_tracing::init();
        // Distinct keys at the always-shared document root merge with no genesis.
        let (alice, bob) = (nick("alice"), nick("bob"));
        let mut left = MeshDoc::new_ungated();
        let mut right = MeshDoc::new_ungated();

        let alice_frame = author(&mut left, &alice, &json!({"a": 1}));
        let bob_frame = author(&mut right, &bob, &json!({"b": 2}));

        left.ingest(&bob_frame);
        right.ingest(&alice_frame);

        let want = json!({"a": 1, "b": 2});
        assert_eq!(
            left.to_json(),
            want,
            "the left replica converges to the wanted json"
        );
        assert_eq!(
            right.to_json(),
            want,
            "the right replica converges to the wanted json"
        );
    }

    #[test]
    fn concurrent_peer_reports_converge_via_shared_genesis() {
        let _guard = ::habilis_network_test_tracing::init();
        // Two peers each vivify their own `/peers/<nick>` entry concurrently. The
        // shared `/peers` genesis makes these distinct keys in one map, so both
        // survive — the case that erased a card before the genesis existed.
        let (alice, bob) = (nick("alice"), nick("bob"));
        let mut left = MeshDoc::new_gated(card_gate());
        let mut right = MeshDoc::new_gated(card_gate());

        let alice_frame = author(&mut left, &alice, &json!({"peers": {"alice": {"m": 1}}}));
        let bob_frame = author(&mut right, &bob, &json!({"peers": {"bob": {"m": 2}}}));

        left.ingest(&bob_frame);
        right.ingest(&alice_frame);

        let want = json!({"peers": {"alice": {"m": 1}, "bob": {"m": 2}}});
        assert_eq!(
            left.to_json(),
            want,
            "the left peer report converges on the shared genesis"
        );
        assert_eq!(
            right.to_json(),
            want,
            "the right peer report converges on the shared genesis"
        );
    }

    #[test]
    fn null_deletes_key_and_preserves_siblings() {
        let _guard = ::habilis_network_test_tracing::init();
        let alice = nick("alice");
        let mut doc = MeshDoc::new_ungated();
        author(
            &mut doc,
            &alice,
            &json!({"peers": {"alice": {"model": "opus", "host": "box"}}}),
        );
        author(
            &mut doc,
            &alice,
            &json!({"peers": {"alice": {"model": "sonnet"}}}),
        );
        author(
            &mut doc,
            &alice,
            &json!({"peers": {"alice": {"host": null}}}),
        );
        assert_eq!(
            doc.to_json(),
            json!({"peers": {"alice": {"model": "sonnet"}}}),
            "a null deletes its key and keeps the siblings"
        );
    }

    /// **A change recorded as applied must actually be in the document.**
    ///
    /// Two docs seeded with the same actor mint different content under the
    /// same `(actor, seq)`. automerge refuses the second with
    /// `DuplicateSeqNumber`, but the error is dropped and the bookkeeping
    /// commits anyway, so `applied` claims a hash the document does not have.
    /// Nothing heals it: anti-entropy re-serves the frame and the dedup check
    /// answers `Duplicate`.
    #[test]
    fn a_change_that_fails_to_apply_is_not_recorded_as_applied() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            super::LOG_TARGET,
            "dropping a channel change automerge refused",
        );
        let alice = nick("alice");
        let seed = b"shared-actor";

        let mut first_doc = MeshDoc::new_ungated();
        let first = author_as(&mut first_doc, &alice, seed, &json!({"a": 1}));
        let mut second_doc = MeshDoc::new_ungated();
        let second = author_as(&mut second_doc, &alice, seed, &json!({"b": 2}));

        let mut sink = MeshDoc::new_ungated();
        assert!(
            matches!(sink.ingest(&first), Ingested::Applied { .. }),
            "a change that fails to apply is not recorded as applied"
        );

        let outcome = sink.ingest(&second);
        if matches!(outcome, Ingested::Applied { .. }) {
            assert_eq!(
                sink.to_json().get("b"),
                Some(&json!(2)),
                "reported applied, but the document never got it: {outcome:?}"
            );
        }

        // The damage compounds: recording the refused change as applied makes
        // its descendant's deps look satisfied, so that one is handed to
        // automerge, parked in its internal queue, and recorded as applied too.
        // A descendant must buffer instead, waiting for a parent that never
        // legitimately arrives.
        let descendant = author_as(&mut second_doc, &alice, seed, &json!({"c": 3}));
        let follow_up = sink.ingest(&descendant);
        assert!(
            !matches!(follow_up, Ingested::Applied { .. }),
            "a descendant of a refused change must not report applied: {follow_up:?}"
        );
        assert_eq!(
            sink.to_json().get("c"),
            None,
            "and its content must not appear"
        );
    }

    /// A chain gossiped without its root parks every link forever: the deps are
    /// never satisfied, so nothing drains and nothing expires.
    #[test]
    fn an_orphan_flood_from_one_author_stays_bounded() {
        let _guard = ::habilis_network_test_tracing::init();
        let alice = nick("alice");
        let mut source = MeshDoc::new_ungated();
        let chain: Vec<Verified> = (0..DOC_PENDING_AUTHOR_MAX + 32)
            .map(|step| author(&mut source, &alice, &json!({ "k": step })))
            .collect();

        let mut sink = MeshDoc::new_ungated();
        // Withhold the root, so not one of these can ever apply.
        for frame in &chain[1..] {
            sink.ingest(frame);
        }

        let (total, per_author) = sink.pending_stats();
        assert!(
            per_author <= DOC_PENDING_AUTHOR_MAX,
            "one author buffered {per_author} orphans, over the {DOC_PENDING_AUTHOR_MAX} ceiling"
        );
        assert!(total <= DOC_PENDING_TOTAL_MAX, "{total} orphans buffered");
    }

    /// The global backstop **refuses the newcomer** rather than evicting across
    /// authors — pubkeys are free, so the per-author ceiling alone is not a
    /// bound, but evicting to make room for a Sybil would let one flush
    /// everyone else out.
    ///
    /// `an_orphan_flood_from_one_author_stays_bounded` above only asserts the
    /// total stays under the cap, which eviction would satisfy too. Named to
    /// match `habilis_network_protocol::reassembly`'s `global_budget_refuses_the_newcomer`,
    /// which states the same rule over the other store.
    #[test]
    fn global_budget_refuses_the_newcomer() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            super::LOG_TARGET,
            "channel orphan buffer full; incoming orphan dropped",
        );
        let mut sink = MeshDoc::new_ungated();

        // One honest orphan parked first, from its own author.
        let honest_nick = nick("honest");
        let mut honest_source = MeshDoc::new_ungated();
        let honest_key = [0x11_u8; 32];
        let _honest_root = author_as(
            &mut honest_source,
            &honest_nick,
            &honest_key,
            &json!({"a": 1}),
        );
        let honest = author_as(
            &mut honest_source,
            &honest_nick,
            &honest_key,
            &json!({"b": 2}),
        );
        assert!(
            matches!(sink.ingest(&honest), Ingested::Buffered),
            "an honest change is buffered under the global budget"
        );

        // Sybil authors, each staying under the per-author ceiling, until the
        // global cap bites.
        let mut refused = false;
        for who in 0..DOC_PENDING_TOTAL_MAX {
            let sybil = nick("sybil");
            let mut source = MeshDoc::new_ungated();
            let key = who.to_be_bytes();
            let _sybil_root = author_as(&mut source, &sybil, &key, &json!({"a": who}));
            let orphan = author_as(&mut source, &sybil, &key, &json!({"b": who}));
            if matches!(sink.ingest(&orphan), Ingested::Ignored) {
                refused = true;
                break;
            }
        }

        assert!(refused, "the global cap must eventually refuse a newcomer");
        // `ingest` also returns `Ignored` for an undecodable change, so pin the
        // reason: refusal happens exactly at the cap, never below it.
        let (total, _) = sink.pending_stats();
        assert_eq!(
            total, DOC_PENDING_TOTAL_MAX,
            "refused at {total} buffered, not at the {DOC_PENDING_TOTAL_MAX} cap"
        );
        assert!(
            sink.pending
                .values()
                .any(|entry| entry.frame.key() == AuthorKey::from([0x11; 32])),
            "the honest orphan survived: the newcomer is refused, not an incumbent evicted"
        );
    }

    /// A newcomer refused at the global cap never reaches `pending`, but the
    /// receive path already marked it seen, so its key is handed back with the
    /// evicted ones or the author's re-send is discarded as a repeat.
    #[test]
    fn an_orphan_refused_at_the_global_cap_is_reported_as_dropped() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            super::LOG_TARGET,
            "channel orphan buffer full; incoming orphan dropped",
        );
        let mut sink = MeshDoc::new_ungated();
        let mut refused = None;
        for who in 0..=DOC_PENDING_TOTAL_MAX {
            let sybil = nick("sybil");
            let mut source = MeshDoc::new_ungated();
            let key = who.to_be_bytes();
            let _root = author_as(&mut source, &sybil, &key, &json!({"a": who}));
            let orphan = author_as(&mut source, &sybil, &key, &json!({"b": who}));
            if matches!(sink.ingest(&orphan), Ingested::Ignored) {
                refused = Some(orphan);
                break;
            }
        }
        let refused = refused.expect("the global cap must refuse a newcomer");
        assert!(
            sink.take_dropped().any(|key| key == refused.dedup_key()),
            "the refused orphan's dedup key must be handed back"
        );
    }

    /// The per-author ceiling exists so a flood costs its author and nobody
    /// else. Evicting across authors would let one hostile stream flush a
    /// joiner's honest backfill out of the buffer.
    #[test]
    fn a_floods_orphans_do_not_evict_another_authors() {
        let _guard = ::habilis_network_test_tracing::init();
        let alice = nick("alice");
        let mallory = nick("mallory");

        let mut alices = MeshDoc::new_ungated();
        let alice_key = [0xaa_u8; 32];
        let alice_root = author_as(&mut alices, &alice, &alice_key, &json!({"a": 1}));
        let alice_orphan = author_as(&mut alices, &alice, &alice_key, &json!({"b": 2}));

        let mut sink = MeshDoc::new_ungated();
        assert!(
            matches!(sink.ingest(&alice_orphan), Ingested::Buffered),
            "alice's orphan is buffered beside the flood"
        );

        let mut mallorys = MeshDoc::new_ungated();
        let flood: Vec<Verified> = (0..DOC_PENDING_AUTHOR_MAX + 32)
            .map(|step| author_as(&mut mallorys, &mallory, &[0xbb; 32], &json!({ "m": step })))
            .collect();
        for frame in &flood[1..] {
            sink.ingest(frame);
        }

        let (_total, per_author) = sink.pending_stats();
        assert!(
            per_author <= DOC_PENDING_AUTHOR_MAX,
            "one author's pending count stays within its cap"
        );

        // Deliver the dep Alice's orphan was waiting on. It drains only if the
        // flood left it alone — re-ingesting the orphan would prove nothing,
        // since an evicted frame simply buffers again.
        sink.ingest(&alice_root);
        assert_eq!(
            sink.to_json(),
            json!({"a": 1, "b": 2}),
            "a flood from one author must not evict another author's orphan"
        );
    }

    /// A chain one change per key, `k0` first, authored by one actor.
    fn keyed_chain(len: usize) -> Vec<Verified> {
        let alice = nick("alice");
        let mut source = MeshDoc::new_ungated();
        (0..len)
            .map(|step| author(&mut source, &alice, &json!({ format!("k{step}"): step })))
            .collect()
    }

    /// The number of chain changes that landed in `doc`.
    fn landed(doc: &MeshDoc) -> usize {
        doc.to_json().as_object().map_or(0, Map::len)
    }

    /// Feed `order` into a fresh sink, then the root prefix `0..root_len`.
    fn deliver(chain: &[Verified], order: &[usize], root_len: usize) -> MeshDoc {
        let mut sink = MeshDoc::new_ungated();
        for &step in order {
            sink.ingest(&chain[step]);
        }
        for frame in &chain[..root_len] {
            sink.ingest(frame);
        }
        sink
    }

    /// A long backfill often reaches a joiner tail first. The buffer must keep
    /// the links next to what the joiner holds, the lowest seqs: a kept tail
    /// cannot drain until every link below it arrives again.
    #[test]
    fn a_full_orphan_buffer_keeps_the_lowest_seqs_of_an_author() {
        let _guard = ::habilis_network_test_tracing::init();
        let chain = keyed_chain(300);
        let tail: Vec<usize> = (100..300).collect();
        let sink = deliver(&chain, &tail, 100);
        assert_eq!(
            landed(&sink),
            100 + DOC_PENDING_AUTHOR_MAX,
            "a full orphan buffer keeps the lowest seqs of an author"
        );
    }

    /// Guard: when the tail arrives lowest seq last, the old arrival order and
    /// the seq order keep the same links.
    #[test]
    fn a_reversed_tail_keeps_the_lowest_seqs_of_an_author() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            super::LOG_TARGET,
            "channel orphan buffer full for this author; highest-seq orphan evicted",
        );
        let chain = keyed_chain(300);
        let tail: Vec<usize> = (100..300).rev().collect();
        let sink = deliver(&chain, &tail, 100);
        assert_eq!(
            landed(&sink),
            100 + DOC_PENDING_AUTHOR_MAX,
            "a reversed tail keeps the lowest seqs of an author"
        );
    }

    /// The arrival order does not change which links stay.
    #[test]
    fn a_shuffled_tail_keeps_the_lowest_seqs_of_an_author() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            super::LOG_TARGET,
            "channel orphan buffer full for this author; highest-seq orphan evicted",
        );
        let chain = keyed_chain(300);
        // 7919 shares no factor with 200, so it walks all 200 slots once each.
        let tail: Vec<usize> = (0..200).map(|slot| 100 + slot * 7919 % 200).collect();
        let sink = deliver(&chain, &tail, 100);
        assert_eq!(
            landed(&sink),
            100 + DOC_PENDING_AUTHOR_MAX,
            "a shuffled tail keeps the lowest seqs of an author"
        );
    }

    /// Every link the buffer let go is handed back to the receive path, and
    /// only those: the rest drain and must stay seen.
    #[test]
    fn a_full_orphan_buffer_reports_the_links_it_let_go() {
        let _guard = ::habilis_network_test_tracing::init();
        let chain = keyed_chain(300);
        let tail: Vec<usize> = (100..300).collect();
        let mut sink = deliver(&chain, &tail, 100);
        let dropped: HashSet<DedupKey> = sink.take_dropped().collect();
        let let_go: HashSet<DedupKey> = chain[100 + DOC_PENDING_AUTHOR_MAX..]
            .iter()
            .map(|frame| frame.dedup_key())
            .collect();
        assert_eq!(
            dropped, let_go,
            "a full orphan buffer reports the links it let go"
        );
    }

    /// A change at the highest buffered seq is refused, not swapped in, even
    /// when its content differs: seq is the only order the buffer trusts.
    #[test]
    fn a_full_orphan_buffer_refuses_a_second_change_at_its_highest_seq() {
        let _guard = ::habilis_network_test_tracing::init();
        let chain = keyed_chain(DOC_PENDING_AUTHOR_MAX + 1);
        let alice = nick("alice");
        let mut fork = MeshDoc::new_ungated();
        let rival = (0..=DOC_PENDING_AUTHOR_MAX)
            .map(|step| author(&mut fork, &alice, &json!({ format!("r{step}"): step })))
            .last()
            .expect("a rival chain");

        let mut sink = MeshDoc::new_ungated();
        for frame in &chain[1..] {
            assert!(
                matches!(sink.ingest(frame), Ingested::Buffered),
                "a full orphan buffer refuses a second change at its highest seq"
            );
        }
        assert!(
            matches!(sink.ingest(&rival), Ingested::Ignored),
            "a full orphan buffer refuses a change at the same highest seq"
        );
        let dropped_keys: Vec<_> = sink.take_dropped().collect();
        assert_eq!(
            dropped_keys,
            vec![rival.dedup_key()],
            "the dropped keys are the ones let go"
        );
    }

    /// Automerge takes one change per `(actor, seq)`. A frame whose signer does
    /// not own the change's actor could take an author's next seq, and the
    /// author's real change would then be refused on every replica.
    #[test]
    fn a_change_signed_by_another_key_cannot_take_an_authors_next_seq() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            super::LOG_TARGET,
            "dropping a channel change whose actor is not its signer's key",
        );
        let (alice, mallory) = (nick("alice"), nick("mallory"));
        let alice_key = [0xaa_u8; 32];

        let mut source = MeshDoc::new_ungated();
        let root = author_as(&mut source, &alice, &alice_key, &json!({"a": 1}));
        let mut sink = MeshDoc::new_ungated();
        assert!(
            matches!(sink.ingest(&root), Ingested::Applied { .. }),
            "a change signed by another key is refused for the author's next seq"
        );

        let forged = sink
            .build_change(&json!({"a": "forged"}), &alice_key)
            .expect("merge applies")
            .expect("merge is not a no-op");
        let forged = frame_as(&mallory, &forged, AuthorKey::from([0xbb; 32]));
        assert!(
            matches!(sink.ingest(&forged), Ingested::Ignored),
            "the forged change is refused for the author's next seq"
        );
        assert_eq!(
            sink.pending_stats().0,
            0,
            "no pending change is kept for the forged seq"
        );

        let real = author_as(&mut source, &alice, &alice_key, &json!({"a": 2}));
        assert!(
            matches!(sink.ingest(&real), Ingested::Applied { .. }),
            "a later change from the real author is accepted"
        );
        assert_eq!(
            sink.to_json(),
            json!({"a": 2}),
            "the document holds only the real author's change"
        );
    }

    /// A forged change whose parents are missing takes no place in the orphan
    /// buffer of its signer.
    #[test]
    fn a_change_signed_by_another_key_is_not_buffered() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            super::LOG_TARGET,
            "dropping a channel change whose actor is not its signer's key",
        );
        let alice_key = [0xaa_u8; 32];
        let mut source = MeshDoc::new_ungated();
        let _root = author_as(&mut source, &nick("alice"), &alice_key, &json!({"a": 1}));
        let orphan = source
            .build_change(&json!({"a": "forged"}), &alice_key)
            .expect("merge applies")
            .expect("merge is not a no-op");
        let forged = frame_as(&nick("mallory"), &orphan, AuthorKey::from([0xbb; 32]));

        let mut sink = MeshDoc::new_ungated();
        assert!(
            matches!(sink.ingest(&forged), Ingested::Ignored),
            "a change signed by another key is not buffered"
        );
        assert_eq!(
            sink.pending_stats().0,
            0,
            "no pending change is kept for the forged key"
        );
    }

    #[test]
    fn out_of_order_change_is_buffered_then_drains() {
        let _guard = ::habilis_network_test_tracing::init();
        let alice = nick("alice");
        let mut source = MeshDoc::new_ungated();
        let first = author(&mut source, &alice, &json!({"a": 1}));
        let second = author(&mut source, &alice, &json!({"b": 2}));

        // Deliver the second change first: it depends on the first, so it buffers.
        let mut sink = MeshDoc::new_ungated();
        assert!(
            matches!(sink.ingest(&second), Ingested::Buffered),
            "an out-of-order change is buffered first"
        );
        assert_eq!(
            sink.to_json(),
            json!({}),
            "the document is empty while the change is pending"
        );
        // The first change unblocks the buffered second in one ingest.
        assert!(
            matches!(sink.ingest(&first), Ingested::Applied { .. }),
            "the first change drains the buffer"
        );
        assert_eq!(
            sink.to_json(),
            json!({"a": 1, "b": 2}),
            "the drained buffer applies both changes in order"
        );
    }

    #[test]
    fn a_doc_holds_its_own_and_earlier_heads_only() {
        let _guard = ::habilis_network_test_tracing::init();
        let alice = nick("alice");
        let mut source = MeshDoc::new_ungated();
        author(&mut source, &alice, &json!({"a": 1}));
        let earlier: Vec<_> = source.heads().collect();
        author(&mut source, &alice, &json!({"b": 2}));
        let mut joiner = MeshDoc::new_ungated();

        let own_heads: Vec<_> = source.heads().collect();
        let fresh_heads: Vec<_> = joiner.heads().collect();
        assert!(source.holds_heads(&own_heads), "its own heads");
        assert!(source.holds_heads(&earlier), "heads it has moved past");
        assert!(source.holds_heads(&fresh_heads), "a fresh doc's genesis");
        assert!(!joiner.holds_heads(&own_heads), "heads it never saw");
        assert!(
            !source.holds_heads(&["not-a-hash".to_owned()]),
            "a head that does not decode"
        );
        for carrier in source.changes_since(&fresh_heads, 100) {
            joiner.ingest(&carrier);
        }
        let backfilled: Vec<_> = source.heads().collect();
        assert!(joiner.holds_heads(&backfilled), "after the backfill");
    }

    #[test]
    fn a_flood_past_the_author_cap_converges_on_the_author_re_send() {
        let _guard = ::habilis_network_test_tracing::init();
        let alice = nick("alice");
        let mut source = MeshDoc::new_ungated();
        let frames: Vec<_> = (0..200)
            .map(|index| author(&mut source, &alice, &json!({ format!("k{index}"): index })))
            .collect();
        let heads: Vec<_> = source.heads().collect();
        let mut joiner = MeshDoc::new_ungated();
        // A relayed flood reaches the joiner tail first, so the author's cap refuses the excess.
        let tail_first: Vec<&Verified> = frames[1..].iter().chain(&frames[..1]).collect();
        for frame in tail_first {
            joiner.ingest(frame);
        }
        assert!(
            !joiner.holds_heads(&heads),
            "the first pass leaves the refused tail out"
        );
        // The author re-sends in causal order, and the refused frames land now.
        for frame in &frames {
            joiner.ingest(frame);
        }
        assert!(
            joiner.holds_heads(&heads),
            "the re-send converges the joiner"
        );
    }

    /// The signer key of a test author: the actor seed, zero-padded, as `author` derives it.
    fn signer(who: &Nickname) -> AuthorKey {
        AuthorKey::from(pad_seed(who.as_str().as_bytes()))
    }

    /// A frame of `who` that writes `merge` on top of what `doc` holds, in the epoch of `doc`. The
    /// doc is not changed.
    fn frame_on(doc: &MeshDoc, who: &Nickname, merge: &Value) -> Verified {
        let seed = pad_seed(who.as_str().as_bytes());
        let bytes = doc
            .build_change(merge, &seed)
            .expect("merge applies")
            .expect("merge is not a no-op");
        let (wire, _plain) = doc.compose_wire_body(&bytes, None).expect("compose");
        let key = signer(who);
        Verified::fixture_unchecked(
            Message::new_channel_event(&MeshId::from("test"), who, wire, Channel::Meta)
                .unverified_key(key),
            key,
        )
    }

    /// [`frame_on`], applied to `doc`.
    fn write(doc: &mut MeshDoc, who: &Nickname, merge: &Value) -> Verified {
        let carrier = frame_on(doc, who, merge);
        let outcome = doc.ingest(&carrier);
        assert!(
            matches!(outcome, Ingested::Applied { .. }),
            "expected applied, got {outcome:?}"
        );
        carrier
    }

    #[test]
    fn a_replay_with_a_leaf_that_does_not_fit_gives_the_error_and_no_merge() {
        let _guard = ::habilis_network_test_tracing::init();
        let doc = MeshDoc::new_ungated().state_epochs();
        let patch = json!({ "a": 1, "b": "x".repeat(200) });
        let fits = |merge: &Value| merge.to_string().len() <= 60;
        let result = doc.split_replay(&patch, fits);
        assert!(
            matches!(result, Err(DocError::TooLarge { .. })),
            "the leaf b is longer than a frame, so the whole replay is refused: {result:?}"
        );
    }

    /// The change that `doc` builds for `merge` as the actor of `actor_seed`.
    fn change_of(doc: &MeshDoc, merge: &Value, actor_seed: &[u8]) -> Vec<u8> {
        let built = doc.build_change(merge, actor_seed).expect("applies");
        built.expect("a change")
    }

    /// `path` as owned keys.
    fn owned_path(path: Vec<&str>) -> Vec<String> {
        path.into_iter().map(str::to_owned).collect()
    }

    /// Ingest `frame` into `doc`, and fail the test if the frame does not apply.
    fn ingest_applies(doc: &mut MeshDoc, frame: &Verified) {
        let outcome = doc.ingest(frame);
        assert!(
            matches!(outcome, Ingested::Applied { .. }),
            "expected applied, got {outcome:?}"
        );
    }

    fn entry(who: &str, card: &str) -> Value {
        json!({ "peers": { who: { "card": card, "status": "idle" } } })
    }

    /// A write of `who` that adds one field of about 2 KB: one frame, below the size of a message.
    fn filler(who: &str, field: &str) -> Value {
        json!({ "peers": { who: { field: long(1_800) } } })
    }

    /// `len` characters that automerge cannot squeeze, so a frame is about as long as its entry.
    fn long(len: usize) -> String {
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let digits = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            char::from(digits[usize::try_from(state >> 33).unwrap_or(0) % digits.len()])
        };
        (0..len).map(|_| next()).collect()
    }

    /// The root frame of `epoch`: the first write of `who` in a fresh document of that epoch.
    fn root_of(epoch: u64, who: &Nickname, card: &str) -> Verified {
        let fresh = MeshDoc::new_gated(card_gate()).at_epoch(epoch);
        frame_on(&fresh, who, &entry(who.as_str(), card))
    }

    fn dropped_keys(doc: &mut MeshDoc) -> Vec<DedupKey> {
        doc.take_dropped().collect()
    }

    #[test]
    fn a_reset_at_the_cap_drops_every_frame_and_hands_back_the_own_entry() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, ghost) = (nick("me"), nick("ghost"));
        let mut doc = MeshDoc::new_gated(card_gate()).epoch_cap(2_000);
        for field in ["a", "b", "c"] {
            write(&mut doc, &ghost, &filler("ghost", field));
        }
        write(&mut doc, &me, &entry("me", "mine"));
        let switch = doc.tick_epoch(&me).expect("over the cap: a reset");
        assert_eq!(switch.epoch, 1, "the reset starts the next epoch");
        assert_eq!(doc.epoch(), 1, "the document holds the new epoch");
        assert_eq!(
            switch.own_entry,
            Some(json!({ "card": "mine", "status": "idle" })),
            "the reset hands back the entry that only its owner can write"
        );
        let census = doc.census(true);
        assert_eq!(
            (census.frames, census.frame_bytes),
            (0, 0),
            "no frame stays"
        );
        assert_eq!(census.changes, 1, "only the genesis stays");
        assert_eq!(
            doc.to_json(),
            json!({ "peers": {} }),
            "the new epoch holds the genesis and no entry"
        );
    }

    #[test]
    fn under_the_cap_a_tick_changes_nothing() {
        let _guard = ::habilis_network_test_tracing::init();
        let me = nick("me");
        let mut doc = MeshDoc::new_gated(card_gate()).epoch_cap(1_000_000);
        write(&mut doc, &me, &entry("me", "mine"));
        assert_eq!(
            doc.tick_epoch(&me),
            None,
            "a document under the cap does not reset"
        );
        assert_eq!(doc.epoch(), 0, "a document under the cap keeps its epoch");
    }

    #[test]
    fn live_entries_over_the_cap_do_not_reset_in_a_loop() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, ann, bob, cat) = (nick("me"), nick("ann"), nick("bob"), nick("cat"));
        let mut doc = MeshDoc::new_gated(card_gate()).epoch_cap(4_000);
        write(&mut doc, &me, &entry("me", "mine"));
        for _ in 0..super::DOC_EPOCH_ADOPT_WAIT_TICKS + 2 {
            assert!(doc.tick_epoch(&me).is_none(), "under the cap");
        }
        for field in ["a", "b"] {
            write(&mut doc, &ann, &filler("ann", field));
        }
        let switch = doc.tick_epoch(&me).expect("over the cap");
        assert_eq!(switch.epoch, 1, "the first reset starts epoch 1");
        // The live entries come back, and they alone are over the cap.
        for who in [&me, &ann, &bob, &cat] {
            write(&mut doc, who, &entry(who.as_str(), &long(800)));
        }
        let live = doc.census(false).frame_bytes;
        assert!(live > 4_000, "the live entries fill the cap: {live}");
        for tick in 0..30 {
            assert!(doc.tick_epoch(&me).is_none(), "no reset at tick {tick}");
        }
        assert_eq!(
            doc.epoch(),
            1,
            "live entries over the cap do not start another epoch"
        );
    }

    #[test]
    fn ten_times_the_cap_of_writes_stays_inside_the_bound() {
        let _guard = ::habilis_network_test_tracing::init();
        let me = nick("me");
        let cap = 4_000;
        let mut doc = MeshDoc::new_gated(card_gate()).epoch_cap(cap);
        write(&mut doc, &me, &entry("me", "mine"));
        let (mut resets, mut peak) = (0, 0);
        for round in 0..200 {
            let merge = json!({ "peers": { "me": { "status": format!("{round}{}", long(300)) } } });
            write(&mut doc, &me, &merge);
            if let Some(switch) = doc.tick_epoch(&me) {
                resets += 1;
                let again = json!({ "peers": { "me": switch.own_entry } });
                write(&mut doc, &me, &again);
            }
            peak = peak.max(doc.census(false).frame_bytes);
        }
        assert!(resets >= 10, "the store reset {resets} times");
        assert!(
            peak <= 4 * cap + 1_500,
            "the peak of {peak} bytes is over 4 x the cap"
        );
    }

    #[test]
    fn a_node_with_no_frame_of_others_adopts_a_higher_epoch_at_once() {
        let _guard = ::habilis_network_test_tracing::init();
        let (joiner, live) = (nick("joiner"), nick("live"));
        let root = root_of(1, &live, "live card");
        let mut doc = MeshDoc::new_gated(card_gate());
        write(&mut doc, &joiner, &entry("joiner", "joiner card"));
        assert!(
            matches!(doc.ingest(&root), Ingested::NewEpoch { epoch: 1 }),
            "a root of a higher epoch becomes the candidate"
        );
        assert_eq!(doc.epoch(), 0, "the frame alone does not switch");
        let switch = doc
            .adopt_if_alone(&joiner, &signer(&joiner))
            .expect("a node that holds nothing from others adopts");
        assert_eq!(switch.epoch, 1, "the node adopts the epoch of the root");
        assert_eq!(
            switch.own_entry,
            Some(json!({ "card": "joiner card", "status": "idle" })),
            "the entry of the joiner is handed back to write again"
        );
        assert_eq!(doc.epoch(), 1, "the document holds the new epoch");
        assert_eq!(
            doc.to_json(),
            json!({ "peers": { "live": { "card": "live card", "status": "idle" } } }),
            "the root applies in the new epoch and nothing of the old one stays"
        );
    }

    #[test]
    fn a_node_that_holds_frames_of_others_waits_then_jumps_to_the_highest_epoch() {
        let _guard = ::habilis_network_test_tracing::init();
        let (quiet, other, live) = (nick("quiet"), nick("other"), nick("live"));
        let mut doc = MeshDoc::new_gated(card_gate());
        write(&mut doc, &other, &entry("other", "other card"));
        write(&mut doc, &quiet, &entry("quiet", "quiet card"));
        assert!(
            matches!(
                doc.ingest(&root_of(1, &live, "one")),
                Ingested::NewEpoch { epoch: 1 }
            ),
            "the root of epoch 1 is the candidate"
        );
        assert!(
            doc.adopt_if_alone(&quiet, &signer(&quiet)).is_none(),
            "a node that holds frames of others does not adopt at once"
        );
        for tick in 1..5 {
            assert!(doc.tick_epoch(&quiet).is_none(), "tick {tick} waits");
        }
        assert!(
            matches!(
                doc.ingest(&root_of(2, &live, "two")),
                Ingested::NewEpoch { epoch: 2 }
            ),
            "the root of epoch 2 takes the place of the root of epoch 1"
        );
        let switch = doc.tick_epoch(&quiet).expect("the wait is over");
        assert_eq!(switch.epoch, 2, "it jumps to the highest epoch that it saw");
        assert_eq!(
            switch.own_entry,
            Some(json!({ "card": "quiet card", "status": "idle" })),
            "the quiet peer keeps its entry for the write"
        );
        assert_eq!(
            doc.to_json(),
            json!({ "peers": { "live": { "card": "two", "status": "idle" } } }),
            "the document holds the entry of the highest epoch only"
        );
    }

    #[test]
    fn a_higher_epoch_frame_that_fails_a_check_changes_nothing() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, alice, mallory) = (nick("me"), nick("alice"), nick("mallory"));
        let mut doc = MeshDoc::new_gated(card_gate());
        write(&mut doc, &alice, &entry("alice", "alice card"));
        // Not a root: it sits on top of another change of its epoch.
        let mut ahead = MeshDoc::new_gated(card_gate()).at_epoch(1);
        write(&mut ahead, &alice, &entry("alice", "first"));
        let not_root = frame_on(&ahead, &alice, &entry("alice", "second"));
        // A write of another peer's entry.
        let fresh = MeshDoc::new_gated(card_gate()).at_epoch(1);
        let forged = frame_on(&fresh, &mallory, &entry("alice", "forged"));
        // A signer that is not the actor of the change.
        let mut wrong_signer = root_of(1, &alice, "x");
        let other_key = signer(&mallory);
        wrong_signer = Verified::fixture_unchecked(
            Message::new_channel_event(
                &MeshId::from("test"),
                &alice,
                wrong_signer.body.clone(),
                Channel::Meta,
            )
            .unverified_key(other_key),
            other_key,
        );
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "dropping a channel change whose actor is not its signer's key",
        );
        // Too far above the epoch of the node.
        let too_far = root_of(super::DOC_EPOCH_JUMP_MAX + 1, &alice, "far");
        for (name, frame) in [
            ("not a root", &not_root),
            ("a foreign entry", &forged),
            ("an actor that is not the signer", &wrong_signer),
            ("an epoch past the jump bound", &too_far),
        ] {
            let outcome = doc.ingest(frame);
            assert!(
                !matches!(
                    outcome,
                    Ingested::NewEpoch { .. } | Ingested::Applied { .. }
                ),
                "{name}: {outcome:?}"
            );
        }
        for _ in 0..20 {
            assert!(
                doc.tick_epoch(&me).is_none(),
                "a refused frame never starts a reset"
            );
        }
        assert_eq!(doc.epoch(), 0, "no refused frame changes the epoch");
        assert_eq!(
            doc.to_json(),
            json!({ "peers": { "alice": { "card": "alice card", "status": "idle" } } }),
            "no refused frame changes the document"
        );
    }

    #[test]
    fn a_frame_of_a_lower_epoch_is_ignored_and_keeps_its_dedup_key() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, alice) = (nick("me"), nick("alice"));
        let old = root_of(0, &alice, "old");
        let mut doc = MeshDoc::new_gated(card_gate()).at_epoch(1);
        write(&mut doc, &me, &entry("me", "mine"));
        assert!(
            matches!(doc.ingest(&old), Ingested::Ignored),
            "a frame of a dead epoch is ignored"
        );
        assert!(dropped_keys(&mut doc).is_empty(), "a dead frame stays seen");
        assert_eq!(
            doc.to_json(),
            json!({ "peers": { "me": { "card": "mine", "status": "idle" } } }),
            "a frame of a dead epoch does not change the document"
        );
    }

    #[test]
    fn a_refused_candidate_frees_its_dedup_key_so_the_re_send_lands() {
        let _guard = ::habilis_network_test_tracing::init();
        let (alice, bob) = (nick("alice"), nick("bob"));
        let mut doc = MeshDoc::new_gated(card_gate());
        write(&mut doc, &alice, &entry("alice", "a"));
        let two = root_of(2, &bob, "two");
        let one = root_of(1, &bob, "one");
        let late_one = root_of(1, &alice, "late");
        assert!(
            matches!(doc.ingest(&one), Ingested::NewEpoch { epoch: 1 }),
            "the root of epoch 1 is the candidate"
        );
        assert!(
            matches!(doc.ingest(&two), Ingested::NewEpoch { epoch: 2 }),
            "the root of epoch 2 takes the place of the root of epoch 1"
        );
        assert_eq!(
            dropped_keys(&mut doc),
            vec![one.dedup_key()],
            "the candidate that lost its place is forgotten"
        );
        assert!(
            matches!(doc.ingest(&late_one), Ingested::Ignored),
            "a lower candidate is refused"
        );
        assert_eq!(
            dropped_keys(&mut doc),
            vec![late_one.dedup_key()],
            "a lower candidate is forgotten, so its re-send is not a repeat"
        );
    }

    /// A doc over its cap with one ghost frame and the entry of `who`, so the next tick resets it.
    fn doc_over_the_cap(who: &Nickname) -> MeshDoc {
        let ghost = nick("ghost");
        let mut doc = MeshDoc::new_gated(card_gate()).epoch_cap(2_000);
        for field in ["a", "b", "c"] {
            write(&mut doc, &ghost, &filler("ghost", field));
        }
        write(&mut doc, who, &entry(who.as_str(), "mine"));
        doc
    }

    fn holds_entry(doc: &MeshDoc, who: &str) -> bool {
        doc.to_json()["peers"].get(who).is_some()
    }

    #[test]
    fn a_candidate_of_the_epoch_a_node_resets_to_is_not_lost_by_the_reset() {
        let _guard = ::habilis_network_test_tracing::init();
        let (alice, bob) = (nick("alice"), nick("bob"));
        let mut doc = doc_over_the_cap(&bob);
        let from_alice = root_of(1, &alice, "hers");
        assert!(
            matches!(doc.ingest(&from_alice), Ingested::NewEpoch { epoch: 1 }),
            "the root of epoch 1 is the candidate of a node that is still at epoch 0"
        );
        doc.tick_epoch(&bob)
            .expect("over the cap: a reset to epoch 1");
        let forgotten = dropped_keys(&mut doc).contains(&from_alice.dedup_key());
        assert!(
            holds_entry(&doc, "alice") || forgotten,
            "the card of alice is in epoch 1 or its re-send is not a repeat"
        );
    }

    #[test]
    fn a_node_that_crosses_the_cap_with_a_higher_candidate_goes_to_the_epoch_of_the_candidate() {
        let _guard = ::habilis_network_test_tracing::init();
        let (alice, bob) = (nick("alice"), nick("bob"));
        let mut doc = doc_over_the_cap(&bob);
        let from_alice = root_of(3, &alice, "hers");
        assert!(
            matches!(doc.ingest(&from_alice), Ingested::NewEpoch { epoch: 3 }),
            "the root of epoch 3 is the candidate"
        );
        let switch = doc.tick_epoch(&bob).expect("over the cap: a switch");
        assert_eq!(
            switch.epoch, 3,
            "the switch goes to the epoch of the candidate"
        );
        assert_eq!(
            doc.epoch(),
            3,
            "the document holds the epoch of the candidate"
        );
        assert!(
            holds_entry(&doc, "alice"),
            "the card of the candidate is in the new epoch"
        );
    }

    #[test]
    fn a_candidate_that_the_new_epoch_does_not_take_is_forgotten_and_reported() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            super::LOG_TARGET,
            "the candidate of the new epoch was not applied",
        );
        let (alice, bob, mallory) = (nick("alice"), nick("bob"), nick("mallory"));
        let mut doc = doc_over_the_cap(&bob);
        let fresh = MeshDoc::new_gated(card_gate()).at_epoch(1);
        let forged = frame_on(&fresh, &mallory, &entry(alice.as_str(), "forged"));
        let forged_change = Change::from_bytes(
            parse_change_full(forged.body.as_str())
                .expect("a change body")
                .bytes,
        )
        .expect("a change");
        doc.candidate = Some(Box::new(super::Candidate::new(
            1,
            forged.clone(),
            &forged_change,
            None,
        )));
        let switch = doc.tick_epoch(&bob).expect("over the cap: a switch");
        assert_eq!(switch.epoch, 1, "the node still goes to the epoch");
        assert!(
            !holds_entry(&doc, "alice"),
            "a frame that fails the gate is not in the document"
        );
        assert_eq!(
            dropped_keys(&mut doc),
            vec![forged.dedup_key()],
            "the key is forgotten, so the re-send is not a repeat"
        );
    }

    /// Eight nodes at epoch 0 that all cross the cap in one minute: the first resets and writes its
    /// card, each of the others gets that frame while it is still at epoch 0, then resets in turn.
    #[test]
    fn eight_nodes_that_reset_in_one_minute_all_hold_the_eight_cards() {
        let _guard = ::habilis_network_test_tracing::init();
        let names: Vec<Nickname> = (0..8).map(|index| nick(&format!("n{index}"))).collect();
        let mut docs: Vec<MeshDoc> = names.iter().map(doc_over_the_cap).collect();
        let mut seen: Vec<HashSet<DedupKey>> = names.iter().map(|_| HashSet::new()).collect();
        let mut sent: Vec<Verified> = Vec::new();
        for first in 0..names.len() {
            docs[first]
                .tick_epoch(&names[first])
                .expect("over the cap: a reset");
            let card = entry(names[first].as_str(), "mine");
            sent.push(write(&mut docs[first], &names[first], &card));
            for index in 0..docs.len() {
                if index != first {
                    receive(&mut docs[index], &mut seen[index], &sent);
                }
            }
        }
        for _ in 0..3 {
            for index in 0..docs.len() {
                receive(&mut docs[index], &mut seen[index], &sent);
            }
        }
        for doc in &docs {
            let cards: usize = names
                .iter()
                .filter(|name| holds_entry(doc, name.as_str()))
                .count();
            assert_eq!(cards, 8, "a node holds every card after the resets");
        }
    }

    /// A receiver in the engine: a repeat of a seen frame is not ingested, and a key that the
    /// document drops is forgotten, so the re-send lands.
    fn receive(doc: &mut MeshDoc, seen: &mut HashSet<DedupKey>, frames: &[Verified]) {
        for frame in frames {
            if seen.insert(frame.dedup_key()) {
                let _ = doc.ingest(frame);
            }
            for key in doc.take_dropped() {
                seen.remove(&key);
            }
        }
    }

    /// A `fits` for `build_seed`: a merge fits when its JSON text is at most `limit` bytes.
    fn within(limit: usize) -> impl FnMut(&Value) -> bool {
        move |merge| merge.to_string().len() <= limit
    }

    fn parse_changes(raw: &[Vec<u8>]) -> Vec<Change> {
        let mut changes: Vec<Change> = Vec::with_capacity(raw.len());
        for bytes in raw {
            changes.push(Change::from_bytes(bytes.clone()).expect("a change"));
        }
        changes
    }

    fn state_doc_of(changes: &[Vec<u8>], epoch: u64) -> Value {
        let mut doc = automerge::Automerge::new();
        doc.apply_changes([super::state_genesis(epoch)])
            .expect("the genesis applies");
        for bytes in changes {
            let change = Change::from_bytes(bytes.clone()).expect("a change");
            doc.apply_changes([change]).expect("the change applies");
        }
        serde_json::to_value(automerge::AutoSerde::from(&doc)).expect("json")
    }

    fn live_state() -> Value {
        json!({
            "board": { "title": "t", "rows": [1, 2, {"a": [true, null]}], "empty": {}, "none": [] },
            "notes": { "a": long(300), "b": long(300), "c": long(300) },
            "n": 7,
            "flag": false,
        })
    }

    fn state_doc_with(live: &Value) -> MeshDoc {
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let me = nick("me");
        write(&mut doc, &me, live);
        doc
    }

    #[test]
    fn a_seed_chain_rebuilds_the_live_json_on_a_fresh_epoch() {
        let _guard = ::habilis_network_test_tracing::init();
        let live = live_state();
        let doc = state_doc_with(&live);
        let chain = doc
            .build_seed(5, b"cutter", within(400))
            .expect("the live json splits");
        assert!(
            chain.changes.len() > 1,
            "the live json needs more than 1 frame"
        );
        assert_eq!(
            state_doc_of(&chain.changes, 5),
            live,
            "the chain on the genesis of epoch 5 gives the live json"
        );
    }

    #[test]
    fn a_seed_chain_is_linear_and_its_mark_names_the_last_change() {
        let _guard = ::habilis_network_test_tracing::init();
        let doc = state_doc_with(&live_state());
        let chain = doc
            .build_seed(5, b"cutter", within(400))
            .expect("the live json splits");
        let changes: Vec<Change> = parse_changes(&chain.changes);
        assert_eq!(
            changes[0].deps(),
            [super::state_genesis(5).hash()],
            "the root depends on the genesis of the epoch"
        );
        for pair in changes.windows(2) {
            assert_eq!(
                pair[1].deps(),
                [pair[0].hash()],
                "each change depends on the one before"
            );
        }
        assert_eq!(
            chain.mark.frames as usize,
            changes.len(),
            "the mark counts the frames"
        );
        let tip: &Change = changes.last().expect("a change");
        let tip_hash: String = tip.hash().to_string();
        assert_eq!(chain.mark.last, tip_hash, "the mark names the last change");
    }

    #[test]
    fn an_empty_live_document_gives_a_seed_of_one_change() {
        let _guard = ::habilis_network_test_tracing::init();
        let doc = MeshDoc::new_ungated();
        let chain = doc
            .build_seed(2, b"cutter", within(400))
            .expect("an empty json splits");
        assert_eq!(chain.changes.len(), 1, "a seed has a root even when empty");
        assert_eq!(
            state_doc_of(&chain.changes, 2),
            json!({}),
            "the seed leaves no key"
        );
    }

    #[test]
    fn a_seed_that_would_pass_the_frame_max_is_not_built() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut live: Map<String, Value> = Map::new();
        for index in 0..=DOC_SEED_FRAMES_MAX {
            live.insert(format!("k{index}"), json!(1));
        }
        let mut doc = MeshDoc::new_ungated();
        write(&mut doc, &nick("me"), &Value::Object(live));
        let result = doc.build_seed(2, b"cutter", within(14));
        assert!(
            matches!(result, Err(DocError::SeedTooLong { .. })),
            "a seed over the max that a node accepts is not cut: {result:?}"
        );
    }

    #[test]
    fn a_leaf_that_does_not_fit_one_frame_is_an_error() {
        let _guard = ::habilis_network_test_tracing::init();
        let doc = state_doc_with(&json!({ "big": long(500) }));
        let result = doc.build_seed(2, b"cutter", within(100));
        assert!(
            matches!(result, Err(DocError::TooLarge { .. })),
            "a leaf over the frame cannot be cut: {result:?}"
        );
    }

    /// The frames of the seed that `cutter` sends for `live` in `epoch`, root first, each cut to
    /// 600 bytes of merge. A `key` seals the bodies, as on a passworded mesh.
    fn seed_frames(
        cutter: &Nickname,
        live: &Value,
        epoch: u64,
        key: Option<&SymmetricKey>,
    ) -> Vec<Verified> {
        let doc = state_doc_with(live);
        seed_frames_of(&doc, cutter, epoch, key)
    }

    /// The frames of the seed that `cutter` cuts from `doc` in `epoch`, each one with the stamps
    /// of the paths that it writes.
    fn seed_frames_of(
        doc: &MeshDoc,
        cutter: &Nickname,
        epoch: u64,
        key: Option<&SymmetricKey>,
    ) -> Vec<Verified> {
        let actor = pad_seed(cutter.as_str().as_bytes());
        let chain = doc
            .build_seed(epoch, &actor, within(600))
            .expect("the live json splits");
        seed_frames_with_key(&chain, cutter, epoch, key)
    }

    /// The frames of a chain that `cutter` cuts in `epoch`.
    fn seed_frames_from(chain: &SeedChain, cutter: &Nickname, epoch: u64) -> Vec<Verified> {
        seed_frames_with_key(chain, cutter, epoch, None)
    }

    fn seed_frames_with_key(
        chain: &SeedChain,
        cutter: &Nickname,
        epoch: u64,
        key: Option<&SymmetricKey>,
    ) -> Vec<Verified> {
        let who = signer(cutter);
        let mut frames: Vec<Verified> = Vec::new();
        let numbered: Vec<(usize, &Vec<u8>)> = chain.changes.iter().enumerate().collect();
        for (index, bytes) in numbered {
            let mark = (index == 0).then_some(&chain.mark);
            let stamps: Vec<Stamp> = chain.origins.get(index).cloned().unwrap_or_default();
            let dead: &[(Vec<String>, Stamp)] =
                chain.tombstones.get(index).map_or(&[], Vec::as_slice);
            let plain =
                change_body_tombstoned(bytes, None, epoch, mark, Some(chain.time), &stamps, dead)
                    .expect("a body");
            let wire = match key {
                Some(sealing) => encrypt_body(&plain, sealing).expect("sealed"),
                None => plain,
            };
            let message =
                Message::new_channel_event(&MeshId::from("test"), cutter, wire, Channel::State);
            frames.push(Verified::fixture_unchecked(
                message.unverified_key(who),
                who,
            ));
        }
        frames
    }

    fn ticks(doc: &mut MeshDoc, me: &Nickname, count: u32) -> Option<super::EpochSwitch> {
        let mut last: Option<super::EpochSwitch> = None;
        for _ in 0..count {
            if let Some(switch) = doc.tick_epoch(me) {
                last = Some(switch);
            }
        }
        last
    }

    /// The frames that `cutter` writes after it adopted the seed `frames` of epoch 3: each one
    /// follows the change before it, the first one follows the tip of the seed.
    fn writes_after_the_seed(
        cutter: &Nickname,
        frames: &[Verified],
        count: usize,
    ) -> Vec<Verified> {
        let mut doc = MeshDoc::new_ungated().state_epochs();
        for frame in frames {
            doc.ingest(frame);
        }
        let me = nick("me");
        for _ in 0..super::DOC_EPOCH_ADOPT_WAIT_TICKS {
            doc.tick_epoch(&me);
        }
        let mut writes: Vec<Verified> = Vec::new();
        for index in 0..count {
            writes.push(write(&mut doc, cutter, &json!({ "after": index })));
        }
        writes
    }

    #[test]
    fn a_write_of_the_cutter_after_the_seed_does_not_take_a_slot_of_the_chain() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter) = (nick("me"), nick("cutter"));
        let live = live_state();
        let frames = seed_frames(&cutter, &live, 3, None);
        let writes = writes_after_the_seed(&cutter, &frames, 1);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let last = frames.len() - 1;
        for frame in &frames[..last] {
            doc.ingest(frame);
        }
        doc.ingest(&writes[0]);
        doc.ingest(&frames[last]);
        let switch = ticks(&mut doc, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS);
        assert!(
            switch.is_some(),
            "the chain is whole, so the seed is adopted"
        );
        assert_eq!(
            doc.to_json(),
            live,
            "the document holds the live json of the seed"
        );
    }

    /// A frame of `cutter` in epoch 3 that follows the root of the chain `frames`, as the second
    /// frame of the chain does, with other content: a fork of the chain.
    fn fork_of_the_root(cutter: &Nickname, frames: &[Verified]) -> Verified {
        let root: Vec<u8> = parse_change_full(frames[0].body.as_str())
            .expect("a root body")
            .bytes;
        let mut doc = automerge::Automerge::new();
        doc.apply_changes([super::state_genesis(3)])
            .expect("the genesis applies");
        doc.apply_changes([Change::from_bytes(root).expect("a change")])
            .expect("the root applies");
        doc.set_actor(super::actor_for(&pad_seed(cutter.as_str().as_bytes())));
        let heads: Vec<automerge::ChangeHash> = doc.get_heads();
        let mut tx = doc.transaction();
        Transactable::put(&mut tx, &automerge::ROOT, "fork", 1_i64).expect("a put");
        tx.commit();
        let mut changes = doc.get_changes(&heads);
        let change: Vec<u8> = changes.pop().expect("a change").raw_bytes().to_vec();
        let plain = change_body_timed(&change, None, 3, None, Some(1)).expect("a body");
        let who = signer(cutter);
        let message =
            Message::new_channel_event(&MeshId::from("test"), cutter, plain, Channel::State);
        Verified::fixture_unchecked(message.unverified_key(who), who)
    }

    #[test]
    fn a_write_after_a_refused_write_of_the_cutter_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let cutter = nick("cutter");
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let writes = writes_after_the_seed(&cutter, &frames, 2);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        doc.ingest(&frames[0]);
        let first = doc.ingest(&writes[0]);
        assert!(
            matches!(first, Ingested::Ignored),
            "a write after the chain is refused: {first:?}"
        );
        let second = doc.ingest(&writes[1]);
        assert!(
            matches!(second, Ingested::Ignored),
            "the write that follows a refused write is refused too, by its seq: {second:?}"
        );
        let held = doc
            .candidate
            .as_ref()
            .map_or(0, |candidate| candidate.tail.len());
        assert_eq!(held, 0, "no slot of the tail is taken");
    }

    #[test]
    fn a_second_child_of_one_parent_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let cutter = nick("cutter");
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let fork = fork_of_the_root(&cutter, &frames);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        doc.ingest(&frames[0]);
        doc.ingest(&frames[1]);
        let taken = doc.ingest(&fork);
        assert!(
            matches!(taken, Ingested::Ignored),
            "a fork of the chain is refused: {taken:?}"
        );
        assert!(
            dropped_keys(&mut doc).contains(&fork.dedup_key()),
            "its key is forgotten"
        );
    }

    #[test]
    fn a_tail_full_of_frames_off_the_chain_still_takes_the_chain() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter) = (nick("me"), nick("cutter"));
        let live = live_state();
        let frames = seed_frames(&cutter, &live, 3, None);
        let writes = writes_after_the_seed(&cutter, &frames, frames.len() + 2);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        doc.ingest(&frames[0]);
        for write_frame in &writes[1..] {
            doc.ingest(write_frame);
        }
        for frame in &frames[1..] {
            doc.ingest(frame);
        }
        let switch = ticks(&mut doc, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS);
        assert!(
            switch.is_some(),
            "the chain pushed the off-chain frames out"
        );
        assert_eq!(
            doc.to_json(),
            live,
            "the document holds the live json of the seed"
        );
    }

    #[test]
    fn a_state_document_refuses_a_seed_until_state_epochs_are_on() {
        let _guard = ::habilis_network_test_tracing::init();
        let cutter = nick("cutter");
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let mut doc = MeshDoc::new_ungated();
        for frame in &frames {
            let taken = doc.ingest(frame);
            assert!(
                matches!(taken, Ingested::Ignored),
                "refused while the policy is off: {taken:?}"
            );
        }
        assert!(
            doc.candidate.is_none(),
            "no candidate is held, so no memory is pinned"
        );
        let forgotten: Vec<DedupKey> = dropped_keys(&mut doc);
        assert!(
            forgotten.contains(&frames[0].dedup_key()),
            "the key of the root is forgotten"
        );
    }

    #[test]
    fn a_state_seed_chain_is_held_whole_and_adopted_after_the_wait() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter) = (nick("me"), nick("cutter"));
        let live = live_state();
        let frames = seed_frames(&cutter, &live, 3, None);
        assert!(frames.len() > 2, "the seed has a tail: {}", frames.len());
        let mut doc = MeshDoc::new_ungated().state_epochs();
        for frame in &frames {
            let taken = doc.ingest(frame);
            assert!(
                matches!(taken, Ingested::NewEpoch { epoch: 3 }),
                "held: {taken:?}"
            );
        }
        assert_eq!(
            doc.epoch(),
            0,
            "the document does not adopt before the wait"
        );
        let switch = ticks(&mut doc, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("adopted");
        assert_eq!(switch.epoch, 3, "the switch names the epoch of the seed");
        assert_eq!(doc.epoch(), 3, "the document holds the epoch of the seed");
        assert_eq!(
            doc.to_json(),
            live,
            "the document holds the live json of the seed"
        );
    }

    #[test]
    fn a_node_that_holds_a_candidate_does_not_cut_an_epoch() {
        let _guard = ::habilis_network_test_tracing::init();
        let cutter = nick("cutter");
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        for frame in &frames {
            let _ = doc.ingest(frame);
        }
        assert!(doc.has_candidate(), "the seed waits to be adopted");
        let built = doc.build_seed(1, b"me", |_| true);
        assert!(
            matches!(built, Err(DocError::CandidateHeld)),
            "a node adopts a candidate and does not cut: {built:?}"
        );
    }

    /// A state document whose clock reads `time`, as after `time` writes.
    fn doc_with_clock_at(time: u64) -> MeshDoc {
        let doc = MeshDoc::new_ungated().state_epochs();
        for _ in 0..time {
            let _ = doc.next_time();
        }
        doc
    }

    /// The Lamport time that the plain body of `frame` carries.
    fn time_of(frame: &Verified) -> Option<u64> {
        parse_change_full(frame.body.as_str()).and_then(|parsed| parsed.time)
    }

    #[test]
    fn a_state_change_carries_a_time_above_every_time_that_its_node_saw() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, other) = (nick("me"), nick("other"));
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let first = write(&mut doc, &me, &json!({ "a": 1 }));
        let second = write(&mut doc, &me, &json!({ "a": 2 }));
        assert_eq!(time_of(&first), Some(1), "the first change of a node");
        assert_eq!(time_of(&second), Some(2), "the next one is above it");
        // A node with a far higher clock writes, and this document sees it.
        let mut ahead = doc_with_clock_at(49);
        let late = write(&mut ahead, &other, &json!({ "z": 1 }));
        assert_eq!(time_of(&late), Some(50), "the other node is at 50");
        assert!(
            matches!(doc.ingest(&late), Ingested::Applied { .. }),
            "the change of the other node applies"
        );
        assert_eq!(
            doc.clock(),
            50,
            "the clock takes the time of a change that it saw"
        );
        let after = write(&mut doc, &me, &json!({ "a": 3 }));
        assert_eq!(time_of(&after), Some(51), "a write after it is above it");
    }

    #[test]
    fn the_stamp_of_a_leaf_is_the_time_and_the_actor_of_the_change_that_holds_its_value() {
        let _guard = ::habilis_network_test_tracing::init();
        let (left, right) = (nick("left"), nick("right"));
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let first = write(&mut doc, &left, &json!({ "shared": 1, "n": { "k": 5 } }));
        // The other node takes it in, and then writes the shared leaf: its write is the later one.
        let mut other = MeshDoc::new_ungated().state_epochs();
        ingest_applies(&mut other, &first);
        let second = write(&mut other, &right, &json!({ "shared": 2 }));
        ingest_applies(&mut doc, &second);
        let tag = |who: &Nickname| {
            super::actor_tag(&super::actor_for(&pad_seed(who.as_str().as_bytes())))
        };
        let paths: Vec<Vec<String>> = vec![
            vec!["shared".to_owned()],
            vec!["n".to_owned(), "k".to_owned()],
            vec!["missing".to_owned()],
        ];
        assert_eq!(
            doc.stamps_of(&paths),
            vec![
                Some(Stamp::new(2, tag(&right))),
                Some(Stamp::new(1, tag(&left))),
                None
            ],
            "the stamp is the time and the actor of the write that made the value"
        );
    }

    #[test]
    fn a_time_at_the_top_of_the_range_is_refused_so_the_clock_cannot_be_pinned() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "a state change with no valid time was refused",
        );
        let me = nick("me");
        let build = |time: u64| {
            let timeless = MeshDoc::new_ungated();
            let bytes = change_of(
                &timeless,
                &json!({ "a": time }),
                &pad_seed(me.as_str().as_bytes()),
            );
            let body = change_body_timed(&bytes, None, 0, None, Some(time)).expect("a body");
            let key = signer(&me);
            Verified::fixture_unchecked(
                Message::new_channel_event(&MeshId::from("test"), &me, body, Channel::State)
                    .unverified_key(key),
                key,
            )
        };
        let top = super::DOC_TIME_MAX;
        let mut doc = MeshDoc::new_ungated().state_epochs();
        assert!(
            matches!(doc.ingest(&build(top - 1)), Ingested::Applied { .. }),
            "the highest time that is allowed"
        );
        let mut pinned = MeshDoc::new_ungated().state_epochs();
        for refused in [top, top + 1] {
            assert!(
                matches!(pinned.ingest(&build(refused)), Ingested::Ignored),
                "a time of {refused} is refused"
            );
        }
        assert_eq!(pinned.clock(), 0, "a refused time does not move the clock");
        assert_eq!(pinned.refused_time(), 2, "both refusals are counted");
    }

    #[test]
    fn a_state_document_after_a_restart_holds_its_writes_until_it_heard_of_another_write() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, other) = (nick("me"), nick("other"));
        let mut ahead = doc_with_clock_at(49);
        let heard = write(&mut ahead, &other, &json!({ "z": 1 }));
        let mut doc = MeshDoc::new_ungated().state_epochs().awaiting_first_sync();
        let bytes = change_of(&doc, &json!({ "a": 1 }), &pad_seed(me.as_str().as_bytes()));
        assert!(
            matches!(
                doc.compose_wire_body(&bytes, None),
                Err(DocError::ClockNotReady)
            ),
            "a write waits: its time would be below the writes before the restart"
        );
        ingest_applies(&mut doc, &heard);
        assert!(
            matches!(
                doc.compose_wire_body(&bytes, None),
                Err(DocError::ClockNotReady)
            ),
            "a frame does not end the wait: it can be an old one, below our own writes"
        );
        doc.finish_sync();
        let after = write(&mut doc, &me, &json!({ "a": 1 }));
        assert_eq!(
            time_of(&after),
            Some(51),
            "a write after the sync is above the frame"
        );
        // A node that is alone ends the wait itself.
        let mut alone = MeshDoc::new_ungated().state_epochs().awaiting_first_sync();
        alone.finish_sync();
        let first = write(&mut alone, &me, &json!({ "a": 1 }));
        assert_eq!(
            time_of(&first),
            Some(1),
            "after finish_sync the node writes"
        );
    }

    #[test]
    fn two_nodes_list_the_paths_of_a_change_in_the_same_order() {
        let _guard = ::habilis_network_test_tracing::init();
        let me = nick("me");
        let mut writer = MeshDoc::new_ungated();
        write(&mut writer, &me, &json!({ "gone": 1, "keep": { "x": 1 } }));
        // One change that writes an object and its leaves, and writes and deletes one leaf.
        let seed = pad_seed(me.as_str().as_bytes());
        let bytes = change_of(
            &writer,
            &json!({ "z": { "b": 2, "a": [1, 2] }, "m": 7, "gone": null, "keep": { "y": 3 } }),
            &seed,
        );
        let change = Change::from_bytes(bytes.clone()).expect("a change");
        let expected: Vec<Vec<String>> = [
            vec!["gone"],
            vec!["keep", "y"],
            vec!["m"],
            vec!["z"],
            vec!["z", "a"],
            vec!["z", "b"],
        ]
        .into_iter()
        .map(owned_path)
        .collect();
        // Two nodes that hold the same history build the list from the same change.
        let mut left = MeshDoc::new_ungated();
        let mut right = MeshDoc::new_ungated();
        for doc in [&mut left, &mut right] {
            for frame in writer.changes_since(&[], 100) {
                doc.ingest(&frame);
            }
            let held = Change::from_bytes(bytes.clone()).expect("a change");
            doc.doc.apply_changes([held]).expect("applies");
        }
        let (one, two) = (
            super::change_leaves(&left.doc, &change),
            super::change_leaves(&right.doc, &change),
        );
        assert_eq!(one, two, "the same change gives the same list on two nodes");
        assert_eq!(
            one, expected,
            "the list is sorted, with the objects and the leaves"
        );
    }

    #[test]
    fn a_seed_carries_the_stamps_of_its_cutter_view_and_a_node_that_adopts_it_reads_them() {
        let _guard = ::habilis_network_test_tracing::init();
        let (left, right, cutter, me) = (nick("left"), nick("right"), nick("cutter"), nick("me"));
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let first = write(&mut doc, &left, &json!({ "shared": 1, "n": { "k": 5 } }));
        let mut other = MeshDoc::new_ungated().state_epochs();
        ingest_applies(&mut other, &first);
        let second = write(&mut other, &right, &json!({ "shared": 2 }));
        ingest_applies(&mut doc, &second);
        // The cutter holds both writes and cuts a seed. A node that adopts it reads, for each leaf,
        // the stamp of the write that made the value, not the stamp of the cutter.
        let frames = seed_frames_of(&doc, &cutter, 3, None);
        let mut adopter = MeshDoc::new_ungated().state_epochs();
        for frame in &frames {
            let _ = adopter.ingest(frame);
        }
        ticks(&mut adopter, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("adopted");
        let tag = |who: &Nickname| {
            super::actor_tag(&super::actor_for(&pad_seed(who.as_str().as_bytes())))
        };
        let paths: Vec<Vec<String>> = vec![
            vec!["shared".to_owned()],
            vec!["n".to_owned(), "k".to_owned()],
        ];
        assert_eq!(
            adopter.stamps_of(&paths),
            vec![
                Some(Stamp::new(2, tag(&right))),
                Some(Stamp::new(1, tag(&left)))
            ],
            "the stamps of the seed are the stamps of the original writes"
        );
    }

    #[test]
    fn a_seed_whose_stamps_do_not_match_its_changes_is_dropped_before_the_switch() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "the stamps of the candidate seed do not match it",
        );
        let (cutter, me) = (nick("cutter"), nick("me"));
        let doc = state_doc_with(&live_state());
        let actor = pad_seed(cutter.as_str().as_bytes());
        let chain = doc
            .build_seed(3, &actor, within(600))
            .expect("the live json splits");
        // The root frame names no stamp, although its change writes paths.
        let who = signer(&cutter);
        let body = change_body_stamped(
            &chain.changes[0],
            None,
            3,
            Some(&chain.mark),
            Some(chain.time),
            &[],
        )
        .expect("a body");
        let mut frames = vec![Verified::fixture_unchecked(
            Message::new_channel_event(&MeshId::from("test"), &cutter, body, Channel::State)
                .unverified_key(who),
            who,
        )];
        let later = chain.changes.iter().enumerate().skip(1);
        for (index, bytes) in later {
            let stamps = &chain.origins[index];
            let tail = change_body_stamped(bytes, None, 3, None, Some(chain.time), stamps)
                .expect("a body");
            frames.push(Verified::fixture_unchecked(
                Message::new_channel_event(&MeshId::from("test"), &cutter, tail, Channel::State)
                    .unverified_key(who),
                who,
            ));
        }
        let mut adopter = MeshDoc::new_ungated().state_epochs();
        for frame in &frames {
            let _ = adopter.ingest(frame);
        }
        assert!(
            ticks(&mut adopter, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).is_none(),
            "a seed with stamps that do not match is not adopted"
        );
        assert_eq!(adopter.epoch(), 0, "the node keeps its epoch");
    }

    #[test]
    fn a_frame_with_more_stamps_than_the_cap_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "a frame carries more stamps than the cap",
        );
        let me = nick("me");
        let timeless = MeshDoc::new_ungated();
        let bytes = change_of(
            &timeless,
            &json!({ "a": 1 }),
            &pad_seed(me.as_str().as_bytes()),
        );
        let build = |count: usize| {
            let stamps: Vec<Stamp> = (0..count).map(|_| Stamp::new(1, "aa".to_owned())).collect();
            let body =
                change_body_stamped(&bytes, None, 0, None, Some(1), &stamps).expect("a body");
            let key = signer(&me);
            Verified::fixture_unchecked(
                Message::new_channel_event(&MeshId::from("test"), &me, body, Channel::State)
                    .unverified_key(key),
                key,
            )
        };
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let taken = doc.ingest(&build(super::DOC_REPLAY_ENTRIES_MAX + 1));
        assert!(
            matches!(taken, Ingested::Ignored),
            "over the cap: {taken:?}"
        );
        assert_eq!(doc.to_json(), json!({}), "nothing was applied");
    }

    #[test]
    fn the_stamp_of_a_seed_leaf_is_rebuilt_from_the_stored_frame_when_the_record_is_gone() {
        let _guard = ::habilis_network_test_tracing::init();
        let (left, right, cutter, me) = (nick("left"), nick("right"), nick("cutter"), nick("me"));
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let first = write(&mut doc, &left, &json!({ "shared": 1 }));
        let mut other = MeshDoc::new_ungated().state_epochs();
        ingest_applies(&mut other, &first);
        let second = write(&mut other, &right, &json!({ "shared": 2 }));
        ingest_applies(&mut doc, &second);
        let frames = seed_frames_of(&doc, &cutter, 3, None);
        let mut adopter = MeshDoc::new_ungated().state_epochs();
        for frame in &frames {
            let _ = adopter.ingest(frame);
        }
        ticks(&mut adopter, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("adopted");
        let tag = super::actor_tag(&super::actor_for(&pad_seed(right.as_str().as_bytes())));
        let paths = vec![vec!["shared".to_owned()]];
        let expected = vec![Some(Stamp::new(2, tag))];
        assert_eq!(adopter.stamps_of(&paths), expected, "read from the record");
        // The record lives in memory only. The frame of the seed carries the stamps, so a node
        // that lost the record reads the same stamps from the frame that it stores.
        adopter.origins = HashMap::new();
        assert_eq!(
            adopter.stamps_of(&paths),
            expected,
            "rebuilt from the stored frame"
        );
    }

    /// A guard for step 4: the cutter adopts its own seed through `adopt`, which keeps the record
    /// of the stamps, so this passes without the rebuild from the stored frame and pins nothing
    /// new today. A glue that switches the cutter some other way must keep it passing.
    #[test]
    fn the_node_that_cut_a_seed_reads_the_stamps_of_the_original_writes_after_its_own_switch() {
        let _guard = ::habilis_network_test_tracing::init();
        let (left, right, cutter) = (nick("left"), nick("right"), nick("cutter"));
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let first = write(&mut doc, &left, &json!({ "shared": 1 }));
        let mut other = MeshDoc::new_ungated().state_epochs();
        ingest_applies(&mut other, &first);
        let second = write(&mut other, &right, &json!({ "shared": 2 }));
        ingest_applies(&mut doc, &second);
        // The cutter sends the seed to itself, as every node does, and adopts it after the wait.
        let actor = pad_seed(cutter.as_str().as_bytes());
        let chain = doc
            .build_seed(3, &actor, within(600))
            .expect("the live json splits");
        let frames = seed_frames_of(&doc, &cutter, 3, None);
        assert_eq!(
            chain.origins.len(),
            frames.len(),
            "one stamp list for each frame"
        );
        for frame in &frames {
            let _ = doc.ingest(frame);
        }
        ticks(&mut doc, &cutter, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("adopted");
        let tag = super::actor_tag(&super::actor_for(&pad_seed(right.as_str().as_bytes())));
        assert_eq!(
            doc.stamps_of(&[vec!["shared".to_owned()]]),
            vec![Some(Stamp::new(2, tag))],
            "the cutter keeps the stamp of the original write"
        );
    }

    #[test]
    fn a_seed_of_more_than_the_cap_of_paths_is_cut_into_frames_inside_the_cap() {
        let _guard = ::habilis_network_test_tracing::init();
        let (cutter, me) = (nick("cutter"), nick("me"));
        let mut wide = Map::new();
        for index in 0..130 {
            wide.insert(format!("k{index:03}"), json!(index));
        }
        let live = Value::Object(wide);
        let doc = state_doc_with(&live);
        let actor = pad_seed(cutter.as_str().as_bytes());
        let chain = doc
            .build_seed(3, &actor, |_| true)
            .expect("the live json splits");
        assert!(chain.changes.len() >= 2, "130 paths need 2 frames or more");
        for stamps in &chain.origins {
            assert!(
                stamps.len() <= super::DOC_REPLAY_ENTRIES_MAX,
                "a frame names at most the cap: {}",
                stamps.len()
            );
        }
        let mut adopter = MeshDoc::new_ungated().state_epochs();
        let who = signer(&cutter);
        let numbered = chain.changes.iter().enumerate();
        for (index, bytes) in numbered {
            let mark = (index == 0).then_some(&chain.mark);
            let body = change_body_stamped(
                bytes,
                None,
                3,
                mark,
                Some(chain.time),
                &chain.origins[index],
            )
            .expect("a body");
            let frame = Verified::fixture_unchecked(
                Message::new_channel_event(&MeshId::from("test"), &cutter, body, Channel::State)
                    .unverified_key(who),
                who,
            );
            let _ = adopter.ingest(&frame);
        }
        ticks(&mut adopter, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("adopted");
        assert_eq!(adopter.to_json(), live, "the node holds the 130 leaves");
    }

    #[test]
    fn a_seed_path_with_no_time_gets_the_stamp_zero_and_is_counted() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "a seed path got the stamp 0 for want of a time",
        );
        let me = nick("me");
        // A document with state epochs off writes bodies with no time.
        let mut doc = MeshDoc::new_ungated();
        write(&mut doc, &me, &json!({ "a": 1, "b": { "c": 2 } }));
        let actor = pad_seed(me.as_str().as_bytes());
        let chain = doc
            .build_seed(3, &actor, within(600))
            .expect("the live json splits");
        let zeros: usize = chain
            .origins
            .iter()
            .flatten()
            .filter(|stamp| stamp.time == 0)
            .count();
        assert!(zeros > 0, "the paths have the stamp 0");
        assert_eq!(
            doc.unstamped_paths(),
            u64::try_from(zeros).unwrap_or(u64::MAX),
            "each one is counted"
        );
        assert_eq!(
            doc.census(false).unstamped_paths,
            doc.unstamped_paths(),
            "the census carries the count, so it is not only a log line"
        );
    }

    #[test]
    fn the_tombstones_stay_inside_the_cap_at_ten_times_the_cap() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let total = super::DOC_SEED_TOMBSTONES_MAX * 10;
        for index in 0..total {
            let stamp = Stamp::new(u64::try_from(index).unwrap_or(0) + 1, "aa".to_owned());
            doc.add_tombstone(vec![format!("k{index}")], stamp);
            assert!(
                doc.tombstones.len() <= super::DOC_SEED_TOMBSTONES_MAX,
                "the map holds at most the cap"
            );
        }
        assert_eq!(
            doc.tombstones.len(),
            super::DOC_SEED_TOMBSTONES_MAX,
            "it is full"
        );
        let lowest = doc.tombstones.values().map(|stamp| stamp.time).min();
        assert_eq!(
            lowest,
            Some(u64::try_from(total - super::DOC_SEED_TOMBSTONES_MAX).unwrap_or(0) + 1),
            "the tombstones with the lowest stamps left first"
        );
        let long = vec!["x".repeat(super::DOC_TOMBSTONE_PATH_BYTES_MAX + 1)];
        doc.add_tombstone(long, Stamp::new(u64::MAX, "aa".to_owned()));
        assert_eq!(
            doc.tombstone_paths_long, 1,
            "a path that is too long has no tombstone"
        );
        assert_eq!(
            doc.tombstones.len(),
            super::DOC_SEED_TOMBSTONES_MAX,
            "and the map is unchanged"
        );
    }

    /// The tombstones of a document that deleted `count` paths of 40 bytes, with growing stamps.
    fn doc_with_tombstones(count: usize) -> MeshDoc {
        let mut doc = MeshDoc::new_ungated().state_epochs();
        for index in 0..count {
            let stamp = Stamp::new(u64::try_from(index).unwrap_or(0) + 1, "aa".to_owned());
            doc.add_tombstone(vec![format!("{index:040}")], stamp);
        }
        doc
    }

    #[test]
    fn a_seed_spreads_many_tombstones_over_its_frames_inside_a_byte_budget() {
        let _guard = ::habilis_network_test_tracing::init();
        let (cutter, me) = (nick("cutter"), nick("me"));
        let doc = doc_with_tombstones(300);
        let actor = pad_seed(cutter.as_str().as_bytes());
        let chain = doc
            .build_seed(3, &actor, within(600))
            .expect("a seed with many tombstones is built");
        let total: usize = chain.tombstones.iter().map(Vec::len).sum();
        assert_eq!(total, 300, "every tombstone is carried by some frame");
        assert_eq!(
            chain.tombstones.len(),
            chain.changes.len(),
            "one list for each frame"
        );
        assert!(
            chain.changes.len() > 1,
            "300 tombstones need more than 1 frame"
        );
        let numbered = chain.tombstones.iter().enumerate();
        for (index, dead) in numbered {
            let bytes: usize = dead
                .iter()
                .map(|(path, _)| {
                    let path_bytes: usize = path.iter().map(String::len).sum();
                    path_bytes + 32
                })
                .sum();
            assert!(
                bytes <= super::DOC_SEED_TOMBSTONE_FRAME_BYTES,
                "the tombstones of frame {index} fit the budget: {bytes}"
            );
            assert!(
                dead.len() + chain.origins[index].len() <= super::DOC_REPLAY_ENTRIES_MAX,
                "the stamps and the tombstones of a frame stay inside the entry cap"
            );
        }
        let frames = seed_frames_of(&doc, &cutter, 3, None);
        let mut adopter = MeshDoc::new_ungated().state_epochs();
        for frame in &frames {
            let _ = adopter.ingest(frame);
        }
        ticks(&mut adopter, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("adopted");
        assert_eq!(
            adopter.tombstones.len(),
            300,
            "the node holds the 300 tombstones"
        );
    }

    /// The tombstones of a document that deleted `count` paths of 250 bytes (the longest path
    /// that a tombstone keeps is 256 bytes), with growing stamps.
    fn doc_with_long_tombstones(count: usize) -> MeshDoc {
        let mut doc = MeshDoc::new_ungated().state_epochs();
        for index in 0..count {
            let stamp = Stamp::new(u64::try_from(index).unwrap_or(0) + 1, "aa".to_owned());
            doc.add_tombstone(vec![format!("{index:0250}")], stamp);
        }
        doc
    }

    #[test]
    fn a_seed_with_the_full_cap_of_long_tombstones_is_adopted_whole_or_not_at_all() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "the seed of the candidate epoch was not complete",
        );
        let (cutter, me) = (nick("cutter"), nick("me"));
        let doc = doc_with_long_tombstones(super::DOC_SEED_TOMBSTONES_MAX);
        let frames = seed_frames_of(&doc, &cutter, 3, None);
        let bodies = frames.iter().map(|frame| frame.body.as_str());
        let longest = bodies.map(str::len).max().unwrap_or(0);
        assert!(
            longest <= super::DOC_SEED_TOMBSTONE_FRAME_BYTES + 400,
            "the longest body stays near the budget of a frame: {longest} bytes in {} frames",
            frames.len()
        );
        // Every frame arrives: the node holds all the tombstones.
        let mut whole = MeshDoc::new_ungated().state_epochs();
        for frame in &frames {
            let _ = whole.ingest(frame);
        }
        ticks(&mut whole, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("adopted");
        assert_eq!(
            whole.tombstones.len(),
            super::DOC_SEED_TOMBSTONES_MAX,
            "the node holds every tombstone"
        );
        // One frame of the middle is missing: the node does not switch and holds no half seed.
        let mut broken = MeshDoc::new_ungated().state_epochs();
        let numbered = frames.iter().enumerate();
        for (index, frame) in numbered {
            if index != frames.len() / 2 {
                let _ = broken.ingest(frame);
            }
        }
        assert!(
            ticks(&mut broken, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).is_none(),
            "a seed with a frame missing is not adopted"
        );
        assert_eq!(broken.epoch(), 0, "the node keeps its epoch");
        assert!(
            broken.tombstones.is_empty(),
            "and holds no tombstone of the seed"
        );
    }

    #[test]
    fn a_tombstone_body_that_is_not_canonical_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let stamp = Stamp::new(9, "aa".to_owned());
        let one = |path: Vec<&str>| (owned_path(path), stamp.clone());
        let cases: Vec<(StampedPaths, &str)> = vec![
            (vec![one(vec!["a"]), one(vec!["a"])], "the same path twice"),
            (vec![one(vec!["b"]), one(vec!["a"])], "paths out of order"),
            (vec![one(vec![])], "an empty path"),
            (
                vec![one(vec![
                    &"x".repeat(super::DOC_TOMBSTONE_PATH_BYTES_MAX + 1),
                ])],
                "a path over the cap",
            ),
        ];
        for (tombstones, why) in cases {
            let body = change_body_tombstoned(&[1, 2, 3], None, 0, None, Some(7), &[], &tombstones)
                .expect("a body");
            assert!(parse_change_full(body.as_str()).is_none(), "refused: {why}");
        }
        let fine = vec![one(vec!["a"]), one(vec!["a", "b"]), one(vec!["b"])];
        let body =
            change_body_tombstoned(&[1, 2, 3], None, 0, None, Some(7), &[], &fine).expect("a body");
        assert!(
            parse_change_full(body.as_str()).is_some(),
            "the control: a canonical list parses"
        );
    }

    #[test]
    fn tombstones_on_a_frame_that_is_not_a_seed_frame_are_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "the stamps of a frame do not match it",
        );
        let me = nick("me");
        let timeless = MeshDoc::new_ungated();
        let bytes = change_of(
            &timeless,
            &json!({ "a": 1 }),
            &pad_seed(me.as_str().as_bytes()),
        );
        let dead = vec![(vec!["k".to_owned()], Stamp::new(1, "aa".to_owned()))];
        let body =
            change_body_tombstoned(&bytes, None, 0, None, Some(1), &[], &dead).expect("a body");
        let key = signer(&me);
        let frame = Verified::fixture_unchecked(
            Message::new_channel_event(&MeshId::from("test"), &me, body, Channel::State)
                .unverified_key(key),
            key,
        );
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let taken = doc.ingest(&frame);
        assert!(
            matches!(taken, Ingested::Ignored),
            "a normal write carries no tombstone: {taken:?}"
        );
        assert_eq!(doc.to_json(), json!({}), "nothing was applied");
    }

    #[test]
    fn a_seed_leaves_out_a_value_that_a_tombstone_of_a_higher_stamp_governs() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter) = (nick("me"), nick("cutter"));
        let mut doc = MeshDoc::new_ungated().state_epochs();
        write(
            &mut doc,
            &me,
            &json!({ "gone": 1, "kept": 2, "o": { "gone": 3, "kept": 4 } }),
        );
        // A replay brought back `gone` and `o.gone`, but a delete of a higher stamp governs them.
        let high = Stamp::new(99, "aa".to_owned());
        doc.add_tombstone(vec!["gone".to_owned()], high.clone());
        doc.add_tombstone(vec!["o".to_owned(), "gone".to_owned()], high);
        let frames = seed_frames_of(&doc, &cutter, 3, None);
        let mut adopter = MeshDoc::new_ungated().state_epochs();
        for frame in &frames {
            let _ = adopter.ingest(frame);
        }
        ticks(
            &mut adopter,
            &nick("adopter"),
            super::DOC_EPOCH_ADOPT_WAIT_TICKS,
        )
        .expect("adopted");
        assert_eq!(
            adopter.to_json(),
            json!({ "kept": 2, "o": { "kept": 4 } }),
            "the seed holds no value that a delete of a higher stamp governs"
        );
    }

    #[test]
    fn a_restore_that_a_newer_write_overtook_is_not_written() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mine, other, third) = (nick("aaa"), nick("zzz"), nick("mmm"));
        // This node holds `shared = 9` at the stamp 100.
        let mut doc = doc_with_clock_at(99);
        let first = write(&mut doc, &mine, &json!({ "shared": 9 }));
        // A replay of another node sets `shared = 5` at the stamp 50, and automerge keeps it (the
        // actor of that node is the higher one), so this node plans to write 9 again.
        let replayer = MeshDoc::new_ungated().state_epochs();
        let change = change_of(
            &replayer,
            &json!({ "shared": 5 }),
            &pad_seed(other.as_str().as_bytes()),
        );
        let stamps = vec![(
            vec!["shared".to_owned()],
            Stamp::new(50, "7a7a7a7a00000000".to_owned()),
        )];
        let body = replayer
            .compose_replay_body(&change, &stamps)
            .expect("a replay body");
        let key = signer(&other);
        let replay = Verified::fixture_unchecked(
            Message::new_channel_event(&MeshId::from("test"), &other, body, Channel::State)
                .unverified_key(key),
            key,
        );
        ingest_applies(&mut doc, &replay);
        assert!(
            doc.has_restores(),
            "the replay lowered the stamp, so a restore waits"
        );
        // Before the restore goes out, a third node that saw both writes a newer value.
        let mut newer = doc_with_clock_at(120);
        let _ = newer.ingest(&first);
        let _ = newer.ingest(&replay);
        let latest = write(&mut newer, &third, &json!({ "shared": 7 }));
        ingest_applies(&mut doc, &latest);
        assert_eq!(
            doc.take_restores(),
            None,
            "the live stamp is read again, so the restore of 9 is not written over the newer 7"
        );
        assert_eq!(
            doc.to_json(),
            json!({ "shared": 7 }),
            "the newer write stays"
        );
    }

    #[test]
    fn an_object_that_a_replay_makes_for_a_leaf_gets_the_stamp_zero() {
        let _guard = ::habilis_network_test_tracing::init();
        let me = nick("me");
        let doc = MeshDoc::new_ungated().state_epochs();
        let change = change_of(
            &doc,
            &json!({ "o": { "x": 1 } }),
            &pad_seed(me.as_str().as_bytes()),
        );
        let stamps = vec![(
            vec!["o".to_owned(), "x".to_owned()],
            Stamp::new(7, "aa".to_owned()),
        )];
        let body = doc
            .compose_replay_body(&change, &stamps)
            .expect("a replay body");
        let parsed = parse_change_full(body.as_str()).expect("it parses");
        assert_eq!(
            parsed.origins,
            vec![
                Stamp::new(0, "0000000000000000".to_owned()),
                Stamp::new(7, "aa".to_owned())
            ],
            "the object has no write of its own, and the leaf keeps its stamp"
        );
    }

    #[test]
    fn a_restore_that_a_delete_of_a_higher_stamp_overtook_is_not_written() {
        let _guard = ::habilis_network_test_tracing::init();
        let me = nick("me");
        let mut doc = doc_with_clock_at(9);
        write(&mut doc, &me, &json!({ "shared": 1 }));
        // A restore of `shared = 2` at the stamp 50 waits, and then a delete of the leaf with the
        // stamp 60 arrives: the delete is the newer write, and the restore must not bring 2 back.
        let path = vec!["shared".to_owned()];
        doc.restores
            .insert(path.clone(), (json!(2), Stamp::new(50, "aa".to_owned())));
        doc.add_tombstone(path, Stamp::new(60, "bb".to_owned()));
        assert_eq!(
            doc.take_restores(),
            None,
            "a delete of a higher stamp governs the leaf, so the restore is stale"
        );
    }

    #[test]
    fn a_restore_that_finds_the_map_full_is_dropped_counted_and_warned() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "a restore was dropped: the map of restores is full",
        );
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let stamp = Stamp::new(5, "aa".to_owned());
        for index in 0..super::DOC_RESTORES_MAX {
            doc.keep_restore(vec![format!("k{index}")], (json!(index), stamp.clone()));
        }
        assert_eq!(
            doc.dropped_restores(),
            0,
            "nothing was dropped while there was room"
        );
        doc.keep_restore(vec!["one-more".to_owned()], (json!(0), stamp));
        assert_eq!(
            doc.dropped_restores(),
            1,
            "the one that found the map full is counted"
        );
        assert_eq!(
            doc.census(false).dropped_restores,
            1,
            "and the census carries it"
        );
        doc.keep_restore(
            vec!["k0".to_owned()],
            (json!(9), Stamp::new(9, "aa".to_owned())),
        );
        assert_eq!(
            doc.dropped_restores(),
            1,
            "a path that is there is updated, not dropped"
        );
    }

    #[test]
    fn the_restores_stay_inside_the_cap_at_ten_times_the_cap() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "a restore was dropped: the map of restores is full",
        );
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let stamp = Stamp::new(5, "aa".to_owned());
        let total = super::DOC_RESTORES_MAX * 10;
        for index in 0..total {
            doc.keep_restore(vec![format!("k{index}")], (json!(index), stamp.clone()));
        }
        assert_eq!(
            doc.restores.len(),
            super::DOC_RESTORES_MAX,
            "the map stays at the cap"
        );
        assert_eq!(
            doc.dropped_restores(),
            u64::try_from(total - super::DOC_RESTORES_MAX).unwrap_or(0),
            "every other one is counted"
        );
    }

    /// A replay frame of `other` that writes `merge`, with `stamps` on its leaves. The actor of
    /// `other` is the higher one, so the frame wins the conflicts in automerge.
    fn replay_frame_of(
        other: &Nickname,
        merge: &Value,
        stamps: &[(Vec<String>, Stamp)],
    ) -> Verified {
        let replayer = MeshDoc::new_ungated().state_epochs();
        let change = change_of(&replayer, merge, &pad_seed(other.as_str().as_bytes()));
        let body = replayer
            .compose_replay_body(&change, stamps)
            .expect("a replay body");
        let key = signer(other);
        Verified::fixture_unchecked(
            Message::new_channel_event(&MeshId::from("test"), other, body, Channel::State)
                .unverified_key(key),
            key,
        )
    }

    /// A node that holds `obj` with 600 leaves, written in rounds of 100, and the last leaf again
    /// at a high stamp.
    fn doc_with_600_leaves(mine: &Nickname) -> MeshDoc {
        let mut doc = doc_with_clock_at(99);
        for round in 0..6 {
            let mut part = Map::new();
            for leaf in 0..100 {
                part.insert(format!("k{:03}", round * 100 + leaf), json!(leaf));
            }
            write(&mut doc, mine, &json!({ "obj": Value::Object(part) }));
        }
        write(&mut doc, mine, &json!({ "obj": { "k599": 7 } }));
        doc
    }

    fn replay_makes_obj_x() -> (Value, Vec<(Vec<String>, Stamp)>) {
        (
            json!({ "obj": { "x": 1 } }),
            vec![(
                vec!["obj".to_owned(), "x".to_owned()],
                Stamp::new(5, "7a7a7a7a00000000".to_owned()),
            )],
        )
    }

    #[test]
    fn a_replay_that_hides_a_large_object_restores_every_leaf_that_it_hid() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mine, other) = (nick("aaa"), nick("zzz"));
        let mut doc = doc_with_600_leaves(&mine);
        let (merge, stamps) = replay_makes_obj_x();
        ingest_applies(&mut doc, &replay_frame_of(&other, &merge, &stamps));
        assert_eq!(
            doc.to_json(),
            json!({ "obj": { "x": 1 } }),
            "the replay hid every leaf"
        );
        let (patch, written) = doc.take_restores().expect("the leaves are written again");
        assert_eq!(
            written.len(),
            600,
            "all 600 leaves come back, the object is not written as a whole"
        );
        assert_eq!(
            patch["obj"]["k599"],
            json!(7),
            "the last leaf, the newest write, is among them"
        );
    }

    /// A node `other` that wrote the key `late` after the seed was cut, a node `me` that holds
    /// the write and never wrote itself, and the seed of a third node that lacks the write. Each
    /// node has the seed and has waited for it.
    fn a_write_that_the_seed_lacks() -> (MeshDoc, MeshDoc, super::EpochSwitch, Nickname) {
        let (me, other, cutter) = (nick("me"), nick("other"), nick("cutter"));
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let mut writer = MeshDoc::new_ungated().state_epochs();
        let late = write(&mut writer, &other, &json!({ "late": 1 }));
        let mut holder = MeshDoc::new_ungated().state_epochs();
        holder.ingest(&late);
        for frame in &frames {
            writer.ingest(frame);
            holder.ingest(frame);
        }
        let author_switch = ticks(&mut writer, &other, super::DOC_EPOCH_ADOPT_WAIT_TICKS)
            .expect("the author adopts");
        ticks(&mut holder, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("the holder adopts");
        (writer, holder, author_switch, me)
    }

    #[test]
    fn the_author_of_a_write_that_the_seed_lacks_writes_it_again_at_once() {
        let _guard = ::habilis_network_test_tracing::init();
        let (_writer, _holder, author_switch, _me) = a_write_that_the_seed_lacks();
        let patch = author_switch.replay.expect("the author writes it again");
        assert_eq!(patch["late"], json!(1), "the write is in the replay");
    }

    #[test]
    fn a_holder_that_is_not_the_author_waits_up_to_three_ticks_before_it_writes_again() {
        let _guard = ::habilis_network_test_tracing::init();
        let (_writer, mut holder, _author_switch, me) = a_write_that_the_seed_lacks();
        assert!(
            holder.has_restores(),
            "the holder keeps the write for later"
        );
        assert_eq!(holder.take_restores(), None, "it does not write at once");
        let mut written = None;
        for waited in 1..=3 {
            let _ = holder.tick_epoch(&me);
            written = holder.take_restores();
            if written.is_some() {
                assert!(waited <= 3, "it writes within 3 ticks");
                break;
            }
        }
        let (patch, _stamps) = written.expect("the holder writes the write again after the wait");
        assert_eq!(patch["late"], json!(1), "the late write is written again");
    }

    #[test]
    fn the_replay_of_an_object_leaves_out_a_child_that_another_node_wrote() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, other, cutter) = (nick("me"), nick("other"), nick("cutter"));
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let mut holder = MeshDoc::new_ungated().state_epochs();
        let made = write(&mut holder, &me, &json!({ "obj": { "mine": 1 } }));
        let mut writer = MeshDoc::new_ungated().state_epochs();
        writer.ingest(&made);
        let child = write(&mut writer, &other, &json!({ "obj": { "late": 2 } }));
        holder.ingest(&child);
        for frame in &frames {
            holder.ingest(frame);
        }
        let switch = ticks(&mut holder, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("adopted");
        let patch = switch.replay.expect("the node writes its own object again");
        assert_eq!(patch["obj"]["mine"], json!(1), "its own leaf is written");
        assert!(
            patch["obj"].get("late").is_none(),
            "the child of another node has its own stamp and its own wait: {patch}"
        );
        assert!(
            switch
                .replay_stamps
                .iter()
                .all(|(path, _)| path.last().map(String::as_str) != Some("late")),
            "and it is not named in the stamps of this replay"
        );
    }

    #[test]
    fn a_holder_keeps_no_object_as_a_whole_for_later() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, other, cutter) = (nick("me"), nick("other"), nick("cutter"));
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let mut writer = MeshDoc::new_ungated().state_epochs();
        let made = write(&mut writer, &other, &json!({ "obj": { "late": 2 } }));
        let mut holder = MeshDoc::new_ungated().state_epochs();
        holder.ingest(&made);
        for frame in &frames {
            holder.ingest(frame);
        }
        ticks(&mut holder, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("adopted");
        let waits: Vec<Vec<String>> = holder.restores.keys().cloned().collect();
        assert_eq!(
            waits,
            vec![vec!["obj".to_owned(), "late".to_owned()]],
            "only the leaf waits: an object as a whole would replace the keys below it"
        );
    }

    #[test]
    fn a_restore_of_an_empty_object_does_not_replace_what_the_document_holds_there() {
        let _guard = ::habilis_network_test_tracing::init();
        let me = nick("me");
        let mut doc = doc_with_clock_at(9);
        write(&mut doc, &me, &json!({ "obj": { "newer": 5 } }));
        doc.restores.insert(
            vec!["obj".to_owned()],
            (json!({}), Stamp::new(50, "aa".to_owned())),
        );
        assert_eq!(
            doc.take_restores(),
            None,
            "the object is there, and an empty object would only wipe its keys"
        );
    }

    #[test]
    fn a_holder_that_is_not_the_author_does_not_write_what_the_author_wrote_first() {
        let _guard = ::habilis_network_test_tracing::init();
        let (writer, mut holder, author_switch, me) = a_write_that_the_seed_lacks();
        let (patch, stamps) = (
            author_switch.replay.expect("the author writes it again"),
            author_switch.replay_stamps,
        );
        let change = change_of(&writer, &patch, &pad_seed(b"other"));
        let body = writer
            .compose_replay_body(&change, &stamps)
            .expect("a replay body");
        let author = nick("other");
        let key = signer(&author);
        let frame = Verified::fixture_unchecked(
            Message::new_channel_event(&MeshId::from("test"), &author, body, Channel::State)
                .unverified_key(key),
            key,
        );
        assert!(holder.has_restores(), "the holder waits with the write");
        holder.ingest(&frame);
        for _ in 0..3 {
            let _ = holder.tick_epoch(&me);
        }
        assert_eq!(
            holder.take_restores(),
            None,
            "the write of the author carries the same stamp, so the holder has nothing to write"
        );
    }

    #[test]
    fn a_replay_that_hides_an_object_of_1100_leaves_loses_no_restore() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mine, other) = (nick("aaa"), nick("zzz"));
        let mut doc = doc_with_clock_at(99);
        for round in 0..11 {
            let mut part = Map::new();
            for leaf in 0..100 {
                part.insert(format!("k{:04}", round * 100 + leaf), json!(leaf));
            }
            write(&mut doc, &mine, &json!({ "obj": Value::Object(part) }));
        }
        let (merge, stamps) = replay_makes_obj_x();
        doc.ingest(&replay_frame_of(&other, &merge, &stamps));
        assert_eq!(doc.dropped_restores(), 0, "no newer write is dropped");
        let (_, written) = doc.take_restores().expect("the leaves are written again");
        assert_eq!(written.len(), 1100, "all 1100 leaves come back");
    }

    #[test]
    fn a_leaf_that_was_deleted_before_the_replay_hid_the_object_is_not_restored() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mine, other) = (nick("aaa"), nick("zzz"));
        let mut doc = doc_with_600_leaves(&mine);
        write(&mut doc, &mine, &json!({ "obj": { "k005": null } }));
        let (merge, stamps) = replay_makes_obj_x();
        doc.ingest(&replay_frame_of(&other, &merge, &stamps));
        let (patch, written) = doc
            .take_restores()
            .expect("the live leaves are written again");
        assert_eq!(written.len(), 599, "the 600 leaves less the deleted one");
        assert!(
            patch["obj"].get("k005").is_none(),
            "the deleted leaf stays out of the patch"
        );
    }

    #[test]
    fn a_delete_that_a_concurrent_replay_undoes_is_written_again() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mine, other) = (nick("aaa"), nick("zzz"));
        let mut doc = doc_with_clock_at(99);
        write(&mut doc, &mine, &json!({ "obj": { "gone": 1, "stay": 2 } }));
        write(&mut doc, &mine, &json!({ "obj": { "gone": null } }));
        // The replay does not know of the delete: it brings `gone` back with the stamp 5, which
        // is below the stamp of the delete.
        let merge = json!({ "obj": { "gone": 5 } });
        let stamps = vec![(
            vec!["obj".to_owned(), "gone".to_owned()],
            Stamp::new(5, "7a7a7a7a00000000".to_owned()),
        )];
        doc.ingest(&replay_frame_of(&other, &merge, &stamps));
        assert_eq!(
            doc.to_json()["obj"]["gone"],
            json!(5),
            "the value came back"
        );
        let (patch, written) = doc.take_restores().expect("the delete is written again");
        assert_eq!(
            written.len(),
            2,
            "the delete, and `stay`, which the replay hid with its object"
        );
        assert_eq!(patch["obj"]["stay"], json!(2), "the hidden leaf is back");
        assert_eq!(patch["obj"]["gone"], Value::Null, "as a delete");
    }

    #[test]
    fn a_gated_channel_never_writes_a_time() {
        let _guard = ::habilis_network_test_tracing::init();
        let me = nick("me");
        let mut doc = MeshDoc::new_gated(card_gate()).state_epochs();
        let frame = write(&mut doc, &me, &entry("me", "mine"));
        assert_eq!(
            time_of(&frame),
            None,
            "a body of the meta channel is the body from before the time"
        );
        assert_eq!(doc.clock(), 0, "a gated channel keeps no clock");
    }

    #[test]
    fn the_clock_does_not_restart_at_an_epoch() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter) = (nick("me"), nick("cutter"));
        let mut doc = MeshDoc::new_ungated().state_epochs();
        for count in 0..9 {
            write(&mut doc, &me, &json!({ "n": count }));
        }
        assert_eq!(doc.clock(), 9, "nine writes");
        for frame in &seed_frames(&cutter, &live_state(), 3, None) {
            let _ = doc.ingest(frame);
        }
        ticks(&mut doc, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("adopted");
        assert_eq!(doc.epoch(), 3, "the document adopted the seed");
        assert!(
            doc.clock() >= 9,
            "the clock is not lower than before the switch"
        );
        let after = write(&mut doc, &me, &json!({ "again": 1 }));
        assert!(
            time_of(&after) > Some(9),
            "a write of the new epoch is above the old clock: {:?}",
            time_of(&after)
        );
    }

    #[test]
    fn a_state_change_with_no_time_is_refused_when_state_epochs_are_on() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "a state change with no valid time was refused",
        );
        let me = nick("me");
        let timeless = MeshDoc::new_ungated();
        let bytes = change_of(
            &timeless,
            &json!({ "a": 1 }),
            &pad_seed(me.as_str().as_bytes()),
        );
        let body = super::wire::change_body_at(&bytes, None, 0).expect("a body");
        let key = signer(&me);
        let frame = Verified::fixture_unchecked(
            Message::new_channel_event(&MeshId::from("test"), &me, body, Channel::State)
                .unverified_key(key),
            key,
        );
        let mut off = MeshDoc::new_ungated();
        assert!(
            matches!(off.ingest(&frame), Ingested::Applied { .. }),
            "a document with state epochs off takes it, as before"
        );
        let mut on = MeshDoc::new_ungated().state_epochs();
        let taken = on.ingest(&frame);
        assert!(
            matches!(taken, Ingested::Ignored),
            "a state epoch document refuses a change with no time: {taken:?}"
        );
        assert_eq!(on.to_json(), json!({}), "nothing was applied");
        assert_eq!(
            on.refused_time(),
            1,
            "the refusal is counted, so it is never silent"
        );
    }

    #[test]
    fn a_node_adopts_only_a_complete_seed_chain() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            super::LOG_TARGET,
            "the seed of the candidate epoch was not complete",
        );
        let (me, cutter) = (nick("me"), nick("cutter"));
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        write(&mut doc, &me, &json!({ "mine": 1 }));
        for frame in &frames[..frames.len() - 1] {
            doc.ingest(frame);
        }
        assert!(
            ticks(&mut doc, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).is_none(),
            "a chain with a missing frame is not adopted"
        );
        assert_eq!(doc.epoch(), 0, "the document stays in its epoch");
        assert_eq!(
            doc.to_json(),
            json!({ "mine": 1 }),
            "the live values are kept"
        );
    }

    #[test]
    fn an_incomplete_seed_is_dropped_and_its_keys_forgotten_when_the_wait_ends() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            super::LOG_TARGET,
            "the seed of the candidate epoch was not complete",
        );
        let (me, cutter) = (nick("me"), nick("cutter"));
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        for frame in &frames[..frames.len() - 1] {
            doc.ingest(frame);
        }
        let _ = ticks(&mut doc, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS);
        let forgotten: Vec<DedupKey> = dropped_keys(&mut doc);
        for frame in &frames[..frames.len() - 1] {
            assert!(
                forgotten.contains(&frame.dedup_key()),
                "the key of a frame of the dropped seed is forgotten, so its re-send is taken"
            );
        }
        assert!(doc.candidate.is_none(), "the candidate is gone");
    }

    #[test]
    fn the_cutter_leaving_in_the_wait_does_not_leave_a_one_frame_state() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            super::LOG_TARGET,
            "the seed of the candidate epoch was not complete",
        );
        let (me, cutter) = (nick("me"), nick("cutter"));
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        write(&mut doc, &me, &json!({ "mine": 1 }));
        doc.ingest(&frames[0]);
        assert!(
            ticks(&mut doc, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).is_none(),
            "a root with no tail is not adopted"
        );
        assert_eq!(doc.to_json(), json!({ "mine": 1 }), "no value is lost");
    }

    #[test]
    fn the_app_sees_no_half_seed_while_the_chain_fills() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter) = (nick("me"), nick("cutter"));
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        write(&mut doc, &me, &json!({ "mine": 1 }));
        for frame in &frames[..frames.len() - 1] {
            let taken = doc.ingest(frame);
            assert!(
                !matches!(taken, Ingested::Applied { .. }),
                "a seed frame is never applied alone: {taken:?}"
            );
            assert_eq!(
                doc.to_json(),
                json!({ "mine": 1 }),
                "the doc shows no half seed"
            );
        }
    }

    #[test]
    fn a_seed_whose_tail_arrives_in_reverse_order_completes() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter) = (nick("me"), nick("cutter"));
        let live = live_state();
        let frames = seed_frames(&cutter, &live, 3, None);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        doc.ingest(&frames[0]);
        let reversed: Vec<&Verified> = frames[1..].iter().rev().collect();
        for frame in reversed {
            doc.ingest(frame);
        }
        ticks(&mut doc, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("adopted");
        assert_eq!(
            doc.to_json(),
            live,
            "the chain in any order gives the live json"
        );
    }

    #[test]
    fn a_root_that_names_more_frames_than_the_bound_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let cutter = nick("cutter");
        let doc_of = state_doc_with(&live_state());
        let chain = doc_of
            .build_seed(3, &pad_seed(b"cutter"), within(600))
            .expect("the live json splits");
        let too_many = u32::try_from(DOC_SEED_FRAMES_MAX + 1).expect("fits");
        let mark = SeedMark::new(too_many, chain.mark.last.clone());
        let plain = change_body_timed(&chain.changes[0], None, 3, Some(&mark), Some(chain.time))
            .expect("a body");
        let who = signer(&cutter);
        let message =
            Message::new_channel_event(&MeshId::from("test"), &cutter, plain, Channel::State);
        let root = Verified::fixture_unchecked(message.unverified_key(who), who);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        assert!(
            matches!(doc.ingest(&root), Ingested::Ignored),
            "a forged count is refused"
        );
        assert!(doc.candidate.is_none(), "no candidate is held");
        assert!(
            dropped_keys(&mut doc).contains(&root.dedup_key()),
            "its key is forgotten"
        );
    }

    #[test]
    fn a_tail_frame_of_another_author_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let (cutter, mallory) = (nick("cutter"), nick("mallory"));
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let foreign = seed_frames(&mallory, &live_state(), 3, None);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        doc.ingest(&frames[0]);
        let taken = doc.ingest(&foreign[1]);
        assert!(
            matches!(taken, Ingested::Ignored),
            "a foreign tail frame is refused: {taken:?}"
        );
        assert!(
            dropped_keys(&mut doc).contains(&foreign[1].dedup_key()),
            "its key is forgotten"
        );
    }

    #[test]
    fn the_seed_chain_buffer_stays_inside_the_bound_at_ten_times_the_frames() {
        let _guard = ::habilis_network_test_tracing::init();
        let cutter = nick("cutter");
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        for _ in 0..10 {
            for frame in &frames {
                doc.ingest(frame);
            }
        }
        let held = doc
            .candidate
            .as_ref()
            .map_or(0, |candidate| candidate.tail.len() + 1);
        assert_eq!(
            held,
            frames.len(),
            "the candidate holds the chain once, not 10 times"
        );
    }

    #[test]
    fn a_joiner_that_holds_nothing_adopts_a_complete_seed_at_once_and_waits_for_the_rest() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter) = (nick("me"), nick("cutter"));
        let live = live_state();
        let frames = seed_frames(&cutter, &live, 3, None);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        let own = signer(&me);
        for frame in &frames[..frames.len() - 1] {
            doc.ingest(frame);
            assert!(
                doc.adopt_if_alone(&me, &own).is_none(),
                "an incomplete seed is kept, not adopted"
            );
        }
        doc.ingest(&frames[frames.len() - 1]);
        let switch = doc
            .adopt_if_alone(&me, &own)
            .expect("the complete seed is adopted");
        assert_eq!(switch.epoch, 3, "the switch names the epoch");
        assert_eq!(doc.to_json(), live, "the joiner holds the live json");
    }

    #[test]
    fn the_operations_of_the_applied_changes_are_counted_once() {
        let _guard = ::habilis_network_test_tracing::init();
        let me = nick("me");
        let mut doc = MeshDoc::new_ungated().state_epochs();
        assert_eq!(doc.ops_held(), 0, "a new document holds no operation");
        let first = write(&mut doc, &me, &json!({ "a": 1, "b": { "c": 2 } }));
        assert_eq!(
            doc.ops_held(),
            3,
            "a leaf, a map and a leaf are 3 operations"
        );
        write(&mut doc, &me, &json!({ "a": 5 }));
        assert_eq!(doc.ops_held(), 4, "an overwrite is one more operation");
        let again = doc.ingest(&first);
        assert!(
            matches!(again, Ingested::Duplicate),
            "the same frame is a duplicate: {again:?}"
        );
        assert_eq!(doc.ops_held(), 4, "a duplicate adds no operation");
    }

    #[test]
    fn the_cutter_and_an_adopter_hold_the_same_seed_counts_and_drop_the_old_ones() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter, joiner) = (nick("me"), nick("cutter"), nick("joiner"));
        let mut doc = state_doc_with(&live_state());
        let history_ops = doc.ops_held();
        assert!(history_ops > 0, "the history of the cutter has operations");
        let frames = seed_frames_of(&doc, &cutter, 3, None);
        let mut adopter = MeshDoc::new_ungated().state_epochs();
        for frame in &frames {
            doc.ingest(frame);
            adopter.ingest(frame);
        }
        for _ in 0..super::DOC_EPOCH_ADOPT_WAIT_TICKS {
            doc.tick_epoch(&me);
            adopter.tick_epoch(&joiner);
        }
        assert_eq!(doc.epoch(), 3, "the cutter adopts its own seed");
        assert_eq!(adopter.epoch(), 3, "the joiner adopts the seed");
        assert!(
            doc.seed_bytes() > 0 && doc.seed_ops() > 0,
            "the cutter counts its seed: {} bytes, {} operations",
            doc.seed_bytes(),
            doc.seed_ops()
        );
        assert_eq!(
            (doc.seed_bytes(), doc.seed_ops()),
            (adopter.seed_bytes(), adopter.seed_ops()),
            "the cutter and the adopter hold equal seed counts"
        );
        assert_eq!(
            doc.ops_held(),
            doc.seed_ops(),
            "the operations of the old epoch are gone: the document holds the seed"
        );
    }

    /// A state document with the lines of a small seed (40 frames: the cut is due at 1590
    /// operations), and `leaves` leaves written in merges of 100.
    fn small_state_doc(leaves: usize) -> MeshDoc {
        let mut doc = MeshDoc::new_ungated().state_epochs();
        write_leaves(&mut doc, &nick("me"), 0, leaves);
        doc.limits(Limits::with_seed_frames(40))
    }

    /// Write the leaves `first` to `first + count` of the map `live`, 100 in each frame.
    fn write_leaves(doc: &mut MeshDoc, who: &Nickname, first: usize, count: usize) {
        let mut done = 0;
        while done < count {
            let take = 100.min(count - done);
            let mut leaves = Map::new();
            for leaf in 0..take {
                leaves.insert(format!("l{:05}", first + done + leaf), json!(leaf));
            }
            write(doc, who, &json!({ "live": Value::Object(leaves) }));
            done += take;
        }
    }

    #[test]
    fn a_cut_is_not_due_while_the_document_is_below_the_ceiling() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut doc = small_state_doc(500);
        for _ in 0..20 {
            doc.tick_epoch(&nick("me"));
        }
        assert!(
            !doc.cut_due(0),
            "{} operations are below the ceiling of {}",
            doc.ops_held(),
            Limits::with_seed_frames(40).ops.ceiling
        );
    }

    #[test]
    fn a_cut_is_due_at_the_ceiling_for_rank_0_at_once_and_for_rank_1_after_2_ticks() {
        let _guard = ::habilis_network_test_tracing::init();
        let me = nick("me");
        let mut doc = small_state_doc(1_700);
        assert!(
            !doc.cut_due(0),
            "nothing says that the size crossed before a tick looks at it"
        );
        doc.tick_epoch(&me);
        assert!(
            doc.cut_due(0),
            "rank 0 cuts at the tick that sees the crossing"
        );
        assert!(!doc.cut_due(1), "rank 1 waits 2 ticks");
        doc.tick_epoch(&me);
        assert!(
            !doc.cut_due(1),
            "1 tick after the crossing is too early for rank 1"
        );
        doc.tick_epoch(&me);
        assert!(
            doc.cut_due(1),
            "2 ticks after the crossing is the slot of rank 1"
        );
        assert!(!doc.cut_due(2), "rank 2 waits 4 ticks");
    }

    #[test]
    fn the_ranks_above_the_slotted_ones_wait_a_spread_that_the_tag_chooses() {
        let _guard = ::habilis_network_test_tracing::init();
        let me = nick("me");
        let mut doc = small_state_doc(1_700);
        let slotted = u32::try_from(DOC_CUT_RANKS_SLOTTED).expect("a small number");
        let first = DOC_CUT_SLOT_TICKS * slotted;
        for _ in 0..first {
            doc.tick_epoch(&me);
        }
        assert!(
            !doc.cut_due(DOC_CUT_RANKS_SLOTTED),
            "a node of rank 16 waits for the 16 slotted ranks, then its spread"
        );
        for _ in 0..=DOC_CUT_SPREAD_TICKS {
            doc.tick_epoch(&me);
        }
        assert!(
            doc.cut_due(DOC_CUT_RANKS_SLOTTED) && doc.cut_due(1_000),
            "after the slots and the whole spread, every higher rank cuts"
        );
    }

    #[test]
    fn a_document_that_began_above_the_ceiling_does_not_cut_again_without_growth() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter, joiner) = (nick("me"), nick("cutter"), nick("joiner"));
        let big = small_state_doc(1_700);
        let frames = seed_frames_of(&big, &cutter, 3, None);
        let mut doc = MeshDoc::new_ungated()
            .state_epochs()
            .limits(Limits::with_seed_frames(40));
        for frame in &frames {
            doc.ingest(frame);
        }
        for _ in 0..super::DOC_EPOCH_ADOPT_WAIT_TICKS {
            doc.tick_epoch(&joiner);
        }
        assert_eq!(doc.epoch(), 3, "the document adopted the seed");
        assert!(
            doc.seed_ops() >= Limits::with_seed_frames(40).ops.ceiling,
            "the seed itself is above the ceiling: {} operations",
            doc.seed_ops()
        );
        for tick in 0..100 {
            doc.tick_epoch(&joiner);
            assert!(!doc.cut_due(0), "no growth since the seed, tick {tick}");
        }
        // The growth comes from the real lines, which refuse nothing at this size: the test is
        // about the growth rule of the cut and not about the refusal of a write.
        let small = doc.limits;
        doc.limits = Limits::real();
        write_leaves(&mut doc, &me, 10_000, 200);
        doc.limits = small;
        doc.tick_epoch(&joiner);
        assert!(
            doc.cut_due(0),
            "200 operations of growth are above the growth of {}",
            Limits::with_seed_frames(40).ops.growth
        );
    }

    #[test]
    fn a_failed_cut_holds_the_next_one_for_6_ticks_and_then_for_12() {
        let _guard = ::habilis_network_test_tracing::init();
        let me = nick("me");
        let mut doc = small_state_doc(1_700);
        doc.tick_epoch(&me);
        assert!(doc.cut_due(0), "the cut is due");
        doc.note_cut_failed();
        assert!(!doc.cut_due(0), "a failed cut holds the next one");
        for tick in 1..DOC_CUT_BACKOFF_FIRST {
            doc.tick_epoch(&me);
            assert!(!doc.cut_due(0), "held at tick {tick} of 6");
        }
        doc.tick_epoch(&me);
        assert!(doc.cut_due(0), "the 6th tick ends the hold");
        doc.note_cut_failed();
        for tick in 1..(2 * DOC_CUT_BACKOFF_FIRST) {
            doc.tick_epoch(&me);
            assert!(!doc.cut_due(0), "held at tick {tick} of 12");
        }
        doc.tick_epoch(&me);
        assert!(doc.cut_due(0), "the 12th tick ends the second hold");
        for _ in 0..10 {
            doc.note_cut_failed();
        }
        for _ in 0..DOC_CUT_BACKOFF_MAX {
            doc.tick_epoch(&me);
        }
        assert!(
            doc.cut_due(0),
            "the hold is at most {DOC_CUT_BACKOFF_MAX} ticks"
        );
    }

    /// The leaves `first` to `first + count` as a merge of the map `live`.
    fn leaves_merge(first: usize, count: usize) -> Value {
        let mut leaves = Map::new();
        for leaf in first..first + count {
            leaves.insert(format!("l{leaf:05}"), json!(leaf % 10));
        }
        json!({ "live": Value::Object(leaves) })
    }

    /// The error that a write of `merge` to `doc` gives, if it gives one.
    fn write_error(doc: &MeshDoc, merge: &Value) -> Option<DocError> {
        doc.build_change(merge, &pad_seed(b"me")).err()
    }

    /// A state document with the lines of a small seed that holds `leaves` leaves: written with the
    /// real lines (which refuse nothing at this size), and then given the small ones.
    fn full_state_doc(leaves: usize) -> MeshDoc {
        let mut doc = MeshDoc::new_ungated().state_epochs();
        write_leaves(&mut doc, &nick("me"), 0, leaves);
        doc.limits(Limits::with_seed_frames(40))
    }

    #[test]
    fn a_write_that_adds_a_value_is_refused_when_the_next_seed_would_pass_the_refusal_line() {
        let _guard = ::habilis_network_test_tracing::init();
        let doc = full_state_doc(1_700);
        let refused = write_error(&doc, &leaves_merge(5_000, 200));
        assert!(
            matches!(&refused, Some(DocError::StateFull { .. })),
            "1 900 operations pass the refusal line of 1 802: {refused:?}"
        );
        let roomy = full_state_doc(700);
        assert!(
            write_error(&roomy, &leaves_merge(5_000, 100)).is_none(),
            "800 operations and about 25 000 bytes of next seed are below both refusal lines"
        );
    }

    #[test]
    fn a_write_of_the_same_value_is_an_add_and_is_refused_at_the_line() {
        let _guard = ::habilis_network_test_tracing::init();
        let doc = full_state_doc(1_790);
        let same = write_error(&doc, &leaves_merge(0, 30));
        assert!(
            matches!(&same, Some(DocError::StateFull { .. })),
            "30 more operations pass the line, also for the same values: {same:?}"
        );
        let text = same.map(|error| error.to_string()).unwrap_or_default();
        assert!(
            text.contains("delete keys") && text.contains("also with the same value"),
            "the text tells what to do: {text}"
        );
    }

    #[test]
    fn a_delete_passes_the_refusal_line_and_stops_at_the_memory_line() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut gone = Map::new();
        for leaf in 0..10 {
            gone.insert(format!("l{leaf:05}"), Value::Null);
        }
        let deletes = json!({ "live": Value::Object(gone) });
        let above_the_line = full_state_doc(1_900);
        assert!(
            write_error(&above_the_line, &leaves_merge(5_000, 5)).is_some(),
            "an add is refused above the refusal line"
        );
        assert!(
            write_error(&above_the_line, &deletes).is_none(),
            "a delete passes: the memory line is 2 120"
        );
        let at_memory = full_state_doc(2_115);
        let refused = write_error(&at_memory, &deletes);
        assert!(
            matches!(&refused, Some(DocError::StateFull { .. })),
            "a delete that passes the memory line is refused: {refused:?}"
        );
    }

    #[test]
    fn a_merge_that_adds_a_value_deeper_than_12_levels_is_refused_and_a_delete_is_not() {
        let _guard = ::habilis_network_test_tracing::init();
        let doc = MeshDoc::new_ungated().state_epochs();
        let nest = |levels: usize, leaf: Value| {
            let mut merge = leaf;
            for level in (0..levels).rev() {
                merge = json!({ format!("k{level}"): merge });
            }
            merge
        };
        assert!(
            write_error(&doc, &nest(12, json!(1))).is_none(),
            "12 levels are allowed"
        );
        let deep = write_error(&doc, &nest(13, json!(1)));
        assert!(
            matches!(
                &deep,
                Some(DocError::StateTooDeep {
                    depth: 13,
                    limit: 12
                })
            ),
            "13 levels are refused: {deep:?}"
        );
        assert!(
            write_error(&doc, &nest(13, Value::Null)).is_none(),
            "a delete of a key deeper than 12 levels passes"
        );
    }

    #[test]
    fn a_restore_is_not_refused_at_the_refusal_line_or_for_its_depth_but_it_is_over_the_memory_line()
     {
        let _guard = ::habilis_network_test_tracing::init();
        let above_the_line = full_state_doc(1_900);
        let merge = leaves_merge(5_000, 5);
        assert!(
            write_error(&above_the_line, &merge).is_some(),
            "an add is refused above the refusal line"
        );
        let restored = above_the_line.build_restore(&merge, &pad_seed(b"me"));
        assert!(
            restored.is_ok(),
            "a restore of the same values passes the refusal line"
        );
        let mut deep = json!(1);
        for level in 0..13 {
            deep = json!({ format!("k{level}"): deep });
        }
        assert!(
            above_the_line
                .build_restore(&deep, &pad_seed(b"me"))
                .is_ok(),
            "a restore of a value deeper than 12 levels is not refused for its depth"
        );
        let at_memory = full_state_doc(2_115);
        let refused = at_memory.build_restore(&leaves_merge(5_000, 20), &pad_seed(b"me"));
        assert!(
            matches!(refused, Err(DocError::StateFull { .. })),
            "a restore over the memory line is refused"
        );
    }

    /// The bytes of the body of the frame of a seed that holds only the leaf `value` at `path`, with
    /// the largest stamp.
    fn seed_body_of(path: &[&str], value: &Value) -> usize {
        let mut merge = value.clone();
        let innermost_first = path.iter().rev();
        for key in innermost_first {
            merge = json!({ *key: merge });
        }
        let timeless = MeshDoc::new_ungated();
        let change = change_of(&timeless, &merge, &pad_seed(b"me"));
        let time = super::DOC_TIME_MAX - 1;
        let worst = Stamp::new(time, "ffffffffffffffff".to_owned());
        let body = change_body_tombstoned(&change, None, 1, None, Some(time), &[worst], &[]);
        body.map_or(usize::MAX, |body| body.as_str().len())
    }

    #[test]
    fn a_leaf_that_a_frame_of_a_seed_could_not_carry_is_refused_when_it_is_written() {
        let _guard = ::habilis_network_test_tracing::init();
        let doc = MeshDoc::new_ungated().state_epochs();
        let fits_a_seed = |value: &Value| {
            let body = seed_body_of(&["a", "b"], value);
            body + super::DOC_EPOCH_FRAME_MARGIN + super::DOC_STATE_ENVELOPE_BYTES
                <= super::MAX_MESSAGE_SIZE
        };
        let mut length = 1_000;
        let mut largest_fitting = 0;
        while length <= 3_200 {
            let value = json!("x".repeat(length));
            let refused = write_error(&doc, &json!({ "a": { "b": value.clone() } }));
            let too_large = matches!(refused, Some(DocError::TooLarge { .. }));
            assert_eq!(
                too_large,
                !fits_a_seed(&value),
                "a leaf of {length} bytes: the write is refused exactly when its seed frame does not fit"
            );
            if !too_large {
                largest_fitting = length;
            }
            length += 50;
        }
        assert!(
            (2_000..3_000).contains(&largest_fitting),
            "the largest leaf that is written is about 2 KB: {largest_fitting}"
        );
        assert!(
            write_error(&doc, &json!({ "a": { "b": Value::Null } })).is_none(),
            "a delete has no leaf to carry"
        );
    }

    #[test]
    fn a_document_with_no_state_epochs_has_no_lines() {
        let _guard = ::habilis_network_test_tracing::init();
        let plain = MeshDoc::new_ungated().limits(Limits::with_seed_frames(40));
        let merge = {
            let mut deep = json!(1);
            for level in 0..20 {
                deep = json!({ format!("k{level}"): deep });
            }
            deep
        };
        assert!(
            write_error(&plain, &merge).is_none(),
            "a document with no state epochs refuses no write of depth or size"
        );
    }

    /// The frames of `leaves` leaves of the map `live` that `who` writes into `doc`, 100 in each.
    fn history_frames(doc: &mut MeshDoc, who: &Nickname, leaves: usize) -> Vec<Verified> {
        let mut frames: Vec<Verified> = Vec::new();
        let mut done = 0;
        while done < leaves {
            let take = 100.min(leaves - done);
            frames.push(write(doc, who, &leaves_merge(done, take)));
            done += take;
        }
        frames
    }

    /// Three nodes that hold the same 2 300 leaves: an author and a holder with the real lines, and
    /// a refuser with the lines of a small seed, which is over its remote line (2 226 operations).
    fn trio_with_a_refuser_over_the_remote_line() -> (MeshDoc, MeshDoc, MeshDoc) {
        let mut origin = MeshDoc::new_ungated().state_epochs();
        let frames = history_frames(&mut origin, &nick("base"), 2_300);
        let mut author = MeshDoc::new_ungated().state_epochs();
        let mut refuser = MeshDoc::new_ungated().state_epochs();
        let mut holder = MeshDoc::new_ungated().state_epochs();
        for frame in &frames {
            author.ingest(frame);
            refuser.ingest(frame);
            holder.ingest(frame);
        }
        let refuser = refuser.limits(Limits::with_seed_frames(40));
        (author, refuser, holder)
    }

    #[test]
    fn a_remote_frame_over_the_remote_line_is_refused_once_and_remembered() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "a frame was refused: the state document is over its remote line",
        );
        let (mut author, mut refuser, mut holder) = trio_with_a_refuser_over_the_remote_line();
        let frame = write(&mut author, &nick("me"), &json!({ "x": 1 }));
        let outcome = holder.ingest(&frame);
        assert!(
            matches!(outcome, Ingested::Applied { .. }),
            "a node under its line applies the frame"
        );
        let outcome_over_the_line = refuser.ingest(&frame);
        assert!(
            matches!(outcome_over_the_line, Ingested::Ignored),
            "a node over its remote line refuses the frame"
        );
        assert_eq!(refuser.refused_remote(), 1, "the refusal is counted");
        assert!(
            refuser.to_json().get("x").is_none(),
            "the refused frame changed nothing"
        );
        let again = refuser.ingest(&frame);
        assert!(
            matches!(again, Ingested::Ignored),
            "the frame that is offered again is dropped"
        );
        assert_eq!(
            (refuser.refused_remote(), refuser.refused_held()),
            (1, 1),
            "a frame that is dropped from the set is not counted again"
        );
    }

    #[test]
    fn the_set_of_refused_frames_stays_inside_its_cap_when_it_is_fed_10_times_the_cap() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "a frame was refused: the state document is over its remote line",
        );
        let (author, mut refuser, _holder) = trio_with_a_refuser_over_the_remote_line();
        let cap = Limits::with_seed_frames(40).refused_max;
        for index in 0..(10 * cap) {
            // Each frame follows the history that the refuser holds, not the frame before it, so
            // none of them waits for a dependency that it refused.
            let frame = frame_on(&author, &nick("me"), &json!({ format!("k{index}"): 1 }));
            refuser.ingest(&frame);
            assert!(
                refuser.refused_held() <= cap,
                "{} hashes after {} frames, the cap is {cap}",
                refuser.refused_held(),
                index + 1
            );
        }
        assert_eq!(
            refuser.refused_remote(),
            u64::try_from(10 * cap).expect("a small number"),
            "every one of the frames was refused and counted"
        );
        assert_eq!(
            refuser.refused_held(),
            cap,
            "the set is full and holds the newest"
        );
    }

    #[test]
    fn a_seed_that_a_node_over_its_remote_line_adopts_is_applied_whole() {
        let _guard = ::habilis_network_test_tracing::init();
        let (_author, mut refuser, _holder) = trio_with_a_refuser_over_the_remote_line();
        let mut big = MeshDoc::new_ungated().state_epochs();
        write_leaves(&mut big, &nick("me"), 0, 2_500);
        let frames = seed_frames_of(&big, &nick("cutter"), 3, None);
        for frame in &frames {
            refuser.ingest(frame);
        }
        for _ in 0..super::DOC_EPOCH_ADOPT_WAIT_TICKS {
            refuser.tick_epoch(&nick("refuser"));
        }
        assert_eq!(refuser.epoch(), 3, "the node adopted the seed");
        assert_eq!(
            refuser.to_json(),
            big.to_json(),
            "the seed is whole: the remote line does not apply to the frames of a seed"
        );
        assert_eq!(
            refuser.refused_remote(),
            0,
            "no frame of the seed was refused"
        );
    }

    /// The restore that `holder` writes after it adopted the seed of `refuser`, with the ticks that
    /// the adoption and the jitter of the restore need.
    fn restore_after_the_cut_of(refuser: &MeshDoc, holder: &mut MeshDoc) -> Option<Value> {
        let cutter = nick("cutter");
        let frames = seed_frames_of(refuser, &cutter, 3, None);
        for frame in &frames {
            holder.ingest(frame);
        }
        ticks(holder, &nick("holder"), super::DOC_EPOCH_ADOPT_WAIT_TICKS);
        assert_eq!(
            holder.epoch(),
            3,
            "the holder adopted the seed of the refuser"
        );
        ticks(holder, &nick("holder"), 3);
        holder.take_restores().map(|(patch, _stamps)| patch)
    }

    #[test]
    fn the_write_that_a_refuser_lost_comes_back_from_a_holder_when_the_author_has_left() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "a frame was refused: the state document is over its remote line",
        );
        let (mut author, mut refuser, mut holder) = trio_with_a_refuser_over_the_remote_line();
        let frame = write(&mut author, &nick("me"), &json!({ "x": 7 }));
        holder.ingest(&frame);
        refuser.ingest(&frame);
        drop(author);
        let patch = restore_after_the_cut_of(&refuser, &mut holder);
        assert_eq!(
            patch.as_ref().and_then(|patch| patch.get("x")),
            Some(&json!(7)),
            "the holder writes x again after the seed that lacks it: {patch:?}"
        );
    }

    #[test]
    fn a_delete_that_a_refuser_lost_is_written_again_by_a_holder_and_not_undone() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "a frame was refused: the state document is over its remote line",
        );
        let (mut author, mut refuser, mut holder) = trio_with_a_refuser_over_the_remote_line();
        let gone = json!({ "live": { "l00005": Value::Null } });
        let frame = write(&mut author, &nick("me"), &gone);
        holder.ingest(&frame);
        refuser.ingest(&frame);
        assert!(
            refuser.to_json().pointer("/live/l00005").is_some(),
            "the refuser still holds the value that the delete removed"
        );
        let patch = restore_after_the_cut_of(&refuser, &mut holder);
        assert_eq!(
            patch
                .as_ref()
                .and_then(|patch| patch.pointer("/live/l00005")),
            Some(&Value::Null),
            "the holder writes the delete again, so the value of the seed is removed: {patch:?}"
        );
    }

    /// Compiles only for a value that can cross to another thread.
    fn is_send(_value: &impl Send) {}

    #[test]
    fn a_chain_built_from_a_plan_has_the_content_of_the_chain_that_build_seed_gives() {
        let _guard = ::habilis_network_test_tracing::init();
        let doc = state_doc_with(&live_state());
        let cutter = pad_seed(b"cutter");
        let direct = doc
            .build_seed(3, &cutter, within(600))
            .expect("the live json splits");
        let plan = doc.seed_plan().expect("a plan");
        is_send(&plan);
        let planned = plan
            .build(3, &cutter, within(600))
            .expect("the plan builds");
        is_send(&planned);
        assert_eq!(planned.changes, direct.changes, "the same changes");
        assert_eq!(planned.origins, direct.origins, "the same stamps");
        assert_eq!(planned.tombstones, direct.tombstones, "the same tombstones");
        assert_eq!(planned.mark, direct.mark, "the same mark: count and tip");
    }

    #[test]
    fn the_stamps_of_a_merge_are_the_stamps_that_the_plan_holds_for_its_paths() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, other) = (nick("me"), nick("other"));
        let mut doc = state_doc_with(&live_state());
        write(&mut doc, &other, &json!({ "n": 8 }));
        let plan = doc.seed_plan().expect("a plan");
        let merge = json!({ "n": 8, "board": { "title": "t" } });
        let stamps = plan.stamps_for(&merge);
        let paths = vec![
            vec!["board".to_owned()],
            vec!["board".to_owned(), "title".to_owned()],
            vec!["n".to_owned()],
        ];
        let held: Vec<Stamp> = doc
            .stamps_of(&paths)
            .into_iter()
            .map(|stamp| stamp.expect("a stamp"))
            .collect();
        let mut expected = held;
        expected.sort();
        let mut got = stamps;
        got.sort();
        assert_eq!(
            got, expected,
            "the object, the leaf under it and the other leaf, each with the stamp of its write"
        );
        let unknown = plan.stamps_for(&json!({ "nowhere": 1 }));
        assert_eq!(
            unknown,
            vec![Stamp::new(0, "0000000000000000".to_owned())],
            "a path that the plan does not hold gets the stamp 0"
        );
        let _ = me;
    }

    #[test]
    fn a_plan_is_the_seed_of_the_document_as_it_was_when_the_plan_was_taken() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter) = (nick("me"), nick("cutter"));
        let mut doc = state_doc_with(&live_state());
        let before = doc.to_json();
        let plan = doc.seed_plan().expect("a plan");
        write(&mut doc, &me, &json!({ "later": 1 }));
        let actor = pad_seed(cutter.as_str().as_bytes());
        let chain = plan.build(3, &actor, within(600)).expect("the plan builds");
        let frames = seed_frames_from(&chain, &cutter, 3);
        let mut adopter = MeshDoc::new_ungated().state_epochs();
        for frame in &frames {
            adopter.ingest(frame);
        }
        ticks(
            &mut adopter,
            &nick("joiner"),
            super::DOC_EPOCH_ADOPT_WAIT_TICKS,
        );
        assert_eq!(
            adopter.to_json(),
            before,
            "the seed holds what the document held at the plan, not the write after it"
        );
    }

    #[test]
    fn a_seed_that_could_not_stamp_a_path_is_counted_when_it_is_noted() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "a seed path got the stamp 0 for want of a time",
        );
        let mut doc = MeshDoc::new_ungated();
        write(&mut doc, &nick("me"), &json!({ "a": 1, "b": 2 }));
        let plan = doc.seed_plan().expect("a plan");
        let chain = plan
            .build(3, &pad_seed(b"cutter"), within(600))
            .expect("the plan builds");
        assert!(
            chain.unstamped > 0,
            "a document with no state epochs has no stamp to give"
        );
        assert_eq!(
            doc.unstamped_paths(),
            0,
            "nothing is counted before it is noted"
        );
        doc.note_seed_built(&chain);
        assert_eq!(
            doc.unstamped_paths(),
            chain.unstamped,
            "the paths without a stamp are counted"
        );
    }

    #[test]
    fn a_candidate_is_whole_when_the_last_frame_of_its_chain_has_arrived() {
        let _guard = ::habilis_network_test_tracing::init();
        let cutter = nick("cutter");
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        assert!(frames.len() > 2, "the chain has several frames");
        let mut doc = MeshDoc::new_ungated().state_epochs();
        assert!(!doc.candidate_whole(), "no candidate is not a whole one");
        for frame in &frames[..frames.len() - 1] {
            doc.ingest(frame);
            assert!(
                !doc.candidate_whole(),
                "a chain that lacks its last frame is not whole"
            );
        }
        doc.ingest(&frames[frames.len() - 1]);
        assert!(
            doc.candidate_whole(),
            "the last frame makes the chain whole"
        );
    }

    #[test]
    fn a_state_document_that_holds_a_candidate_has_no_cut_due() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter) = (nick("me"), nick("cutter"));
        let mut doc = small_state_doc(1_700);
        doc.tick_epoch(&me);
        assert!(doc.cut_due(0), "the cut is due");
        let frames = seed_frames(&cutter, &live_state(), 7, None);
        for frame in &frames {
            doc.ingest(frame);
        }
        assert!(doc.has_candidate(), "the document holds the candidate");
        assert!(
            !doc.cut_due(0),
            "a node that holds a candidate adopts it and does not cut"
        );
    }

    #[test]
    fn a_state_document_made_for_the_daemon_has_epochs_the_cap_and_the_wait_for_the_first_sync() {
        let _guard = ::habilis_network_test_tracing::init();
        let doc = MeshDoc::new_state(None);
        assert!(doc.has_state_epochs(), "the state channel has epochs");
        let change = change_of(&doc, &json!({ "a": 1 }), &pad_seed(b"me"));
        let outcome = doc.compose_wire_body(&change, None);
        assert!(
            matches!(outcome, Err(DocError::ClockNotReady)),
            "the body of a write waits for the first sync: {outcome:?}"
        );
    }

    #[test]
    fn the_epoch_switch_of_a_state_document_carries_no_entry() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter) = (nick("me"), nick("cutter"));
        let frames = seed_frames(&cutter, &live_state(), 3, None);
        let mut doc = MeshDoc::new_ungated().state_epochs();
        for frame in &frames {
            doc.ingest(frame);
        }
        let switch = ticks(&mut doc, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("adopted");
        assert_eq!(
            switch.own_entry, None,
            "a state switch has no entry to write again"
        );
        assert_eq!(switch.map, "", "a state switch names no per-peer map");
        assert_eq!(
            switch.replay, None,
            "a node that holds nothing writes nothing again"
        );
    }

    #[test]
    fn a_seed_on_a_passworded_mesh_is_adopted_through_its_sealed_frames() {
        let _guard = ::habilis_network_test_tracing::init();
        let (me, cutter) = (nick("me"), nick("cutter"));
        let key = SymmetricKey::from([7u8; 32]);
        let live = live_state();
        let frames = seed_frames(&cutter, &live, 3, Some(&key));
        let mut doc = MeshDoc::new_ungated().state_epochs().key(Some(key));
        for frame in &frames {
            doc.ingest(frame);
        }
        ticks(&mut doc, &me, super::DOC_EPOCH_ADOPT_WAIT_TICKS).expect("adopted");
        assert_eq!(doc.to_json(), live, "the sealed seed gives the live json");
    }

    /// Golden: the hash of the genesis of state epochs 1, 2 and a large one. A replica of another
    /// build must reach the same hash, or the epoch frames of the two builds do not meet. The large
    /// epoch pins the encoding of the `u64` that the genesis writes.
    #[test]
    fn state_genesis_bytes_are_pinned() {
        let _guard = ::habilis_network_test_tracing::init();
        let pinned = [
            (
                1,
                "bfb565389605341479209de04fbd2be2ba2d7831ab1fc4f0cf162293a8e8e1f5",
            ),
            (
                2,
                "2938c155a12397b7bad436dba6ad3bde04358dbbdceca75a1b2c37906def0171",
            ),
            (
                u64::MAX,
                "b0c86ed12e33b25a1d80657a967aff0ce9650e223856399771c09484e13c00f1",
            ),
        ];
        for (epoch, hex) in pinned {
            assert_eq!(
                super::state_genesis(epoch).hash().to_string(),
                hex,
                "the state genesis hash of epoch {epoch} is pinned"
            );
        }
    }

    #[test]
    fn a_state_genesis_leaves_no_key_and_differs_per_epoch() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut doc = automerge::Automerge::new();
        doc.apply_changes([super::state_genesis(3)])
            .expect("the genesis applies");
        assert_eq!(
            doc.get_changes(&[]).len(),
            1,
            "the genesis is one change, though it leaves no key"
        );
        let json = serde_json::to_value(automerge::AutoSerde::from(&doc)).expect("json");
        assert_eq!(
            json,
            json!({}),
            "the genesis of a state epoch leaves no key"
        );
        let hash = |epoch| super::state_genesis(epoch).hash();
        assert_ne!(hash(1), hash(2), "epoch 2 has another genesis than epoch 1");
        assert_ne!(
            hash(1),
            super::peers_genesis("peers", 1).hash(),
            "the state genesis is not the meta genesis"
        );
    }

    #[test]
    fn an_ungated_document_restarted_at_an_epoch_holds_the_genesis_of_that_epoch() {
        let _guard = ::habilis_network_test_tracing::init();
        let doc = MeshDoc::new_ungated().at_epoch(3);
        assert_eq!(doc.epoch(), 3, "the epoch is 3");
        assert_eq!(doc.change_count(), 1, "the document holds its genesis");
        assert_eq!(doc.to_json(), json!({}), "the genesis leaves no key");
        let fresh = MeshDoc::new_ungated();
        assert_eq!(
            fresh.change_count(),
            0,
            "epoch 0 of a state document has no genesis"
        );
    }

    #[test]
    fn each_epoch_has_its_own_genesis() {
        let _guard = ::habilis_network_test_tracing::init();
        let hash = |epoch| super::peers_genesis("peers", epoch).hash();
        assert_ne!(hash(1), hash(0), "epoch 1 has another genesis than epoch 0");
        assert_ne!(hash(1), hash(2), "epoch 2 has another genesis than epoch 1");
    }

    #[test]
    fn the_gate_still_rejects_a_foreign_entry_in_a_new_epoch() {
        let _guard = ::habilis_network_test_tracing::init();
        let (alice, mallory) = (nick("alice"), nick("mallory"));
        let mut doc = MeshDoc::new_gated(card_gate()).at_epoch(1);
        write(&mut doc, &alice, &entry("alice", "mine"));
        let forged = frame_on(&doc, &mallory, &entry("alice", "forged"));
        assert!(
            matches!(doc.ingest(&forged), Ingested::Rejected),
            "a foreign entry is rejected in a new epoch"
        );
    }

    #[test]
    fn a_capped_answer_holds_the_oldest_changes_first() {
        let _guard = ::habilis_network_test_tracing::init();
        let alice = nick("alice");
        let mut source = MeshDoc::new_ungated();
        let frames: Vec<_> = (0..6)
            .map(|index| author(&mut source, &alice, &json!({ format!("k{index}"): index })))
            .collect();
        let served: Vec<_> = source.changes_since(&[], 2).collect();
        let first_two: Vec<_> = frames[..2].iter().map(|frame| frame.dedup_key()).collect();
        let served_keys: Vec<_> = served.iter().map(|frame| frame.dedup_key()).collect();
        assert_eq!(
            served_keys, first_two,
            "a capped answer starts at the roots"
        );
    }

    #[test]
    fn heads_and_changes_since_reconcile_a_late_joiner() {
        let _guard = ::habilis_network_test_tracing::init();
        // A source authors two changes; a fresh joiner advertises its (empty)
        // heads and pulls exactly the frames it lacks, then converges.
        let alice = nick("alice");
        let mut source = MeshDoc::new_ungated();
        author(&mut source, &alice, &json!({"a": 1}));
        author(&mut source, &alice, &json!({"b": 2}));

        let mut joiner = MeshDoc::new_ungated();
        let joiner_heads: Vec<_> = joiner.heads().collect();
        let missing: Vec<_> = source.changes_since(&joiner_heads, 100).collect();
        assert_eq!(missing.len(), 2, "joiner lacks both changes");
        for carrier in &missing {
            joiner.ingest(carrier);
        }
        assert_eq!(
            joiner.to_json(),
            json!({"a": 1, "b": 2}),
            "the late joiner converges to the wanted json"
        );
        // Now converged, the source has nothing more to offer.
        let converged: Vec<_> = joiner.heads().collect();
        assert!(
            source.changes_since(&converged, 100).next().is_none(),
            "the changes since the converged heads are empty"
        );
    }

    #[test]
    fn encrypted_change_converges_with_the_key_and_is_opaque_without() {
        let _guard = ::habilis_network_test_tracing::init();
        let alice = nick("alice");
        let key = [42u8; 32];
        // Author builds the change and seals the wire body, as the daemon does.
        let merge = json!({"secret": "value"});
        let author_doc = MeshDoc::new_ungated().key(Some(SymmetricKey::from(key)));
        let seed = pad_seed(alice.as_str().as_bytes());
        let bytes: Vec<u8> = author_doc
            .build_change(&merge, &seed)
            .expect("builds")
            .expect("not a no-op");
        let (wire, _plain) = author_doc
            .compose_wire_body(&bytes, Some(&merge))
            .expect("compose");
        let signer = AuthorKey::from(pad_seed(alice.as_str().as_bytes()));
        let carrier = Verified::fixture_unchecked(
            Message::new_channel_event(&MeshId::from("test"), &alice, wire, Channel::State)
                .unverified_key(signer),
            signer,
        );
        assert!(
            !carrier.body.as_str().contains("value"),
            "the plaintext value must not appear on the wire"
        );

        // A peer holding the key applies it and converges; surface_body recovers
        // the plaintext for the delta.
        let mut with_key = MeshDoc::new_ungated().key(Some(SymmetricKey::from(key)));
        assert!(
            matches!(with_key.ingest(&carrier), Ingested::Applied { .. }),
            "an encrypted change converges with the key"
        );
        assert_eq!(
            with_key.to_json(),
            json!({"secret": "value"}),
            "the keyed sink holds the change json"
        );
        assert!(
            with_key
                .surface_body(&carrier)
                .expect("the keyed sink holds the key that sealed the carrier")
                .contains("secret"),
            "the keyed sink can surface the body"
        );

        // A peer without the key (or with the wrong key) cannot read it — the
        // body is an opaque no-op, never applied.
        let mut no_key = MeshDoc::new_ungated();
        assert!(
            matches!(no_key.ingest(&carrier), Ingested::Ignored),
            "an encrypted change is buffered without the key"
        );
        assert_eq!(
            no_key.to_json(),
            json!({}),
            "the no-key sink holds no change json"
        );
        let mut wrong_key = MeshDoc::new_ungated().key(Some(SymmetricKey::from([7u8; 32])));
        assert!(
            matches!(wrong_key.ingest(&carrier), Ingested::Ignored),
            "an encrypted change is buffered with the wrong key"
        );
        assert_eq!(
            wrong_key.to_json(),
            json!({}),
            "the wrong-key sink holds no change json"
        );
    }

    #[test]
    fn foreign_card_write_is_rejected_own_is_allowed() {
        let _guard = ::habilis_network_test_tracing::init();
        let (alice, bob) = (nick("alice"), nick("bob"));

        // Craft both changes on one ungated replica so the forge is built atop
        // Bob's card (deps satisfied) — what an attacker who has synced holds.
        let mut attacker = MeshDoc::new_gated(card_gate()).synced_but_ungated();
        let bob_card = author(
            &mut attacker,
            &bob,
            &json!({"peers": {"bob": {"card": {"metadata": {"pubkey": "bb"}}}}}),
        );
        let forged = author(
            &mut attacker,
            &alice,
            &json!({"peers": {"bob": {"card": {"metadata": {"pubkey": "ff"}}}}}),
        );

        // A gated victim accepts Bob's real card, then refuses Alice's forge.
        let mut victim = MeshDoc::new_gated(card_gate());
        assert!(
            matches!(victim.ingest(&bob_card), Ingested::Applied { .. }),
            "a foreign card write is rejected"
        );
        assert!(
            matches!(victim.ingest(&forged), Ingested::Rejected),
            "a forged card write is rejected"
        );
        assert_eq!(
            victim.to_json(),
            json!({"peers": {"bob": {"card": {"metadata": {"pubkey": "bb"}}}}}),
            "the victim keeps its card after a forged write"
        );

        // Alice writing her OWN card through the gate is allowed.
        let mut alice_doc = MeshDoc::new_gated(card_gate());
        let own_bytes: Vec<u8> = alice_doc
            .build_change(
                &json!({"peers": {"alice": {"card": {"name": "alice"}}}}),
                &pad_seed(alice.as_str().as_bytes()),
            )
            .expect("builds")
            .expect("not a no-op");
        assert!(
            matches!(
                alice_doc.ingest(&frame(&alice, &own_bytes)),
                Ingested::Applied { .. }
            ),
            "a card written by its own author is allowed"
        );
    }

    #[test]
    fn self_entry_delete_passes_gate_foreign_delete_is_rejected() {
        let _guard = ::habilis_network_test_tracing::init();
        // The leave-time retraction: a peer nulls its own `/peers/<nick>`
        // entry. The gate must let the owner do it and refuse anyone else —
        // which is why departed peers can only ever be pruned by themselves.
        let (alice, bob) = (nick("alice"), nick("bob"));

        // Craft on one ungated replica so deps are satisfied: alice's card,
        // then alice's own retraction.
        let mut source = MeshDoc::new_ungated();
        let alice_card = author(
            &mut source,
            &alice,
            &json!({"peers": {"alice": {"card": {"name": "alice"}, "model": "m1"}}}),
        );
        let self_delete = author(&mut source, &alice, &json!({"peers": {"alice": null}}));

        let mut victim = MeshDoc::new_gated(card_gate());
        assert!(
            matches!(victim.ingest(&alice_card), Ingested::Applied { .. }),
            "a self-entry delete passes the gate"
        );
        assert!(
            matches!(victim.ingest(&self_delete), Ingested::Applied { .. }),
            "a foreign delete is rejected"
        );
        assert_eq!(
            victim.to_json().pointer("/peers/alice"),
            None,
            "the whole entry — card and agent facts — is gone"
        );

        // The same delete authored by bob alters alice's card → rejected, and
        // alice's entry survives on the gated replica.
        let mut foreign_source = MeshDoc::new_gated(card_gate()).synced_but_ungated();
        let card_frame = author(
            &mut foreign_source,
            &alice,
            &json!({"peers": {"alice": {"card": {"name": "alice"}}}}),
        );
        let foreign_delete = author(
            &mut foreign_source,
            &bob,
            &json!({"peers": {"alice": null}}),
        );
        let mut gated = MeshDoc::new_gated(card_gate());
        assert!(
            matches!(gated.ingest(&card_frame), Ingested::Applied { .. }),
            "the gated sink accepts a self-entry card"
        );
        assert!(
            matches!(gated.ingest(&foreign_delete), Ingested::Rejected),
            "the gated sink rejects a foreign delete"
        );
        assert_eq!(
            gated.to_json().pointer("/peers/alice/card/name"),
            Some(&json!("alice")),
            "the gated sink keeps the card after the rejected delete"
        );
    }

    /// The rejoin-after-retraction shape: a replica holds a peer's card and
    /// its self-delete; a *fresh* session (same nickname, new signing key →
    /// new actor seed, no shared history beyond genesis) publishes a new
    /// card. The concurrent re-add must survive the merge on both sides — a
    /// departed nickname is never burned. This is exactly why the actor seed
    /// is the session key, not the nickname: a nickname-derived actor makes
    /// the new session's seq-1 change collide with the old session's and
    /// every replica rejects it as `DuplicateSeqNumber` equivocation.
    #[test]
    fn fresh_republish_survives_a_prior_self_delete() {
        let _guard = ::habilis_network_test_tracing::init();
        let alice = nick("alice");

        // Old session: card, then the leave-time retraction.
        let mut old_session = MeshDoc::new_gated(card_gate());
        let old_card = author_as(
            &mut old_session,
            &alice,
            b"alice-session-key-old",
            &json!({"peers": {"alice": {"card": {"name": "alice", "session": "old"}}}}),
        );
        let retraction = author_as(
            &mut old_session,
            &alice,
            b"alice-session-key-old",
            &json!({"peers": {"alice": null}}),
        );

        // A staying peer applied both.
        let mut host = MeshDoc::new_gated(card_gate());
        assert!(
            matches!(host.ingest(&old_card), Ingested::Applied { .. }),
            "a fresh republish is accepted after a prior self delete"
        );
        assert!(
            matches!(host.ingest(&retraction), Ingested::Applied { .. }),
            "the retraction is accepted"
        );
        assert_eq!(
            host.to_json().pointer("/peers/alice"),
            None,
            "the republished card survives the prior self delete"
        );

        // New session: fresh doc, fresh key, deps = genesis only.
        let mut new_session = MeshDoc::new_gated(card_gate());
        let new_card = author_as(
            &mut new_session,
            &alice,
            b"alice-session-key-new",
            &json!({"peers": {"alice": {"card": {"name": "alice", "session": "new"}}}}),
        );

        // Both directions converge on the new card.
        let outcome = host.ingest(&new_card);
        assert!(
            matches!(outcome, Ingested::Applied { .. }),
            "expected applied, got {outcome:?}"
        );
        assert_eq!(
            host.to_json().pointer("/peers/alice/card/session"),
            Some(&json!("new")),
            "the fresh publish must survive the earlier delete: {}",
            host.to_json()
        );
        assert!(
            matches!(new_session.ingest(&old_card), Ingested::Applied { .. }),
            "a new session accepts the old card"
        );
        assert!(
            matches!(new_session.ingest(&retraction), Ingested::Applied { .. }),
            "a new session accepts the retraction"
        );
        assert_eq!(
            new_session.to_json().pointer("/peers/alice/card/session"),
            Some(&json!("new")),
            "backfilling the old history must not erase the new card: {}",
            new_session.to_json()
        );
    }
}
