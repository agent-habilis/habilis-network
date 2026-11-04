use std::collections::{HashMap, HashSet};

use automerge::transaction::Transactable;
use automerge::{
    AutoSerde, Automerge, Change, ChangeHash, ObjId, ObjType, ROOT, ReadDoc, Value as AmValue,
};
use serde_json::{Map, Value};

use habilis_network_protocol::messages::Verified;
use habilis_network_protocol::{AuthorKey, DedupKey, Message, Nickname, SymmetricKey};
use habilis_network_util::consts::{
    DOC_EPOCH_ADOPT_WAIT_TICKS, DOC_EPOCH_FRAME_CAP_BYTES, DOC_EPOCH_JUMP_MAX,
    DOC_PENDING_AUTHOR_MAX, DOC_PENDING_TOTAL_MAX,
};

use crate::{DocError, wire};

use automerge::transaction;
use std::mem;
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

/// The root frame of a higher epoch that the document keeps until it adopts the epoch.
#[derive(Debug)]
struct Candidate {
    epoch: u64,
    frame: Verified,
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
    /// The bytes of each entry of the per-peer map as JSON, by owner, when the caller asked for
    /// the heavy census. Empty for a document with no gate.
    pub peer_entry_bytes: Option<HashMap<String, usize>>,
    /// The wire bytes of the frames kept to serve again, by the nickname that signed them, when
    /// the caller asked for the heavy census.
    pub author_frame_bytes: Option<HashMap<String, usize>>,
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
    candidate: Option<Candidate>,
    /// The ticks since the candidate took its place.
    candidate_ticks: u32,
    /// The ticks since the epoch began.
    epoch_ticks: u32,
    /// The frame bytes of the epoch when it settled, 0 before. The live entries are back by then.
    settled_bytes: usize,
    /// The frame bytes that start a reset, before the settled size is known.
    frame_cap: usize,
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
            settled_bytes: 0,
            frame_cap: DOC_EPOCH_FRAME_CAP_BYTES,
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
    fn change_bytes(&self, frame: &Message) -> Option<(Vec<u8>, u64)> {
        match self.key.as_ref() {
            // Passwordless: parse directly — no decrypt indirection, no clone.
            None => wire::parse_change(frame.body.as_str()),
            Some(key) => {
                let plain = wire::decrypt_body(frame.body.as_str(), Some(key))?;
                wire::parse_change(&plain)
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
    /// the change does not encode.
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
        let plain = wire::change_body_at(change, merge, self.epoch)?;
        let wire = match self.key.as_ref() {
            Some(key) => wire::encrypt_body(&plain, key)?,
            None => plain.clone(),
        };
        Ok((wire, plain))
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
        let peer_entry_bytes: Option<HashMap<String, usize>> =
            json.as_ref().map(|json| self.entry_bytes(json));
        let author_frame_bytes: Option<HashMap<String, usize>> =
            heavy.then(|| self.author_frame_bytes());
        DocCensus {
            epoch: self.epoch,
            changes: self.applied.len(),
            frames: self.frames.len(),
            frame_bytes: self.frame_bytes,
            save_bytes,
            json_bytes,
            peer_nicks,
            peer_entry_bytes,
            author_frame_bytes,
        }
    }

    /// The JSON bytes of each entry of the gated map of `json`, by owner. Empty for a document
    /// with no gate.
    fn entry_bytes(&self, json: &Value) -> HashMap<String, usize> {
        let Some(gate) = self.gate.as_ref() else {
            return HashMap::new();
        };
        let owners = gated_entries(json, gate);
        let peers = json.get(&gate.map).and_then(Value::as_object);
        let size = |entry: &Value| serde_json::to_vec(entry).map_or(0, |bytes| bytes.len());
        let entries = peers.into_iter().flatten();
        let owned = entries.filter(|(nick, _)| owners.contains_key(*nick));
        let sized = owned.map(|(nick, entry)| (nick.clone(), size(entry)));
        sized.collect()
    }

    /// The wire bytes of the frames kept to serve again, by the nickname that signed them.
    fn author_frame_bytes(&self) -> HashMap<String, usize> {
        let mut bytes: HashMap<String, usize> = HashMap::new();
        for frame in self.frames.values() {
            *bytes.entry(frame.author.to_string()).or_default() += wire_len(frame);
        }
        bytes
    }

    /// The nicknames with an entry in the gated map of `json`. Empty for a document with no gate.
    fn gated_nicks(&self, json: &Value) -> Vec<String> {
        let Some(gate) = self.gate.as_ref() else {
            return Vec::new();
        };
        let entries = gated_entries(json, gate);
        entries.keys().cloned().collect()
    }

    /// The epoch of the history that this document holds.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
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
        self.candidate.as_ref()?;
        let alone = self.frames.values().all(|frame| frame.key() == *own);
        if alone { self.adopt(me) } else { None }
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
    /// gated channel has epochs: the free-form `state` channel keeps every frame.
    pub fn tick_epoch(&mut self, me: &Nickname) -> Option<EpochSwitch> {
        self.epoch_ticks = self.epoch_ticks.saturating_add(1);
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
            return Some(self.switch_to(self.epoch.saturating_add(1), me));
        }
        None
    }

    /// Switch to the epoch of the candidate and apply its root frame.
    fn adopt(&mut self, me: &Nickname) -> Option<EpochSwitch> {
        let candidate = self.candidate.take()?;
        let switch = self.switch_to(candidate.epoch, me);
        let _ = self.ingest(&candidate.frame);
        Some(switch)
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
        EpochSwitch {
            epoch,
            map,
            own_entry,
        }
    }

    /// Forget the history: a document of `epoch` that holds its genesis and nothing else. The
    /// orphans go with it, and their dedup keys stay seen, because an old epoch is dead.
    fn restart(&mut self, epoch: u64) {
        let mut doc = Automerge::new();
        let mut applied = HashSet::new();
        if let Some(gate) = self.gate.as_ref() {
            let genesis = peers_genesis(&gate.map, epoch);
            applied.insert(genesis.hash());
            let _ = doc.apply_changes([genesis]);
        }
        *self.doc = doc;
        self.applied = applied;
        self.frames = HashMap::new();
        self.frame_bytes = 0;
        self.pending = HashMap::new();
        self.candidate = None;
        self.candidate_ticks = 0;
        self.epoch = epoch;
        self.epoch_ticks = 0;
        self.settled_bytes = 0;
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
        fork.set_actor(actor_for(actor_seed));
        let heads = fork.get_heads();
        {
            let mut tx = fork.transaction();
            write_map(&mut tx, &ROOT, merge).map_err(DocError::encode)?;
            tx.commit();
        }
        let mut changes = fork.get_changes(&heads);
        Ok(changes.pop().map(|change| change.raw_bytes().to_vec()))
    }

    /// Ingest one verified frame carrying an automerge change. Verifies causal
    /// readiness and card authorization before applying; buffers orphans (as
    /// frames, so re-serve and the gate both see the original signed frame). The
    /// `Verified` proof means the signature was checked before the frame got here,
    /// so the signer is `frame.key()`, never a field of the body.
    pub fn ingest(&mut self, frame: &Verified) -> Ingested {
        let Some((bytes, epoch)) = self.change_bytes(frame) else {
            return Ingested::Ignored;
        };
        let Ok(change) = Change::from_bytes(bytes) else {
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
        if epoch != self.epoch {
            return self.ingest_other_epoch(epoch, &change, frame);
        }
        let hash = change.hash();
        if self.applied.contains(&hash) {
            return Ingested::Duplicate;
        }
        if !self.deps_satisfied(change.deps()) {
            return self.buffer_orphan(author, hash, change, frame);
        }
        // Hoisted above the gate so the two share one hydration: nothing
        // mutates the document between them, and `doc_json` over the whole
        // `meta` map was the dominant cost of ingesting a frame. On the
        // rejection path this pays for a hydration it does not use, which is
        // the rare adversarial case rather than the steady-state one.
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
    fn ingest_other_epoch(&mut self, epoch: u64, change: &Change, frame: &Verified) -> Ingested {
        if epoch < self.epoch {
            return Ingested::Ignored;
        }
        let refuse = |doc: &mut Self| {
            doc.dropped.push(frame.dedup_key());
            Ingested::Ignored
        };
        let Some(gate) = self.gate.clone() else {
            return refuse(self);
        };
        if epoch - self.epoch > DOC_EPOCH_JUMP_MAX {
            return refuse(self);
        }
        if change.deps() != [peers_genesis(&gate.map, epoch).hash()] {
            return refuse(self);
        }
        let fresh = Self::new_gated(gate).at_epoch(epoch);
        if fresh.forges_foreign_entry(change, &frame.author, None) {
            return Ingested::Rejected;
        }
        match self.candidate.as_ref() {
            Some(held) if held.epoch == epoch && held.frame.dedup_key() == frame.dedup_key() => {
                return Ingested::Duplicate;
            }
            Some(held) if held.epoch >= epoch => return refuse(self),
            _ => {}
        }
        let kept = Candidate {
            epoch,
            frame: frame.clone(),
        };
        match self.candidate.replace(kept) {
            Some(beaten) => self.dropped.push(beaten.frame.dedup_key()),
            None => self.candidate_ticks = 0,
        }
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
        if let Err(error) = self.doc.apply_changes([change]) {
            if let Some(changes) = self.warn_due("dropping a channel change automerge refused") {
                tracing::warn!(target: LOG_TARGET, changes, %error, author = %frame.author, "dropping a channel change automerge refused");
            }
            return false;
        }
        self.applied.insert(hash);
        self.frame_bytes += wire_len(&frame);
        if let Some(replaced) = self.frames.insert(hash, frame) {
            self.frame_bytes -= wire_len(&replaced);
        }
        true
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
    use super::{DOC_PENDING_AUTHOR_MAX, DOC_PENDING_TOTAL_MAX, Ingested, MeshDoc, SelfWriteGate};
    use automerge::Change;
    use habilis_network_protocol::messages::Verified;
    use habilis_network_protocol::{
        AuthorKey, Channel, DedupKey, MeshId, Message, Nickname, SymmetricKey,
    };
    use serde_json::{Value, json};
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
    /// engine's, which is why `messages::VERSION` is `12.0`.
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
    /// mesh `test`: 103 bytes of fixed text (the keys, the quotes, the commas and `{"v":"12.0"`
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
        let entry_bytes: HashMap<String, usize> =
            HashMap::from([("alice".to_owned(), 10), ("bob".to_owned(), 10)]);
        assert_eq!(
            heavy.peer_entry_bytes,
            Some(entry_bytes),
            "the bytes of each entry, `{{\"card\":1}}` is 10"
        );
        let first_len = hand_counted_wire_len(&first);
        let second_len = hand_counted_wire_len(&second);
        let frame_bytes: HashMap<String, usize> = HashMap::from([
            ("alice".to_owned(), first_len),
            ("bob".to_owned(), second_len),
        ]);
        assert_eq!(
            heavy.author_frame_bytes,
            Some(frame_bytes),
            "the frame bytes by the nickname that signed them"
        );
        assert_eq!(
            doc.census(false).author_frame_bytes,
            None,
            "the light census does not walk the frames"
        );
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
        doc.to_json().as_object().map_or(0, serde_json::Map::len)
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
