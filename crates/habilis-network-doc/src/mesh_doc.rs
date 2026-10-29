use std::collections::{HashMap, HashSet};

use automerge::transaction::Transactable;
use automerge::{
    AutoSerde, Automerge, Change, ChangeHash, ObjId, ObjType, ROOT, ReadDoc, Value as AmValue,
};
use serde_json::{Map, Value};

use habilis_network_protocol::message::Verified;
use habilis_network_protocol::{AuthorKey, DedupKey, Message, Nickname, SymmetricKey};
use habilis_network_util::consts::{DOC_PENDING_AUTHOR_MAX, DOC_PENDING_TOTAL_MAX};

use crate::{DocError, wire};

/// Matches the receive path these drops happen on, so a reader filtering the
/// gossip target sees the orphan buffer alongside the frames feeding it.
const LOG_TARGET: &str = "habilis_network::gossip";

/// A refusal that the WARN reports is logged for the first one of its kind and then for every
/// `WARN_EVERY`th, with the number of refusals since the last WARN of that kind. An author who
/// floods a channel would otherwise log one line per frame. This crate keeps no clock, because it
/// runs in a browser, so the window is a count of refusals.
const WARN_EVERY: u64 = 16;

/// How many refusals of one kind the doc has seen, and how many of them a WARN has reported.
#[derive(Debug, Default)]
struct Refusals {
    seen: u64,
    reported: u64,
}

/// The outcome of ingesting one frame into a [`MeshDoc`].
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

/// One channel's automerge document plus the bookkeeping to apply changes in
/// causal order and re-serve them.
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
        Self::from_parts(Automerge::new(), HashSet::new(), None)
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
        let genesis = peers_genesis(&gate.map);
        let hash = genesis.hash();
        let _ = doc.apply_changes([genesis]);
        applied.insert(hash);
        Self::from_parts(doc, applied, Some(gate))
    }

    fn from_parts(
        doc: Automerge,
        applied: HashSet<ChangeHash>,
        gate: Option<SelfWriteGate>,
    ) -> Self {
        Self {
            doc: Box::new(doc),
            applied,
            frames: HashMap::new(),
            pending: HashMap::new(),
            pending_arrivals: 0,
            refusals: HashMap::new(),
            dropped: Vec::new(),
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
        before
            .keys()
            .chain(after.keys())
            .any(|nick| nick.as_str() != author.as_str() && before.get(nick) != after.get(nick))
    }

    /// Set this channel's encryption key (the daemon's per-channel
    /// mesh-password-derived key). `None` leaves the channel in plaintext.
    #[must_use]
    pub fn with_key(mut self, key: Option<SymmetricKey>) -> Self {
        self.key = key;
        self
    }

    /// The plaintext automerge change bytes carried by `frame`, decrypting an
    /// `enc` body with this channel's key first. `None` for an opaque/foreign
    /// body (or, on a passworded mesh, an unsealed or unopenable body) — a
    /// no-op on the doc.
    fn change_bytes(&self, frame: &Message) -> Option<Vec<u8>> {
        match self.key.as_ref() {
            // Passwordless: parse directly — no decrypt indirection, no clone.
            None => wire::parse_change_body(frame.body.as_str()),
            Some(key) => {
                let plain = wire::decrypt_body(frame.body.as_str(), Some(key))?;
                wire::parse_change_body(&plain)
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
        let plain = wire::change_body(change, merge)?;
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

    /// How many changes this document holds, the internal genesis included.
    #[must_use]
    pub fn change_count(&self) -> usize {
        self.applied.len()
    }

    /// The signed frames for changes a peer with heads `have` is missing, newest
    /// causal frontier first, capped at `max`. Undecodable heads are ignored (we
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
        self.doc
            .get_changes(&have)
            .into_iter()
            .filter_map(|change| self.frames.get(&change.hash()))
            .filter(move |frame| author.is_none_or(|skipped| &frame.key() != skipped))
            .take(max)
            .cloned()
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
        let Some(bytes) = self.change_bytes(frame) else {
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
        self.frames.insert(hash, frame);
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
    /// mirror the reassembly store.
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
                if let Some(changes) = self.warn_due("channel orphan buffer full for this author; incoming higher-seq orphan refused") {
                    tracing::warn!(target: LOG_TARGET, changes, author = %frame.author, "channel orphan buffer full for this author; incoming higher-seq orphan refused");
                }
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
        std::mem::take(&mut self.dropped).into_iter()
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
        self.pending
            .iter()
            .filter(|(_, entry)| entry.frame.key() == *author)
            .max_by_key(|(_, entry)| (entry.change.seq(), entry.arrival))
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
        (
            self.pending.len(),
            per_author.values().copied().max().unwrap_or(0),
        )
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
            let ready: Vec<ChangeHash> = self
                .pending
                .iter()
                .filter(|(_, entry)| self.deps_satisfied(entry.change.deps()))
                .map(|(hash, _)| *hash)
                .collect();
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
fn peers_genesis(map: &str) -> Change {
    let mut doc = Automerge::new();
    doc.set_actor(automerge::ActorId::from(b"habilis-mesh/genesis".as_slice()));
    {
        let mut tx = doc.transaction();
        tx.put_object(&ROOT, map, ObjType::Map)
            .expect("root is a map");
        tx.commit_with(automerge::transaction::CommitOptions::default().with_time(0));
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
    tx: &mut automerge::transaction::Transaction<'_>,
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
    tx: &mut automerge::transaction::Transaction<'_>,
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
    tx: &mut automerge::transaction::Transaction<'_>,
    obj: &ObjId,
    key: &str,
    value: &Value,
) -> anyhow::Result<()> {
    match value {
        Value::Array(items) => {
            let list = tx.put_object(obj, key, ObjType::List)?;
            for (index, item) in items.iter().enumerate() {
                append_item(tx, &list, index, item)?;
            }
        }
        Value::Object(_) | Value::Null => unreachable!("handled by write_map"),
        Value::Bool(_) | Value::String(_) | Value::Number(_) => put_scalar(tx, obj, key, value)?,
    }
    Ok(())
}

fn append_item(
    tx: &mut automerge::transaction::Transaction<'_>,
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
            for (inner_index, inner_item) in inner.iter().enumerate() {
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
    tx: &mut automerge::transaction::Transaction<'_>,
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
    tx: &mut automerge::transaction::Transaction<'_>,
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
    tx: &mut automerge::transaction::Transaction<'_>,
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
        DOC_PENDING_AUTHOR_MAX, DOC_PENDING_TOTAL_MAX, Ingested, MeshDoc, SelfWriteGate, WARN_EVERY,
    };
    use automerge::Change;
    use habilis_network_protocol::message::Verified;
    use habilis_network_protocol::{
        AuthorKey, Channel, DedupKey, MeshId, Message, Nickname, SymmetricKey,
    };
    use habilis_network_test_tracing::{expect_warn, test};
    use serde_json::{Value, json};
    use std::collections::HashSet;

    fn nick(name: &str) -> Nickname {
        Nickname::from(name)
    }

    /// Wrap change bytes in a signed-frame stand-in, signed by the change's
    /// actor. The doc layer reads `author`, `pubkey` and `body`; a valid
    /// signature is `gossip::ingest`'s job.
    fn frame(who: &Nickname, bytes: &[u8]) -> Verified {
        let change = Change::from_bytes(bytes.to_vec()).expect("a change");
        let actor = AuthorKey::from_hex(&change.actor_id().to_hex_string())
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
            .with_unverified_key(key),
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
    /// engine's, which is why `message::VERSION` is `12.0`.
    #[test]
    fn genesis_bytes_are_pinned() {
        let genesis = super::peers_genesis("peers");
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
        let key = SymmetricKey::from_bytes([3u8; 32]);
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

    #[test]
    fn distinct_top_level_keys_converge_either_order() {
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
        expect_warn(
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
        expect_warn(
            super::LOG_TARGET,
            "channel orphan buffer full for this author; incoming higher-seq orphan refused",
        );
        let alice = nick("alice");
        let mut source = MeshDoc::new_ungated();
        let chain: Vec<Verified> = (0..DOC_PENDING_AUTHOR_MAX + 32)
            .map(|step| author(&mut source, &alice, &json!({ "k": step })))
            .collect();

        let mut sink = MeshDoc::new_ungated();
        // Withhold the root, so not one of these can ever apply.
        for frame in chain.iter().skip(1) {
            sink.ingest(frame);
        }

        let (total, per_author) = sink.pending_stats();
        assert!(
            per_author <= DOC_PENDING_AUTHOR_MAX,
            "one author buffered {per_author} orphans, over the {DOC_PENDING_AUTHOR_MAX} ceiling"
        );
        assert!(total <= DOC_PENDING_TOTAL_MAX, "{total} orphans buffered");
    }

    /// Collects the `changes` field of every WARN that the thread logs while it is the default
    /// subscriber. A subscriber of the thread, so the guard of the test sees none of these events.
    struct WarnCounts(std::sync::Arc<std::sync::Mutex<Vec<u64>>>);

    impl tracing::Subscriber for WarnCounts {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Changes(u64);
            impl tracing::field::Visit for Changes {
                fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                    if field.name() == "changes" {
                        self.0 = value;
                    }
                }
                fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
            }
            if *event.metadata().level() == tracing::Level::WARN {
                let mut changes = Changes(0);
                event.record(&mut changes);
                self.0.lock().expect("no poison").push(changes.0);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// A flood of refused changes from one author logs the first refusal at once and then one WARN
    /// for every `WARN_EVERY` refusals, each with the number of refusals since the last WARN. The
    /// crate keeps no clock, so the window is a count of refusals.
    #[test]
    fn a_flood_of_refused_changes_logs_one_warn_per_window() {
        let alice = nick("alice");
        let mut source = MeshDoc::new_ungated();
        let chain: Vec<Verified> = (0..DOC_PENDING_AUTHOR_MAX + 200)
            .map(|step| author(&mut source, &alice, &json!({ "k": step })))
            .collect();
        let mut sink = MeshDoc::new_ungated();
        let counts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        // The root is withheld, so every change is an orphan: the first
        // `DOC_PENDING_AUTHOR_MAX` fill the buffer and each later one is refused.
        tracing::subscriber::with_default(WarnCounts(std::sync::Arc::clone(&counts)), || {
            for frame in chain.iter().skip(1) {
                sink.ingest(frame);
            }
        });
        let logged = counts.lock().expect("no poison").clone();
        let refused = u64::try_from(chain.len() - 1 - DOC_PENDING_AUTHOR_MAX).expect("fits");
        assert_eq!(
            logged.first(),
            Some(&1),
            "the first refusal is logged at once"
        );
        assert!(
            logged.iter().skip(1).all(|&changes| changes == WARN_EVERY),
            "every later WARN counts a full window: {logged:?}"
        );
        assert_eq!(
            u64::try_from(logged.len()).expect("fits"),
            1 + (refused - 1) / WARN_EVERY,
            "{refused} refusals logged {logged:?}"
        );
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
        expect_warn(
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
                .any(|entry| entry.frame.key() == AuthorKey::from_bytes([0x11; 32])),
            "the honest orphan survived: the newcomer is refused, not an incumbent evicted"
        );
    }

    /// A newcomer refused at the global cap never reaches `pending`, but the
    /// receive path already marked it seen, so its key is handed back with the
    /// evicted ones or the author's re-send is discarded as a repeat.
    #[test]
    fn an_orphan_refused_at_the_global_cap_is_reported_as_dropped() {
        expect_warn(
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
        expect_warn(
            super::LOG_TARGET,
            "channel orphan buffer full for this author; incoming higher-seq orphan refused",
        );
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
        for frame in flood.iter().skip(1) {
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
        expect_warn(
            super::LOG_TARGET,
            "channel orphan buffer full for this author; incoming higher-seq orphan refused",
        );
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
        expect_warn(
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
        expect_warn(
            super::LOG_TARGET,
            "channel orphan buffer full for this author; highest-seq orphan evicted",
        );
        expect_warn(
            super::LOG_TARGET,
            "channel orphan buffer full for this author; incoming higher-seq orphan refused",
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
        expect_warn(
            super::LOG_TARGET,
            "channel orphan buffer full for this author; incoming higher-seq orphan refused",
        );
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
        expect_warn(
            super::LOG_TARGET,
            "channel orphan buffer full for this author; incoming higher-seq orphan refused",
        );
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

    /// automerge takes one change per `(actor, seq)`. A frame whose signer does
    /// not own the change's actor could take an author's next seq, and the
    /// author's real change would then be refused on every replica.
    #[test]
    fn a_change_signed_by_another_key_cannot_take_an_authors_next_seq() {
        expect_warn(
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
        let forged = frame_as(&mallory, &forged, AuthorKey::from_bytes([0xbb; 32]));
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
        expect_warn(
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
        let forged = frame_as(&nick("mallory"), &orphan, AuthorKey::from_bytes([0xbb; 32]));

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
    fn heads_and_changes_since_reconcile_a_late_joiner() {
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
        let alice = nick("alice");
        let key = [42u8; 32];
        // Author builds the change and seals the wire body, as the daemon does.
        let merge = json!({"secret": "value"});
        let author_doc = MeshDoc::new_ungated().with_key(Some(SymmetricKey::from_bytes(key)));
        let bytes: Vec<u8> = author_doc
            .build_change(&merge, &pad_seed(alice.as_str().as_bytes()))
            .expect("builds")
            .expect("not a no-op");
        let (wire, _plain) = author_doc
            .compose_wire_body(&bytes, Some(&merge))
            .expect("compose");
        let signer = AuthorKey::from_bytes(pad_seed(alice.as_str().as_bytes()));
        let carrier = Verified::fixture_unchecked(
            Message::new_channel_event(&MeshId::from("test"), &alice, wire, Channel::State)
                .with_unverified_key(signer),
            signer,
        );
        assert!(
            !carrier.body.as_str().contains("value"),
            "the plaintext value must not appear on the wire"
        );

        // A peer holding the key applies it and converges; surface_body recovers
        // the plaintext for the delta.
        let mut with_key = MeshDoc::new_ungated().with_key(Some(SymmetricKey::from_bytes(key)));
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
            with_key.surface_body(&carrier).unwrap().contains("secret"),
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
        let mut wrong_key =
            MeshDoc::new_ungated().with_key(Some(SymmetricKey::from_bytes([7u8; 32])));
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
