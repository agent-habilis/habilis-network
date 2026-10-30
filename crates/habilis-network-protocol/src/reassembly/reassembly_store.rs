//! The dedicated buffer of partial multipart bodies, and its synthesis.

use super::{RepairTicket, ShardIngest};

use std::collections::{BTreeMap, HashMap};

use crate::messages::{Authored, Verified};
use crate::{AuthorKey, Message, MessageBody, MessageId, MessageKind, Nickname, ShardGroup};
use habilis_network_util::clock::Instant;
use habilis_network_util::consts::{
    LOGGED_SHARD_GROUP_MAX_TOTAL, REASSEMBLY_AUTHOR_BUDGET_BYTES, REASSEMBLY_GROUP_MAX_BYTES,
    REASSEMBLY_MAX_GROUP_LIFETIME, REASSEMBLY_REPAIR_IDLE, REASSEMBLY_REPAIR_MAX_IDXS,
    REASSEMBLY_SLOT_MIN_CHARGE_BYTES, REASSEMBLY_SLOT_OVERHEAD_BYTES, REASSEMBLY_STALE,
    REASSEMBLY_TOTAL_BUDGET_BYTES,
};

/// What one buffered shard costs against the byte budgets: its body plus the
/// per-slot overhead (map nodes, keys, the shard-0 envelope clone), floored so
/// a 1-byte crafted shard still pays for the ~KB of state it occupies.
///
/// # Examples
///
/// Every slot pays a floor charge, and a larger body pays more.
///
/// ```
/// use habilis_network_protocol::reassembly::slot_charge;
///
/// assert!(slot_charge(0) > 0);
/// assert!(slot_charge(4096) > slot_charge(1));
/// ```
#[must_use]
pub fn slot_charge(body_len: usize) -> usize {
    (body_len + REASSEMBLY_SLOT_OVERHEAD_BYTES).max(REASSEMBLY_SLOT_MIN_CHARGE_BYTES)
}

/// `tracing` target for reassembly (matches the owning gossip plane).
const LOG_TARGET: &str = "habilis_network::gossip";

/// One in-flight multipart body: the buffered shard bodies slotted by `idx`.
///
/// `slots` is a `BTreeMap`, never a `total`-sized allocation — a crafted
/// `total` must cost the sender shards, not us memory. `header` is the idx-0
/// shard, the envelope template `synthesize_logical` builds the view from.
#[derive(Debug, Clone)]
pub(super) struct PartialGroup {
    total: u32,
    /// Kind pinned at the first shard; a later shard of a different kind is a
    /// crafted stream and is dropped.
    kind: MessageKind,
    /// The author's nickname (from the first shard) — where a repair request
    /// for this group is addressed.
    author: Nickname,
    slots: BTreeMap<u32, String>,
    header: Option<Verified>,
    bytes: usize,
    /// Last **progress** (a new slot filled) — duplicates don't refresh it,
    /// so resends can't keepalive a dead group past the idle TTL.
    last_seen: Instant,
    /// Birth instant, for the absolute lifetime ceiling.
    created_at: Instant,
    /// When we last asked the author to re-send missing shards, if ever.
    last_repair: Option<Instant>,
}

impl PartialGroup {
    fn is_complete(&self) -> bool {
        self.slots.len() as u64 == u64::from(self.total)
    }
}

/// Groups are keyed by `(author key, group)` — the same security boundary
/// the message-log reassembly had: only the signer fills its own slots, so a
/// crafted shard carrying a victim's group id forms a separate,
/// never-completing set and can't inject a slice into the victim's body.
type GroupKey = (AuthorKey, ShardGroup);

/// The dedicated buffer partial multipart bodies reassemble in — decoupled
/// from the message log so log eviction can never break reassembly, and
/// bounded by **byte budgets** (per group, per author, global) plus a
/// stale-group TTL instead of a shard-count cap. "Unbounded message size" is
/// achieved by budgeted, evictable buffering, never an unbounded collection.
///
/// # Examples
///
/// A new store holds no group.
///
/// ```
/// use std::time::Instant;
///
/// use habilis_network_protocol::reassembly::ReassemblyStore;
///
/// let mut store = ReassemblyStore::default();
/// assert_eq!(store.sweep_stale(Instant::now()), 0);
/// ```
#[derive(Debug, Default, Clone)]
pub struct ReassemblyStore {
    pub(super) groups: HashMap<GroupKey, PartialGroup>,
    pub(super) author_bytes: HashMap<AuthorKey, usize>,
    pub(super) total_bytes: usize,
}

impl ReassemblyStore {
    /// Buffer one shard; when it completes its group, synthesize and return
    /// the logical message and free the group's budget. The caller keys
    /// surfacing-once separately (`reassembled_groups`). A message with no shard header,
    /// is dropped: a `Verified` shard always has its author key.
    ///
    /// # Panics
    /// Never: the group that just completed is by construction still stored.
    pub fn ingest(&mut self, shard_msg: &Verified, now: Instant) -> ShardIngest {
        let Some(shard) = shard_msg.shard.as_ref() else {
            return ShardIngest::Dropped;
        };
        let key: GroupKey = (shard_msg.key(), shard.group.clone());
        let charge = slot_charge(shard_msg.body.as_str().len());

        if let Some(group) = self.groups.get(&key) {
            // A signer contradicting its own group header (different total or
            // kind) is a crafted stream — drop the shard, keep the group.
            if group.total != shard.total || group.kind != shard_msg.kind {
                return ShardIngest::Dropped;
            }
            if group.slots.contains_key(&shard.index) {
                // First-seen wins per idx. Deliberately NO liveness refresh: a
                // resent duplicate is not progress, and refreshing on it would
                // let an attacker keepalive a dead group forever.
                return ShardIngest::Dropped;
            }
            if group.bytes + charge > REASSEMBLY_GROUP_MAX_BYTES {
                self.evict(&key);
                tracing::warn!(
                    target: LOG_TARGET,
                    group = %key.1,
                    "partial shard group exceeded its byte budget; dropped"
                );
                return ShardIngest::Dropped;
            }
        }

        if !self.admit(&key, charge, now) {
            return ShardIngest::Dropped;
        }

        let group: &mut PartialGroup =
            self.groups
                .entry(key.clone())
                .or_insert_with(|| PartialGroup {
                    total: shard.total,
                    kind: shard_msg.kind.clone(),
                    author: shard_msg.author.clone(),
                    slots: BTreeMap::new(),
                    header: None,
                    bytes: 0,
                    last_seen: now,
                    created_at: now,
                    last_repair: None,
                });
        group.last_seen = now;
        group.bytes += charge;
        group
            .slots
            .insert(shard.index, shard_msg.body.as_str().to_owned());
        if shard.index == 0 {
            group.header = Some(shard_msg.clone());
        }
        *self.author_bytes.entry(key.0).or_default() += charge;
        self.total_bytes += charge;

        if !group.is_complete() {
            return ShardIngest::Buffered;
        }
        let group_id = &key.1;
        let complete = self.evict(&key).expect("just-completed group is stored");
        match synthesize_logical(complete, group_id) {
            Some(logical) => ShardIngest::Complete(Box::new(logical)),
            None => ShardIngest::Dropped,
        }
    }

    /// Reap partial groups that made no progress for [`REASSEMBLY_STALE`]
    /// or outlived [`REASSEMBLY_MAX_GROUP_LIFETIME`] outright (a trickle
    /// of one shard per idle window must not pin its bytes forever); returns
    /// how many were dropped (the prune tick warns when non-zero).
    pub fn sweep_stale(&mut self, now: Instant) -> usize {
        let stale: Vec<GroupKey> = self
            .groups
            .iter()
            .filter(|(_, group)| {
                now.duration_since(group.last_seen) >= REASSEMBLY_STALE
                    || now.duration_since(group.created_at) >= REASSEMBLY_MAX_GROUP_LIFETIME
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in &stale {
            self.evict(key);
        }
        stale.len()
    }

    /// Make room for `charge` under the author and global budgets. The author
    /// budget evicts *that author's* stalest incomplete group (a hostile peer
    /// exhausts only itself); a global breach refuses the newcomer outright —
    /// evicting across authors would let a Sybil stream push out honest
    /// transfers.
    fn admit(&mut self, key: &GroupKey, charge: usize, _now: Instant) -> bool {
        while self.author_bytes.get(&key.0).copied().unwrap_or(0) + charge
            > REASSEMBLY_AUTHOR_BUDGET_BYTES
        {
            let Some(victim) = self.stalest_group_of(&key.0, key) else {
                tracing::warn!(
                    target: LOG_TARGET,
                    group = %key.1,
                    "author reassembly budget exhausted by one group; dropped"
                );
                return false;
            };
            self.evict(&victim);
            tracing::warn!(
                target: LOG_TARGET,
                group = %victim.1,
                "author reassembly budget breached; stalest partial group evicted"
            );
        }
        if self.total_bytes + charge > REASSEMBLY_TOTAL_BUDGET_BYTES {
            tracing::warn!(
                target: LOG_TARGET,
                group = %key.1,
                "global reassembly budget breached; incoming shard group dropped"
            );
            return false;
        }
        true
    }

    /// The author's least-recently-touched group other than `except`.
    fn stalest_group_of(&self, author: &AuthorKey, except: &GroupKey) -> Option<GroupKey> {
        let candidates = self
            .groups
            .iter()
            .filter(|(key, _)| key.0 == *author && *key != except);
        candidates
            .min_by_key(|(_, group)| group.last_seen)
            .map(|(key, _)| key.clone())
    }

    /// Accounting snapshot `(groups, total_bytes, max_author_bytes)` for the
    /// adversarial suite's budget tripwires.
    #[cfg(feature = "adversarial")]
    #[must_use]
    pub fn stats(&self) -> (usize, usize, usize) {
        let groups = self.groups.len();
        (
            groups,
            self.total_bytes,
            self.author_bytes.values().copied().max().unwrap_or(0),
        )
    }

    /// Drop the partial group that `shard_msg` belongs to (its author's group) and release
    /// its budget — the log-backed completion path calls this after finishing a group the
    /// store had only a fragment of (e.g. post-TTL, when dedup let just one healed shard
    /// re-ingest). A message with no shard header or no author key names no group.
    pub fn forget(&mut self, shard_msg: &Verified) {
        if let Some(shard) = shard_msg.shard.as_ref() {
            self.evict(&(shard_msg.key(), shard.group.clone()));
        }
    }

    /// The big (unlogged) groups that stalled long enough to ask their author
    /// for the missing shards, each at most once per
    /// [`REASSEMBLY_REPAIR_IDLE`] window. Small groups are excluded —
    /// their shards live in the message log and heal via anti-entropy, which
    /// re-sends a directed shard point-to-point to its addressee.
    pub fn repair_tickets(&mut self, now: Instant) -> impl Iterator<Item = RepairTicket> {
        let mut tickets = Vec::new();
        for ((_, group_id), group) in &mut self.groups {
            if group.total <= LOGGED_SHARD_GROUP_MAX_TOTAL || group.is_complete() {
                continue;
            }
            let idle = now.duration_since(group.last_seen);
            let asked_recently = group
                .last_repair
                .is_some_and(|at| now.duration_since(at) < REASSEMBLY_REPAIR_IDLE);
            if idle < REASSEMBLY_REPAIR_IDLE || asked_recently {
                continue;
            }
            group.last_repair = Some(now);
            let missing: Vec<u32> = (0..group.total)
                .filter(|index| !group.slots.contains_key(index))
                .take(REASSEMBLY_REPAIR_MAX_IDXS)
                .collect();
            tickets.push(RepairTicket {
                author: group.author.clone(),
                group: group_id.clone(),
                missing,
            });
        }
        tickets.into_iter()
    }

    /// Remove a group and release its budget.
    fn evict(&mut self, key: &GroupKey) -> Option<PartialGroup> {
        let group = self.groups.remove(key)?;
        self.total_bytes = self.total_bytes.saturating_sub(group.bytes);
        if let Some(author) = self.author_bytes.get_mut(&key.0) {
            *author = author.saturating_sub(group.bytes);
            if *author == 0 {
                self.author_bytes.remove(&key.0);
            }
        }
        Some(group)
    }
}

/// Build the logical-message surfacing view from a completed group: shard 0's
/// envelope (kind/author/pubkey/mesh/ts), the concatenated body, the group as
/// `id`, and no `shard`/chain (the view is neither a wire message nor a chain
/// entry — the shards are). `None` only when the concatenated body fails
/// validation — fail closed rather than surface a malformed body.
fn synthesize_logical(group: PartialGroup, group_id: &ShardGroup) -> Option<Authored> {
    // Sized up front: this runs on every completed multipart body, and the
    // total is already known from the slots.
    let mut body = String::with_capacity(group.slots.values().map(String::len).sum());
    for slot in group.slots.values() {
        body.push_str(slot);
    }
    let body = MessageBody::try_new(&body).ok()?;
    let header = group.header?;
    Some(synthesize_from(&header, body, group_id))
}

/// The shared synthesis step: `envelope` (a shard-0 frame) becomes the logical
/// view with the concatenated `body`, the group as `id`, and no `shard`/chain.
/// Also used by the message-log completion path (`EventLoopState::
/// reassemble_from_log`) so the two paths can't drift.
#[must_use]
/// # Panics
/// If the envelope carries no shard header; callers only pass shard messages.
///
/// # Examples
///
/// It builds the logical message of a completed group. `ShardGroup` is in the private shard module, so this is not compiled.
///
/// ```ignore
/// use habilis_network_protocol::identity::Identity;
/// use habilis_network_protocol::messages::{AppTag, BuildMsgParams, ChainCtx, MessageBody, build_msg_bytes};
/// use habilis_network_protocol::meshes::MeshId;
/// use habilis_network_protocol::Nickname;
///
/// use habilis_network_protocol::{Mesh, MeshConfig, MeshName, Seed};
///
/// let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
/// let mesh = Mesh::try_new(Seed::new([4u8; 32]), MeshName::try_new("chat").expect("a name"), config)
///     .expect("a mesh");
///
/// let id = MeshId::try_new(&mesh.to_string()).expect("a valid id");
/// let identity = Identity::generate();
/// let author = Nickname::try_new("alice").expect("a nickname");
/// let tag = AppTag::try_new("chat").expect("a tag");
/// let body = MessageBody::try_new("hello").expect("a body");
/// let params = BuildMsgParams::new(tag, &id, &author, body, ChainCtx::genesis());
/// let (_frame, verified) = build_msg_bytes(params, &identity).expect("a message builds");
///
/// // The ShardGroup of the shard header.
/// let authored = synthesize_from(&verified, MessageBody::try_new("hello").expect("a body"), &group);
/// ```
pub fn synthesize_from(header: &Verified, body: MessageBody, group_id: &ShardGroup) -> Authored {
    let mut envelope = Message::clone(header);
    envelope.id =
        MessageId::try_new(group_id.as_str()).expect("a shard group is a valid message id");
    envelope.body = body;
    envelope.shard = None;
    envelope.seq = None;
    envelope.previous = None;
    envelope.parents = Vec::new();
    Authored::new(envelope, header.key())
}
