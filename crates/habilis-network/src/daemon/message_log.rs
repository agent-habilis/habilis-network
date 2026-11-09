use crate::protocol;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::protocol::messages::Verified;
use crate::protocol::{AuthorKey, DedupKey, MessageKind, PresenceSubtype, UnixSecs};

/// A bounded buffer of the recent messages a member retains — the
/// anti-entropy recovery source and the poll/fetch history. Held in arrival
/// order (push order ≈ ascending timestamp) for the poll cursor and the
/// positional digest windows. When full, one message is discarded — *not* the
/// front — chosen so the **retained set** is a deterministic function of the
/// message set, identical on every node regardless of gossip delivery order
/// (see [`MessageLog::eviction_index`]).
#[derive(Debug, Clone)]
pub struct MessageLog {
    capacity: usize,
    messages: VecDeque<Verified>,
    /// How many messages each author currently holds.
    ///
    /// Maintained on every push and eviction rather than rebuilt, because
    /// [`Self::eviction_index`] needs it on nearly every steady-state message:
    /// at capacity it was hashing a thousand base58 author keys to recount what two
    /// counter updates already know. The map is the *only* derived state here,
    /// and both mutation sites are in [`Self::push`], so it cannot drift. Every held message is
    /// a [`Verified`], so it has an author key: there is no unsigned entry to special-case.
    per_author: HashMap<AuthorKey, usize>,
    /// The dedup key of every held message, so a frame that is pushed twice is held once.
    keys: HashSet<DedupKey>,
}

impl MessageLog {
    pub(crate) fn new(capacity: usize) -> Self {
        MessageLog {
            capacity,
            messages: VecDeque::with_capacity(capacity),
            per_author: HashMap::new(),
            keys: HashSet::new(),
        }
    }

    /// Add a message to the log, keeping arrival order. If that overflows
    /// the capacity, evict (and return) the message with the smallest
    /// **eviction key** — *not* the front — so the retained set is a
    /// deterministic function of `(message set, capacity)`, identical on
    /// every node regardless of gossip delivery order. That makes the
    /// mesh-wide retained set well-defined: peers agree on which messages
    /// survive, so anti-entropy recovery converges on one set instead of the
    /// union of divergent arrival-order windows. The returned eviction lets
    /// callers prune side indexes keyed by it (the DAG `by_hash`, fork map). A message whose
    /// dedup key is already held is not added, and nothing is evicted.
    pub fn push(&mut self, message: Verified) -> Option<Verified> {
        // A frame that is already held is held once: two paths that retain the same frame
        // (an author that logs its own send and a consumer that pushes it too) cost a lookup.
        if !self.keys.insert(message.dedup_key()) {
            return None;
        }
        *self.per_author.entry(message.key()).or_default() += 1;
        self.messages.push_back(message);
        if self.messages.len() <= self.capacity {
            return None;
        }
        let victim = self.eviction_index();
        let evicted = self.messages.remove(victim);
        if let Some(gone) = &evicted {
            self.keys.remove(&gone.dedup_key());
        }
        if let Some(gone) = &evicted
            && let Some(held) = self.per_author.get_mut(&gone.key())
        {
            *held -= 1;
            // No zero entries: one would win the lowest-author-key tie-break in
            // `eviction_index` while holding nothing to evict.
            if *held == 0 {
                self.per_author.remove(&gone.key());
            }
        }
        evicted
    }

    /// Which message to drop when over capacity: the smallest eviction key
    /// *within the author holding the most of the log*, rather than the
    /// smallest overall.
    ///
    /// Every field of the key travels on the wire, so leading with it made
    /// eviction something a sender chooses. A peer stamping its frames far
    /// enough ahead never lost one, and each honest message that arrived was
    /// picked as its own victim the moment it landed — history stopped
    /// existing, identically everywhere. Charging the fullest author instead
    /// means a flood exhausts the flooder's own share and leaves everyone
    /// else's alone. Bounding the timestamp would not do: any future a sender
    /// is allowed still sorts above every honest message.
    ///
    /// Still a pure function of the message set — the counts, the author-key
    /// tie-break and the key comparison all read wire fields, never arrival
    /// order — so peers agree on the retained set, which is what lets
    /// anti-entropy converge on one set rather than a union of windows.
    ///
    /// Not a Sybil defence: author keys are free, so N identities hold N shares.
    /// It removes the case where one identity costs everyone their history.
    fn eviction_index(&self) -> usize {
        // Ties go to the lowest author key, so the choice is total and identical
        // on every node.
        let fullest: AuthorKey = self
            .per_author
            .iter()
            .max_by(|(lhs_key, lhs_count), (rhs_key, rhs_count)| {
                lhs_count.cmp(rhs_count).then_with(|| rhs_key.cmp(lhs_key))
            })
            .map(|(author, _)| *author)
            .expect("over-capacity log is non-empty");
        let indexed = self.messages.iter().enumerate();
        let candidates = indexed.filter(|(_, message)| message.key() == fullest);
        candidates
            .min_by(|(_, lhs), (_, rhs)| eviction_key(lhs).cmp(&eviction_key(rhs)))
            .map(|(index, _)| index)
            .expect("the fullest author holds at least one message")
    }

    pub(crate) fn contains(&self, key: &DedupKey) -> bool {
        self.keys.contains(key)
    }

    /// Drop the presence frames of `author` and return them, so the caller can prune the indexes
    /// it keeps beside the log. A key that said goodbye never speaks again, and eviction charges
    /// the fullest author, so a small departed author's `joined` frames would otherwise stay
    /// resend subjects for the life of the node. Its chat and its `left` stay: a node that missed
    /// them can still backfill them. Every node that holds the goodbye does the same, so the
    /// retained set stays a function of the message set.
    pub(crate) fn drop_presence_of(&mut self, author: &AuthorKey) -> Vec<Verified> {
        let is_departed_presence = |message: &Verified| {
            message.key() == *author
                && matches!(
                    message.kind,
                    MessageKind::Presence {
                        subtype: PresenceSubtype::Joined | PresenceSubtype::Alive
                    }
                )
        };
        let mut dropped = Vec::new();
        self.messages.retain(|message| {
            if is_departed_presence(message) {
                dropped.push(message.clone());
                false
            } else {
                true
            }
        });
        for gone in &dropped {
            self.keys.remove(&gone.dedup_key());
        }
        match self.per_author.get_mut(author) {
            Some(held) if *held > dropped.len() => *held -= dropped.len(),
            Some(_) => {
                self.per_author.remove(author);
            }
            None => {}
        }
        dropped
    }

    #[cfg(any(test, feature = "iroh-test-utils"))]
    pub(crate) fn len(&self) -> usize {
        self.messages.len()
    }

    /// The retained shards of multipart `group` authored by `author`, slotted by
    /// `idx` (first-seen wins per idx); `total` slots, each `None` until its shard
    /// arrives. Keying on the author as well as `group` is the security boundary: a
    /// peer can only sign shards under its own key, so a crafted shard carrying
    /// someone else's `group` forms a separate, never-completing set and can't
    /// inject a slice into the victim's body. Only **small** (logged) groups ever
    /// reach this — `total` is bounded by `LOGGED_SHARD_GROUP_MAX_TOTAL` at the
    /// call site, so the `total`-sized allocation is safe.
    pub(crate) fn collect_shards<'a>(
        &'a self,
        group: &protocol::ShardGroup,
        author: &AuthorKey,
        total: u32,
    ) -> Vec<Option<&'a Verified>> {
        let mut slots: Vec<Option<&Verified>> = vec![None; total as usize];
        for message in &self.messages {
            let Some(shard) = &message.shard else {
                continue;
            };
            if shard.group == *group
                && shard.total == total
                && message.key() == *author
                && let Some(slot) = slots.get_mut(shard.index as usize)
                && slot.is_none()
            {
                *slot = Some(message);
            }
        }
        slots
    }
}

/// Total order deciding which of an author's messages goes first (smallest is
/// dropped): oldest `timestamp`, then author key, the author's `seq` (so one
/// author's burst evicts in send order — `seq 0` goes first), and finally the
/// message id as a tie-break. Every field travels on the wire and is identical
/// on every node, so retention is a pure function of the message set, not of
/// arrival order.
///
/// Ranks *within* one author, not across them: because a sender picks these
/// fields, ordering the whole log by them let one peer stamp its way to
/// permanent residency. [`MessageLog::eviction_index`] picks the author first.
fn eviction_key(message: &Verified) -> (UnixSecs, AuthorKey, Option<u64>, &str) {
    (
        message.timestamp,
        message.key(),
        message.seq,
        message.id.as_str(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{AuthorKey, MessageLog, UnixSecs, Verified};
    use crate::protocol::{Message, Nickname};

    use crate::protocol;
    fn message(id: &str) -> Verified {
        signed(plain(id))
    }

    /// One fixed author for the plain fixtures, so that they share a victim pool the way the
    /// unsigned messages of these tests always did. A signature is not what these tests check.
    fn signed(message: Message) -> Verified {
        Verified::fixture_unchecked(message, AuthorKey::from([0x11; 32]))
    }

    fn plain(id: &str) -> Message {
        Message::new_app(
            &protocol::MeshId::from("test"),
            &Nickname::from("author"),
            protocol::AppFrameParams::new(
                protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                None,
                None,
                protocol::MessageBody::from(id),
            ),
        )
    }

    /// The same frame pushed twice is held once, and the digest lists it once.
    #[test]
    fn a_frame_pushed_twice_is_held_once() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut log = MessageLog::new(10);
        let frame = msg_at("once", 10);
        assert!(
            log.push(frame.clone()).is_none(),
            "the first push of a frame holds it"
        );
        assert!(
            log.push(frame).is_none(),
            "the second push of a held frame is not held again"
        );
        assert_eq!(log.len(), 1, "the log holds one frame after two pushes");
    }

    /// A key leaves the index with its message: a frame that was evicted can be held again.
    /// `contains` is what the dedup gate reads for a retained frame, so it must say no the
    /// moment the log lets a frame go, or a re-send of an evicted frame is never processed.
    #[test]
    fn contains_follows_eviction() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut log = MessageLog::new(2);
        let first = message("m1");
        let second = message("m2");
        assert!(
            log.push(first.clone()).is_none(),
            "the first frame is pushed into the log"
        );
        assert!(
            log.push(second.clone()).is_none(),
            "the second frame is pushed into the log"
        );
        assert!(
            log.contains(&first.dedup_key()) && log.contains(&second.dedup_key()),
            "both frames are contained before eviction"
        );
        let gone = log.push(message("m3")).expect("a third frame evicts one");
        assert!(
            !log.contains(&gone.dedup_key()),
            "an evicted frame is still held"
        );
        let kept = if gone.dedup_key() == first.dedup_key() {
            &second
        } else {
            &first
        };
        assert!(
            log.contains(&kept.dedup_key()),
            "the frame that stayed is not held"
        );
    }

    #[test]
    fn an_evicted_frame_can_be_held_again() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut log = MessageLog::new(1);
        assert!(
            log.push(msg_at("first", 10)).is_none(),
            "an evicted frame is held again when pushed"
        );
        let evicted = log.push(msg_at("second", 20)).expect("the log is full");
        assert!(
            log.push(evicted).is_some(),
            "the evicted frame is new again, so the push evicts one of the two"
        );
        assert_eq!(log.len(), 1, "the log holds one frame after the re-push");
    }

    /// A message tagged with an explicit timestamp, for window tests.
    fn msg_at(body: &str, ts: i64) -> Verified {
        signed(plain_at(body, ts))
    }

    fn plain_at(body: &str, ts: i64) -> Message {
        let mut message = plain(body);
        message.timestamp = UnixSecs::from(ts);
        message
    }

    // ── the addressee gate ─────────────────────────────────────────

    // ── MessageLog ─────────────────────────────────────────────────

    /// **A far-future stamp must not make a message unevictable.**
    ///
    /// The eviction key leads with the wire timestamp and drops the *smallest*,
    /// so frames stamped at the end of time sort highest and never lose. Fill
    /// the log with those and every honest message that arrives is chosen as
    /// its own victim the instant it lands — history stops existing, and it
    /// stops identically on every node, because the key is wire-derived by
    /// design.
    #[test]
    fn a_far_future_stamp_does_not_make_a_message_unevictable() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut log = MessageLog::new(4);
        for index in 0..4 {
            let flood = Verified::fixture_unchecked(
                plain_at(&format!("flood{index}"), i64::MAX),
                AuthorKey::from([0xff; 32]),
            );
            log.push(flood);
        }
        let honest = Verified::fixture_unchecked(
            plain_at("honest", 1_700_000_000),
            AuthorKey::from([0xaa; 32]),
        );
        let evicted = log.push(honest);
        assert!(
            evicted.is_some_and(|message| message.body.as_str() != "honest"),
            "an honest message must not be evicted the moment it arrives"
        );
        let bodies: HashSet<&str> = log
            .messages
            .iter()
            .map(|message| message.body.as_str())
            .collect();
        assert!(bodies.contains("honest"), "the honest message must survive");
    }

    /// The author counts are maintained incrementally rather than recounted,
    /// so the one way this can go wrong is the map drifting from the log it
    /// describes — silently picking the wrong victim, on every node, forever.
    #[test]
    fn the_author_counts_match_a_fresh_recount_after_churn() {
        use std::collections::HashMap;

        let _guard = ::habilis_network_test_tracing::init();
        let mut log = MessageLog::new(8);
        // Three authors at different rates, well past capacity, so eviction
        // fires repeatedly and each author is both added and dropped.
        for step in 0..60i64 {
            let author = ["aa", "bb", "cc"][usize::try_from(step).expect("fits") % 3];
            let message = Verified::fixture_unchecked(
                plain_at(&format!("{author}-{step}"), 1_700_000_000 + step),
                AuthorKey::decode_hex(&author.repeat(32)).expect("hex"),
            );
            log.push(message);

            let mut recounted: HashMap<AuthorKey, usize> = HashMap::new();
            for held in &log.messages {
                *recounted.entry(held.key()).or_default() += 1;
            }
            assert_eq!(log.per_author, recounted, "counts drifted at step {step}");
        }
        // A dropped author leaves no zero entry behind, or it would win the
        // lowest-author-key tie-break while holding nothing.
        assert!(
            log.per_author.values().all(|count| *count > 0),
            "every author count is positive after churn"
        );
    }

    /// **Retention must not depend on arrival order**, across authors too.
    ///
    /// This is what lets anti-entropy converge: every node has to keep the same
    /// set, or peers reconcile toward the union of their own windows instead of
    /// one agreed set. Eviction reads only wire fields for exactly this reason,
    /// so any change to how the victim is chosen has to preserve it.
    #[test]
    fn retention_is_the_same_whatever_order_messages_arrive_in() {
        let _guard = ::habilis_network_test_tracing::init();
        let authors = ["aa", "bb", "cc"];
        let build = || {
            let mut batch = Vec::new();
            let indexed_authors: Vec<(usize, &&str)> = authors.iter().enumerate().collect();
            for (index, author) in indexed_authors {
                for step in 0..4i64 {
                    let mut message = plain_at(&format!("{author}-{step}"), 1_700_000_000 + step);
                    // One author also stamps far ahead, the shape that used to
                    // buy immunity.
                    if index == 0 {
                        message.timestamp = UnixSecs::from(i64::MAX - step);
                    }
                    batch.push(Verified::fixture_unchecked(
                        message,
                        AuthorKey::decode_hex(&author.repeat(32)).expect("hex"),
                    ));
                }
            }
            batch
        };

        let mut forward = MessageLog::new(6);
        for message in build() {
            forward.push(message);
        }
        let mut backward = MessageLog::new(6);
        let mut reversed: Vec<Verified> = build();
        reversed.reverse();
        for message in reversed {
            backward.push(message);
        }

        let kept = |log: &MessageLog| -> HashSet<String> {
            let messages = &log.messages;
            let to_body = |message: &Verified| message.body.as_str().to_owned();
            let bodies = messages.iter().map(to_body);
            bodies.collect()
        };
        assert_eq!(
            kept(&forward),
            kept(&backward),
            "the retained set must be a function of the message set, not arrival order"
        );
    }

    #[test]
    fn message_log_evicts_lowest_key_when_full() {
        // Eviction drops the smallest eviction key (here: oldest timestamp),
        // not the front, so retention is independent of push order. Push the
        // newest first to prove arrival order doesn't decide who survives.
        let _guard = ::habilis_network_test_tracing::init();
        let mut log = MessageLog::new(2);
        log.push(msg_at("c", 30));
        log.push(msg_at("a", 10));
        log.push(msg_at("b", 20)); // over cap → evicts "a" (ts=10), the oldest
        assert_eq!(
            log.messages.len(),
            2,
            "the log keeps the two highest keys when full"
        );
        let bodies: HashSet<&str> = log
            .messages
            .iter()
            .map(|message| message.body.as_str())
            .collect();
        assert_eq!(
            bodies,
            HashSet::from(["b", "c"]),
            "kept the two newest by ts"
        );
    }

    mod prop {
        use proptest::{prop_assert, proptest};

        use super::{MessageLog, message};

        use crate::proptest_support;
        proptest! {
            #![proptest_config(proptest_support::config())]
            #[test]
            fn prop_message_log_never_exceeds_capacity(
                cap in 1..50usize,
                n_pushes in 0..200usize,
            ) {
                let _guard = ::habilis_network_test_tracing::init();
                let mut log = MessageLog::new(cap);
                for pushed in 0..n_pushes {
                    log.push(message(&format!("m{pushed}")));
                }
                prop_assert!(log.messages.len() <= cap);
                        }
        }
    }
}
