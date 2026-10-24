use std::collections::{HashMap, HashSet, VecDeque};

use crate::protocol::message::Verified;
use crate::protocol::message::sole_addressee;
use crate::protocol::{AuthorKey, DedupKey, Nickname, UnixSecs};

/// Where a message sits in the log's total order: its timestamp, then its id
/// key. Timestamps are whole seconds and a mesh puts hundreds of messages in one
/// second, so the timestamp alone cannot say which side of a window's edge a
/// message is on; the key breaks every tie.
pub(crate) type Bound = (UnixSecs, DedupKey);

/// The smallest bound that sorts after `bound`.
fn bound_after((timestamp, key): Bound) -> Bound {
    match u128::from_be_bytes(key.to_bytes()).checked_add(1) {
        Some(next) => (timestamp, DedupKey::from_bytes(next.to_be_bytes())),
        None => (timestamp + std::time::Duration::from_secs(1), DedupKey::MIN),
    }
}

/// One anti-entropy digest window: the inclusive `[lo, hi]` range of
/// [`Bound`]s it covers and the compact dedup keys the sender holds
/// in that range. The window is a contiguous slice of the log in bound order, so
/// the ids it lists are **every** message the sender holds in the range. A
/// receiver can then re-send only real gaps, and advertising a sub-window of a
/// large log never makes peers perpetually re-send what the sender already has.
pub(crate) struct DigestWindow {
    pub lo: Bound,
    pub hi: Bound,
    pub ids: Vec<DedupKey>,
    /// The window holds the first message of the log: nothing sorts before it.
    pub from_start: bool,
}

/// Inclusive `[lo, hi]` bounds to filter by — the shape shared by a
/// [`DigestWindow`] and a wire-decoded digest window entry (the anti-entropy
/// caller's own type), grouped so [`MessageLog::missing_in_window`] doesn't
/// need either concrete type by name.
#[derive(Clone, Copy)]
pub(crate) struct WindowRange {
    pub lo: Bound,
    pub hi: Bound,
}

/// A range of whole seconds: every message from second `lo` to second `hi`.
#[cfg(test)]
pub(crate) fn seconds(lo: UnixSecs, hi: UnixSecs) -> WindowRange {
    WindowRange {
        lo: (lo, DedupKey::MIN),
        hi: (hi, DedupKey::MAX),
    }
}

/// One gap query against the log: the window to search, the ids the requester
/// already advertised, the resend budget left for this round, and **who** is
/// asking — the last because entitlement is per-peer, not global (see
/// [`resendable_to`]).
#[derive(Clone, Copy)]
pub(crate) struct MissingQuery<'a> {
    pub range: WindowRange,
    pub have: &'a HashSet<DedupKey>,
    pub max: usize,
    pub requester: &'a Nickname,
}

/// A bounded buffer of the recent messages a member retains — the
/// anti-entropy recovery source and the poll/fetch history. Held in arrival
/// order (push order ≈ ascending timestamp) for the poll cursor and the
/// positional digest windows. When full, one message is discarded — *not* the
/// front — chosen so the **retained set** is a deterministic function of the
/// message set, identical on every node regardless of gossip delivery order
/// (see [`MessageLog::eviction_index`]).
#[derive(Debug)]
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
    pub fn push(&mut self, msg: Verified) -> Option<Verified> {
        // A frame that is already held is held once: two paths that retain the same frame
        // (an author that logs its own send and a consumer that pushes it too) cost a lookup.
        if !self.keys.insert(msg.dedup_key()) {
            return None;
        }
        *self.per_author.entry(msg.key()).or_default() += 1;
        self.messages.push_back(msg);
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
        let fullest = self
            .per_author
            .iter()
            .max_by(|(lhs_key, lhs_count), (rhs_key, rhs_count)| {
                lhs_count.cmp(rhs_count).then_with(|| rhs_key.cmp(lhs_key))
            })
            .map(|(author, _)| *author)
            .expect("over-capacity log is non-empty");
        self.messages
            .iter()
            .enumerate()
            .filter(|(_, msg)| msg.key() == fullest)
            .min_by(|(_, lhs), (_, rhs)| eviction_key(lhs).cmp(&eviction_key(rhs)))
            .map(|(index, _)| index)
            .expect("the fullest author holds at least one message")
    }

    pub(crate) fn contains(&self, key: &DedupKey) -> bool {
        self.keys.contains(key)
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
        group: &crate::protocol::ShardGroup,
        author: &AuthorKey,
        total: u32,
    ) -> Vec<Option<&'a Verified>> {
        let mut slots: Vec<Option<&Verified>> = vec![None; total as usize];
        for msg in &self.messages {
            let Some(shard) = &msg.shard else { continue };
            if shard.group == *group
                && shard.total == total
                && msg.key() == *author
                && let Some(slot) = slots.get_mut(shard.idx as usize)
                && slot.is_none()
            {
                *slot = Some(msg);
            }
        }
        slots
    }

    /// The keys of the log in bound order: the order windows are cut in. The log
    /// itself is in arrival order, which is not the same on every node, so a
    /// window cut from it would cover a different set on each.
    ///
    /// This sorts the whole log, and one digest calls it up to three times. At
    /// `MESSAGE_LOG_SIZE` entries every `ANTIENTROPY_INTERVAL` that costs
    /// nothing that matters. Look at it before a log a hundred times larger.
    fn bounds(&self) -> Vec<Bound> {
        let mut bounds: Vec<Bound> = self
            .messages
            .iter()
            .map(|msg| (msg.timestamp, msg.dedup_key()))
            .collect();
        bounds.sort_unstable();
        bounds
    }

    /// A contiguous window of the log in bound order: up to `max` messages
    /// starting at position `start`, bounded by the first and the last of them,
    /// so the ids it lists are every message the log holds in `[lo, hi]`. `None`
    /// if the log is empty or `start` is past the end.
    #[cfg(test)]
    pub(crate) fn window_at(&self, start: usize, max: usize) -> Option<DigestWindow> {
        Self::cut(&self.bounds(), start, max, false)
    }

    /// With `reach_back`, `lo` is the first bound after the message before the
    /// slice instead of the first message of the slice. Windows cut one after
    /// the other then tile the log. Without it, a message that the peer
    /// lacks and that sorts between two windows lies in neither range, and no
    /// digest ever asks for it.
    fn cut(bounds: &[Bound], start: usize, max: usize, reach_back: bool) -> Option<DigestWindow> {
        let slice = bounds.get(start..)?;
        let slice = &slice[..slice.len().min(max)];
        let mut lo = *slice.first()?;
        if reach_back && start > 0 {
            lo = bound_after(bounds[start - 1]);
        }
        Some(DigestWindow {
            lo,
            hi: *slice.last()?,
            ids: slice.iter().map(|(_, key)| *key).collect(),
            from_start: start == 0,
        })
    }

    /// How many of `bounds` are stamped at or before the local clock. A sender
    /// stamps its own messages and nothing bounds how far ahead, so a message
    /// stamped ahead of the clock sorts above every honest one. Those are
    /// left out of the newest window and reached by the sweep like the old
    /// ones. If every message is ahead, it is the local clock that is wrong,
    /// and all of them count.
    fn settled_len(bounds: &[Bound]) -> usize {
        let now = UnixSecs::now();
        match bounds.partition_point(|(timestamp, _)| *timestamp <= now) {
            0 => bounds.len(),
            settled => settled,
        }
    }

    /// The newest `recent` messages that the local clock allows, as a digest
    /// window: "I hold everything from `lo` onward except the gaps not in
    /// `ids`." This is what drives reconnect recovery: a peer that froze
    /// advertises it, and holders re-send every *newer* message it lacks. With
    /// no message stamped ahead of the clock, `hi` is past every message, so that
    /// a message newer than our own newest is covered. With one, `hi` stops at
    /// the clock, or the window would cover messages that it does not list.
    /// `None` only if the log is empty.
    pub(crate) fn recent_window(&self, recent: usize) -> Option<DigestWindow> {
        let bounds = self.bounds();
        let settled = Self::settled_len(&bounds);
        let mut window = Self::cut(&bounds, settled.saturating_sub(recent), recent, true)?;
        window.hi = if settled == bounds.len() {
            (UnixSecs::MAX, DedupKey::MAX)
        } else {
            (UnixSecs::now(), DedupKey::MAX)
        };
        Some(window)
    }

    /// Number of messages outside the newest window: the portion the rolling
    /// [`older_window`](Self::older_window) sweeps. It holds the old messages
    /// and the ones stamped ahead of the clock.
    pub(crate) fn older_len(&self, recent: usize) -> usize {
        let bounds = self.bounds();
        bounds.len() - Self::settled_len(&bounds).min(recent)
    }

    /// A rolling **closed** window over the older portion (everything outside
    /// the newest window): up to `max` ids starting at `start` *within*
    /// that portion, with exact `[lo, hi]` bounds so receivers reconcile
    /// deep interior gaps without re-sending the out-of-window remainder. A
    /// window never crosses the newest window: it stops where the newest begins.
    /// `None` when there is no older portion.
    pub(crate) fn older_window(
        &self,
        recent: usize,
        start: usize,
        max: usize,
    ) -> Option<DigestWindow> {
        let bounds = self.bounds();
        let settled = Self::settled_len(&bounds);
        let newest_start = settled.saturating_sub(recent);
        let older_len = bounds.len() - (settled - newest_start);
        if older_len == 0 {
            return None;
        }
        let start = start % older_len;
        if start < newest_start {
            Self::cut(&bounds, start, max.min(newest_start - start), true)
        } else {
            // The last window of the log is open-ended, as the newest is when
            // nothing is ahead of the clock: a message above the last one that we
            // hold is covered too.
            let first = settled + (start - newest_start);
            let mut window = Self::cut(&bounds, first, max, true)?;
            if first + window.ids.len() == bounds.len() {
                window.hi = (UnixSecs::MAX, DedupKey::MAX);
            }
            Some(window)
        }
    }

    /// Up to `max` of our messages (newest first) within the `[lo, hi]`
    /// window whose compact id is **not** in `have`, and which
    /// `requester` is entitled to — the in-window gap to re-send so a peer that
    /// advertised that window recovers what it missed. Out-of-window messages
    /// are never re-sent.
    pub(crate) fn missing_in_window(&self, query: MissingQuery<'_>) -> Vec<Verified> {
        let MissingQuery {
            range,
            have,
            max,
            requester,
        } = query;
        self.messages
            .iter()
            .rev()
            .filter(|msg| {
                let key = msg.dedup_key();
                let bound = (msg.timestamp, key);
                bound >= range.lo
                    && bound <= range.hi
                    && !have.contains(&key)
                    && resendable_to(msg, requester)
            })
            .take(max)
            .cloned()
            .collect()
    }
}

/// Whether `msg` is an anti-entropy subject **for `requester`**.
///
/// A frame with a sole addressee is unicast-only by construction (see
/// [`crate::transport::deliver`]) — gossip never carries it, so it is not a
/// subject of the gossip-wide anti-entropy plane either. Only its own addressee
/// is entitled to a re-send, and only when that addressee is the peer whose
/// digest advertised the gap. Everything else — broadcast content, presence —
/// is everyone's.
///
/// The gate belongs here rather than at the call site because the caller's
/// `.take(max)` spends a *shared* resend budget: a directed frame filtered
/// afterwards would still consume a slot and truncate the genuinely-missing
/// tail.
///
/// Note the advertise side ([`MessageLog::window_at`] and friends) deliberately
/// does **not** filter: a directed frame the addressee holds must keep
/// appearing in its digest ids, or the author would see it as perpetually
/// missing and re-send it every round forever.
fn resendable_to(msg: &Verified, requester: &Nickname) -> bool {
    sole_addressee(&msg.kind).is_none_or(|to| to == requester)
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
fn eviction_key(msg: &Verified) -> (UnixSecs, AuthorKey, Option<u64>, &str) {
    (msg.timestamp, msg.key(), msg.seq, msg.id.as_str())
}

#[cfg(test)]
mod tests {
    use habilis_network_test_tracing::test;
    use std::collections::HashSet;

    use super::{
        AuthorKey, DedupKey, MessageLog, MissingQuery, Nickname, UnixSecs, Verified, WindowRange,
    };
    use crate::protocol::Message;

    /// A whole-log gap query for `requester` with nothing already held — the
    /// shape every gate test wants.
    fn all_missing_for<'a>(
        have: &'a HashSet<DedupKey>,
        max: usize,
        requester: &'a Nickname,
    ) -> MissingQuery<'a> {
        MissingQuery {
            range: super::seconds(UnixSecs::ZERO, UnixSecs::MAX),
            have,
            max,
            requester,
        }
    }

    fn msg(id: &str) -> Verified {
        signed(plain(id))
    }

    /// One fixed author for the plain fixtures, so that they share a victim pool the way the
    /// unsigned messages of these tests always did. A signature is not what these tests check.
    fn signed(message: Message) -> Verified {
        Verified::fixture_unchecked(message, AuthorKey::from_bytes([0x11; 32]))
    }

    fn plain(id: &str) -> Message {
        Message::new_app(
            &crate::protocol::MeshId::from("test"),
            &Nickname::from("author"),
            crate::protocol::AppFrameParams {
                tag: crate::protocol::AppTag::from("app_msg"),
                to: None,
                corr: None,
                body: crate::protocol::MessageBody::from(id),
            },
        )
    }

    /// A log of `count` messages in an arrival order that is not timestamp
    /// order, spread over `seconds` distinct timestamps.
    fn shuffled_log(count: usize, seconds: usize) -> MessageLog {
        let mut log = MessageLog::new(1000);
        for index in 0..count {
            // 7 is coprime to every count used here, so this visits each
            // message once, in a scrambled order.
            let slot = (index * 7) % count;
            log.push(msg_at(
                &format!("m{slot}"),
                1_700_000_000 + i64::try_from(slot % seconds).expect("small"),
            ));
        }
        log
    }

    /// Every window a digest could send: the newest, and the older portion swept
    /// 70 ids at a time, as the cursor does across rounds.
    fn every_window(log: &MessageLog) -> Vec<super::DigestWindow> {
        let mut windows = vec![log.recent_window(70).expect("a non-empty log")];
        for start in (0..log.older_len(70)).step_by(70) {
            windows.extend(log.older_window(70, start, 70));
        }
        windows
    }

    /// A window's range must hold exactly the messages whose ids it lists: a
    /// message inside the range and not listed reads as a gap to every holder
    /// of the same log, and is re-sent to a node that already has it.
    fn assert_range_matches_ids(log: &MessageLog) {
        for window in every_window(log) {
            let listed: HashSet<DedupKey> = window.ids.iter().copied().collect();
            for message in &log.messages {
                if in_range(message, &window) {
                    assert!(
                        listed.contains(&message.dedup_key()),
                        "{:?} is inside [{:?}, {:?}] but not listed",
                        message.body.as_str(),
                        window.lo.0,
                        window.hi.0
                    );
                }
            }
        }
    }

    fn in_range(message: &Message, window: &super::DigestWindow) -> bool {
        let bound = (message.timestamp, message.dedup_key());
        bound >= window.lo && bound <= window.hi
    }

    #[test]
    fn a_window_lists_every_message_inside_its_range() {
        // 300 messages in 12 seconds: about 25 per second, scrambled.
        assert_range_matches_ids(&shuffled_log(300, 12));
    }

    #[test]
    fn a_second_with_more_messages_than_a_window_is_still_listed() {
        // The join burst: every message in one second, far past the 70 a window
        // lists.
        assert_range_matches_ids(&shuffled_log(300, 1));
    }

    /// The same frame pushed twice is held once, and the digest lists it once.
    #[test]
    fn a_frame_pushed_twice_is_held_once() {
        let mut log = MessageLog::new(10);
        let frame = msg_at("once", 10);
        assert!(log.push(frame.clone()).is_none());
        assert!(log.push(frame.clone()).is_none());
        assert_eq!(log.len(), 1);
        let window = log.window_at(0, 1).expect("one message");
        assert_eq!(window.ids, vec![frame.dedup_key()]);
    }

    /// A key leaves the index with its message: a frame that was evicted can be held again.
    /// `contains` is what the dedup gate reads for a retained frame, so it must say no the
    /// moment the log lets a frame go, or a re-send of an evicted frame is never processed.
    #[test]
    fn contains_follows_eviction() {
        let mut log = MessageLog::new(2);
        let first = msg("m1");
        let second = msg("m2");
        assert!(log.push(first.clone()).is_none());
        assert!(log.push(second.clone()).is_none());
        assert!(log.contains(&first.dedup_key()) && log.contains(&second.dedup_key()));
        let gone = log.push(msg("m3")).expect("a third frame evicts one");
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
        let mut log = MessageLog::new(1);
        assert!(log.push(msg_at("first", 10)).is_none());
        let evicted = log.push(msg_at("second", 20)).expect("the log is full");
        assert!(
            log.push(evicted).is_some(),
            "the evicted frame is new again, so the push evicts one of the two"
        );
        assert_eq!(log.len(), 1);
    }

    /// A message tagged with an explicit timestamp, for window tests.
    fn msg_at(body: &str, ts: i64) -> Verified {
        signed(plain_at(body, ts))
    }

    fn plain_at(body: &str, ts: i64) -> Message {
        let mut message = plain(body);
        message.timestamp = UnixSecs::from_secs(ts);
        message
    }

    /// A message directed at `to` — the frames that ride unicast only.
    fn msg_to(body: &str, ts: i64, to: &str) -> Verified {
        signed(plain_to(body, ts, to))
    }

    fn plain_to(body: &str, ts: i64, to: &str) -> Message {
        let mut message = Message::new_app(
            &crate::protocol::MeshId::from("test"),
            &Nickname::from("author"),
            crate::protocol::AppFrameParams {
                tag: crate::protocol::AppTag::from("app_msg"),
                to: Some(Nickname::from(to)),
                corr: None,
                body: crate::protocol::MessageBody::from(body),
            },
        );
        message.timestamp = UnixSecs::from_secs(ts);
        message
    }

    fn nick(name: &str) -> Nickname {
        Nickname::from(name)
    }

    /// Everything, for a requester with no directed frames in play.
    const ANYONE: &str = "requester";

    // ── windowed digest ────────────────────────────────────────────

    #[test]
    fn window_at_returns_slice_with_ts_bounds() {
        let mut log = MessageLog::new(10);
        for ts in [10, 20, 30, 40, 50] {
            log.push(msg_at(&ts.to_string(), ts));
        }
        // A middle slice of 2, starting at index 1 (ts=20).
        let window = log.window_at(1, 2).expect("non-empty window");
        assert_eq!((window.lo.0.as_secs(), window.hi.0.as_secs()), (20, 30));
        assert_eq!(window.ids.len(), 2);
        // A max wider than the log starting at 0 covers everything.
        let full = log.window_at(0, 100).expect("non-empty window");
        assert_eq!((full.lo.0.as_secs(), full.hi.0.as_secs()), (10, 50));
        assert_eq!(full.ids.len(), 5);
        // Past the end ⇒ None.
        assert!(log.window_at(5, 2).is_none());
    }

    /// The log keeps arrival order, and gossip does not deliver in timestamp
    /// order, so the slice a window covers is not sorted. Its bounds must
    /// still be the extent of what it lists: one early frame with a late
    /// stamp at the head of the slice must not become `lo` and hide every
    /// older gap from the peers that could fill it.
    #[test]
    fn window_bounds_are_the_extent_of_the_slice_not_its_ends() {
        // One copy of each frame, so both logs share ids. The holder has all
        // four; at the advertiser a late-stamped frame arrived first, then
        // the older ones, and the one at ts=20 never arrived at all.
        let frames: Vec<Verified> = [10, 20, 30, 50]
            .into_iter()
            .map(|ts| msg_at(&ts.to_string(), ts))
            .collect();
        let mut holder = MessageLog::new(10);
        for frame in &frames {
            holder.push(frame.clone());
        }
        let mut advertiser = MessageLog::new(10);
        for index in [3, 0, 2] {
            advertiser.push(frames[index].clone());
        }
        let window = advertiser.window_at(0, 10).expect("non-empty window");
        assert_eq!((window.lo.0.as_secs(), window.hi.0.as_secs()), (10, 50));

        // The holder answers that window with the gap.
        let have: HashSet<DedupKey> = window.ids.into_iter().collect();
        let gap = holder.missing_in_window(MissingQuery {
            range: WindowRange {
                lo: window.lo,
                hi: window.hi,
            },
            have: &have,
            max: 10,
            requester: &nick(ANYONE),
        });
        let bodies: Vec<&str> = gap.iter().map(|msg| msg.body.as_str()).collect();
        assert_eq!(bodies, ["20"]);
    }

    #[test]
    fn rolling_window_covers_whole_buffer() {
        // Sweeping the rolling cursor in `max`-sized steps must advertise
        // every id at least once over a full cycle — so a peer behind by
        // more than one window's worth still recovers across rounds.
        let mut log = MessageLog::new(50);
        for index in 0..50 {
            log.push(msg_at(&format!("m{index}"), 100 + index));
        }
        let max = 7;
        let len = log.len();
        let mut advertised: HashSet<DedupKey> = HashSet::new();
        let mut cursor = 0usize;
        // ceil(50/7) = 8 rounds covers the cycle; loop a little extra.
        for _ in 0..16 {
            let start = if max >= len { 0 } else { cursor % len };
            let window = log.window_at(start, max).expect("non-empty");
            advertised.extend(window.ids);
            cursor = if max >= len { 0 } else { (start + max) % len };
        }
        assert_eq!(advertised.len(), 50, "every buffered id advertised");
    }

    #[test]
    fn missing_in_window_excludes_out_of_window_and_have() {
        let mut log = MessageLog::new(10);
        for ts in [10, 20, 30, 40, 50] {
            log.push(msg_at(&ts.to_string(), ts));
        }
        // The receiver already has the ts=30 message.
        let have: HashSet<DedupKey> = log
            .window_at(2, 1)
            .expect("ts=30 window")
            .ids
            .into_iter()
            .collect();
        let gap = log.missing_in_window(MissingQuery {
            range: super::seconds(UnixSecs::from_secs(20), UnixSecs::from_secs(40)),
            have: &have,
            max: 10,
            requester: &nick(ANYONE),
        });
        let bodies: HashSet<&str> = gap.iter().map(|msg| msg.body.as_str()).collect();
        // ts 20 and 40 are in-window and missing; 30 is in `have`; 10 and 50
        // are out of window — never re-sent.
        assert_eq!(bodies, HashSet::from(["20", "40"]));
    }

    // ── the addressee gate ─────────────────────────────────────────

    #[test]
    fn directed_frame_is_never_offered_to_a_third_party() {
        let mut log = MessageLog::new(10);
        log.push(msg_at("public", 10));
        log.push(msg_to("private", 20, "bob"));
        let gap = log.missing_in_window(all_missing_for(&HashSet::new(), 10, &nick("carol")));
        let bodies: HashSet<&str> = gap.iter().map(|msg| msg.body.as_str()).collect();
        assert_eq!(
            bodies,
            HashSet::from(["public"]),
            "a bystander must never be offered a frame directed elsewhere"
        );
    }

    #[test]
    fn directed_frame_is_offered_to_its_own_addressee() {
        // The recovery property the gate must preserve: a small multipart body
        // has no repair path other than anti-entropy (see `repair_tickets`), so
        // dropping the addressee's own backfill would lose the message whole.
        let mut log = MessageLog::new(10);
        log.push(msg_at("public", 10));
        log.push(msg_to("private", 20, "bob"));
        let gap = log.missing_in_window(all_missing_for(&HashSet::new(), 10, &nick("bob")));
        let bodies: HashSet<&str> = gap.iter().map(|msg| msg.body.as_str()).collect();
        assert_eq!(bodies, HashSet::from(["public", "private"]));
    }

    #[test]
    fn directed_frame_does_not_consume_a_third_party_resend_budget() {
        // Why the gate lives inside the filter rather than at the call site:
        // iteration is newest-first and `max` is a shared budget, so a directed
        // frame filtered *after* the take would spend the only slot and starve
        // the broadcast the requester actually needs.
        let mut log = MessageLog::new(10);
        log.push(msg_at("public", 10));
        log.push(msg_to("private", 20, "bob")); // newest → seen first
        let gap = log.missing_in_window(all_missing_for(&HashSet::new(), 1, &nick("carol")));
        let bodies: Vec<&str> = gap.iter().map(|msg| msg.body.as_str()).collect();
        assert_eq!(bodies, vec!["public"], "the budget went to a usable frame");
    }

    #[test]
    fn digest_windows_still_advertise_directed_ids() {
        // The other half of the both-sides-agree invariant. If the advertise
        // side ever filtered too, the addressee would stop listing a directed
        // frame it holds, the author would read that as a permanent gap, and
        // every round would re-send it forever.
        let mut log = MessageLog::new(10);
        log.push(msg_at("public", 10));
        log.push(msg_to("private", 20, "bob"));
        assert_eq!(log.window_at(0, 10).expect("non-empty").ids.len(), 2);
        assert_eq!(log.recent_window(10).expect("non-empty").ids.len(), 2);
    }

    #[test]
    fn recent_window_is_open_ended_and_recovers_newer() {
        // The core reconnect-recovery property: a peer that only has the
        // older messages advertises an open-ended newest window, and a
        // holder must offer everything *newer* it lacks. A closed `hi` at
        // the requester's own newest would miss exactly those.
        let mut requester = MessageLog::new(100);
        let mut holder = MessageLog::new(100);
        let mut newer: HashSet<String> = HashSet::new();
        for ts in 1..=10i64 {
            let message = msg_at(&ts.to_string(), ts);
            holder.push(message.clone());
            if ts <= 5 {
                requester.push(message);
            } else {
                newer.insert(ts.to_string());
            }
        }
        let window = requester.recent_window(50).expect("non-empty");
        assert_eq!(
            window.hi.0,
            UnixSecs::MAX,
            "newest window must be open-ended"
        );
        let have: HashSet<DedupKey> = window.ids.into_iter().collect();
        let offered: HashSet<String> = holder
            .missing_in_window(MissingQuery {
                range: WindowRange {
                    lo: window.lo,
                    hi: window.hi,
                },
                have: &have,
                max: 100,
                requester: &nick(ANYONE),
            })
            .iter()
            .map(|msg| msg.body.as_str().to_string())
            .collect();
        assert_eq!(offered, newer, "holder offers exactly the newer messages");
    }

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
        let mut log = MessageLog::new(4);
        for index in 0..4 {
            let flood = Verified::fixture_unchecked(
                plain_at(&format!("flood{index}"), i64::MAX),
                AuthorKey::from_bytes([0xff; 32]),
            );
            log.push(flood);
        }
        let honest = Verified::fixture_unchecked(
            plain_at("honest", 1_700_000_000),
            AuthorKey::from_bytes([0xaa; 32]),
        );
        let evicted = log.push(honest);
        assert!(
            evicted.is_some_and(|msg| msg.body.as_str() != "honest"),
            "an honest message must not be evicted the moment it arrives"
        );
        let bodies: HashSet<&str> = log.messages.iter().map(|msg| msg.body.as_str()).collect();
        assert!(bodies.contains("honest"), "the honest message must survive");
    }

    /// The author counts are maintained incrementally rather than recounted,
    /// so the one way this can go wrong is the map drifting from the log it
    /// describes — silently picking the wrong victim, on every node, forever.
    #[test]
    fn the_author_counts_match_a_fresh_recount_after_churn() {
        use std::collections::HashMap;

        let mut log = MessageLog::new(8);
        // Three authors at different rates, well past capacity, so eviction
        // fires repeatedly and each author is both added and dropped.
        for step in 0..60i64 {
            let author = ["aa", "bb", "cc"][usize::try_from(step).expect("fits") % 3];
            let message = Verified::fixture_unchecked(
                plain_at(&format!("{author}-{step}"), 1_700_000_000 + step),
                AuthorKey::from_hex(&author.repeat(32)).expect("hex"),
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
        assert!(log.per_author.values().all(|count| *count > 0));
    }

    /// **Retention must not depend on arrival order**, across authors too.
    ///
    /// This is what lets anti-entropy converge: every node has to keep the same
    /// set, or peers reconcile toward the union of their own windows instead of
    /// one agreed set. Eviction reads only wire fields for exactly this reason,
    /// so any change to how the victim is chosen has to preserve it.
    #[test]
    fn retention_is_the_same_whatever_order_messages_arrive_in() {
        let authors = ["aa", "bb", "cc"];
        let build = || {
            let mut batch = Vec::new();
            for (index, author) in authors.iter().enumerate() {
                for step in 0..4i64 {
                    let mut message = plain_at(&format!("{author}-{step}"), 1_700_000_000 + step);
                    // One author also stamps far ahead, the shape that used to
                    // buy immunity.
                    if index == 0 {
                        message.timestamp = UnixSecs::from_secs(i64::MAX - step);
                    }
                    batch.push(Verified::fixture_unchecked(
                        message,
                        AuthorKey::from_hex(&author.repeat(32)).expect("hex"),
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
        for message in build().into_iter().rev() {
            backward.push(message);
        }

        let kept = |log: &MessageLog| -> HashSet<String> {
            log.messages
                .iter()
                .map(|msg| msg.body.as_str().to_owned())
                .collect()
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
        let mut log = MessageLog::new(2);
        log.push(msg_at("c", 30));
        log.push(msg_at("a", 10));
        log.push(msg_at("b", 20)); // over cap → evicts "a" (ts=10), the oldest
        assert_eq!(log.messages.len(), 2);
        let bodies: HashSet<&str> = log.messages.iter().map(|msg| msg.body.as_str()).collect();
        assert_eq!(
            bodies,
            HashSet::from(["b", "c"]),
            "kept the two newest by ts"
        );
    }

    mod prop {
        use habilis_network_test_tracing::test;
        use proptest::{prop_assert, proptest};

        use super::{MessageLog, msg};

        proptest! {
            #![proptest_config(crate::proptest_support::config())]
            #[test]
            fn prop_message_log_never_exceeds_capacity(
                cap in 1..50usize,
                n_pushes in 0..200usize,
            ) {
                let mut log = MessageLog::new(cap);
                for i in 0..n_pushes {
                    log.push(msg(&format!("m{i}")));
                }
                prop_assert!(log.messages.len() <= cap);
            }
        }
    }
}
