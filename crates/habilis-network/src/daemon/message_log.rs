use std::collections::{HashMap, HashSet, VecDeque};

use crate::protocol::message::sole_addressee;
use crate::protocol::{Message, Nickname};

/// One anti-entropy digest window: the inclusive `[lo, hi]` timestamp
/// range it covers and the compact (raw 16-byte UUID) ids the sender holds
/// in that range. The bounds let a receiver re-send only **in-window** gaps,
/// so advertising a sub-window of a large log never makes peers perpetually
/// re-send the out-of-window remainder.
pub(crate) struct DigestWindow {
    pub lo: i64,
    pub hi: i64,
    pub ids: Vec<[u8; 16]>,
}

/// Inclusive `[lo, hi]` timestamp bounds to filter by — the shape shared by a
/// [`DigestWindow`] and a wire-decoded digest window entry (the anti-entropy
/// caller's own type), grouped so [`MessageLog::missing_in_window`] doesn't
/// need either concrete type by name.
#[derive(Clone, Copy)]
pub(crate) struct WindowRange {
    pub lo: i64,
    pub hi: i64,
}

/// One gap query against the log: the window to search, the ids the requester
/// already advertised, the resend budget left for this round, and **who** is
/// asking — the last because entitlement is per-peer, not global (see
/// [`resendable_to`]).
#[derive(Clone, Copy)]
pub(crate) struct MissingQuery<'a> {
    pub range: WindowRange,
    pub have: &'a HashSet<[u8; 16]>,
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
    messages: VecDeque<Message>,
    /// How many messages each author currently holds.
    ///
    /// Maintained on every push and eviction rather than rebuilt, because
    /// [`Self::eviction_index`] needs it on nearly every steady-state message:
    /// at capacity it was hashing a thousand base58 pubkeys to recount what two
    /// counter updates already know. The map is the *only* derived state here,
    /// and both mutation sites are in [`Self::push`], so it cannot drift.
    per_author: HashMap<String, usize>,
}

impl MessageLog {
    pub(crate) fn new(capacity: usize) -> Self {
        MessageLog {
            capacity,
            messages: VecDeque::with_capacity(capacity),
            per_author: HashMap::new(),
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
    /// callers prune side indexes keyed by it (the DAG `by_hash`, fork map).
    pub fn push(&mut self, msg: Message) -> Option<Message> {
        *self.per_author.entry(msg.pubkey.clone()).or_default() += 1;
        self.messages.push_back(msg);
        if self.messages.len() <= self.capacity {
            return None;
        }
        let victim = self.eviction_index();
        let evicted = self.messages.remove(victim);
        if let Some(gone) = &evicted
            && let Some(held) = self.per_author.get_mut(&gone.pubkey)
        {
            *held -= 1;
            // No zero entries: one would win the lowest-pubkey tie-break in
            // `eviction_index` while holding nothing to evict.
            if *held == 0 {
                self.per_author.remove(&gone.pubkey);
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
    /// Still a pure function of the message set — the counts, the pubkey
    /// tie-break and the key comparison all read wire fields, never arrival
    /// order — so peers agree on the retained set, which is what lets
    /// anti-entropy converge on one set rather than a union of windows.
    ///
    /// Not a Sybil defence: pubkeys are free, so N identities hold N shares.
    /// It removes the case where one identity costs everyone their history.
    fn eviction_index(&self) -> usize {
        // Ties go to the lowest pubkey, so the choice is total and identical
        // on every node.
        let fullest = self
            .per_author
            .iter()
            .max_by(|(lhs_key, lhs_count), (rhs_key, rhs_count)| {
                lhs_count.cmp(rhs_count).then_with(|| rhs_key.cmp(lhs_key))
            })
            .map(|(pubkey, _)| pubkey.as_str())
            .expect("over-capacity log is non-empty");
        self.messages
            .iter()
            .enumerate()
            .filter(|(_, msg)| msg.pubkey.as_str() == fullest)
            .min_by(|(_, lhs), (_, rhs)| eviction_key(lhs).cmp(&eviction_key(rhs)))
            .map(|(index, _)| index)
            .expect("the fullest author holds at least one message")
    }

    pub(crate) fn len(&self) -> usize {
        self.messages.len()
    }

    /// The retained shards of multipart `group` authored by `pubkey`, slotted by
    /// `idx` (first-seen wins per idx); `total` slots, each `None` until its shard
    /// arrives. Keying on `pubkey` as well as `group` is the security boundary: a
    /// peer can only sign shards under its own key, so a crafted shard carrying
    /// someone else's `group` forms a separate, never-completing set and can't
    /// inject a slice into the victim's body. Only **small** (logged) groups ever
    /// reach this — `total` is bounded by `LOGGED_SHARD_GROUP_MAX_TOTAL` at the
    /// call site, so the `total`-sized allocation is safe.
    pub(crate) fn collect_shards<'a>(
        &'a self,
        group: &crate::protocol::ShardGroup,
        pubkey: &str,
        total: u32,
    ) -> Vec<Option<&'a Message>> {
        let mut slots: Vec<Option<&Message>> = vec![None; total as usize];
        for msg in &self.messages {
            let Some(shard) = &msg.shard else { continue };
            if shard.group == *group
                && shard.total == total
                && msg.pubkey == pubkey
                && let Some(slot) = slots.get_mut(shard.idx as usize)
                && slot.is_none()
            {
                *slot = Some(msg);
            }
        }
        slots
    }

    /// A contiguous window of the log: up to `max` messages starting at
    /// index `start`, with their inclusive `[lo, hi]` timestamp bounds and
    /// compact ids. `None` if the log is empty or `start` is past the end.
    pub(crate) fn window_at(&self, start: usize, max: usize) -> Option<DigestWindow> {
        let slice: Vec<&Message> = self.messages.iter().skip(start).take(max).collect();
        // The extent of the slice, not its ends: the log is in arrival order,
        // which is not timestamp order, so the first and last entries bound
        // nothing. A bound that excludes an id the window lists makes every
        // holder answer "nothing missing" for the gap around it.
        let lo = slice.iter().map(|msg| msg.timestamp).min()?;
        let hi = slice.iter().map(|msg| msg.timestamp).max()?;
        let ids = slice.iter().map(|msg| msg.dedup_key()).collect();
        Some(DigestWindow { lo, hi, ids })
    }

    /// The newest `recent` messages as an **open-ended** digest window
    /// (`hi = i64::MAX`): "I hold everything from `lo` onward except the
    /// gaps not in `ids`." This is what drives reconnect recovery — a peer
    /// that froze advertises it, and holders re-send every *newer* message
    /// it lacks (a closed `hi` would never cover messages past the sender's
    /// own newest). `None` only if the log is empty.
    pub(crate) fn recent_window(&self, recent: usize) -> Option<DigestWindow> {
        let start = self.len().saturating_sub(recent);
        let mut window = self.window_at(start, recent)?;
        window.hi = i64::MAX;
        Some(window)
    }

    /// Number of messages older than the newest `recent` — the portion the
    /// rolling [`older_window`](Self::older_window) sweeps.
    pub(crate) fn older_len(&self, recent: usize) -> usize {
        self.len().saturating_sub(recent)
    }

    /// A rolling **closed** window over the older portion (everything before
    /// the newest `recent`): up to `max` ids starting at `start` *within*
    /// that portion, with exact `[lo, hi]` bounds so receivers reconcile
    /// deep interior gaps without re-sending the out-of-window remainder.
    /// `None` when there is no older portion (`len <= recent`).
    pub(crate) fn older_window(
        &self,
        recent: usize,
        start: usize,
        max: usize,
    ) -> Option<DigestWindow> {
        let older_len = self.older_len(recent);
        if older_len == 0 {
            return None;
        }
        let start = start % older_len;
        let count = max.min(older_len - start);
        self.window_at(start, count)
    }

    /// Up to `max` of our messages (newest first) within the `[lo, hi]`
    /// timestamp window whose compact id is **not** in `have`, and which
    /// `requester` is entitled to — the in-window gap to re-send so a peer that
    /// advertised that window recovers what it missed. Out-of-window messages
    /// are never re-sent.
    pub(crate) fn missing_in_window(&self, query: MissingQuery<'_>) -> Vec<Message> {
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
                msg.timestamp >= range.lo
                    && msg.timestamp <= range.hi
                    && !have.contains(&msg.dedup_key())
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
fn resendable_to(msg: &Message, requester: &Nickname) -> bool {
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
fn eviction_key(msg: &Message) -> (i64, &str, Option<u64>, &str) {
    (msg.timestamp, msg.pubkey.as_str(), msg.seq, msg.id.as_str())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{Message, MessageLog, MissingQuery, Nickname, WindowRange};

    /// A whole-log gap query for `requester` with nothing already held — the
    /// shape every gate test wants.
    fn all_missing_for<'a>(
        have: &'a HashSet<[u8; 16]>,
        max: usize,
        requester: &'a Nickname,
    ) -> MissingQuery<'a> {
        MissingQuery {
            range: WindowRange {
                lo: 0,
                hi: i64::MAX,
            },
            have,
            max,
            requester,
        }
    }

    fn msg(id: &str) -> Message {
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

    /// A message tagged with an explicit timestamp, for window tests.
    fn msg_at(body: &str, ts: i64) -> Message {
        let mut message = msg(body);
        message.timestamp = ts;
        message
    }

    /// A message directed at `to` — the frames that ride unicast only.
    fn msg_to(body: &str, ts: i64, to: &str) -> Message {
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
        message.timestamp = ts;
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
        assert_eq!((window.lo, window.hi), (20, 30));
        assert_eq!(window.ids.len(), 2);
        // A max wider than the log starting at 0 covers everything.
        let full = log.window_at(0, 100).expect("non-empty window");
        assert_eq!((full.lo, full.hi), (10, 50));
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
        let frames: Vec<Message> = [10, 20, 30, 50]
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
        assert_eq!((window.lo, window.hi), (10, 50));

        // The holder answers that window with the gap.
        let have: HashSet<[u8; 16]> = window.ids.into_iter().collect();
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
        let mut advertised: HashSet<[u8; 16]> = HashSet::new();
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
        let have: HashSet<[u8; 16]> = log
            .window_at(2, 1)
            .expect("ts=30 window")
            .ids
            .into_iter()
            .collect();
        let gap = log.missing_in_window(MissingQuery {
            range: WindowRange { lo: 20, hi: 40 },
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
        assert_eq!(window.hi, i64::MAX, "newest window must be open-ended");
        let have: HashSet<[u8; 16]> = window.ids.into_iter().collect();
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
            let mut flood = msg_at(&format!("flood{index}"), i64::MAX);
            flood.pubkey = "ff".repeat(32);
            log.push(flood);
        }
        let mut honest = msg_at("honest", 1_700_000_000);
        honest.pubkey = "aa".repeat(32);
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
            let mut message = msg_at(&format!("{author}-{step}"), 1_700_000_000 + step);
            message.pubkey = author.repeat(32);
            log.push(message);

            let mut recounted: HashMap<&str, usize> = HashMap::new();
            for held in &log.messages {
                *recounted.entry(held.pubkey.as_str()).or_default() += 1;
            }
            let maintained: HashMap<&str, usize> = log
                .per_author
                .iter()
                .map(|(key, count)| (key.as_str(), *count))
                .collect();
            assert_eq!(maintained, recounted, "counts drifted at step {step}");
        }
        // A dropped author leaves no zero entry behind, or it would win the
        // lowest-pubkey tie-break while holding nothing.
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
                    let mut message = msg_at(&format!("{author}-{step}"), 1_700_000_000 + step);
                    message.pubkey = author.repeat(32);
                    // One author also stamps far ahead, the shape that used to
                    // buy immunity.
                    if index == 0 {
                        message.timestamp = i64::MAX - step;
                    }
                    batch.push(message);
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
