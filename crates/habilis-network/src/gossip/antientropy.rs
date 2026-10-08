//! Anti-entropy: periodic digest broadcast + gap-fill resend. Recovers
//! messages a node missed while partitioned/asleep/just-joined.
//!
//! The digest advertises a **window** of the message log: an inclusive
//! `[lo, hi]` timestamp range plus the compact ids the sender holds in it
//! (raw 16-byte UUIDs, Base58-packed, so ~10× more fit one gossip message
//! than the old 36-char strings). A log larger than one window is swept
//! across rounds via a rolling cursor; the `[lo, hi]` bounds let a receiver
//! re-send only **in-window** gaps, so advertising a sub-window never makes
//! peers perpetually re-broadcast the out-of-window remainder.
//!
//! A chat resend rides the same plane the original send chose: broadcast
//! content goes back on gossip, and a directed frame goes point-to-point to
//! its addressee — never to the peer that merely asked. Both follow from
//! routing every chat resend through [`crate::transport::resolve`], the
//! decision of [`crate::transport::deliver`]. Only a few members answer a
//! digest ([`answers_digest`]), and the event loop only queues the answer: a
//! task sends it (see `transport::outbox`). A state
//! or meta answer is the exception: it goes point-to-point to the linked
//! neighbor that asked, see [`handle_state_digest`].

use std::collections::{HashMap, HashSet};
use std::hash::{Hash as _, Hasher as _};
use std::time::Duration;

use crate::transport::MeshSender;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::daemon::ctx::HandlerCtx;
use crate::daemon::message_log::{DigestWindow, KEY_MIN, MissingQuery, WindowRange};
use crate::daemon::state::EventLoopState;
use crate::protocol::{Channel, MeshId, Message, Nickname};
use crate::util::clock::Instant;
use crate::util::tuning::{
    ANTIENTROPY_ANSWERERS, ANTIENTROPY_DIGEST_WINDOW_IDS, ANTIENTROPY_SERVE_COOLDOWN_SECS,
    ANTIENTROPY_SERVES_PER_WINDOW, FAST_ROUND_ACTIVE_MS, FAST_ROUND_AHEAD_MAX,
    FAST_ROUND_AHEAD_TTL_SECS, FAST_ROUND_MIN_INTERVAL_MS, FAST_ROUND_RETRY_MS,
    antientropy_max_resend,
};

use super::broadcast_msg;

/// One window on the wire: its `[lo, hi]` bounds (`hi` timestamp `i64::MAX` ⇒
/// open-ended), each a timestamp and the id key of the message at that edge, plus
/// its ids packed as raw 16-byte UUIDs, Base58-encoded. The key is what lets an
/// edge fall inside a second that holds more messages than a window lists.
#[derive(Serialize, Deserialize)]
struct WireWindow {
    lo: i64,
    lo_key: String,
    hi: i64,
    hi_key: String,
    ids: String,
}

fn encode_key(key: &[u8; 16]) -> String {
    bs58::encode(key).into_string()
}

fn decode_key(text: &str) -> Option<[u8; 16]> {
    bs58::decode(text).into_vec().ok()?.try_into().ok()
}

impl WireWindow {
    fn encode(window: &DigestWindow) -> Self {
        let mut packed = Vec::with_capacity(window.ids.len() * 16);
        for id in &window.ids {
            packed.extend_from_slice(id);
        }
        WireWindow {
            lo: window.lo.0,
            lo_key: encode_key(&window.lo.1),
            hi: window.hi.0,
            hi_key: encode_key(&window.hi.1),
            ids: bs58::encode(packed).into_string(),
        }
    }

    /// The window's bounds, or `None` if a key is malformed.
    fn range(&self) -> Option<WindowRange> {
        Some(WindowRange {
            lo: (self.lo, decode_key(&self.lo_key)?),
            hi: (self.hi, decode_key(&self.hi_key)?),
        })
    }

    /// Decode the packed ids into a set, or `None` if the Base58 / length
    /// is malformed.
    fn decode_ids(&self) -> Option<HashSet<[u8; 16]>> {
        let raw = bs58::decode(&self.ids).into_vec().ok()?;
        if raw.len() % 16 != 0 {
            return None;
        }
        Some(
            raw.chunks_exact(16)
                .map(|chunk| {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(chunk);
                    id
                })
                .collect(),
        )
    }
}

/// The on-the-wire digest body: up to two windows (open-ended newest +
/// rolling closed older).
#[derive(Serialize, Deserialize)]
struct DigestBody {
    windows: Vec<WireWindow>,
}

/// The state/meta anti-entropy digest body: this channel's automerge heads
/// (Base58 change hashes). Heads compactly represent the whole causal frontier,
/// so a holder computes exactly what the sender is missing in one step — no
/// windowing. Replaces the windowed [`DigestBody`] for these two channels.
///
/// `closing` marks the heads that end a point-to-point answer: information on
/// how far the holder is, not a request. Left out when false, so a request's
/// bytes and its heads key are what they always were.
#[derive(Serialize, Deserialize)]
struct HeadsBody {
    heads: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    closing: bool,
}

/// Broadcast an anti-entropy digest: an **open-ended newest** window (so
/// holders re-send every newer message we lack — reconnect recovery) plus,
/// when the log is larger than one window, a rolling **closed** older
/// window (deep interior reconcile, swept across rounds via
/// `digest_cursor`). A node that missed messages while
/// partitioned/asleep/just-joined recovers. Like `PeerInfo`, never logged.
pub(crate) async fn broadcast_digest(
    state: &mut EventLoopState,
    sender: &MeshSender,
    mesh: &MeshId,
    author: &Nickname,
) {
    // No real peer has ever linked — a digest would broadcast into the
    // void (mirrors `tick_heal`/`tick_alive` no-peer guards).
    if !state.meshed {
        return;
    }
    let Some(windows) = digest_windows(state) else {
        return; // empty log
    };
    let total_ids: usize = windows.iter().map(|window| window.ids.len()).sum();
    let Some(body) = super::json_body(&DigestBody { windows }) else {
        return;
    };
    tracing::trace!(ids = total_ids, "anti-entropy digest broadcast");
    state.idle.broadcasts += 1;
    broadcast_msg(
        sender,
        &Message::new_digest(mesh, author, body).signed(&state.identity),
    )
    .await;
}

/// The windows a digest advertises: the newest, plus the next slice of the
/// rolling older one when the log outgrows a window. `None` on an empty log.
fn digest_windows(state: &mut EventLoopState) -> Option<Vec<WireWindow>> {
    let recent = ANTIENTROPY_DIGEST_WINDOW_IDS;
    let mut newest = state.message_log.recent_window(recent)?;
    let older_len = state.message_log.older_len(recent);
    // The window that holds our oldest message reaches back to the moment we
    // joined: a node alone at start logs nothing until a link forms, and
    // without this floor what the mesh said before that was never asked for.
    // Nothing older than `joined_at` is ever surfaced, so asking from there
    // costs no budget on history. The floor takes in the whole second of the
    // earlier of the two: a message of that second with a smaller id key than
    // the first one we hold sorts before it, and is in range.
    let floor = |window: &mut DigestWindow| {
        window.lo = (state.joined_at.min(window.lo.0), KEY_MIN);
    };
    if newest.from_start {
        floor(&mut newest);
    }
    let mut windows = vec![WireWindow::encode(&newest)];

    if older_len == 0 {
        state.digest_cursor = 0;
    } else {
        let start = state.digest_cursor % older_len;
        if let Some(mut older) = state.message_log.older_window(recent, start, recent) {
            if older.from_start {
                floor(&mut older);
            }
            state.digest_cursor = (start + older.ids.len()) % older_len;
            windows.push(WireWindow::encode(&older));
        }
    }
    Some(windows)
}

/// Say once per author that its digest could not be read. A build with another
/// window format sends one every round, and the two builds never repair each
/// other's gaps: without this line nothing tells the user why.
fn report_unreadable_digest(message: &Message, state: &mut EventLoopState) {
    if state.report_unreadable_digest(&message.pubkey, Instant::now()) {
        tracing::warn!(
            target: "habilis_network::gossip",
            author = %message.author,
            "digest from this peer could not be read: its window format differs, so \
             it and this node do not repair each other's gaps"
        );
    }
}

/// Handle a received anti-entropy digest: for each advertised window, re-send
/// our logged messages the sender lacks **within that window** (open-ended
/// newest ⇒ everything newer; closed older ⇒ that slice only), newest-first, up
/// to `antientropy_max_resend()` total. Receivers that already have them drop
/// the repeat (dedup); the sender (and anyone else who missed them) recovers.
/// Never logged.
///
/// Each resend is routed by [`crate::transport::resolve`] rather than sent
/// straight onto gossip, so it takes the plane its addressing dictates — the same
/// decision the original send made. Paired with `missing_in_window`'s own
/// addressee gate, a directed frame is re-sent point-to-point to its addressee
/// and to nobody else, so backfill can't put on the gossip flood what the send
/// path structurally kept off it.
///
/// The windows' `have` sets are **unioned** before the diff (as in
/// [`handle_state_digest`]): the open-ended newest (`[lo, MAX]`) and closed
/// older (`[lo, hi]`) windows' ranges overlap at one-second-equal timestamps,
/// so a per-window `have` would re-send a message the sender holds but listed
/// under the *other* window — wasting the shared resend budget on messages the
/// peer already has and starving the genuinely-missing tail.
pub(crate) fn handle_digest(message: &Message, state: &mut EventLoopState, me: &Nickname) {
    let Ok(body) = serde_json::from_str::<DigestBody>(message.body.as_str()) else {
        report_unreadable_digest(message, state);
        return;
    };
    // Only a few members answer one digest (see `answers_digest`).
    let members = state.peers.iter().chain(std::iter::once(me));
    if !answers_digest(me, &message.author, message.id.as_str(), members) {
        return;
    }
    // One serve per author per window. Answering costs up to
    // `ANTIENTROPY_MAX_RESEND` mesh-wide broadcasts, so ungated this turns one
    // small frame into that much flooding from every member that hears it —
    // the cost scaling with the mesh rather than with the sender.
    if !state.admit_digest(&message.pubkey, Instant::now()) {
        tracing::debug!(
            target: "habilis_network::gossip",
            author = %message.author,
            "digest ignored: this peer was served within the window"
        );
        return;
    }
    let mut have: HashSet<[u8; 16]> = HashSet::new();
    for window in &body.windows {
        if let Some(ids) = window.decode_ids() {
            have.extend(ids);
        }
    }
    let mut budget = antientropy_max_resend();
    let mut resent = 0usize;
    for window in &body.windows {
        if budget == 0 {
            break;
        }
        let Some(range) = window.range() else {
            report_unreadable_digest(message, state);
            continue;
        };
        for msg in state.message_log.missing_in_window(MissingQuery {
            range,
            have: &have,
            max: budget,
            requester: &message.author,
        }) {
            if !resend_one(&msg, state) {
                continue;
            }
            // Mark it sent so the next (overlapping) window doesn't re-send it
            // and waste budget — equal-timestamp ranges overlap heavily.
            // Charged even when the send failed: an addressee with no endpoint
            // yet must not be retried inside this digest; it retries next round.
            have.insert(msg.dedup_key());
            resent += 1;
            budget -= 1;
        }
    }
    if resent > 0 {
        tracing::debug!(resent, "anti-entropy: resent messages a peer was missing");
    }
}

/// Queue one message on the plane its addressing dictates, for the task that
/// drains the outbox. Never waits. Returns whether it was attempted at all —
/// `false` only for the unserializable frame we somehow hold, which must not be
/// charged to the round's budget.
fn resend_one(msg: &Message, state: &mut EventLoopState) -> bool {
    let Ok(bytes) = msg.serialize() else {
        return false;
    };
    match crate::transport::resolve(msg, Bytes::from(bytes), state) {
        Ok(resend) => {
            if state.resend_outbox.offer(resend) {
                state.idle.resent += 1;
            } else {
                state.idle.resend_dropped += 1;
            }
        }
        Err(error) => {
            tracing::debug!(target: "habilis_network::gossip", %error, "anti-entropy resend failed");
        }
    }
    true
}

/// A member's place in the line for one digest: lower answers first.
///
/// A hash of the digest id and the member, so it is the same on every member
/// that knows both, with no message to agree on it, and it changes with each
/// digest. SHA-256 and not `DefaultHasher`, whose output may differ between
/// builds: members on different builds would then pick different answerers.
fn answer_rank(digest_id: &str, member: &Nickname) -> (u64, String) {
    use sha2::{Digest as _, Sha256};

    let hash = Sha256::new()
        .chain_update(digest_id.as_bytes())
        .chain_update([0])
        .chain_update(member.as_str().as_bytes())
        .finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&hash[..8]);
    // The name breaks a tie, so the order is total.
    (u64::from_be_bytes(head), member.as_str().to_owned())
}

/// Whether `me` is one of the [`ANTIENTROPY_ANSWERERS`] members that answer this
/// digest: the first of the members in the order of [`answer_rank`], the asker
/// left out.
///
/// Every member that holds what the asker lacks used to answer, and all but the
/// first copy of each message were waste. A uniform rule that needs no talk
/// between members: each one hashes the digest id with every member name and
/// answers when it is among the lowest. Members that know slightly different
/// rosters can pick slightly different sets, and that costs a duplicate or a
/// missing answer, which the next digest repairs: a new digest id picks again.
pub(crate) fn answers_digest<'a>(
    me: &Nickname,
    asker: &Nickname,
    digest_id: &str,
    members: impl Iterator<Item = &'a Nickname>,
) -> bool {
    let mine = answer_rank(digest_id, me);
    let ahead = members
        .filter(|member| *member != asker && *member != me)
        .filter(|member| answer_rank(digest_id, member) < mine)
        .count();
    ahead < ANTIENTROPY_ANSWERERS
}

/// Sweep both shared-state channels' anti-entropy digests (one tick).
///
/// Each digest advertises the channel's automerge heads — see
/// [`HeadsBody`] and [`handle_state_digest`]. Broadcast whenever the overlay
/// is reachable (see [`state_digest`]), even on an empty document, so a fresh
/// joiner advertises its empty frontier and gets backfilled.
pub(crate) async fn broadcast_state_digests(
    state: &mut EventLoopState,
    sender: &MeshSender,
    mesh: &MeshId,
    author: &Nickname,
    trigger: DigestTrigger,
) {
    let origin = DigestOrigin { mesh, author };
    broadcast_state_digest(state, sender, origin, Channel::State, trigger).await;
    broadcast_state_digest(state, sender, origin, Channel::Meta, trigger).await;
}

/// What sends a state digest. The tick is the fallback of a stalled fast
/// round, so it goes out even while one runs; a digest that an event sends
/// (a new peer, the first real-peer link) waits for the round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestTrigger {
    Event,
    Tick,
}

#[derive(Clone, Copy)]
struct DigestOrigin<'a> {
    mesh: &'a MeshId,
    author: &'a Nickname,
}

async fn broadcast_state_digest(
    state: &mut EventLoopState,
    sender: &MeshSender,
    origin: DigestOrigin<'_>,
    channel: Channel,
    trigger: DigestTrigger,
) {
    let now = Instant::now();
    if trigger == DigestTrigger::Event
        && (state.fast_rounds.active(channel, now)
            || state.fast_rounds.changed_recently(channel, now))
    {
        return;
    }
    let Some(digest) = state_digest(state, origin, channel) else {
        return;
    };
    state.idle.broadcasts += 1;
    tracing::debug!(me = %origin.author, ?channel, heads = heads_key(&digest), ?trigger, "broadcast a state digest on gossip");
    broadcast_msg(sender, &digest).await;
}

/// The signed heads digest for `channel`, or `None` while no gossip path can
/// carry it. Unlike the chat digest this does not wait for `meshed`: a node
/// whose only neighbor is the rendezvous relay still exchanges presence over
/// that link, so its documents must travel the same way. Gating on `meshed`
/// left two peers behind one relay with converged rosters and documents that
/// never met — a card published before anyone joined sat unadvertised until a
/// real-peer link happened to form, minutes later or never.
fn state_digest(
    state: &EventLoopState,
    origin: DigestOrigin<'_>,
    channel: Channel,
) -> Option<Message> {
    heads_digest(state, origin, channel, false)
}

/// Our heads for `channel` as a digest frame, a request or, with `closing`,
/// the end of an answer.
fn heads_digest(
    state: &EventLoopState,
    origin: DigestOrigin<'_>,
    channel: Channel,
    closing: bool,
) -> Option<Message> {
    if !state.overlay_reachable() {
        return None;
    }
    let heads = state.doc(channel).heads();
    let body = super::json_body(&HeadsBody { heads, closing })?;
    Some(
        Message::new_channel_digest(origin.mesh, origin.author, body, channel)
            .signed(&state.identity),
    )
}

/// The state digest answers served in the current window, per asker, channel
/// and plane: at most [`ANTIENTROPY_SERVES_PER_WINDOW`] on the unicast plane,
/// one on gossip. On unicast the same heads are answered again only after
/// [`FAST_ROUND_MIN_INTERVAL_MS`], so a burst of one asker's digests draws one
/// answer and a lost answer can still be asked for again. A serve is counted
/// when the answer is handed to the pool, not when it is delivered, so a batch
/// that fails costs one serve, and the asker's next ask is answered. The
/// heads alone cannot be the gate: the holder does not check them, so a
/// digest with made-up heads would be new every time.
#[derive(Debug, Default)]
pub(crate) struct ServeBudget {
    windows: HashMap<(String, Channel, Plane), Served>,
}

#[derive(Debug)]
struct Served {
    since: Instant,
    answers: usize,
    /// When each heads was last answered.
    heads: HashMap<u64, Instant>,
}

impl ServeBudget {
    const WINDOW: Duration = Duration::from_secs(ANTIENTROPY_SERVE_COOLDOWN_SECS);
    /// The same heads are answered again after this on the unicast plane: the
    /// asker repeats them when an answer was lost.
    const REPEAT: Duration = Duration::from_millis(FAST_ROUND_MIN_INTERVAL_MS);

    /// Fast rounds run point-to-point only, so only the unicast plane needs
    /// more than one answer per window.
    fn limit(plane: Plane) -> usize {
        match plane {
            Plane::Unicast => ANTIENTROPY_SERVES_PER_WINDOW,
            Plane::Gossip => 1,
        }
    }

    /// Whether an answer to these heads may go out now.
    pub(crate) fn admits(&self, key: &(String, Channel, Plane), heads: u64, now: Instant) -> bool {
        match self.windows.get(key) {
            Some(served) if now.duration_since(served.since) < Self::WINDOW => {
                let repeat_too_soon = served.heads.get(&heads).is_some_and(|at| {
                    key.2 == Plane::Gossip || now.duration_since(*at) < Self::REPEAT
                });
                !repeat_too_soon && served.answers < Self::limit(key.2)
            }
            _ => true,
        }
    }

    /// Record an answer to these heads, dropping windows that have ended.
    pub(crate) fn note(&mut self, key: (String, Channel, Plane), heads: u64, now: Instant) {
        self.windows
            .retain(|_, served| now.duration_since(served.since) < Self::WINDOW);
        let served = self.windows.entry(key).or_insert_with(|| Served {
            since: now,
            answers: 0,
            heads: HashMap::new(),
        });
        served.answers += 1;
        served.heads.insert(heads, now);
    }
}

/// The running fast round of one channel: the peer we ask, when we last
/// asked, and our heads and change count at that ask.
#[derive(Debug)]
struct Round {
    peer: String,
    at: Instant,
    heads: u64,
    changes: usize,
}

/// A peer whose heads showed it is ahead of us.
#[derive(Debug, Clone)]
struct Waiting {
    pubkey: String,
    author: Nickname,
    heads: Vec<String>,
    noted: Instant,
}

/// This node's fast rounds: when a linked neighbor's digest shows heads we do
/// not hold, we ask that neighbor directly, and its answer ends with its heads,
/// so we ask again until we hold them. The tick asked once per interval, and
/// an answer carries one resend budget, so a long history took one tick per
/// budget. One round runs per channel, with one peer: every linked holder is
/// ahead of a backfilling node, and a round with each would multiply the
/// frames that reach its unicast inbox.
#[derive(Debug, Default)]
pub(crate) struct FastRounds {
    /// The running round per channel.
    rounds: HashMap<Channel, Round>,
    /// Per channel, the peers whose heads showed they are ahead of us. A
    /// round can die with no progress (a request or its answer is lost, or its
    /// peer refuses us), and nothing else would ask them before the tick.
    ahead: HashMap<Channel, Vec<Waiting>>,
    /// When a change last landed per channel: an answer's frames still arrive.
    last_change: HashMap<Channel, Instant>,
}

impl FastRounds {
    const MIN_INTERVAL: Duration = Duration::from_millis(FAST_ROUND_MIN_INTERVAL_MS);
    const ACTIVE: Duration = Duration::from_millis(FAST_ROUND_ACTIVE_MS);

    /// The peer of the running round may be asked at once once a full answer
    /// landed since the last ask: the heads that close an answer are the cue
    /// to go on. New heads alone are not, because two answers can be in
    /// flight at once and our heads move with every frame of either; asking
    /// on each ran two chains of asks at two serves per round. Otherwise the
    /// round waits [`FAST_ROUND_MIN_INTERVAL_MS`] or the retry tick, 400 to
    /// 800 ms, so a peer that advertises heads nobody can hold costs one small
    /// frame per interval. A holder with a smaller resend budget never sends a
    /// full answer, so each of its rounds takes that wait. Another peer starts
    /// a round only when the running one went quiet for
    /// [`FAST_ROUND_ACTIVE_MS`].
    fn may_ask(
        &self,
        peer: &str,
        channel: Channel,
        heads: u64,
        changes: usize,
        now: Instant,
    ) -> bool {
        self.rounds.get(&channel).is_none_or(|round| {
            if round.peer == peer {
                let quiet = now.duration_since(self.quiet_since(channel, round));
                let answered = changes.saturating_sub(round.changes) >= antientropy_max_resend();
                (round.heads != heads && answered) || quiet >= Self::MIN_INTERVAL
            } else {
                now.duration_since(round.at) >= Self::ACTIVE
            }
        })
    }

    fn note_asked(
        &mut self,
        peer: String,
        channel: Channel,
        heads: u64,
        changes: usize,
        now: Instant,
    ) {
        self.rounds.insert(
            channel,
            Round {
                peer,
                at: now,
                heads,
                changes,
            },
        );
    }

    /// A change landed on `channel`: an answer's frames are still arriving.
    pub(crate) fn note_change(&mut self, channel: Channel, now: Instant) {
        self.last_change.insert(channel, now);
    }

    /// Whether a change landed on `channel` within [`FAST_ROUND_MIN_INTERVAL_MS`]:
    /// a holder is serving us, so a digest an event would send now draws a
    /// second answer that overlaps the one arriving.
    pub(crate) fn changed_recently(&self, channel: Channel, now: Instant) -> bool {
        self.last_change
            .get(&channel)
            .is_some_and(|&changed| now.duration_since(changed) < Self::MIN_INTERVAL)
    }

    /// Where a round's wait starts: its ask, or the last change that landed
    /// after it, since under load an answer's frames arrive over more than the
    /// wait and an ask sent meanwhile draws an answer that overlaps it. Capped
    /// at [`FAST_ROUND_ACTIVE_MS`] after the ask, so live writes cannot hold a
    /// stalled round; an answer slower than that overlaps again.
    fn quiet_since(&self, channel: Channel, round: &Round) -> Instant {
        let latest = self
            .last_change
            .get(&channel)
            .map_or(round.at, |&changed| changed.max(round.at));
        latest.min(round.at + Self::ACTIVE)
    }

    /// Our heads when we last asked for `channel`, if a round ran.
    #[cfg(test)]
    pub(crate) fn asked_heads(&self, channel: Channel) -> Option<u64> {
        self.rounds.get(&channel).map(|round| round.heads)
    }

    fn note_ahead(
        &mut self,
        channel: Channel,
        pubkey: String,
        author: Nickname,
        heads: Vec<String>,
        now: Instant,
    ) {
        let ahead = self.ahead.entry(channel).or_default();
        ahead.retain(|peer| Self::fresh(peer, now));
        let peer = Waiting {
            pubkey,
            author,
            heads,
            noted: now,
        };
        if let Some(known) = ahead.iter_mut().find(|known| known.pubkey == peer.pubkey) {
            *known = peer;
        } else if ahead.len() < FAST_ROUND_AHEAD_MAX {
            ahead.push(peer);
        }
    }

    /// The peers remembered as ahead for `channel`.
    fn ahead(&self, channel: Channel) -> Vec<Waiting> {
        self.ahead.get(&channel).cloned().unwrap_or_default()
    }

    fn fresh(peer: &Waiting, now: Instant) -> bool {
        now.duration_since(peer.noted) < Duration::from_secs(FAST_ROUND_AHEAD_TTL_SECS)
    }

    /// The peer to ask again for `channel` once nothing was asked for
    /// [`FAST_ROUND_RETRY_MS`]. Peers whose heads we now hold (`holds`), or
    /// whose heads have not shown for [`FAST_ROUND_AHEAD_TTL_SECS`], are
    /// forgotten first. While the round brings progress (`ours`, our heads
    /// now, moved since the last ask) its own peer stays first; when it does
    /// not, the next `reachable` peer after it takes a turn, so one peer that
    /// never answers cannot hold the pull.
    fn retry_target(
        &mut self,
        channel: Channel,
        now: Instant,
        ours: u64,
        holds: impl Fn(&[String]) -> bool,
        reachable: impl Fn(&str) -> bool,
    ) -> Option<(String, Nickname)> {
        let waiting = self.rounds.get(&channel).is_some_and(|round| {
            now.duration_since(self.quiet_since(channel, round))
                < Duration::from_millis(FAST_ROUND_RETRY_MS)
        });
        let ahead = self.ahead.get_mut(&channel)?;
        ahead.retain(|peer| !holds(&peer.heads) && Self::fresh(peer, now));
        let round = self.rounds.get(&channel);
        if waiting {
            return None;
        }
        let candidates: Vec<&Waiting> = ahead
            .iter()
            .filter(|peer| reachable(&peer.pubkey))
            .collect();
        let round_index =
            round.and_then(|round| candidates.iter().position(|peer| peer.pubkey == round.peer));
        let progress = round.is_none_or(|round| round.heads != ours);
        let pick = match round_index {
            Some(index) if progress => candidates.get(index),
            Some(index) => candidates.get((index + 1) % candidates.len()),
            None => candidates.first(),
        };
        pick.map(|peer| (peer.pubkey.clone(), peer.author.clone()))
    }

    /// Whether a direct round runs for `channel`: we asked a peer within
    /// [`FAST_ROUND_ACTIVE_MS`]. Our broadcast digests wait meanwhile: during
    /// a backfill each one draws a full answer from every linked holder, and
    /// together they overflow our unicast inbox.
    pub(crate) fn active(&self, channel: Channel, now: Instant) -> bool {
        self.rounds
            .get(&channel)
            .is_some_and(|round| now.duration_since(round.at) < Self::ACTIVE)
    }
}

/// Ask the author of `digest` directly for what we miss, when its heads show
/// it is ahead of us. The peer is remembered either way, so a retry can reach
/// it when this ask cannot go out or its answer is lost.
async fn ask_back(
    channel: Channel,
    digest: &Message,
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
) {
    let Ok(body) = serde_json::from_str::<HeadsBody>(digest.body.as_str()) else {
        return;
    };
    if state.doc(channel).holds_heads(&body.heads) {
        return;
    }
    let now = Instant::now();
    state.fast_rounds.note_ahead(
        channel,
        digest.pubkey.clone(),
        digest.author.clone(),
        body.heads,
        now,
    );
    if state.fast_rounds.may_ask(
        &digest.pubkey,
        channel,
        heads_key_of(state, channel),
        state.doc(channel).change_count(),
        now,
    ) {
        ask(channel, &digest.pubkey, &digest.author, state, ctx).await;
    } else {
        tracing::debug!(me = %ctx.author, peer = %digest.author, ?channel, "a peer is ahead, but a fast round waits");
    }
}

/// Our own heads key for `channel`, as a digest of ours would carry it (its
/// body is the heads JSON), without building and signing one.
fn heads_key_of(state: &EventLoopState, channel: Channel) -> u64 {
    let heads = HeadsBody {
        heads: state.doc(channel).heads(),
        closing: false,
    };
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    serde_json::to_string(&heads)
        .unwrap_or_default()
        .hash(&mut hasher);
    hasher.finish()
}

/// Ask again when a round stalled: a request or its answer was lost, or the
/// peer refused us. Runs on a short timer; asks one peer that is still ahead
/// and reachable now, once nothing was asked for a retry interval.
pub(crate) async fn resume_fast_rounds(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    for channel in [Channel::State, Channel::Meta] {
        let now = Instant::now();
        let ahead = state.fast_rounds.ahead(channel);
        let held: Vec<&[String]> = ahead
            .iter()
            .filter(|peer| state.doc(channel).holds_heads(&peer.heads))
            .map(|peer| peer.heads.as_slice())
            .collect();
        let reachable: Vec<&str> = ahead
            .iter()
            .filter(|peer| crate::transport::unicast_answer_target(&peer.pubkey, state).is_some())
            .map(|peer| peer.pubkey.as_str())
            .collect();
        let ours = heads_key_of(state, channel);
        let target = state.fast_rounds.retry_target(
            channel,
            now,
            ours,
            |heads| held.contains(&heads),
            |pubkey| reachable.contains(&pubkey),
        );
        let Some((pubkey, author)) = target else {
            continue;
        };
        if ask(channel, &pubkey, &author, state, ctx).await {
            tracing::debug!(me = %ctx.author, peer = %author, ?channel, "retried a fast round with a peer that is ahead");
        }
    }
}

/// Send our digest for `channel` to `author` point-to-point, if it is a linked
/// neighbor with a usable path. The caller decides whether the round allows
/// it. Returns whether it went out.
async fn ask(
    channel: Channel,
    pubkey: &str,
    author: &Nickname,
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
) -> bool {
    let Some(eid) = crate::transport::unicast_answer_target(pubkey, state) else {
        return false;
    };
    let origin = DigestOrigin {
        mesh: ctx.mesh,
        author: ctx.author,
    };
    let Some(ours) = state_digest(state, origin, channel) else {
        return false;
    };
    let ours_key = heads_key(&ours);
    let now = Instant::now();
    let Ok(bytes) = ours.serialize().map(Bytes::from) else {
        return false;
    };
    if !state
        .unicast_pool
        .send_batch_in_background(eid, vec![bytes])
        .await
    {
        return false;
    }
    let changes = state.doc(channel).change_count();
    state
        .fast_rounds
        .note_asked(pubkey.to_owned(), channel, ours_key, changes, now);
    tracing::debug!(me = %ctx.author, peer = %author, ?channel, heads = ours_key, "asked a peer that is ahead for state directly (fast round)");
    true
}

/// A digest's heads as the serve budget keys them: its body is the heads. The
/// same heads in another order hash differently and get one more answer.
fn heads_key(digest: &Message) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    digest.body.as_str().hash(&mut hasher);
    hasher.finish()
}

/// Which plane a state digest answer takes; part of the serve gate's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Plane {
    Unicast,
    Gossip,
}

/// How [`handle_state_digest`] sent its answer, in frames. `unicast` counts
/// frames handed to a background send, not proof that they arrived, and not
/// the heads frame that closes a point-to-point answer.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Answered {
    pub(crate) unicast: usize,
    pub(crate) broadcast: usize,
}

/// Handle a received state digest: the sender advertised its automerge heads, so
/// re-send the signed change frames it is missing (`changes_since`), up to an
/// own resend budget; automerge's DAG collapses "what's missing" into one query.
/// The answer goes point-to-point to a linked neighbor (see
/// [`crate::transport::unicast_answer_target`]), else on gossip, where every
/// hop already holds these frames and pushing them costs a prune each; the
/// unicast plane also drops no message id as seen, so an evicted orphan can come
/// again at once. How often one asker is served is limited per channel and
/// plane by [`ServeBudget`], checked before the query; a digest with nothing
/// missing uses no serve.
pub(crate) async fn handle_state_digest(
    channel: Channel,
    message: &Message,
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
) -> Answered {
    ask_back(channel, message, state, ctx).await;
    if serde_json::from_str::<HeadsBody>(message.body.as_str()).is_ok_and(|body| body.closing) {
        return Answered::default();
    }
    let now = Instant::now();
    let heads = heads_key(message);
    let serve = |plane| (message.pubkey.clone(), channel, plane);
    let target = crate::transport::unicast_answer_target(&message.pubkey, state);
    let plane = if target.is_some() {
        Plane::Unicast
    } else {
        Plane::Gossip
    };
    // Before the query: a refused digest costs no `changes_since`.
    if !state.state_digest_serves.admits(&serve(plane), heads, now) {
        tracing::debug!(me = %ctx.author, author = %message.author, ?channel, ?plane, heads, "state digest ignored: this asker was served within the window");
        return Answered::default();
    }
    let frames: Vec<Bytes> = missing_frames(channel, message, state)
        .iter()
        .filter_map(|frame| frame.serialize().ok().map(Bytes::from))
        .collect();
    let mut answered = Answered::default();
    if frames.is_empty() {
        return answered;
    }
    let count = frames.len();
    // A point-to-point answer ends with our own heads: the asker compares them
    // with its document and asks again while it is behind (see `ask_back`).
    let origin = DigestOrigin {
        mesh: ctx.mesh,
        author: ctx.author,
    };
    let our_heads = heads_digest(state, origin, channel, true)
        .and_then(|ours| ours.serialize().ok())
        .map(Bytes::from);
    let fallback = match target {
        None => Some("asker has no proven endpoint that is a linked neighbor with a direct path"),
        Some(eid)
            if state
                .unicast_pool
                .send_batch_in_background(eid, frames.iter().cloned().chain(our_heads).collect())
                .await =>
        {
            None
        }
        Some(_) => Some(
            "the send could not start: a dial in flight, a dial cooldown, or a relay-only path",
        ),
    };
    if fallback.is_some() {
        if plane == Plane::Unicast
            && !state
                .state_digest_serves
                .admits(&serve(Plane::Gossip), heads, now)
        {
            tracing::debug!(me = %ctx.author, author = %message.author, ?channel, heads, "state digest ignored: the unicast send could not start and the gossip answers are used up for this window");
            return answered;
        }
        for bytes in frames {
            let _ = ctx.sender.broadcast(bytes).await;
        }
        answered.broadcast = count;
        state
            .state_digest_serves
            .note(serve(Plane::Gossip), heads, now);
    } else {
        answered.unicast = count;
        state
            .state_digest_serves
            .note(serve(Plane::Unicast), heads, now);
    }
    tracing::debug!(
        me = %ctx.author,
        asker = %message.author,
        ?channel,
        heads,
        unicast = answered.unicast,
        broadcast = answered.broadcast,
        on_gossip_because = fallback.unwrap_or("-"),
        "state anti-entropy: resent frames a peer lacked"
    );
    answered
}

/// The signed change frames the author of `digest` lacks on `channel`, up to
/// the resend budget, less the ones it signed itself: with heads we do not
/// hold we cannot tell what it has and send everything, but its own changes
/// it always has. Empty for an undecodable digest body.
fn missing_frames(channel: Channel, digest: &Message, state: &EventLoopState) -> Vec<Message> {
    let Ok(body) = serde_json::from_str::<HeadsBody>(digest.body.as_str()) else {
        return Vec::new();
    };
    state
        .doc(channel)
        .changes_since_not_by(&body.heads, &digest.pubkey, antientropy_max_resend())
}

#[cfg(test)]
mod budget_tests {
    use std::time::Duration;

    use super::{FastRounds, Plane, ServeBudget};
    use crate::protocol::Channel;
    use crate::testing::nick;
    use crate::util::clock::Instant;
    use crate::util::tuning::{
        ANTIENTROPY_SERVES_PER_WINDOW, FAST_ROUND_ACTIVE_MS, FAST_ROUND_RETRY_MS,
        antientropy_max_resend,
    };

    fn key() -> (String, Channel, Plane) {
        ("asker".to_owned(), Channel::State, Plane::Unicast)
    }

    #[test]
    fn the_serve_budget_takes_new_heads_up_to_its_count() {
        let now = Instant::now();
        let mut budget = ServeBudget::default();
        let gossip = ("asker".to_owned(), Channel::State, Plane::Gossip);
        budget.note(gossip.clone(), 1, now);
        assert!(
            !budget.admits(&gossip, 2, now),
            "one gossip answer per window"
        );
        assert!(budget.admits(&key(), 1, now));
        budget.note(key(), 1, now);
        assert!(
            !budget.admits(&key(), 1, now),
            "the same heads again at once"
        );
        let retry = now + Duration::from_millis(250);
        assert!(
            budget.admits(&key(), 1, retry),
            "the same heads again after a lost answer"
        );
        for heads in 2..=ANTIENTROPY_SERVES_PER_WINDOW as u64 {
            assert!(budget.admits(&key(), heads, now), "new heads {heads}");
            budget.note(key(), heads, now);
        }
        assert!(
            !budget.admits(&key(), 99, now),
            "one more than {ANTIENTROPY_SERVES_PER_WINDOW} in a window"
        );
        let later = now + Duration::from_secs(6);
        assert!(budget.admits(&key(), 1, later), "a new window");
    }

    /// Every peer that showed heads we do not hold is remembered, linked or
    /// not, round or no round. When nothing was asked for a retry interval,
    /// one of them that is reachable now is asked, the round's own peer
    /// first; a peer whose heads we now hold is forgotten. One lost message
    /// then costs a retry interval, not a tick.
    #[test]
    fn a_peer_that_is_ahead_is_retried_once_asking_went_quiet() {
        let now = Instant::now();
        let mut rounds = FastRounds::default();
        let channel = Channel::State;
        let early_heads = vec!["e".to_owned()];
        let alice_heads = vec!["a".to_owned()];
        rounds.note_ahead(channel, "early".to_owned(), nick("early"), early_heads, now);
        rounds.note_ahead(
            channel,
            "alice".to_owned(),
            nick("alice"),
            alice_heads.clone(),
            now,
        );
        rounds.note_asked("alice".to_owned(), channel, 1, 0, now);
        let never_held = |_: &[String]| false;
        let all_reachable = |_: &str| true;
        let moved = 2;
        let pick = |fast: &mut FastRounds,
                    at,
                    ours,
                    holds: &dyn Fn(&[String]) -> bool,
                    reachable: &dyn Fn(&str) -> bool| {
            fast.retry_target(channel, at, ours, holds, reachable)
                .map(|(pubkey, _)| pubkey)
        };

        let soon = now + Duration::from_millis(100);
        assert_eq!(
            pick(&mut rounds, soon, moved, &never_held, &all_reachable),
            None,
            "asked moments ago"
        );
        let quiet = now + Duration::from_millis(500);
        assert_eq!(
            pick(&mut rounds, quiet, moved, &never_held, &all_reachable).as_deref(),
            Some("alice"),
            "the round's peer first, while it brings progress"
        );
        assert_eq!(
            pick(&mut rounds, quiet, 1, &never_held, &all_reachable).as_deref(),
            Some("early"),
            "no progress since the last ask: the next peer"
        );
        let alice_away = |pubkey: &str| pubkey != "alice";
        assert_eq!(
            pick(&mut rounds, quiet, moved, &never_held, &alice_away).as_deref(),
            Some("early"),
            "else one reachable now"
        );
        let alice_held = |heads: &[String]| heads == alice_heads.as_slice();
        assert_eq!(
            pick(&mut rounds, quiet, moved, &alice_held, &all_reachable).as_deref(),
            Some("early"),
            "alice is no longer ahead"
        );
        let stale = now + Duration::from_secs(61);
        assert_eq!(
            pick(&mut rounds, stale, moved, &never_held, &all_reachable),
            None,
            "a peer noted a minute ago is forgotten"
        );
    }

    /// While a fast round runs, a digest an event sends waits, but the tick's
    /// goes out: when the round's peers never answer, the tick is the only
    /// thing left that asks the whole mesh.
    #[tokio::test]
    async fn the_tick_digest_goes_out_while_a_fast_round_runs() {
        use super::{DigestTrigger, broadcast_state_digests};
        use crate::protocol::MeshId;

        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .expect("bind a local endpoint");
        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([5u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let sender = crate::transport::MeshSender::new(gossip_sender);
        let mut state = crate::testing::fresh_state();
        state.meshed = true;
        state
            .fast_rounds
            .note_asked("holder".to_owned(), Channel::State, 1, 0, Instant::now());
        let (mesh, author) = (MeshId::from("test"), nick("late"));

        let before = state.idle.broadcasts;
        broadcast_state_digests(&mut state, &sender, &mesh, &author, DigestTrigger::Event).await;
        assert_eq!(
            state.idle.broadcasts - before,
            1,
            "only the meta digest: state waits"
        );
        let before_tick = state.idle.broadcasts;
        broadcast_state_digests(&mut state, &sender, &mesh, &author, DigestTrigger::Tick).await;
        assert_eq!(
            state.idle.broadcasts - before_tick,
            2,
            "the tick sends both"
        );
        endpoint.close().await;
    }

    /// A node that just got a change has a holder serving it, so a digest an
    /// event sends then waits: sent while the first answer arrives, it drew
    /// a second answer that overlapped the first. The tick still goes out.
    #[tokio::test]
    async fn an_event_digest_waits_while_changes_arrive() {
        use super::{DigestTrigger, broadcast_state_digests};
        use crate::protocol::MeshId;

        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .expect("bind a local endpoint");
        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([6u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let sender = crate::transport::MeshSender::new(gossip_sender);
        let mut state = crate::testing::fresh_state();
        state.meshed = true;
        state
            .fast_rounds
            .note_change(Channel::State, Instant::now());
        let (mesh, author) = (MeshId::from("test"), nick("late"));

        let before = state.idle.broadcasts;
        broadcast_state_digests(&mut state, &sender, &mesh, &author, DigestTrigger::Event).await;
        assert_eq!(
            state.idle.broadcasts - before,
            1,
            "only the meta digest: a state change just landed"
        );
        let before_tick = state.idle.broadcasts;
        broadcast_state_digests(&mut state, &sender, &mesh, &author, DigestTrigger::Tick).await;
        assert_eq!(
            state.idle.broadcasts - before_tick,
            2,
            "the tick sends both"
        );
        endpoint.close().await;
    }

    /// The fast rounds compare our heads through two keys: the one stored
    /// when an ask goes out (the hash of the digest's body) and the one read
    /// back later (the hash of our heads). If they drift apart, every retry
    /// looks like progress and the pace and the turns stop working.
    #[test]
    fn our_heads_key_matches_the_key_of_our_digest() {
        use super::{DigestOrigin, heads_key, heads_key_of, state_digest};
        use crate::protocol::MeshId;

        let mut state = crate::testing::fresh_state();
        state.meshed = true;
        let (mesh, author) = (MeshId::from("test"), nick("alice"));
        let seed = *state.identity.public().as_bytes();
        let change = state
            .doc(Channel::State)
            .build_change(&serde_json::json!({ "k": 1 }), &seed)
            .expect("a JSON object merges")
            .expect("a non-empty merge yields a change");
        let (wire, _plain) = state
            .doc(Channel::State)
            .compose_wire_body(&change, None)
            .expect("compose the wire body");
        let frame =
            crate::protocol::Message::new_channel_event(&mesh, &author, wire, Channel::State)
                .signed(&state.identity);
        let _ = state.doc_mut(Channel::State).ingest(&frame);
        let origin = DigestOrigin {
            mesh: &mesh,
            author: &author,
        };
        let digest = state_digest(&state, origin, Channel::State).expect("a digest");
        assert_eq!(heads_key_of(&state, Channel::State), heads_key(&digest));
    }

    /// Under load an answer's frames arrive over more than the wait, and an
    /// ask sent while they arrive draws an answer that overlaps it. The wait
    /// counts from the last change that landed, not only from the ask.
    #[test]
    fn a_round_waits_while_an_answers_frames_still_arrive() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let state = Channel::State;
        let mut rounds = FastRounds::default();
        rounds.note_ahead(
            state,
            "alice".to_owned(),
            nick("alice"),
            vec!["a".to_owned()],
            t0,
        );
        rounds.note_asked("alice".to_owned(), state, 1, 0, t0);
        rounds.note_change(state, t0 + ms(150));
        assert!(
            !rounds.may_ask("alice", state, 1, 0, t0 + ms(250)),
            "the same heads 100 ms after a change"
        );
        rounds.note_change(state, t0 + ms(300));
        let retry = |fast: &mut FastRounds, at| {
            fast.retry_target(state, at, 1, |_| false, |_| true)
                .map(|(pubkey, _)| pubkey)
        };
        assert_eq!(
            retry(&mut rounds, t0 + ms(450)),
            None,
            "150 ms after a change"
        );
        assert_eq!(
            retry(&mut rounds, t0 + ms(750)),
            Some("alice".to_owned()),
            "quiet for 450 ms"
        );
    }

    /// A steady stream of changes, such as live writes, must not hold a stalled
    /// round forever: the wait is capped at `FAST_ROUND_ACTIVE_MS` after the ask.
    #[test]
    fn the_wait_after_changes_is_capped() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let state = Channel::State;
        let mut rounds = FastRounds::default();
        rounds.note_ahead(
            state,
            "alice".to_owned(),
            nick("alice"),
            vec!["a".to_owned()],
            t0,
        );
        rounds.note_asked("alice".to_owned(), state, 1, 0, t0);
        let later = t0 + ms(FAST_ROUND_ACTIVE_MS + FAST_ROUND_RETRY_MS);
        let mut at = t0;
        while at < later {
            rounds.note_change(state, at);
            at += ms(100);
        }
        let target = rounds
            .retry_target(state, later, 1, |_| false, |_| true)
            .map(|(pubkey, _)| pubkey);
        assert_eq!(target, Some("alice".to_owned()));
    }

    #[test]
    fn a_fast_round_waits_for_a_full_answer_or_the_interval() {
        let now = Instant::now();
        let full = antientropy_max_resend();
        let mut rounds = FastRounds::default();
        let state = Channel::State;
        assert!(rounds.may_ask("holder", state, 1, 0, now));
        rounds.note_asked("holder".to_owned(), state, 1, 0, now);
        assert!(rounds.active(state, now));
        assert!(!rounds.active(Channel::Meta, now));
        assert!(
            !rounds.may_ask("holder", state, 1, 0, now),
            "the same heads at once"
        );
        assert!(
            !rounds.may_ask("holder", state, 2, 5, now),
            "new heads after a partial answer wait"
        );
        assert!(
            rounds.may_ask("holder", state, 2, full, now),
            "new heads after a full answer at once"
        );
        assert!(
            !rounds.may_ask("other", state, 2, full, now),
            "another peer while the round runs"
        );
        assert!(
            rounds.may_ask("other", Channel::Meta, 2, full, now),
            "another channel"
        );
        let later = now + Duration::from_millis(250);
        assert!(
            rounds.may_ask("holder", state, 1, 0, later),
            "the same heads after the interval"
        );
        let quiet = now + Duration::from_secs(2);
        assert!(!rounds.active(state, quiet));
        assert!(
            rounds.may_ask("other", state, 2, full, quiet),
            "another peer once the round is quiet"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        ANTIENTROPY_DIGEST_WINDOW_IDS, DigestBody, DigestOrigin, HeadsBody, WireWindow,
        digest_windows, encode_key, missing_frames, state_digest,
    };
    use crate::daemon::message_log::{DigestWindow, MessageLog, MissingQuery};
    use crate::daemon::state::EventLoopState;
    use crate::doc::Ingested;
    use crate::protocol::{Channel, MeshId, Message, MessageBody, Nickname};
    use crate::testing::{fresh_state, nick};

    fn members(count: usize) -> Vec<Nickname> {
        (0..count)
            .map(|index| nick(&format!("member-{index:02}")))
            .collect()
    }

    /// One digest is answered by `ANTIENTROPY_ANSWERERS` members, not by every
    /// member that holds what the asker lacks.
    #[test]
    fn one_digest_is_answered_by_k_members_not_by_all() {
        let members = members(48);
        let asker = &members[0];
        let answering = members
            .iter()
            .filter(|me| *me != asker)
            .filter(|me| super::answers_digest(me, asker, "digest-1", members.iter()))
            .count();
        assert_eq!(answering, crate::util::tuning::ANTIENTROPY_ANSWERERS);
    }

    /// The answerers change with the digest, so a message that only one member
    /// holds comes back once that member has had a turn.
    #[test]
    fn every_member_gets_a_turn_to_answer() {
        let members = members(48);
        let asker = &members[0];
        let mut had_a_turn = HashSet::new();
        for round in 0..200 {
            let id = format!("digest-{round}");
            for me in members.iter().filter(|me| *me != asker) {
                if super::answers_digest(me, asker, &id, members.iter()) {
                    had_a_turn.insert(me.clone());
                }
            }
        }
        assert_eq!(had_a_turn.len(), 47, "all but the asker answered once");
    }

    /// A mesh no larger than the answerers has nobody to hold back.
    #[test]
    fn a_small_mesh_is_answered_by_every_member() {
        let members = members(3);
        let asker = &members[0];
        for me in members.iter().filter(|me| *me != asker) {
            assert!(super::answers_digest(me, asker, "digest-1", members.iter()));
        }
    }

    /// The digest of a node that holds nothing: one open-ended window with no
    /// ids, so every message of the holder is a gap.
    fn digest_of_an_empty_log(asker: &Nickname) -> Message {
        let window = DigestWindow {
            lo: (0, crate::daemon::message_log::KEY_MIN),
            hi: (i64::MAX, crate::daemon::message_log::KEY_MAX),
            ids: Vec::new(),
            from_start: true,
        };
        let body = crate::gossip::json_body(&DigestBody {
            windows: vec![WireWindow::encode(&window)],
        })
        .expect("a digest serializes");
        Message::new_digest(&MeshId::from("test"), asker, body)
    }

    /// The event loop answers a digest without waiting on anything: the resends
    /// go to a bounded outbox, and what does not fit is dropped and counted. The
    /// next digest asks again. An answer used to broadcast up to 64 messages from
    /// inside the loop, and a command queue that the gossip actor did not drain
    /// held the loop there for minutes.
    #[test]
    fn a_digest_answer_does_not_wait_for_a_full_outbox() {
        let (me, asker) = (nick("holder"), nick("asker"));
        let mut state = fresh_state();
        state.peers.insert(asker.clone());
        for index in 0..100 {
            state
                .message_log
                .push(chat_at(&format!("message {index}"), 1_700_000_000 + index));
        }
        // Nobody drains this outbox.
        let (outbox, _undrained) = crate::transport::ResendOutbox::new(4);
        state.resend_outbox = outbox;

        super::handle_digest(&digest_of_an_empty_log(&asker), &mut state, &me);

        assert_eq!(state.resend_outbox.queued(), 4, "the outbox is full");
        assert_eq!(
            state.resend_outbox.dropped(),
            crate::util::tuning::ANTIENTROPY_MAX_RESEND as u64 - 4,
            "the rest of the answer is dropped, and counted"
        );
    }

    /// A node whose only gossip neighbor is the rendezvous relay: linked to it,
    /// never to a real peer.
    fn rendezvous_only() -> EventLoopState {
        let mut state = fresh_state();
        state.meshed = false;
        state.rendezvous_linked = true;
        state
    }

    /// Apply a meta merge locally the way `broadcast_state_merge` does, minus
    /// the wire: build, sign, ingest. What the doc holds afterwards is exactly
    /// what anti-entropy can re-serve.
    fn publish_meta(
        state: &mut EventLoopState,
        mesh: &MeshId,
        author: &Nickname,
        merge: &serde_json::Value,
    ) {
        let seed = *state.identity.public().as_bytes();
        let change = state
            .doc(Channel::Meta)
            .build_change(merge, &seed)
            .expect("a JSON object merges")
            .expect("a non-empty merge yields a change");
        let (wire, _plain) = state
            .doc(Channel::Meta)
            .compose_wire_body(&change, None)
            .expect("compose the wire body");
        let frame =
            Message::new_channel_event(mesh, author, wire, Channel::Meta).signed(&state.identity);
        assert!(
            matches!(
                state.doc_mut(Channel::Meta).ingest(&frame),
                Ingested::Applied { .. }
            ),
            "a locally-built change applies"
        );
    }

    /// One anti-entropy round on the meta channel, from `joiner`'s side:
    /// `joiner` advertises its heads, `holder` re-serves every change frame
    /// the digest shows missing, `joiner` ingests them. Returns how many frames
    /// travelled, or `None` when `joiner` sent no digest at all.
    fn round(
        joiner: &mut EventLoopState,
        joiner_nick: &Nickname,
        holder: &EventLoopState,
        mesh: &MeshId,
    ) -> Option<usize> {
        let origin = DigestOrigin {
            mesh,
            author: joiner_nick,
        };
        let digest = state_digest(joiner, origin, Channel::Meta)?;
        let frames = missing_frames(Channel::Meta, &digest, holder);
        for frame in &frames {
            joiner.doc_mut(Channel::Meta).ingest(frame);
        }
        Some(frames.len())
    }

    /// The scenario behind the fix: A publishes its meta card while alone on
    /// the mesh, B joins later, and the two only ever share the rendezvous
    /// relay as a gossip neighbor (`meshed` never flips on either side). B's
    /// meta doc must converge to A's within two anti-entropy rounds.
    #[test]
    fn late_joiner_converges_meta_over_a_rendezvous_only_link() {
        let mesh = MeshId::from("test");
        let alice_nick = nick("alice");
        let bob_nick = nick("bob");
        let mut alice = rendezvous_only();
        publish_meta(
            &mut alice,
            &mesh,
            &alice_nick,
            &serde_json::json!({"peers": {"alice": {"status": "idle", "model": "m"}}}),
        );
        let mut bob = rendezvous_only();
        assert_ne!(
            bob.doc(Channel::Meta).heads(),
            alice.doc(Channel::Meta).heads(),
            "bob joins knowing nothing"
        );

        // Round 1: bob's empty frontier pulls alice's change; alice's digest
        // finds nothing bob holds that she lacks.
        let served = round(&mut bob, &bob_nick, &alice, &mesh)
            .expect("a rendezvous-only joiner still advertises its heads");
        assert_eq!(served, 1, "bob lacked exactly alice's one change");
        assert_eq!(
            round(&mut alice, &alice_nick, &bob, &mesh),
            Some(0),
            "alice lacks nothing"
        );
        assert_eq!(
            bob.doc(Channel::Meta).heads(),
            alice.doc(Channel::Meta).heads(),
            "converged within one round"
        );
        assert_eq!(
            bob.doc(Channel::Meta).to_json(),
            alice.doc(Channel::Meta).to_json()
        );

        // Round 2 is a no-op: nothing left to serve either way.
        assert_eq!(round(&mut bob, &bob_nick, &alice, &mesh), Some(0));
        assert_eq!(round(&mut alice, &alice_nick, &bob, &mesh), Some(0));
    }

    /// The gate itself: a digest goes out when a real peer *or* the rendezvous
    /// relay is linked, and stays silent with no neighbor at all — or while
    /// degraded, when the overlay is suspected dead.
    #[test]
    fn state_digest_needs_some_gossip_path() {
        let mesh = MeshId::from("test");
        let author = nick("alice");
        let origin = DigestOrigin {
            mesh: &mesh,
            author: &author,
        };
        let mut state = fresh_state();
        state.meshed = false;
        state.rendezvous_linked = false;
        assert!(
            state_digest(&state, origin, Channel::Meta).is_none(),
            "no neighbor: nobody to advertise to"
        );

        state.rendezvous_linked = true;
        assert!(
            state_digest(&state, origin, Channel::Meta).is_some(),
            "a rendezvous-only link carries the digest"
        );

        state.note_degraded();
        assert!(
            state_digest(&state, origin, Channel::Meta).is_none(),
            "degraded: the relay link is no proof the overlay is alive"
        );

        state.rendezvous_linked = false;
        state.meshed = true;
        state.degraded = false;
        assert!(
            state_digest(&state, origin, Channel::State).is_some(),
            "meshed, as before"
        );
    }

    /// A full two-window digest must serialize within the gossip message
    /// cap — the regression guard for the former overflow (200 UUID
    /// *strings* ≈ 8 KB, ~2× over `MAX_MESSAGE_SIZE`, silently dropped by
    /// gossip).
    #[test]
    fn digest_fits_gossip_cap() {
        // Enough messages that both a newest and a rolling older window are
        // full (each `ANTIENTROPY_DIGEST_WINDOW_IDS` ids).
        let total = ANTIENTROPY_DIGEST_WINDOW_IDS * 3;
        let mut log = MessageLog::new(total);
        for index in 0..total {
            let mut message = Message::new_app(
                &MeshId::from("test"),
                &Nickname::from("author"),
                crate::protocol::message::AppFrameParams {
                    tag: crate::protocol::AppTag::from("app_msg"),
                    to: None,
                    corr: None,
                    body: MessageBody::from(format!("m{index}").as_str()),
                },
            );
            message.timestamp = 1_700_000_000 + i64::try_from(index).unwrap();
            log.push(message);
        }
        let newest = log.recent_window(ANTIENTROPY_DIGEST_WINDOW_IDS).unwrap();
        let older = log
            .older_window(
                ANTIENTROPY_DIGEST_WINDOW_IDS,
                0,
                ANTIENTROPY_DIGEST_WINDOW_IDS,
            )
            .unwrap();
        let digest_body = DigestBody {
            windows: vec![WireWindow::encode(&newest), WireWindow::encode(&older)],
        };
        let json = serde_json::to_string(&digest_body).unwrap();
        let body = MessageBody::new(json).expect("digest body has no control chars");

        // Worst-case envelope: a realistically long mesh id.
        let mesh = MeshId::from(
            "6bLvZNPGxuqnsbaPVGwf277NyTp8cYPCMiBxXED8d6TyBZpDDzZADkKHL7tTB1EjFagbCXYZ",
        );
        let digest = Message::new_digest(&mesh, &Nickname::from("a-fairly-long-nickname"), body);
        let wire = digest.serialize().expect("serialize digest");
        assert!(
            wire.len() <= crate::util::consts::MAX_MESSAGE_SIZE,
            "digest is {} bytes, over the {}-byte gossip cap",
            wire.len(),
            crate::util::consts::MAX_MESSAGE_SIZE
        );
    }

    /// The packed-id wire codec must round-trip exactly — a regression here
    /// would silently break cross-node reconciliation.
    #[test]
    fn wire_window_round_trips_ids() {
        let ids: Vec<[u8; 16]> = (0..5u8).map(|seed| [seed; 16]).collect();
        let window = DigestWindow {
            lo: (1, crate::daemon::message_log::KEY_MIN),
            hi: (i64::MAX, crate::daemon::message_log::KEY_MAX),
            ids: ids.clone(),
            from_start: false,
        };
        let wire = WireWindow::encode(&window);
        let decoded = wire.decode_ids().expect("valid window decodes");
        assert_eq!(decoded, ids.into_iter().collect::<HashSet<_>>());
    }

    /// The digest of the build before the window keys has no `lo_key` and
    /// `hi_key`. It does not decode, and `handle_digest` reports its author once.
    #[test]
    fn a_digest_of_the_build_without_window_keys_does_not_decode() {
        let old = r#"{"windows":[{"lo":1,"hi":2,"ids":""}]}"#;
        assert!(serde_json::from_str::<DigestBody>(old).is_err());
    }

    /// A malformed digest body must decode to `None` (so `handle_digest`
    /// skips it) rather than panic or yield garbage ids.
    #[test]
    fn decode_ids_rejects_malformed() {
        // Not valid Base58 (`0`, `O`, `I`, `l`, space are outside the alphabet).
        let bad_alphabet = WireWindow {
            lo: 0,
            lo_key: String::new(),
            hi: 0,
            hi_key: String::new(),
            ids: "0OIl not base58".to_string(),
        };
        assert!(bad_alphabet.decode_ids().is_none(), "bad Base58 ⇒ None");

        // Valid Base58 but not a whole number of 16-byte ids (5 bytes).
        let odd_length = WireWindow {
            lo: 0,
            lo_key: String::new(),
            hi: 0,
            hi_key: String::new(),
            ids: bs58::encode([1u8; 5]).into_string(),
        };
        assert!(odd_length.decode_ids().is_none(), "non-16-multiple ⇒ None");

        // Empty is well-formed: zero ids.
        let empty = WireWindow {
            lo: 0,
            lo_key: String::new(),
            hi: 0,
            hi_key: String::new(),
            ids: String::new(),
        };
        assert_eq!(empty.decode_ids().map(|set| set.len()), Some(0));
    }

    /// A state/meta heads digest round-trips and stays tiny — automerge heads are
    /// a bounded frontier (a handful of 32-byte hashes), so unlike the windowed
    /// chat digest there is no overflow risk as the doc's history grows.
    #[test]
    fn state_heads_digest_round_trips_and_is_small() {
        let mesh = MeshId::from(
            "6bLvZNPGxuqnsbaPVGwf277NyTp8cYPCMiBxXED8d6TyBZpDDzZADkKHL7tTB1EjFagbCXYZ",
        );
        let author = Nickname::from("a-fairly-long-nickname");
        let heads: Vec<String> = (0..4u8)
            .map(|seed| bs58::encode([seed; 32]).into_string())
            .collect();
        let json = serde_json::to_string(&HeadsBody {
            heads: heads.clone(),
            closing: false,
        })
        .expect("serialize heads body");
        let back: HeadsBody = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back.heads, heads);

        let body = MessageBody::new(json).expect("heads body has no control chars");
        let digest = Message::new_state_digest(&mesh, &author, body);
        let wire = digest.serialize().expect("serialize state digest");
        assert!(
            wire.len() <= crate::util::consts::MAX_MESSAGE_SIZE,
            "heads digest is {} bytes, over the {}-byte gossip cap",
            wire.len(),
            crate::util::consts::MAX_MESSAGE_SIZE
        );
    }

    fn chat_at(body: &str, timestamp: i64) -> Message {
        let mut message = Message::new_app(
            &MeshId::from("test"),
            &Nickname::from("author"),
            crate::protocol::message::AppFrameParams {
                tag: crate::protocol::AppTag::from("app_msg"),
                to: None,
                corr: None,
                body: MessageBody::from(body),
            },
        );
        message.timestamp = timestamp;
        message
    }

    /// What `holder` re-sends in answer to `node`'s digest, as `handle_digest`
    /// computes it.
    fn answer(node: &mut EventLoopState, holder: &MessageLog) -> HashSet<String> {
        let windows = digest_windows(node).expect("a non-empty log advertises");
        let have: HashSet<[u8; 16]> = windows
            .iter()
            .flat_map(|window| window.decode_ids().expect("our own encoding"))
            .collect();
        windows
            .iter()
            .flat_map(|window| {
                holder.missing_in_window(MissingQuery {
                    range: window.range().expect("our own encoding"),
                    have: &have,
                    max: 100,
                    requester: &nick("node"),
                })
            })
            .map(|message| message.body.as_str().to_string())
            .collect()
    }

    /// 300 messages in a scrambled order, over `seconds` seconds.
    fn scrambled_messages(seconds: usize) -> Vec<Message> {
        (0..300usize)
            .map(|index| {
                let slot = (index * 7) % 300;
                chat_at(
                    &format!("m{slot}"),
                    1_700_000_000 + i64::try_from(slot % seconds).expect("small"),
                )
            })
            .collect()
    }

    /// A log of 300 messages in a scrambled arrival order over `seconds`
    /// seconds, as two nodes that heard the same mesh would hold it.
    fn same_log_on_two_nodes(seconds: usize) -> (EventLoopState, MessageLog) {
        let mut node = fresh_state();
        let mut holder = MessageLog::new(1000);
        for message in scrambled_messages(seconds) {
            node.message_log.push(message.clone());
            holder.push(message);
        }
        (node, holder)
    }

    /// Two nodes that hold the same messages ask each other for nothing, however
    /// many messages they hold and however few seconds those fall in. The log
    /// is longer than the 140 ids a digest lists, so the older window sweeps
    /// across rounds: every round must be clean.
    #[test]
    fn nodes_with_identical_logs_of_more_than_140_messages_ask_each_other_for_nothing() {
        for seconds in [12, 1] {
            let (mut node, holder) = same_log_on_two_nodes(seconds);
            for round in 0..6 {
                assert_eq!(
                    answer(&mut node, &holder),
                    HashSet::new(),
                    "round {round}, {seconds} s"
                );
            }
        }
    }

    /// What `holder` sends in answer to `node`'s digest, as `handle_digest`
    /// sends it: the windows in order, one budget across them, and a message
    /// that an earlier window already chose is not chosen again.
    fn answer_within_budget(
        node: &mut EventLoopState,
        holder: &MessageLog,
        mut budget: usize,
    ) -> Vec<Message> {
        let windows = digest_windows(node).expect("a non-empty log advertises");
        let mut have: HashSet<[u8; 16]> = windows
            .iter()
            .flat_map(|window| window.decode_ids().expect("our own encoding"))
            .collect();
        let mut sent = Vec::new();
        for window in &windows {
            if budget == 0 {
                break;
            }
            for message in holder.missing_in_window(MissingQuery {
                range: window.range().expect("our own encoding"),
                have: &have,
                max: budget,
                requester: &nick("node"),
            }) {
                have.insert(message.dedup_key());
                sent.push(message);
                budget -= 1;
            }
        }
        sent
    }

    /// A node that lost a quarter of the messages gets exactly those back, round
    /// by round under the resend budget, and is sent nothing it already holds.
    /// One second, the join burst, is the hard case: the lost messages sit among
    /// hundreds with the same timestamp.
    #[test]
    fn a_node_that_lost_messages_recovers_them_and_only_them() {
        let budget = crate::util::tuning::antientropy_max_resend();
        for seconds in [12, 1] {
            let all = scrambled_messages(seconds);
            let mut holder = MessageLog::new(1000);
            let mut node = fresh_state();
            node.joined_at = 1_699_999_999;
            let mut lost = HashSet::new();
            for (index, message) in all.iter().enumerate() {
                holder.push(message.clone());
                if index % 4 == 0 {
                    lost.insert(message.dedup_key());
                } else {
                    node.message_log.push(message.clone());
                }
            }
            let mut recovered = HashSet::new();
            let mut last_round = 0;
            for round in 0..12 {
                for message in answer_within_budget(&mut node, &holder, budget) {
                    assert!(
                        lost.contains(&message.dedup_key()),
                        "round {round}, {seconds} s: sent a message the node already holds"
                    );
                    if recovered.insert(message.dedup_key()) {
                        last_round = round;
                    }
                    node.message_log.push(message);
                }
            }
            assert!(
                last_round <= 2,
                "{seconds} s: the last lost message came back in round {last_round}"
            );
            assert_eq!(recovered, lost, "{seconds} s: every lost message came back");
        }
    }

    /// The windows of a digest tile the log. A message that sorts between two
    /// windows, and that the node lacks, is asked for within a few rounds even
    /// when nothing else changes and no window moves.
    /// A node that joined in the second of its first message must still ask for a message of
    /// that second with a smaller id key: the floor lowers `lo` to `joined_at` only when it is
    /// earlier than the first message, and `(second, key)` of that message leaves the smaller keys
    /// of the same second out of every window.
    #[test]
    fn a_message_of_the_second_a_node_joined_in_is_asked_for_whatever_its_key() {
        let second = 1_700_000_000;
        let mut pair = [chat_at("first", second), chat_at("second", second)];
        pair.sort_by_key(Message::dedup_key);
        let [smaller, larger] = pair;
        let mut holder = MessageLog::new(1000);
        holder.push(smaller.clone());
        holder.push(larger.clone());
        let mut node = fresh_state();
        node.joined_at = second;
        node.message_log.push(larger);
        let budget = crate::util::tuning::antientropy_max_resend();

        let answered = answer_within_budget(&mut node, &holder, budget);

        assert!(
            answered
                .iter()
                .any(|message| message.dedup_key() == smaller.dedup_key()),
            "the holder never offered the message of the same second with the smaller key"
        );
    }

    /// The first message of the log is from a peer and stamped before `joined_at` (a clock that
    /// runs behind). Nothing sorts before it in the log, so a message of its second with a
    /// smaller key is in the range that the window must reach back to.
    #[test]
    fn a_message_of_the_second_of_the_first_logged_message_is_asked_for_whatever_its_key() {
        let second = 1_700_000_000;
        let mut pair = [chat_at("first", second - 1), chat_at("second", second - 1)];
        pair.sort_by_key(Message::dedup_key);
        let [smaller, larger] = pair;
        let mut holder = MessageLog::new(1000);
        holder.push(smaller.clone());
        holder.push(larger.clone());
        let mut node = fresh_state();
        node.joined_at = second;
        node.message_log.push(larger);
        let budget = crate::util::tuning::antientropy_max_resend();

        let answered = answer_within_budget(&mut node, &holder, budget);

        assert!(
            answered
                .iter()
                .any(|message| message.dedup_key() == smaller.dedup_key()),
            "the holder never offered the message of the same second with the smaller key"
        );
    }

    #[test]
    fn a_message_between_two_windows_is_asked_for() {
        let mut all = scrambled_messages(12);
        all.sort_by_key(|message| (message.timestamp, message.dedup_key()));
        let mut holder = MessageLog::new(1000);
        let mut node = fresh_state();
        node.joined_at = 1_699_999_999;
        for (index, message) in all.iter().enumerate() {
            holder.push(message.clone());
            if index != ANTIENTROPY_DIGEST_WINDOW_IDS {
                node.message_log.push(message.clone());
            }
        }
        let lost = all[ANTIENTROPY_DIGEST_WINDOW_IDS].dedup_key();
        let budget = crate::util::tuning::antientropy_max_resend();
        let asked = (0..12).any(|_| {
            answer_within_budget(&mut node, &holder, budget)
                .iter()
                .any(|message| message.dedup_key() == lost)
        });
        assert!(
            asked,
            "the message between the first two windows never came back"
        );
    }

    /// A message is stamped by its sender, and nothing bounds how far ahead. One
    /// author with a fast clock then sorts above every honest message. The newest
    /// window must still be the newest messages up to the local clock, or the
    /// fresh messages of everyone else wait for the sweep, as many rounds as
    /// the log holds windows. The messages of the fast author are not lost:
    /// the sweep brings them back.
    #[test]
    fn an_author_with_a_fast_clock_does_not_slow_the_newest_messages() {
        let budget = crate::util::tuning::antientropy_max_resend();
        let base = crate::util::clock::unix_secs() - 3600;
        let ahead = 80;
        let mut all: Vec<Message> = Vec::new();
        let (mut next_honest, mut next_fast) = (0usize, 0usize);
        let mut honest_at = Vec::new();
        let mut fast_at = Vec::new();
        while all.len() < 1000 {
            if all.len().is_multiple_of(12) && next_fast < ahead {
                fast_at.push(all.len());
                all.push(chat_at(&format!("f{next_fast}"), base + 100_000));
                next_fast += 1;
            } else {
                honest_at.push(all.len());
                let second = i64::try_from(next_honest / 20).expect("small");
                all.push(chat_at(&format!("h{next_honest}"), base + second));
                next_honest += 1;
            }
        }
        let rounds_until_back = |lost_index: usize| {
            let mut holder = MessageLog::new(1000);
            let mut node = fresh_state();
            node.joined_at = base - 1;
            let lost = all[lost_index].dedup_key();
            for (index, message) in all.iter().enumerate() {
                holder.push(message.clone());
                if index != lost_index {
                    node.message_log.push(message.clone());
                }
            }
            (1..=40).find(|_| {
                answer_within_budget(&mut node, &holder, budget)
                    .iter()
                    .any(|message| message.dedup_key() == lost)
            })
        };
        let newest_honest = honest_at.len() - 1;
        for slot in [newest_honest, newest_honest - 30] {
            let rounds = rounds_until_back(honest_at[slot]);
            assert!(
                rounds.is_some_and(|rounds| rounds <= 2),
                "the honest message {} from the newest came back after {rounds:?} rounds",
                newest_honest - slot
            );
        }
        // The fast author's messages sort last. The one that sorts highest is
        // above everything the node holds, so only an open end reaches it.
        let mut by_bound = fast_at.clone();
        by_bound.sort_by_key(|index| (all[*index].timestamp, all[*index].dedup_key()));
        for index in [
            by_bound[by_bound.len() - 1],
            by_bound[by_bound.len() / 2],
            by_bound[0],
        ] {
            let rounds = rounds_until_back(index);
            assert!(
                rounds.is_some_and(|rounds| rounds <= 20),
                "a message of the fast author never came back: {rounds:?}"
            );
        }
    }

    /// Two nodes whose logs are over their capacity keep the newest messages
    /// they saw. The one that joined earlier saw more, so their retained sets
    /// differ at the old edge. Neither may keep asking the other for what it
    /// evicted, or the other keeps sending it and it evicts it again.
    #[test]
    fn two_full_logs_with_different_history_ask_each_other_for_nothing() {
        let budget = crate::util::tuning::antientropy_max_resend();
        let base = 1_700_000_000;
        let common: Vec<Message> = (0..300)
            .map(|index| chat_at(&format!("c{index}"), base + i64::from(index / 3)))
            .collect();
        let earlier: Vec<Message> = (0..150)
            .map(|index| chat_at(&format!("e{index}"), base + i64::from(index * 2 / 3)))
            .collect();
        let mut older = fresh_state();
        older.joined_at = base - 1;
        older.message_log = MessageLog::new(100);
        let mut newer = fresh_state();
        newer.joined_at = base + 1;
        newer.message_log = MessageLog::new(100);
        for message in earlier.iter().chain(&common) {
            older.message_log.push(message.clone());
        }
        for message in &common {
            newer.message_log.push(message.clone());
        }

        let mut sent_per_round = Vec::new();
        for _ in 0..8 {
            let mut sent = 0;
            let to_newer = answer_within_budget(&mut newer, &older.message_log, budget);
            let to_older = answer_within_budget(&mut older, &newer.message_log, budget);
            sent += to_newer.len() + to_older.len();
            for message in to_newer {
                newer.message_log.push(message);
            }
            for message in to_older {
                older.message_log.push(message);
            }
            sent_per_round.push(sent);
        }
        assert!(
            sent_per_round[2..].iter().all(|sent| *sent == 0),
            "messages sent per round between two full logs: {sent_per_round:?}"
        );
    }

    /// A node gets back every message it missed after it joined, even one sent
    /// well before its own first entry. A node alone for its first moments logs
    /// nothing until a link forms and it announces itself, and the digest used
    /// to start its window at that first entry, so what the mesh said in
    /// between was never asked for and never arrived. Messages from before the
    /// node joined stay out: it never surfaces them (`lifecycle`), so asking
    /// for them would only spend the resend budget.
    #[test]
    fn a_digest_asks_for_everything_missed_since_joining() {
        let joined_at = 1_700_000_000;
        let own_joined = chat_at("own joined", joined_at + 5);
        let mut node = fresh_state();
        node.joined_at = joined_at;
        node.message_log.push(own_joined.clone());

        let mut holder = MessageLog::new(10);
        for message in [
            chat_at("before joining", joined_at - 5),
            chat_at("4 s before the first entry", joined_at + 1),
            chat_at("1 s before the first entry", joined_at + 4),
            own_joined,
        ] {
            holder.push(message);
        }

        assert_eq!(
            answer(&mut node, &holder),
            HashSet::from(
                ["4 s before the first entry", "1 s before the first entry"].map(String::from)
            )
        );
    }

    /// The full digest body survives a serde round-trip, preserving the
    /// open-ended (`i64::MAX`) upper bound that drives reconnect recovery.
    #[test]
    fn digest_body_serde_round_trips() {
        let body = DigestBody {
            windows: vec![
                WireWindow {
                    lo: 100,
                    lo_key: encode_key(&[3; 16]),
                    hi: i64::MAX,
                    hi_key: encode_key(&[u8::MAX; 16]),
                    ids: bs58::encode([7u8; 16]).into_string(),
                },
                WireWindow {
                    lo: 10,
                    lo_key: encode_key(&[1; 16]),
                    hi: 50,
                    hi_key: encode_key(&[2; 16]),
                    // Two *distinct* 16-byte ids (identical halves would
                    // dedup to one in the decoded set).
                    ids: {
                        let mut raw = [0u8; 32];
                        raw[16..].fill(1);
                        bs58::encode(raw).into_string()
                    },
                },
            ],
        };
        let json = serde_json::to_string(&body).unwrap();
        let back: DigestBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back.windows.len(), 2);
        assert_eq!(back.windows[0].hi, i64::MAX, "open-ended bound preserved");
        assert_eq!(back.windows[0].decode_ids().unwrap().len(), 1);
        assert_eq!(back.windows[1].decode_ids().unwrap().len(), 2);
    }
}
