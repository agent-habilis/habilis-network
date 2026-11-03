use std::collections::HashMap;
use std::time::Duration;

use crate::protocol::{AuthorKey, Channel, Nickname};
use crate::util::clock::Instant;
use crate::util::tuning::{
    FAST_ROUND_ACTIVE, FAST_ROUND_AHEAD_MAX, FAST_ROUND_AHEAD_TTL, FAST_ROUND_MIN_INTERVAL,
    FAST_ROUND_RETRY, antientropy_max_resend,
};

/// The running fast round of one channel: the peer we ask, when we last
/// asked, and our heads and change count at that ask.
#[derive(Debug, Clone)]
pub(super) struct Round {
    pub(super) peer: AuthorKey,
    pub(super) at: Instant,
    pub(super) heads: u64,
    pub(super) changes: usize,
}

/// A peer whose heads showed it is ahead of us.
#[derive(Debug, Clone)]
pub(super) struct Waiting {
    pub(super) key: AuthorKey,
    pub(super) author: Nickname,
    pub(super) heads: Vec<String>,
    pub(super) noted: Instant,
    /// The retries in a row that found our heads unmoved.
    pub(super) stalls: u32,
    /// Not before this: the retry of this peer waits out its backoff.
    pub(super) not_before: Option<Instant>,
}

/// This node's fast rounds: when a linked neighbor's digest shows heads we do
/// not hold, we ask that neighbor directly, and its answer ends with its heads,
/// so we ask again until we hold them. The tick asked once per interval, and
/// an answer carries one resend budget, so a long history took one tick per
/// budget. One round runs per channel, with one peer: every linked holder is
/// ahead of a backfilling node, and a round with each would multiply the
/// frames that reach its unicast inbox.
#[derive(Debug, Default, Clone)]
pub(crate) struct FastRounds {
    /// The running round per channel.
    pub(super) rounds: HashMap<Channel, Round>,
    /// Per channel, the peers whose heads showed they are ahead of us. A
    /// round can die with no progress (a request or its answer is lost, or its
    /// peer refuses us), and nothing else would ask them before the tick.
    pub(super) ahead: HashMap<Channel, Vec<Waiting>>,
    /// When a change last landed per channel: an answer's frames still arrive.
    pub(super) last_change: HashMap<Channel, Instant>,
    /// The longest backoff of a stalled retry (see `FAST_ROUND_STALL_BACKOFF_CAP`). Zero is off.
    pub(super) stall_cap: Duration,
}

impl FastRounds {
    pub(crate) fn new(stall_cap: Duration) -> Self {
        Self {
            stall_cap,
            ..Self::default()
        }
    }

    /// The peer of the running round may be asked at once once a full answer
    /// landed since the last ask: the heads that close an answer are the cue
    /// to go on. New heads alone are not, because two answers can be in
    /// flight at once and our heads move with every frame of either; asking
    /// on each ran two chains of asks at two serves per round. Otherwise the
    /// round waits [`FAST_ROUND_MIN_INTERVAL`] or the retry tick, 400 to
    /// 800 ms, so a peer that advertises heads nobody can hold costs one small
    /// frame per interval. A holder with a smaller resend budget never sends a
    /// full answer, so each of its rounds takes that wait. Another peer starts
    /// a round only when the running one went quiet for
    /// [`FAST_ROUND_ACTIVE`].
    pub(super) fn may_ask(
        &self,
        peer: &AuthorKey,
        channel: Channel,
        heads: u64,
        changes: usize,
        now: Instant,
    ) -> bool {
        self.rounds.get(&channel).is_none_or(|round| {
            if round.peer == *peer {
                let quiet = now.duration_since(self.quiet_since(channel, round));
                let answered = changes.saturating_sub(round.changes) >= antientropy_max_resend();
                (round.heads != heads && answered) || quiet >= FAST_ROUND_MIN_INTERVAL
            } else {
                now.duration_since(round.at) >= FAST_ROUND_ACTIVE
            }
        })
    }

    pub(super) fn note_asked(
        &mut self,
        peer: AuthorKey,
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

    /// Whether a change landed on `channel` within [`FAST_ROUND_MIN_INTERVAL`]:
    /// a holder is serving us, so a digest an event would send now draws a
    /// second answer that overlaps the one arriving.
    pub(crate) fn changed_recently(&self, channel: Channel, now: Instant) -> bool {
        self.last_change
            .get(&channel)
            .is_some_and(|&changed| now.duration_since(changed) < FAST_ROUND_MIN_INTERVAL)
    }

    /// Where a round's wait starts: its ask, or the last change that landed
    /// after it, since under load an answer's frames arrive over more than the
    /// wait and an ask sent meanwhile draws an answer that overlaps it. Capped
    /// at [`FAST_ROUND_ACTIVE`] after the ask, so live writes cannot hold a
    /// stalled round; an answer slower than that overlaps again.
    pub(super) fn quiet_since(&self, channel: Channel, round: &Round) -> Instant {
        let latest = self
            .last_change
            .get(&channel)
            .map_or(round.at, |&changed| changed.max(round.at));
        latest.min(round.at + FAST_ROUND_ACTIVE)
    }

    /// Our heads when we last asked for `channel`, if a round ran.
    #[cfg(test)]
    pub(crate) fn asked_heads(&self, channel: Channel) -> Option<u64> {
        self.rounds.get(&channel).map(|round| round.heads)
    }

    pub(super) fn note_ahead(
        &mut self,
        channel: Channel,
        key: AuthorKey,
        author: Nickname,
        heads: Vec<String>,
        now: Instant,
    ) {
        let ahead = self.ahead.entry(channel).or_default();
        ahead.retain(|peer| Self::fresh(peer, now));
        let peer = Waiting {
            key,
            author,
            heads,
            noted: now,
            stalls: 0,
            not_before: None,
        };
        if let Some(known) = ahead.iter_mut().find(|known| known.key == peer.key) {
            // The same heads again are the same stall: a peer that is stuck says so at every
            // digest. Other heads are news, so the backoff starts again.
            if known.heads == peer.heads {
                known.noted = now;
            } else {
                *known = peer;
            }
        } else if ahead.len() < FAST_ROUND_AHEAD_MAX {
            ahead.push(peer);
        }
    }

    /// The peers remembered as ahead, summed over the channels.
    pub(crate) fn ahead_count(&self) -> usize {
        self.ahead.values().map(Vec::len).sum()
    }

    /// The peers remembered as ahead for `channel`.
    pub(super) fn ahead(&self, channel: Channel) -> Vec<Waiting> {
        self.ahead.get(&channel).cloned().unwrap_or_default()
    }

    pub(super) fn fresh(peer: &Waiting, now: Instant) -> bool {
        now.duration_since(peer.noted) < FAST_ROUND_AHEAD_TTL
    }

    /// The peer to ask again for `channel` once nothing was asked for
    /// [`FAST_ROUND_RETRY`]. Peers whose heads we now hold (`holds`), or
    /// whose heads have not shown for [`FAST_ROUND_AHEAD_TTL`], are
    /// forgotten first. While the round brings progress (`ours`, our heads
    /// now, moved since the last ask) its own peer stays first; when it does
    /// not, the next `reachable` peer after it takes a turn, so one peer that
    /// never answers cannot hold the pull.
    pub(super) fn retry_target(
        &mut self,
        channel: Channel,
        now: Instant,
        ours: u64,
        holds: impl Fn(&[String]) -> bool,
        reachable: impl Fn(&AuthorKey) -> bool,
    ) -> Option<(AuthorKey, Nickname)> {
        let round_entry = self.rounds.get(&channel);
        let waiting = round_entry.is_some_and(|round| {
            now.duration_since(self.quiet_since(channel, round)) < FAST_ROUND_RETRY
        });
        let ahead = self.ahead.get_mut(&channel)?;
        ahead.retain(|peer| !holds(&peer.heads) && Self::fresh(peer, now));
        let round = self.rounds.get(&channel);
        if waiting {
            return None;
        }
        let candidates: Vec<&Waiting> = ahead
            .iter()
            .filter(|peer| reachable(&peer.key) && peer.not_before.is_none_or(|until| now >= until))
            .collect();
        let round_index =
            round.and_then(|round| candidates.iter().position(|peer| peer.key == round.peer));
        let progress = round.is_none_or(|round| round.heads != ours);
        let candidate_count = candidates.len();
        let pick = match round_index {
            Some(index) if progress => candidates.get(index),
            Some(index) => candidates.get((index + 1) % candidate_count),
            None => candidates.first(),
        };
        let picked = pick.map(|peer| (peer.key, peer.author.clone()));
        if !self.stall_cap.is_zero() {
            self.back_off(channel, picked.as_ref().map(|(key, _)| key), progress, now);
        }
        picked
    }

    /// A pick after progress starts every peer of the channel afresh. A pick without it is a stall
    /// of that peer: its next retry waits twice as long, up to the cap.
    fn back_off(
        &mut self,
        channel: Channel,
        picked: Option<&AuthorKey>,
        progress: bool,
        now: Instant,
    ) {
        let Some(ahead) = self.ahead.get_mut(&channel) else {
            return;
        };
        if progress {
            for peer in ahead.iter_mut() {
                peer.stalls = 0;
                peer.not_before = None;
            }
            return;
        }
        let Some(peer) = ahead.iter_mut().find(|peer| Some(&peer.key) == picked) else {
            return;
        };
        peer.stalls = peer.stalls.saturating_add(1);
        let wait = FAST_ROUND_RETRY.saturating_mul(2_u32.saturating_pow(peer.stalls));
        peer.not_before = Some(now + wait.min(self.stall_cap));
    }

    /// Whether a direct round runs for `channel`: we asked a peer within
    /// [`FAST_ROUND_ACTIVE`]. Our broadcast digests wait meanwhile: during
    /// a backfill each one draws a full answer from every linked holder, and
    /// together they overflow our unicast inbox.
    pub(crate) fn active(&self, channel: Channel, now: Instant) -> bool {
        self.rounds
            .get(&channel)
            .is_some_and(|round| now.duration_since(round.at) < FAST_ROUND_ACTIVE)
    }
}
