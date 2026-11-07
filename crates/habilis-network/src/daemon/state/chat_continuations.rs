use std::collections::HashMap;
use std::time::Duration;

use crate::protocol::AuthorKey;
use crate::util::clock::Instant;
use crate::util::tuning::{
    CHAT_CONTINUATION_AUTHORS_MAX, CHAT_RETRIES_MAX, FAST_ROUND_MIN_INTERVAL,
};

/// One author's run of continuations inside one cooldown window.
#[derive(Debug, Clone, Copy)]
struct Run {
    /// When the first continuation of the run was served.
    since: Instant,
    /// When the last one was served.
    last: Instant,
    /// How many were served.
    served: u32,
}

/// The continuations of a chat digest that a holder serves to an author inside its cooldown.
///
/// An asker whose chat gap is longer than one answer repeats its digest by unicast while each answer
/// is full (`retry_chat_ask`, at most `CHAT_RETRIES_MAX` repeats, at least `FAST_ROUND_MIN_INTERVAL`
/// apart). The one-serve-per-window cooldown of the holder dropped every repeat, so the gap waited
/// one tick for each answer. A repeat that comes by unicast is served here, at the pace of the
/// asker and up to its count, and nothing else is: the answer goes to the asker alone, so no mesh
/// is flooded.
///
/// Bound: a run opens when a digest is served and lives for one cooldown window; the table drops the
/// runs that outlived it at each call; at most `CHAT_CONTINUATION_AUTHORS_MAX` authors hold a run at
/// once. When the table is full the digest of a new author opens no run (nothing is evicted, so a
/// flood of keys cannot push out an honest asker), its continuations are refused, and its repeats meet
/// the cooldown as before.
#[derive(Debug, Default)]
pub(crate) struct ChatContinuations {
    runs: HashMap<AuthorKey, Run>,
}

impl ChatContinuations {
    /// A digest of `author` was served, which opens its window: a run that holds no continuation yet.
    /// A table that is full opens none: the continuations of that author are refused.
    pub(crate) fn begin(&mut self, author: AuthorKey, now: Instant, window: Duration) {
        self.runs
            .retain(|_, run| now.duration_since(run.since) < window);
        if self.runs.len() >= CHAT_CONTINUATION_AUTHORS_MAX && !self.runs.contains_key(&author) {
            return;
        }
        self.runs.insert(
            author,
            Run {
                since: now,
                last: now,
                served: 0,
            },
        );
    }

    /// Whether a unicast digest of `author` inside its cooldown is a continuation to serve now: its
    /// window holds a run, the digest is at least `FAST_ROUND_MIN_INTERVAL` after the last serve, and
    /// the run has not reached `CHAT_RETRIES_MAX`.
    pub(crate) fn admit(&mut self, author: AuthorKey, now: Instant, window: Duration) -> bool {
        self.runs
            .retain(|_, run| now.duration_since(run.since) < window);
        let Some(run) = self.runs.get_mut(&author) else {
            return false;
        };
        let too_soon = now.duration_since(run.last) < FAST_ROUND_MIN_INTERVAL;
        if too_soon || run.served >= CHAT_RETRIES_MAX {
            return false;
        }
        run.served += 1;
        run.last = now;
        true
    }

    /// How many authors hold a run.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.runs.len()
    }
}
