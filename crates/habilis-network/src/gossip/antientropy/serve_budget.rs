use super::Plane;
use std::collections::HashMap;

use crate::protocol::{AuthorKey, Channel};
use crate::util::clock::Instant;
use crate::util::tuning::{
    ANTIENTROPY_SERVE_COOLDOWN, ANTIENTROPY_SERVES_PER_WINDOW, FAST_ROUND_MIN_INTERVAL,
};

/// The state digest answers served in the current window, per asker, channel
/// and plane: at most [`ANTIENTROPY_SERVES_PER_WINDOW`] on the unicast plane,
/// one on gossip. On unicast the same heads are answered again only after
/// [`FAST_ROUND_MIN_INTERVAL`], so a burst of one asker's digests draws one
/// answer and a lost answer can still be asked for again. A serve is counted
/// when the answer is handed to the pool, not when it is delivered, so a batch
/// that fails costs one serve, and the asker's next ask is answered. The
/// heads alone cannot be the gate: the holder does not check them, so a
/// digest with made-up heads would be new every time.
#[derive(Debug, Default, Clone)]
pub(crate) struct ServeBudget {
    /// The asker's key: every digest is verified, so it always has one.
    pub(super) windows: HashMap<(AuthorKey, Channel, Plane), Served>,
    /// The chat frames that digest answers re-sent to each asker lately.
    pub(crate) resends: super::ResendMemory,
}

#[derive(Debug, Clone)]
pub(super) struct Served {
    pub(super) since: Instant,
    pub(super) answers: usize,
    /// When each heads was last answered.
    pub(super) heads: HashMap<u64, Instant>,
}

impl ServeBudget {
    /// Fast rounds run point-to-point only, so only the unicast plane needs
    /// more than one answer per window.
    pub(super) fn limit(plane: Plane) -> usize {
        match plane {
            Plane::Unicast => ANTIENTROPY_SERVES_PER_WINDOW,
            Plane::Gossip => 1,
        }
    }

    /// Whether an answer to these heads may go out now.
    pub(crate) fn admits(
        &self,
        key: &(AuthorKey, Channel, Plane),
        heads: u64,
        now: Instant,
    ) -> bool {
        match self.windows.get(key) {
            Some(served) if now.duration_since(served.since) < ANTIENTROPY_SERVE_COOLDOWN => {
                // The same heads are answered again after the fast-round interval on
                // the unicast plane: the asker repeats them when an answer was lost.
                let repeat_too_soon = served.heads.get(&heads).is_some_and(|at| {
                    key.2 == Plane::Gossip || now.duration_since(*at) < FAST_ROUND_MIN_INTERVAL
                });
                !repeat_too_soon && served.answers < Self::limit(key.2)
            }
            _ => true,
        }
    }

    /// Record an answer to these heads, dropping windows that have ended.
    pub(crate) fn note(&mut self, key: (AuthorKey, Channel, Plane), heads: u64, now: Instant) {
        self.windows
            .retain(|_, served| now.duration_since(served.since) < ANTIENTROPY_SERVE_COOLDOWN);
        let served = self.windows.entry(key).or_insert_with(|| Served {
            since: now,
            answers: 0,
            heads: HashMap::new(),
        });
        served.answers += 1;
        served.heads.insert(heads, now);
    }
}
