use super::Plane;
use std::collections::HashMap;

use iroh::EndpointId;

use crate::protocol::{AuthorKey, Channel};
use crate::util::clock::Instant;
use crate::util::tuning::{
    ANTIENTROPY_SERVE_COOLDOWN, ANTIENTROPY_SERVES_PER_WINDOW, FAST_ROUND_MIN_INTERVAL,
};

/// Who is asking, for the budget. On gossip the digest reaches the whole mesh and a few members
/// answer it, so the asker is its author key. On unicast the asker is the connection that the digest
/// came on: a member mints author keys for free, so a budget for each key would give one connection
/// as many answers as it has keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Asker {
    Key(AuthorKey),
    Connection(EndpointId),
}

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
    pub(super) windows: HashMap<(Asker, Channel, Plane), Served>,
    /// The unicast form of the digests: the switch, the connection that the frame at hand came on,
    /// and the chat digest that is out.
    pub(crate) unicast: super::UnicastDigests,
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
    pub(crate) fn admits(&self, key: &(Asker, Channel, Plane), heads: u64, now: Instant) -> bool {
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

    /// Record an answer that went out on gossip, and, when it fell back from a unicast answer, the serve of
    /// the connection too.
    pub(crate) fn note_fallback(
        &mut self,
        gossip: (Asker, Channel, Plane),
        connection: Option<(Asker, Channel, Plane)>,
        heads: u64,
        now: Instant,
    ) {
        self.note(gossip, heads, now);
        if let Some(key) = connection {
            self.note(key, heads, now);
        }
    }

    /// Record an answer to these heads, dropping windows that have ended.
    pub(crate) fn note(&mut self, key: (Asker, Channel, Plane), heads: u64, now: Instant) {
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
