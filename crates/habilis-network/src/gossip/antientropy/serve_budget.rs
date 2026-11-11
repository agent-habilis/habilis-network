use super::Plane;
use std::collections::HashMap;

use iroh::EndpointId;

use crate::protocol::{AuthorKey, Channel};
use crate::util::clock::Instant;
use crate::util::tuning::{
    ANTIENTROPY_SERVE_COOLDOWN, ANTIENTROPY_SERVES_PER_WINDOW, FAST_ROUND_MIN_INTERVAL,
};

/// The most windows that the budget keeps. A digest names any author key, so a member feeds this
/// map from outside: without a cap one burst of digests under fresh keys holds a window for each
/// key, and the scan for the windows that ended grows with them. A window that goes early gives
/// its asker one answer more, which is what an asker that never asked gets anyway.
const WINDOWS_MAX: usize = 256;

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

    /// Room for one window more, at the cap: the windows that ended go first, and then the oldest
    /// of the ones that are live. A window that ended holds no answer back ([`Self::admits`] reads
    /// its age), so it is kept until the cap for the scan that it saves.
    fn make_room(&mut self, now: Instant) {
        if self.windows.len() < WINDOWS_MAX {
            return;
        }
        self.windows
            .retain(|_, served| now.duration_since(served.since) < ANTIENTROPY_SERVE_COOLDOWN);
        while self.windows.len() >= WINDOWS_MAX {
            let oldest = self.windows.iter().min_by_key(|(_, served)| served.since);
            let Some(key) = oldest.map(|(key, _)| *key) else {
                return;
            };
            self.windows.remove(&key);
        }
    }

    /// Record an answer to these heads, inside the cap of the windows.
    pub(crate) fn note(&mut self, key: (Asker, Channel, Plane), heads: u64, now: Instant) {
        if !self.windows.contains_key(&key) {
            self.make_room(now);
        }
        let served = self.windows.entry(key).or_insert_with(|| Served {
            since: now,
            answers: 0,
            heads: HashMap::new(),
        });
        // A window that ended starts again at this answer. `admits` reads the age of `since`, so a
        // window that keeps the old one stays ended: from there it admits every ask, and the map of
        // its heads grows with every answer. The cooldown is longer than `FAST_ROUND_MIN_INTERVAL`,
        // so no heads of the window that ended would hold a repeat back.
        if now.duration_since(served.since) >= ANTIENTROPY_SERVE_COOLDOWN {
            served.since = now;
            served.answers = 0;
            served.heads.clear();
        }
        served.answers += 1;
        served.heads.insert(heads, now);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::Plane;
    use super::{Asker, ServeBudget, WINDOWS_MAX};
    use crate::protocol::Channel;
    use crate::testing;
    use crate::util::clock::Instant;
    use crate::util::tuning::ANTIENTROPY_SERVE_COOLDOWN;

    /// A window that ended starts again at the answer that follows it. `admits` reads the age of
    /// `since`, so a window that keeps the `since` of the window that ended stays ended: from there
    /// it holds no answer back, and the map of its heads grows with every one of them.
    #[test]
    fn a_window_that_ended_starts_again_at_the_answer_that_follows_it() {
        let mut budget = ServeBudget::default();
        let now = Instant::now();
        let asker = Asker::Key(testing::test_key("asker"));
        let key = (asker, Channel::State, Plane::Gossip);
        budget.note(key, 1, now);
        let later = now + ANTIENTROPY_SERVE_COOLDOWN + Duration::from_secs(1);
        assert!(budget.admits(&key, 2, later), "the first window ended");
        budget.note(key, 2, later);

        assert!(
            !budget.admits(&key, 3, later),
            "one gossip answer per window, and the answer at the end of the first window opened a \
             window of its own"
        );
    }

    /// One member mints author keys for free, and a digest names any of them: the map of the
    /// windows stays inside its cap when it is fed 10 times the cap inside one window.
    #[test]
    fn the_windows_stay_inside_their_cap_when_they_are_fed_10_times_the_cap() {
        let mut budget = ServeBudget::default();
        let now = Instant::now();
        let fed = WINDOWS_MAX * 10;
        for index in 0..fed {
            let asker = Asker::Key(testing::test_key(&format!("asker-{index}")));
            let heads = u64::try_from(index).unwrap_or(u64::MAX);
            budget.note((asker, Channel::State, Plane::Gossip), heads, now);
        }

        assert!(
            budget.windows.len() <= WINDOWS_MAX,
            "{fed} askers of one window must leave at most {WINDOWS_MAX} windows, and {} are held",
            budget.windows.len()
        );
    }
}
