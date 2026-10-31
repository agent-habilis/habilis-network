use std::collections::{HashMap, HashSet};
use std::time::Duration;

use crate::protocol::{AuthorKey, DedupKey};
use crate::util::clock::Instant;

/// How many times one frame is re-sent to one asker in a [`ANTIENTROPY_RESEND_WINDOW`]. Zero
/// turns the memory off: every digest is answered with every frame its author lacks, as before
/// the memory existed.
pub(crate) const ANTIENTROPY_RESEND_REPEATS: usize = 0;

/// The window in which [`ANTIENTROPY_RESEND_REPEATS`] counts.
pub(crate) const ANTIENTROPY_RESEND_WINDOW: Duration = Duration::from_secs(300);

/// The most pairs remembered. Past it the memory starts again, which only costs a repeat.
const MAX_REMEMBERED: usize = 8192;

#[derive(Debug, Clone, Copy)]
struct Sent {
    since: Instant,
    count: usize,
}

/// The frames that this node already re-sent to an asker, and how often. A digest is a pure
/// function of what its author holds, so an asker that cannot keep a frame lists it as missing
/// in every digest, and each answer re-floods the frame with a new nonce. The memory lets a
/// frame go to an asker `repeats` times in a `window`, and skips it after that. A frame that
/// was lost on the way is still sent again in the next round, and a frame that is still missing
/// when the window ends is sent again.
#[derive(Debug, Clone)]
pub(crate) struct ResendMemory {
    repeats: usize,
    window: Duration,
    sent: HashMap<(AuthorKey, DedupKey), Sent>,
}

impl Default for ResendMemory {
    fn default() -> Self {
        Self::new(ANTIENTROPY_RESEND_REPEATS, ANTIENTROPY_RESEND_WINDOW)
    }
}

impl ResendMemory {
    pub(crate) fn new(repeats: usize, window: Duration) -> Self {
        Self {
            repeats,
            window,
            sent: HashMap::new(),
        }
    }

    /// Add the frames that `asker` was sent `repeats` times in the window to `have`, so that
    /// the query skips them and its budget goes to the frames that were sent less often.
    pub(crate) fn extend_have(
        &self,
        asker: &AuthorKey,
        now: Instant,
        have: &mut HashSet<DedupKey>,
    ) {
        have.extend(
            self.sent
                .iter()
                .filter(|((sent_to, _), sent)| {
                    sent_to == asker
                        && sent.count >= self.repeats
                        && now.saturating_duration_since(sent.since) < self.window
                })
                .map(|((_, key), _)| *key),
        );
    }

    /// Remember that `key` was sent to `asker` now.
    pub(crate) fn note(&mut self, asker: AuthorKey, key: DedupKey, now: Instant) {
        if self.repeats == 0 {
            return;
        }
        if self.sent.len() >= MAX_REMEMBERED {
            self.sent.clear();
        }
        self.sent
            .retain(|_, sent| now.saturating_duration_since(sent.since) < self.window);
        self.sent
            .entry((asker, key))
            .and_modify(|sent| sent.count += 1)
            .or_insert(Sent {
                since: now,
                count: 1,
            });
    }
}
