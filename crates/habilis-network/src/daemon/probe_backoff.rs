//! The wait between two rival probes of a member that keeps finding the rival.
//!
//! A member that must probe before it claims the rendezvous starts a probe at each heal tick
//! while it holds no rendezvous. In a settled mesh every probe finds the rival, and every
//! probe costs an endpoint, a relay registration and a connection on the host. Each probe that
//! finds the rival now doubles the wait before the next one, from one heal interval up to
//! [`HEAL_PROBE_BACKOFF_MAX_SECS`]. A probe that reads the rendezvous as free holds nothing
//! back and starts the waits over, so the second free reading that a claim needs comes at the
//! next heal tick, as before.
//!
//! Only the heal tick is held back. The reclaim window, which a `NeighborDown` of the
//! rendezvous opens, probes at once, and so does anything that reopens the arbitration: see
//! [`ProbeBackoff::reset`].

use std::time::Duration;

use crate::util::clock::Instant;
use crate::util::tuning::{HEAL_PROBE_BACKOFF_MAX_SECS, heal_interval_secs};

/// The jitter on a wait, as a fraction either way, so that members that probed together do not
/// probe together again.
const JITTER: f64 = 0.2;

/// The exponent of the longest wait: 2^3 = 8 heal intervals.
const MAX_STEPS: u32 = 3;

/// A reclaim window that opens while the rival is still up resets the wait, and its own probes
/// find the rival and raise it again: up to 60 s at once, by design.
#[derive(Debug, Default)]
pub(crate) struct ProbeBackoff {
    /// Probes in a row that found the rival.
    rivals_in_a_row: u32,
    /// Before this instant no probe starts on the heal tick.
    next_at: Option<Instant>,
}

impl ProbeBackoff {
    /// Whether a probe may start on the heal tick at `now`.
    pub(crate) fn due(&self, now: Instant) -> bool {
        self.next_at.is_none_or(|next_at| now >= next_at)
    }

    /// A probe ended with `found_rival` at `now`. `spread` is a draw in `-1.0..=1.0` for the
    /// jitter.
    pub(crate) fn note_verdict(&mut self, found_rival: bool, now: Instant, spread: f64) {
        if found_rival {
            let wait = self.wait();
            self.rivals_in_a_row = self.rivals_in_a_row.saturating_add(1);
            self.next_at = Some(now + wait.mul_f64(1.0 + JITTER * spread.clamp(-1.0, 1.0)));
        } else {
            self.reset();
        }
    }

    /// The arbitration was reopened: a probe may start on the next heal tick, and the wait
    /// starts again at one heal interval.
    pub(crate) fn reset(&mut self) {
        self.rivals_in_a_row = 0;
        self.next_at = None;
    }

    /// The wait that the next probe finding the rival earns, before the jitter.
    fn wait(&self) -> Duration {
        let base = Duration::from_secs(heal_interval_secs());
        let longest = Duration::from_secs(HEAL_PROBE_BACKOFF_MAX_SECS).min(base * 2u32.pow(MAX_STEPS));
        (base * 2u32.pow(self.rivals_in_a_row.min(MAX_STEPS))).min(longest)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::ProbeBackoff;
    use crate::util::clock::Instant;

    fn secs(count: u64) -> Duration {
        Duration::from_secs(count)
    }

    /// A probe that finds the rival at `now`; returns how long until the next one may start.
    fn rival_at(backoff: &mut ProbeBackoff, now: Instant, spread: f64) -> Duration {
        backoff.note_verdict(true, now, spread);
        let mut wait = Duration::ZERO;
        while !backoff.due(now + wait) {
            wait += Duration::from_millis(100);
        }
        wait
    }

    #[test]
    fn a_probe_may_start_before_any_verdict() {
        assert!(ProbeBackoff::default().due(Instant::now()));
    }

    #[test]
    fn each_probe_that_finds_the_rival_doubles_the_wait_up_to_the_longest() {
        let mut backoff = ProbeBackoff::default();
        let now = Instant::now();
        let waits: Vec<Duration> = (0..5).map(|_| rival_at(&mut backoff, now, 0.0)).collect();
        assert_eq!(
            waits,
            vec![secs(15), secs(30), secs(60), secs(120), secs(120)]
        );
    }

    #[test]
    fn a_free_reading_lets_the_next_probe_start_at_the_next_tick_and_the_waits_start_over() {
        let mut backoff = ProbeBackoff::default();
        let now = Instant::now();
        for _ in 0..3 {
            rival_at(&mut backoff, now, 0.0);
        }
        backoff.note_verdict(false, now, 0.0);
        assert!(backoff.due(now), "the second free reading is not held back");
        assert_eq!(rival_at(&mut backoff, now, 0.0), secs(15));
    }

    #[test]
    fn a_reset_lets_a_probe_start_at_once_and_starts_the_waits_over() {
        let mut backoff = ProbeBackoff::default();
        let now = Instant::now();
        for _ in 0..4 {
            rival_at(&mut backoff, now, 0.0);
        }
        assert!(!backoff.due(now));
        backoff.reset();
        assert!(backoff.due(now));
        assert_eq!(rival_at(&mut backoff, now, 0.0), secs(15));
    }

    #[test]
    fn the_jitter_stays_within_a_fifth_either_way() {
        let now = Instant::now();
        let mut low = ProbeBackoff::default();
        let mut high = ProbeBackoff::default();
        assert_eq!(rival_at(&mut low, now, -1.0), secs(12));
        assert_eq!(rival_at(&mut high, now, 1.0), secs(18));
        let mut beyond = ProbeBackoff::default();
        assert_eq!(rival_at(&mut beyond, now, 7.0), secs(18), "a draw outside -1..1 is clamped");
    }
}
