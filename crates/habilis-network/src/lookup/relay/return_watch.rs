use std::mem;
use std::time::Duration;

use iroh::RelayUrl;
use n0_future::time::Instant;

/// The lower rungs that a member homed on a later rung can return to, each with the time since
/// which it answered every probe round.
#[derive(Debug, Default)]
pub(super) struct ReturnWatch {
    answering: Vec<(RelayUrl, Instant)>,
}

impl ReturnWatch {
    /// Note the rungs below the home that answered the probe round at `now`, lowest first. Returns
    /// the lowest rung that answered every round for `hold`. A rung that misses a round starts its
    /// own wait again, and only its own: a rung that flaps does not hold back a steady one.
    pub(super) fn observe(
        &mut self,
        answered: &[RelayUrl],
        now: Instant,
        hold: Duration,
    ) -> Option<RelayUrl> {
        let previous = mem::take(&mut self.answering);
        for rung in answered {
            let seen = previous.iter().find(|(seen, _)| seen == rung);
            let since = seen.map_or(now, |(_, since)| *since);
            self.answering.push((rung.clone(), since));
        }
        let (held_rung, _) = self
            .answering
            .iter()
            .find(|(_, since)| now.duration_since(*since) >= hold)?;
        Some(held_rung.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::ReturnWatch;
    use iroh::RelayUrl;
    use n0_future::time::Instant;
    use std::time::Duration;

    const HOLD: Duration = Duration::from_mins(3);
    const ROUND: Duration = Duration::from_mins(1);

    fn rung(host: &str) -> RelayUrl {
        format!("https://{host}.example/")
            .parse()
            .expect("a test host forms a valid https URL")
    }

    #[test]
    fn a_lower_rung_that_answers_for_the_hold_wins() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut watch = ReturnWatch::default();
        for round in 0..3 {
            assert_eq!(
                watch.observe(&[rung("a")], start + ROUND * round, HOLD),
                None,
                "no return in round {round}, before the hold"
            );
        }
        assert_eq!(
            watch.observe(&[rung("a")], start + ROUND * 3, HOLD),
            Some(rung("a")),
            "the rung answered every round for the hold"
        );
    }

    #[test]
    fn a_round_with_no_answer_starts_the_wait_again() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut watch = ReturnWatch::default();
        watch.observe(&[rung("a")], start, HOLD);
        watch.observe(&[], start + ROUND, HOLD);
        assert_eq!(
            watch.observe(&[rung("a")], start + ROUND * 3, HOLD),
            None,
            "the rung missed a round, so its wait starts at round 3"
        );
        assert_eq!(
            watch.observe(&[rung("a")], start + ROUND * 6, HOLD),
            Some(rung("a")),
            "the rung answered every round since round 3"
        );
    }

    /// **A rung that flaps does not hold back a steady rung above it.**
    ///
    /// The member is on rung 3. Rung 1 answers every second round, and rung 2 answers every
    /// round. The member returns to rung 2 after the hold, not to rung 1, and not never.
    #[test]
    fn a_flapping_rung_does_not_hold_back_a_steady_rung() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut watch = ReturnWatch::default();
        let (flapping, steady) = (rung("b"), rung("c"));
        let mut returned = None;
        for round in 0..4 {
            let answered = if round % 2 == 0 {
                vec![flapping.clone(), steady.clone()]
            } else {
                vec![steady.clone()]
            };
            returned = watch.observe(&answered, start + ROUND * round, HOLD);
        }
        assert_eq!(
            returned,
            Some(steady),
            "the steady rung 2 answered every round for the hold"
        );
    }

    /// Once the flapping rung is steady for the hold too, it wins: it is the lower rung.
    #[test]
    fn the_lowest_rung_that_answered_for_the_hold_wins() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut watch = ReturnWatch::default();
        let both = [rung("b"), rung("c")];
        for round in 0..3 {
            watch.observe(&both, start + ROUND * round, HOLD);
        }
        assert_eq!(
            watch.observe(&both, start + ROUND * 3, HOLD),
            Some(rung("b")),
            "both rungs answered for the hold, and rung 1 is the lower one"
        );
    }
}
