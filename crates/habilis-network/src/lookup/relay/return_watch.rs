use std::time::Duration;

use iroh::RelayUrl;
use n0_future::time::Instant;

/// The lower rung that a member homed on a later rung waits to return to, and since when that
/// rung answers every probe round.
#[derive(Debug, Default)]
pub(super) struct ReturnWatch {
    candidate: Option<(RelayUrl, Instant)>,
}

impl ReturnWatch {
    /// Note the lowest rung below the home that answered the probe round at `now`, or `None` when
    /// no rung below the home answered. Returns that rung once it answered every round for `hold`.
    /// A round that a lower rung wins, or that no rung wins, starts the wait again.
    pub(super) fn observe(
        &mut self,
        lowest: Option<RelayUrl>,
        now: Instant,
        hold: Duration,
    ) -> Option<RelayUrl> {
        let Some(lowest) = lowest else {
            self.candidate = None;
            return None;
        };
        let since = match self.candidate.take() {
            Some((rung, since)) if rung == lowest => since,
            Some(_) | None => now,
        };
        if now.duration_since(since) >= hold {
            return Some(lowest);
        }
        self.candidate = Some((lowest, since));
        None
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
                watch.observe(Some(rung("a")), start + ROUND * round, HOLD),
                None,
                "no return in round {round}, before the hold"
            );
        }
        assert_eq!(
            watch.observe(Some(rung("a")), start + ROUND * 3, HOLD),
            Some(rung("a")),
            "the rung answered every round for the hold"
        );
    }

    #[test]
    fn a_round_with_no_answer_starts_the_wait_again() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut watch = ReturnWatch::default();
        watch.observe(Some(rung("a")), start, HOLD);
        watch.observe(None, start + ROUND, HOLD);
        assert_eq!(
            watch.observe(Some(rung("a")), start + ROUND * 3, HOLD),
            None,
            "the rung missed a round, so its wait starts at round 3"
        );
        assert_eq!(
            watch.observe(Some(rung("a")), start + ROUND * 6, HOLD),
            Some(rung("a")),
            "the rung answered every round since round 3"
        );
    }

    #[test]
    fn a_rung_lower_still_starts_the_wait_again() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut watch = ReturnWatch::default();
        watch.observe(Some(rung("b")), start, HOLD);
        assert_eq!(
            watch.observe(Some(rung("a")), start + ROUND * 3, HOLD),
            None,
            "rung a starts to answer in round 3, so its wait starts there"
        );
        assert_eq!(
            watch.observe(Some(rung("a")), start + ROUND * 6, HOLD),
            Some(rung("a")),
            "rung a answered every round since round 3"
        );
    }
}
