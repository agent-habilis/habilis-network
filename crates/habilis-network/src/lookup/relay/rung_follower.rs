use std::time::Duration;

use iroh::RelayUrl;
use n0_future::time::Instant;

use super::return_watch::ReturnWatch;
use super::{HomingTimes, next_return_wait, rungs_below, rungs_to_walk, should_evict_rung};

/// The state of a member that follows its ladder, with no timer and no I/O. The driver
/// (`follow_rung`) feeds it the events (a liveness read, a walk, a return round, a move) with the
/// time of each, and does what it decides: walk now, move to a rung, start a return round, and read
/// the liveness at a time.
#[derive(Debug)]
pub(super) struct RungFollower<'ladder> {
    ladder: &'ladder [RelayUrl],
    rung: RelayUrl,
    times: HomingTimes,
    fails: u32,
    /// The first walk of a rung that never connected does not probe it again: the probe would wait
    /// out its time. A later walk probes the whole ladder, because a net report under load can drop
    /// the preferred relay of a live rung, and the walk must be able to stay on it.
    skip_rung: bool,
    next_read: Instant,
    watch: ReturnWatch,
    return_wait: Duration,
    next_round: Instant,
    round_runs: bool,
}

impl<'ladder> RungFollower<'ladder> {
    /// A follower on `rung` at `now`. A rung that did not connect in the probe time counts as
    /// dead at once, so the first call to [`Self::walk_due`] walks.
    pub(super) fn new(
        ladder: &'ladder [RelayUrl],
        rung: RelayUrl,
        times: HomingTimes,
        connected: bool,
        now: Instant,
    ) -> Self {
        Self {
            ladder,
            rung,
            times,
            fails: if connected {
                0
            } else {
                super::RELAY_LIVENESS_FAILS_TO_EVICT
            },
            skip_rung: !connected,
            next_read: now + times.interval,
            watch: ReturnWatch::default(),
            return_wait: times.return_every,
            next_round: now + times.return_every,
            round_runs: false,
        }
    }

    /// The rung that the member is on.
    pub(super) fn rung(&self) -> &RelayUrl {
        &self.rung
    }

    /// The time of the next liveness read.
    pub(super) fn read_at(&self) -> Instant {
        self.next_read
    }

    /// The rungs to walk now, after enough failed reads. The driver stops the return round in
    /// flight first: a walk ends it.
    pub(super) fn walk_due(&mut self) -> Option<Vec<RelayUrl>> {
        if !should_evict_rung(self.fails) {
            return None;
        }
        self.fails = 0;
        self.round_runs = false;
        let walk = rungs_to_walk(self.ladder, &self.rung, self.skip_rung);
        self.skip_rung = false;
        Some(walk)
    }

    /// Note the rung that a walk picked at `now`. Returns the rung to move to, or `None` to stay:
    /// the walk found no rung, or found the same rung. The rung failed either way, so the waits of
    /// the lower rungs start over.
    pub(super) fn walked(&mut self, selected: Option<RelayUrl>, now: Instant) -> Option<RelayUrl> {
        self.restart(now);
        selected.filter(|next| *next != self.rung)
    }

    /// Note a liveness read at `now`.
    pub(super) fn read(&mut self, alive: bool, now: Instant) {
        self.next_read = now + self.times.interval;
        self.fails = if alive { 0 } else { self.fails + 1 };
    }

    /// The rungs of a return round to start at `now`: on a later rung whose last read was alive,
    /// with no round in flight, once the wait of the round ends.
    pub(super) fn round_due(&mut self, now: Instant) -> Option<Vec<RelayUrl>> {
        let below = rungs_below(self.ladder, &self.rung);
        if self.fails > 0 || self.round_runs || below.is_empty() || now < self.next_round {
            return None;
        }
        self.round_runs = true;
        Some(below.to_vec())
    }

    /// Note the rungs that answered the return round that ended at `completed_at`, read at `now`.
    /// Returns the rung to return to, once it answered every round for the hold. The round counts
    /// at the time that it ended, not at the time that the member read it: after a stall, the gap
    /// to the round before it is long, and the streak starts again.
    pub(super) fn round_ended(
        &mut self,
        answered: &[RelayUrl],
        completed_at: Instant,
        now: Instant,
    ) -> Option<RelayUrl> {
        self.round_runs = false;
        // This round was due one wait (the current one, which doubles after empty rounds) after the
        // last, started at the next pass of the loop (a read interval at most), and ended within
        // the probe time. A longer gap had no round, so it is no evidence for the hold.
        let max_gap = self.return_wait + self.times.interval + self.times.probe;
        self.return_wait = next_return_wait(self.return_wait, !answered.is_empty(), self.times);
        self.next_round = now + self.return_wait;
        self.watch
            .observe(answered, completed_at, self.times.return_hold, max_gap)
    }

    /// Note the move of the member to `rung`, done at `now`. The failed reads of the old rung say
    /// nothing of the new one, and the next read comes one interval after the move.
    pub(super) fn moved(&mut self, rung: RelayUrl, now: Instant) {
        self.rung = rung;
        self.fails = 0;
        self.restart(now);
    }

    /// Start the read schedule and the waits of the lower rungs over from `now`.
    fn restart(&mut self, now: Instant) {
        self.next_read = now + self.times.interval;
        self.watch = ReturnWatch::default();
        self.return_wait = self.times.return_every;
        self.next_round = now + self.times.return_every;
        self.round_runs = false;
    }
}

#[cfg(test)]
mod tests {
    use super::RungFollower;
    use crate::lookup::relay::HomingTimes;
    use crate::util::tuning::RELAY_LIVENESS_FAILS_TO_EVICT;
    use iroh::RelayUrl;
    use n0_future::time::Instant;
    use std::time::Duration;

    const TIMES: HomingTimes = HomingTimes {
        probe: Duration::from_secs(2),
        interval: Duration::from_secs(1),
        return_every: Duration::from_mins(1),
        return_backoff_max: Duration::from_mins(5),
        return_hold: Duration::from_mins(3),
    };

    fn rung(host: &str) -> RelayUrl {
        format!("https://{host}.example/")
            .parse()
            .expect("a test host forms a valid https URL")
    }

    fn ladder() -> Vec<RelayUrl> {
        vec![rung("a"), rung("b"), rung("c")]
    }

    /// Run a return round at `now` that `answered` answer. Returns the rung to return to.
    fn round(
        follower: &mut RungFollower<'_>,
        answered: &[RelayUrl],
        now: Instant,
    ) -> Option<RelayUrl> {
        let below = follower.round_due(now).expect("a return round is due");
        assert!(!below.is_empty(), "a round probes at least 1 rung");
        follower.round_ended(answered, now, now)
    }

    /// Fail enough reads in a row at `now` to walk.
    fn fail_until_walk(follower: &mut RungFollower<'_>, now: Instant) -> Vec<RelayUrl> {
        for _ in 0..RELAY_LIVENESS_FAILS_TO_EVICT {
            assert_eq!(
                follower.walk_due(),
                None,
                "no walk before the last failed read"
            );
            follower.read(false, now);
        }
        follower.walk_due().expect("the failed reads walk")
    }

    #[test]
    fn a_rung_that_did_not_connect_walks_at_once_without_itself() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let mut follower = RungFollower::new(&ladder, rung("a"), TIMES, false, Instant::now());
        assert_eq!(
            follower.walk_due(),
            Some(vec![rung("b"), rung("c")]),
            "the first walk does not wait out the probe of a rung that never connected"
        );
        assert_eq!(follower.walk_due(), None, "the walk reset the failed reads");
    }

    #[test]
    fn a_later_walk_probes_the_rung_too() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("a"), TIMES, false, start);
        let first = follower
            .walk_due()
            .expect("a rung that never connected walks");
        assert_eq!(
            first,
            vec![rung("b"), rung("c")],
            "the first walk skips the rung"
        );
        assert_eq!(
            follower.walked(None, start),
            None,
            "a walk that finds no rung stays"
        );
        assert_eq!(
            fail_until_walk(&mut follower, start),
            ladder,
            "a later walk can stay on a live rung that a net report under load dropped"
        );
    }

    #[test]
    fn one_failed_read_does_not_walk_and_a_live_read_clears_it() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("a"), TIMES, true, start);
        assert_eq!(follower.walk_due(), None, "a connected rung does not walk");
        follower.read(false, start);
        assert_eq!(follower.walk_due(), None, "1 failed read is a blip");
        follower.read(true, start);
        follower.read(false, start);
        assert_eq!(
            follower.walk_due(),
            None,
            "a live read between 2 failed reads starts the count over"
        );
        follower.read(false, start);
        assert_eq!(
            follower.walk_due(),
            Some(ladder),
            "2 failed reads in a row walk"
        );
    }

    #[test]
    fn each_read_schedules_the_next_one_interval_later() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("a"), TIMES, true, start);
        assert_eq!(follower.read_at(), start + TIMES.interval, "the first read");
        let late = start + Duration::from_secs(7);
        follower.read(true, late);
        assert_eq!(
            follower.read_at(),
            late + TIMES.interval,
            "a read schedules from itself"
        );
    }

    #[test]
    fn a_walk_moves_only_to_another_rung() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("b"), TIMES, true, start);
        assert_eq!(
            follower.walked(None, start),
            None,
            "a walk that finds no rung stays"
        );
        assert_eq!(
            follower.walked(Some(rung("b")), start),
            None,
            "a walk that picks the same rung stays"
        );
        assert_eq!(
            follower.walked(Some(rung("c")), start),
            Some(rung("c")),
            "a walk that picks another rung moves"
        );
        assert_eq!(
            follower.rung(),
            &rung("b"),
            "only the move changes the rung"
        );
        follower.moved(rung("c"), start);
        assert_eq!(follower.rung(), &rung("c"), "the move changes the rung");
    }

    #[test]
    fn a_lower_rung_that_answers_for_the_hold_is_the_return() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("c"), TIMES, true, start);
        assert_eq!(
            follower.round_due(start),
            None,
            "the first round waits 1 interval"
        );
        for minute in 1..4 {
            let now = start + TIMES.return_every * minute;
            assert_eq!(
                round(&mut follower, &[rung("a")], now),
                None,
                "minute {minute}"
            );
        }
        let now = start + TIMES.return_every * 4;
        assert_eq!(
            round(&mut follower, &[rung("a"), rung("b")], now),
            Some(rung("a")),
            "rung 0 answered every round for the hold"
        );
    }

    #[test]
    fn a_return_round_waits_for_a_live_read_and_runs_alone() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("c"), TIMES, true, start);
        let due = start + TIMES.return_every;
        follower.read(false, due);
        assert_eq!(
            follower.round_due(due),
            None,
            "no round on a rung that just failed a read"
        );
        follower.read(true, due);
        assert!(
            follower.round_due(due).is_some(),
            "the round starts after a live read"
        );
        assert_eq!(follower.round_due(due), None, "1 round at a time");
    }

    #[test]
    fn a_return_round_that_finds_no_rung_doubles_the_wait() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("c"), TIMES, true, start);
        let first = start + TIMES.return_every;
        assert_eq!(round(&mut follower, &[], first), None, "no rung answered");
        let doubled = first + TIMES.return_every * 2;
        assert_eq!(
            follower.round_due(doubled - Duration::from_secs(1)),
            None,
            "the next round waits 2 intervals"
        );
        assert!(
            follower.round_due(doubled).is_some(),
            "the round after the doubled wait"
        );
    }

    #[test]
    fn a_walk_ends_the_return_round_in_flight() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("c"), TIMES, true, start);
        let due = start + TIMES.return_every;
        assert!(follower.round_due(due).is_some(), "a round starts");
        fail_until_walk(&mut follower, due);
        assert_eq!(follower.walked(None, due), None, "the walk stays on rung 2");
        let next = due + TIMES.return_every;
        follower.read(true, next);
        assert!(
            follower.round_due(next).is_some(),
            "the walk ended the round, so a new round can start"
        );
    }

    /// **After an eviction walk that stays on the rung, the waits of the lower rungs start over.**
    ///
    /// Rung 0 answers 3 rounds, then the member fails its reads and walks, and the walk stays on
    /// rung 2. Rung 2 failed, so the rounds of rung 0 before the walk do not count to the hold.
    #[test]
    fn a_walk_that_stays_starts_the_waits_of_the_lower_rungs_over() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("c"), TIMES, true, start);
        for minute in 1..4 {
            let now = start + TIMES.return_every * minute;
            assert_eq!(
                round(&mut follower, &[rung("a")], now),
                None,
                "minute {minute}"
            );
        }
        let walked_at = start + TIMES.return_every * 3 + Duration::from_secs(30);
        fail_until_walk(&mut follower, walked_at);
        assert_eq!(
            follower.walked(Some(rung("c")), walked_at),
            None,
            "the walk stays"
        );
        let after = walked_at + TIMES.return_every;
        follower.read(true, after);
        assert_eq!(
            round(&mut follower, &[rung("a")], after),
            None,
            "rung 0 answered 1 round since the walk, not the hold"
        );
    }

    /// **After a return in place, the next read comes one interval after the move.**
    ///
    /// A read due before the move would read the new rung before it connects, and count a
    /// failure.
    #[test]
    fn a_return_schedules_the_next_read_from_the_move() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("c"), TIMES, true, start);
        let mut lower = None;
        for minute in 1..5 {
            lower = round(
                &mut follower,
                &[rung("a")],
                start + TIMES.return_every * minute,
            );
        }
        let lower = lower.expect("rung 0 answered for the hold");
        let moved_at = start + TIMES.return_every * 4 + Duration::from_millis(300);
        follower.moved(lower, moved_at);
        assert_eq!(
            follower.read_at(),
            moved_at + TIMES.interval,
            "the next read is one interval after the move"
        );
    }

    /// **After a move, the failed reads of the old rung do not count.**
    ///
    /// A read of the old rung fails while the return round runs, and the round returns. One failed
    /// read of the new rung is a blip, not the second failure of a walk.
    #[test]
    fn a_move_starts_the_failed_reads_over() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("c"), TIMES, true, start);
        for minute in 1..4 {
            round(
                &mut follower,
                &[rung("a")],
                start + TIMES.return_every * minute,
            );
        }
        let last = start + TIMES.return_every * 4;
        follower.read(true, last);
        assert!(follower.round_due(last).is_some(), "the last round starts");
        follower.read(false, last);
        let lower = follower
            .round_ended(&[rung("a")], last, last)
            .expect("rung 0 answered for the hold");
        follower.moved(lower, last);
        follower.read(false, last + TIMES.interval);
        assert_eq!(
            follower.walk_due(),
            None,
            "1 failed read of the new rung is a blip"
        );
    }

    /// **A round after a backed-off wait is not a gap.**
    ///
    /// Rung 0 answers, misses a round, and the wait doubles to 2 minutes. The round after that wait
    /// is on time, so the rung returns 3 minutes after it answered again, not later.
    #[test]
    fn a_round_after_a_backed_off_wait_counts_to_the_hold() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("c"), TIMES, true, start);
        let minute = |count: u32| start + TIMES.return_every * count;
        assert_eq!(
            round(&mut follower, &[rung("a")], minute(1)),
            None,
            "minute 1"
        );
        assert_eq!(
            round(&mut follower, &[], minute(2)),
            None,
            "rung 0 misses minute 2"
        );
        assert_eq!(
            follower.round_due(minute(3)),
            None,
            "the wait doubled, so no round at minute 3"
        );
        for count in 4..7 {
            assert_eq!(
                round(&mut follower, &[rung("a")], minute(count)),
                None,
                "minute {count}"
            );
        }
        assert_eq!(
            round(&mut follower, &[rung("a")], minute(7)),
            Some(rung("a")),
            "rung 0 answered every round for the hold since minute 4"
        );
    }

    /// **A round after a stall of the member is a gap.**
    ///
    /// Rung 0 answers 1 round, then the member stalls for 3 minutes. The answer before the stall
    /// does not count: the hold starts at the round after it.
    #[test]
    fn a_round_after_a_stall_starts_the_hold_again() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("c"), TIMES, true, start);
        let minute = |count: u32| start + TIMES.return_every * count;
        assert_eq!(
            round(&mut follower, &[rung("a")], minute(1)),
            None,
            "minute 1"
        );
        for count in 4..7 {
            assert_eq!(
                round(&mut follower, &[rung("a")], minute(count)),
                None,
                "minute {count}"
            );
        }
        assert_eq!(
            round(&mut follower, &[rung("a")], minute(7)),
            Some(rung("a")),
            "the hold counts from minute 4, the first round after the stall"
        );
    }

    /// **A round that ended before a stall of the member does not start the hold at the resume.**
    ///
    /// Rung 0 answers a round, the member stalls, and the next round ends just before the stall
    /// and is read after it. Its answer is old: the rung can be down since. It must not count as the
    /// first sample of a new streak, or the member returns after 2 minutes of live answers, not 3.
    #[test]
    fn a_round_read_after_a_stall_is_not_the_first_sample_of_a_streak() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("c"), TIMES, true, start);
        let minute = |count: u32| start + TIMES.return_every * count;
        assert_eq!(
            round(&mut follower, &[rung("a")], minute(1)),
            None,
            "minute 1"
        );
        let ended_at = minute(2);
        assert!(follower.round_due(ended_at).is_some(), "minute 2 starts");
        let resumed_at = minute(7);
        assert_eq!(
            follower.round_ended(&[rung("a")], ended_at, resumed_at),
            None,
            "an old answer returns nothing"
        );
        for count in 1..4 {
            assert_eq!(
                round(
                    &mut follower,
                    &[rung("a")],
                    resumed_at + TIMES.return_every * count
                ),
                None,
                "live round {count} after the resume: the old answer is no sample"
            );
        }
        assert_eq!(
            round(
                &mut follower,
                &[rung("a")],
                resumed_at + TIMES.return_every * 4
            ),
            Some(rung("a")),
            "3 minutes after the first live round"
        );
    }

    /// **A round that the member reads at once keeps its credit.**
    #[test]
    fn a_round_read_at_once_counts_to_the_hold() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = ladder();
        let start = Instant::now();
        let mut follower = RungFollower::new(&ladder, rung("c"), TIMES, true, start);
        let lag = TIMES.interval / 2;
        let mut returned = None;
        for count in 1..5 {
            let ended_at = start + (TIMES.return_every + lag) * count;
            assert!(
                follower.round_due(ended_at).is_some(),
                "round {count} starts"
            );
            returned = follower.round_ended(&[rung("a")], ended_at, ended_at + lag);
        }
        assert_eq!(
            returned,
            Some(rung("a")),
            "4 rounds, read within a read interval of their end, make the hold"
        );
    }
}
