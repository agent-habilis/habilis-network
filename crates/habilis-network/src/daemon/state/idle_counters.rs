//! Wakeup attribution for the idle-cost work: one counter per `select!` arm,
//! the wakes of the two tickers that run off the loop, and the CPU time the
//! process used. All of it is reported as a delta on each `mesh census` line.

use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use iroh_gossip::api::{ApiError, Event};

use super::gossip_msgs::GossipMsgs;
use super::socket_bytes::{GossipPathBytes, SocketBytes};
use super::wire_out_tally::{WireIn, WireOut, WireOutTally};
use crate::util::process_usage;

/// Wakes of the orphan watch (`daemon::shutdown`). It is a task of its own, so
/// it cannot reach the event loop's `&mut` counters.
static PPID_WAKES: AtomicU64 = AtomicU64::new(0);
/// Wakes of the admission sampler (`transport::admission`), for the same reason.
static SAMPLER_WAKES: AtomicU64 = AtomicU64::new(0);

/// Count one wake of the orphan watch.
#[cfg(any(all(unix, feature = "host"), test))]
pub(crate) fn note_ppid_wake() {
    PPID_WAKES.fetch_add(1, Ordering::Relaxed);
}

/// Count one wake of the admission sampler.
pub(crate) fn note_sampler_wake() {
    SAMPLER_WAKES.fetch_add(1, Ordering::Relaxed);
}

/// Wakeup attribution, one counter per `select!` arm, reset on each census.
///
/// Plain `u64`, not atomics — the event loop owns `&mut EventLoopState`, so a
/// bump is an increment with no synchronization. That matters more than it
/// looks: the arms being measured fire up to 150×/min, and the cheapest thing
/// that could observe them (a `debug!` per tick) costs a write per wakeup and
/// would price its own instrumentation into the measurement.
///
/// Counting arms rather than timers is deliberate. It splits timer work from
/// inbound traffic, which is the split that says whether an idle daemon is
/// paying for its own housekeeping or for the peers talking to it.
#[derive(Clone, Default, Debug)]
pub(crate) struct IdleCounters {
    /// Every loop iteration, whichever arm won. The denominator for the rest.
    pub wakeups: u64,
    pub prune: u64,
    pub alive: u64,
    pub sweep: u64,
    pub heal: u64,
    pub reclaim: u64,
    pub backfill: u64,
    pub state_refresh: u64,
    pub linkstate: u64,
    /// The arm of a build of a seed that ended. It is no timer and no inbound frame: the tick of a
    /// cut started the build, and the loop wakes when it is done.
    pub seed_built: u64,
    /// The arms driven by something other than a maintenance timer. Their sum
    /// is the census field `idle_external`.
    pub ext: ExternalArms,
    /// Signed frames put on the wire by a maintenance tick. The direct cost
    /// driver behind `user` CPU: each one is an Ed25519 signature plus a
    /// serialization.
    pub broadcasts: u64,
    /// Authenticated frames that the app dedup dropped as already seen.
    pub duplicates: u64,
    /// Authenticated frames that the app dedup kept as first sightings. With `duplicates`, it
    /// gives the frames per interval that reached the dedup.
    pub fresh: u64,
    /// The frames received in the interval, by kind and by what became of them.
    pub wire_in: WireIn,
    /// The process CPU time at the last census. It is not reset by `take`.
    cpu_mark: Duration,
    /// The readings of the socket, the gossip transport and the gossip actor at the last census.
    /// They belong to this loop, whose endpoint they read, so two loops in one process do not
    /// take each other's bytes. `take` keeps them.
    pub(crate) socket_mark: SocketBytes,
    pub(crate) gossip_path_mark: GossipPathBytes,
    pub(crate) gossip_msgs_mark: Option<GossipMsgs>,
    /// The frames that the senders of this loop sent in the interval. The senders hold a clone.
    /// `take` keeps the handle and empties what it holds.
    pub(crate) wire_out: WireOutTally,
}

/// The wakes of each arm that is not a maintenance timer.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct ExternalArms {
    pub gossip_rx: u64,
    pub neighbor_up: u64,
    pub neighbor_down: u64,
    pub lagged: u64,
    /// The gossip stream ended or gave an error.
    pub gossip_end: u64,
    pub unicast: u64,
    /// The chunk requests that the event loop answered.
    pub chunk: u64,
    pub path_rx: u64,
    pub address: u64,
    pub direct_rx: u64,
    pub rung_change: u64,
    pub rung_report: u64,
    pub probe_verdict: u64,
    pub ipc: u64,
    pub http: u64,
    pub session: u64,
    /// The ping round, the app poll and the app deadline arms.
    pub deadlines: u64,
    /// The flush-failed, slot-freed, underlay-slot, route-wake and LAN arms.
    pub other: u64,
}

impl ExternalArms {
    /// Count one wake of the gossip arm, by the kind of event it carried.
    pub(crate) fn note_gossip(&mut self, event: Option<&Result<Event, ApiError>>) {
        let slot = match event {
            Some(Ok(Event::Received(_))) => &mut self.gossip_rx,
            Some(Ok(Event::NeighborUp(_))) => &mut self.neighbor_up,
            Some(Ok(Event::NeighborDown(_))) => &mut self.neighbor_down,
            Some(Ok(Event::Lagged)) => &mut self.lagged,
            Some(Err(_)) | None => &mut self.gossip_end,
        };
        *slot += 1;
    }

    /// The sum of every arm: the census field `idle_external`.
    #[must_use]
    pub(crate) fn total(&self) -> u64 {
        self.gossip_rx
            + self.neighbor_up
            + self.neighbor_down
            + self.lagged
            + self.gossip_end
            + self.unicast
            + self.chunk
            + self.path_rx
            + self.address
            + self.direct_rx
            + self.rung_change
            + self.rung_report
            + self.probe_verdict
            + self.ipc
            + self.http
            + self.session
            + self.deadlines
            + self.other
    }
}

/// What one census reports: the loop counters, the off-loop ticker wakes and
/// the CPU time of the interval.
#[derive(Debug)]
pub(crate) struct IdleReading {
    pub loop_arms: IdleCounters,
    pub ppid: u64,
    pub sampler: u64,
    /// The frames sent in the interval. They are kept off the loop, where the send paths run.
    pub wire_out: WireOut,
    /// `None` where the platform gives no process CPU clock.
    pub cpu: Option<Duration>,
}

impl IdleCounters {
    /// Read the counters and zero them, so each census line carries the
    /// interval's own work rather than a running total a reader has to
    /// difference (and that a rotated log would corrupt).
    pub(crate) fn take(&mut self) -> IdleReading {
        let cpu_now = process_usage::cpu_time();
        let mark = self.cpu_mark;
        let mut loop_arms = mem::take(self);
        self.cpu_mark = cpu_now.unwrap_or(mark);
        self.socket_mark = mem::take(&mut loop_arms.socket_mark);
        self.gossip_path_mark = mem::take(&mut loop_arms.gossip_path_mark);
        self.gossip_msgs_mark = loop_arms.gossip_msgs_mark.take();
        self.wire_out = mem::take(&mut loop_arms.wire_out);
        let wire_out = self.wire_out.take();
        IdleReading {
            loop_arms,
            ppid: PPID_WAKES.swap(0, Ordering::Relaxed),
            sampler: SAMPLER_WAKES.swap(0, Ordering::Relaxed),
            wire_out,
            cpu: cpu_now.map(|now| now.saturating_sub(mark)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hint::black_box;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use iroh_gossip::api::Event;

    use super::{IdleCounters, note_ppid_wake, note_sampler_wake};

    /// `take` drains process-wide statics, so the tests that call it run one at a time.
    static TAKES: Mutex<()> = Mutex::new(());

    #[test]
    fn two_loops_take_only_the_frames_that_their_own_senders_sent() {
        let _one_at_a_time = TAKES.lock().expect("another census test panicked");
        let (mut first, mut second) = (IdleCounters::default(), IdleCounters::default());
        let frame = br#"{"v":"18.0","id":"i","type":"app","tag":"t","mesh":"m","author":"a","ts":1,"body":"b","pubkey":"ab","sig":"cd","ext":{}}"#;
        let handle_of_first = first.wire_out.clone();

        handle_of_first.note(frame);
        let second_reading = second.take();
        let first_reading = first.take();

        assert_eq!(
            second_reading.wire_out.frames, 0,
            "the other loop took nothing"
        );
        assert_eq!(
            first_reading.wire_out.frames, 1,
            "one frame was handed to the transport"
        );
        assert_eq!(
            first_reading.wire_out.wire,
            frame.len() as u64,
            "the wire bytes are the length of the frame"
        );

        handle_of_first.note(frame);

        assert_eq!(
            first.take().wire_out.frames,
            1,
            "take keeps the handle that the senders hold"
        );
    }

    #[test]
    fn take_zeroes_the_arms_and_sums_the_external_split() {
        let _drain = TAKES.lock().expect("another census test panicked");
        let mut counters = IdleCounters {
            reclaim: 3,
            duplicates: 4,
            fresh: 6,
            ..IdleCounters::default()
        };
        counters.ext.note_gossip(Some(&Ok(Event::Lagged)));
        counters.ext.note_gossip(None);
        counters.ext.unicast += 2;
        counters.ext.deadlines += 1;
        counters.wire_in.frames = 5;

        let reading = counters.take();
        assert_eq!(
            reading.loop_arms.reclaim, 3,
            "reclaim is read as it was set"
        );
        assert_eq!(
            reading.loop_arms.duplicates, 4,
            "duplicates is read as it was set"
        );
        assert_eq!(reading.loop_arms.fresh, 6, "fresh is read as it was set");
        assert_eq!(
            reading.loop_arms.ext.lagged, 1,
            "ext lagged is read as it was set"
        );
        assert_eq!(
            reading.loop_arms.ext.gossip_end, 1,
            "ext gossip_end is read as it was set"
        );
        assert_eq!(
            reading.loop_arms.ext.total(),
            5,
            "ext total is read as it was set"
        );
        assert_eq!(
            reading.loop_arms.wire_in.frames, 5,
            "wire_in frames is read as it was set"
        );

        let next = counters.take();
        assert_eq!(next.loop_arms.reclaim, 0, "take resets the arms");
        assert_eq!(next.loop_arms.duplicates, 0, "take resets the duplicates");
        assert_eq!(next.loop_arms.fresh, 0, "take resets the first sightings");
        assert_eq!(next.loop_arms.ext.total(), 0, "take resets the split");
        assert_eq!(
            next.loop_arms.wire_in.frames, 0,
            "take resets the received frames"
        );
    }

    #[test]
    fn take_drains_the_off_loop_wakes() {
        let _drain = TAKES.lock().expect("another census test panicked");
        let mut counters = IdleCounters::default();
        note_ppid_wake();
        note_sampler_wake();
        note_sampler_wake();
        // Other tests can bump the same statics in parallel, so only a lower bound holds.
        let reading = counters.take();
        assert!(reading.ppid >= 1, "the parent-process ticker woke once");
        assert!(reading.sampler >= 2, "the sampler ticker woke twice");
    }

    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn take_reports_the_cpu_time_of_the_interval() {
        let _drain = TAKES.lock().expect("another census test panicked");
        let mut counters = IdleCounters::default();
        let first = counters
            .take()
            .cpu
            .expect("the CPU clock works on a unix host");
        // A busy loop of 50 ms, so the next interval holds CPU time.
        let start = Instant::now();
        let mut spin = 0_u64;
        while start.elapsed() < Duration::from_millis(50) {
            spin = black_box(spin.wrapping_add(1));
        }
        let second = counters
            .take()
            .cpu
            .expect("the CPU clock works on a unix host");
        assert!(
            second >= Duration::from_millis(20),
            "the interval holds the busy loop: {second:?}"
        );
        // Deltas add up to the last mark; totals would count the first interval twice.
        assert_eq!(
            first + second,
            counters.cpu_mark,
            "the deltas add up to the last mark, so no interval counts twice"
        );
    }
}
