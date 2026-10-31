//! Wakeup attribution for the idle-cost work: one counter per `select!` arm,
//! the wakes of the two tickers that run off the loop, and the CPU time the
//! process used. All of it is reported as a delta on each `mesh census` line.

use std::collections::HashMap;
use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};

use iroh_gossip::api::{ApiError, Event};

use crate::protocol::Nickname;
use crate::util::process_usage::{CpuTimes, cpu_times};

/// Wakes of the orphan watch (`daemon::shutdown`). It is a task of its own, so
/// it cannot reach the event loop's `&mut` counters.
static PPID_WAKES: AtomicU64 = AtomicU64::new(0);
/// Wakes of the admission sampler (`transport::admission`), for the same reason.
static SAMPLER_WAKES: AtomicU64 = AtomicU64::new(0);

/// Count one wake of the orphan watch.
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
    pub antientropy: u64,
    pub state_refresh: u64,
    pub linkstate: u64,
    /// The arms driven by something other than a maintenance timer. Their sum
    /// is the census field `idle_external`.
    pub ext: ExternalArms,
    /// Signed frames put on the wire by a maintenance tick. The direct cost
    /// driver behind `user` CPU: each one is an Ed25519 signature plus a
    /// serialization.
    pub broadcasts: u64,
    /// Messages a digest answer put in the resend outbox.
    pub resent: u64,
    /// Messages a digest answer could not put there because it was full: the
    /// next digest asks for them again.
    pub resend_dropped: u64,
    /// Authenticated frames that the app dedup dropped as already seen.
    pub duplicates: u64,
    /// The anti-entropy resends queued, by the author of the digest that asked.
    pub resent_by: HashMap<Nickname, u64>,
    /// The process CPU time at the last census. It is not reset by `take`.
    cpu_mark: CpuTimes,
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
    pub(crate) const fn total(&self) -> u64 {
        self.gossip_rx
            + self.neighbor_up
            + self.neighbor_down
            + self.lagged
            + self.gossip_end
            + self.unicast
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
    /// `None` where the platform gives no `getrusage`.
    pub cpu: Option<CpuTimes>,
}

impl IdleCounters {
    /// Read the counters and zero them, so each census line carries the
    /// interval's own work rather than a running total a reader has to
    /// difference (and that a rotated log would corrupt).
    pub(crate) fn take(&mut self) -> IdleReading {
        let cpu_now = cpu_times();
        let mark = self.cpu_mark;
        let loop_arms = mem::take(self);
        self.cpu_mark = cpu_now.unwrap_or(mark);
        IdleReading {
            loop_arms,
            ppid: PPID_WAKES.swap(0, Ordering::Relaxed),
            sampler: SAMPLER_WAKES.swap(0, Ordering::Relaxed),
            cpu: cpu_now.map(|now| now.since(mark)),
        }
    }

    /// Count one resend queued for the digest of `requester`.
    pub(crate) fn note_resend_for(&mut self, requester: &Nickname) {
        *self.resent_by.entry(requester.clone()).or_default() += 1;
    }
}

/// The 3 requesters that got the most resends, as `nick:count` joined by `,`.
/// Empty when nobody got one. Ties go by nickname, so the line is stable.
pub(crate) fn top_requesters(resent_by: &HashMap<Nickname, u64>) -> String {
    let mut rows: Vec<(&Nickname, u64)> = resent_by
        .iter()
        .map(|(nick, count)| (nick, *count))
        .collect();
    rows.sort_unstable_by(|(left_nick, left_count), (right_nick, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_nick.as_str().cmp(right_nick.as_str()))
    });
    rows.iter()
        .take(3)
        .map(|(nick, count)| format!("{nick}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::testing::nick;

    #[test]
    fn take_zeroes_the_arms_and_sums_the_external_split() {
        let mut counters = IdleCounters {
            reclaim: 3,
            duplicates: 4,
            ..IdleCounters::default()
        };
        counters.ext.note_gossip(Some(&Ok(Event::Lagged)));
        counters.ext.note_gossip(None);
        counters.ext.unicast += 2;
        counters.ext.deadlines += 1;
        counters.note_resend_for(&nick("ant-bee"));

        let reading = counters.take();
        assert_eq!(reading.loop_arms.reclaim, 3);
        assert_eq!(reading.loop_arms.duplicates, 4);
        assert_eq!(reading.loop_arms.ext.lagged, 1);
        assert_eq!(reading.loop_arms.ext.gossip_end, 1);
        assert_eq!(reading.loop_arms.ext.total(), 5);
        assert_eq!(reading.loop_arms.resent_by.len(), 1);

        let next = counters.take();
        assert_eq!(next.loop_arms.reclaim, 0, "take resets the arms");
        assert_eq!(next.loop_arms.duplicates, 0, "take resets the duplicates");
        assert_eq!(next.loop_arms.ext.total(), 0, "take resets the split");
        assert!(
            next.loop_arms.resent_by.is_empty(),
            "take resets the requesters"
        );
    }

    #[test]
    fn top_requesters_keeps_the_3_largest_in_a_stable_order() {
        let mut counters = IdleCounters::default();
        for (name, count) in [
            ("ant-bee", 2),
            ("cat-dog", 5),
            ("elk-fox", 2),
            ("gnu-hen", 1),
        ] {
            for _ in 0..count {
                counters.note_resend_for(&nick(name));
            }
        }
        assert_eq!(
            top_requesters(&counters.resent_by),
            "cat-dog:5,ant-bee:2,elk-fox:2"
        );
        assert_eq!(top_requesters(&HashMap::new()), "");
    }

    #[test]
    fn take_drains_the_off_loop_wakes() {
        let mut counters = IdleCounters::default();
        note_ppid_wake();
        note_sampler_wake();
        note_sampler_wake();
        // Other tests can bump the same statics in parallel, so only a lower bound holds.
        let reading = counters.take();
        assert!(reading.ppid >= 1);
        assert!(reading.sampler >= 2);
    }

    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn take_reports_the_cpu_time_of_the_interval() {
        let mut counters = IdleCounters::default();
        let first = counters.take().cpu.expect("getrusage works on a unix host");
        // A busy loop of 50 ms, so the next interval holds user time.
        let start = Instant::now();
        let mut spin = 0_u64;
        while start.elapsed() < Duration::from_millis(50) {
            spin = black_box(spin.wrapping_add(1));
        }
        let second = counters.take().cpu.expect("getrusage works on a unix host");
        assert!(
            second.user >= Duration::from_millis(20),
            "the interval holds the busy loop: {second:?}"
        );
        // Deltas add up to the last mark; totals would count the first interval twice.
        assert_eq!(first.user + second.user, counters.cpu_mark.user);
        assert_eq!(first.system + second.system, counters.cpu_mark.system);
    }
}
