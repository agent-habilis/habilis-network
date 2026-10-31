//! Time-driven housekeeping ticks with no subsystem of their own: the
//! warn-only resident-memory leak check and the state-file liveness
//! heartbeat. The `Alive`/sweep heartbeat ticks live in
//! `lifecycle::heartbeat`; the gossip healer in `gossip::heal`.

use crate::daemon::state::{Latch, Standing};
use std::time::Duration;

use iroh::Endpoint;

use super::state::{EventLoopState, top_requesters};
use crate::gossip::event::{NodeEvent, NodeSink};
use crate::util::clock::{Instant, millis_saturating};
use crate::util::process_usage::load_average_1m;
use crate::util::{resident_memory, tuning, unix_secs};

use crate::gossip::PathSummary;
use crate::net;
use crate::transport::payload_path;
/// The warn-only resident-memory leak check, run on the slow (1-minute)
/// housekeeping tick (see `run`'s `intervals.prune`). Kept on this tick now
/// that rate-limiter pruning — its original co-tenant — is gone.
pub(crate) fn tick_prune(state: &mut EventLoopState, sink: &dyn NodeSink) {
    warn_on_high_resident_memory(state, sink, tuning::RESIDENT_MEMORY_WARN_MB);
    let evicted = state.reassembly.sweep_stale(Instant::now());
    if evicted > 0 {
        // A reaped group means a transfer stalled past the TTL — the body is
        // gone for good (a chat surfaces nothing; an RPC ends as its waiter's
        // timeout), so make the loss loud.
        tracing::warn!(
            target: "habilis_network::gossip",
            evicted,
            "stale partial shard groups evicted from the reassembly store"
        );
    }
}

/// One-shot leak-visibility signal: if resident memory has crossed
/// `threshold_mb` (`consts::RESIDENT_MEMORY_WARN_MB`), emit a `warn` (file sink)
/// plus a JSON `info` event (`--output json` stream) exactly once. Warn-only —
/// never exits or alters behavior; the distributed soak that crashed a host had
/// no such in-process signal. `threshold_mb` is passed in (not read here) so the
/// threshold stays a single source of truth and the latch is unit-testable.
fn warn_on_high_resident_memory(
    state: &mut EventLoopState,
    sink: &dyn NodeSink,
    threshold_mb: u64,
) {
    if threshold_mb == 0 || state.latches.contains(&Latch::ResidentMemoryWarned) {
        return;
    }
    let Some(resident_bytes) = resident_memory::peak_resident_memory_bytes() else {
        return;
    };
    let resident_mb = resident_bytes / (1024 * 1024);
    if resident_mb >= threshold_mb {
        state.latches.insert(Latch::ResidentMemoryWarned);
        tracing::warn!(
            target: "habilis_network::lifecycle",
            resident_mb,
            threshold_mb,
            "resident memory crossed the warn threshold (possible leak); not exiting — see consts::RESIDENT_MEMORY_WARN_MB"
        );
        sink.emit(NodeEvent::Info(format!(
            "resident memory {resident_mb} MiB crossed warn threshold {threshold_mb} MiB (possible memory leak)"
        )));
    }
}

/// Re-asserts `peer_count` + `last_updated` into the state
/// file so external readers can treat a fresh `last_updated` as
/// liveness. No-op without `--state-file`.
///
/// Also logs a neighbor census: `meshed` yet zero peer links while the
/// roster is non-empty is the silent-partition signature, surfaced at
/// `warn` for post-freeze diagnosis. At `debug` it also classifies each
/// live peer link `direct`/`relay`/`mixed` (see
/// [`crate::net::conn_path`]) — this periodic reading is the
/// representative one (post hole-punch upgrade), unlike the `NeighborUp`
/// snapshot which skews `relay`. Gated on `debug` being live so the
/// per-peer `remote_info` round-trips are skipped at the default level.
///
/// Takes `&mut` because it also drains [`IdleCounters`](super::state::IdleCounters)
/// onto the census line — this tick is the reporting interval for them.
pub(crate) async fn tick_state_refresh(state: &mut EventLoopState, endpoint: &Endpoint) {
    state.write_peer_count();
    let roster_len = state.peers.len();
    let link_len = state.linked_endpoints.len();

    // Drained on every path, including the silent-partition return below: a
    // counter that survived one census would fold that interval's work into
    // the next line's delta and read as a spike that never happened.
    // `wakeups` is bumped *after* each arm body, so this iteration's own bump
    // lands in the next interval — and the previous census's bump landed in
    // this one. The two cancel: a line's `wakeups` still equals the sum of its
    // own arm columns. Do not "correct" it by adding one here; that
    // double-counts the census iteration and inflates the total every interval.
    let reading = state.idle.take();
    let idle = reading.loop_arms;
    let ext = idle.ext;
    let cpu = reading.cpu.unwrap_or_default();
    let links = state.direct_counts();

    if state.silent_partition_due(roster_len, Instant::now()) {
        tracing::warn!(
            target: "habilis_network::lifecycle",
            roster_len,
            link_len,
            meshed = state.standing.contains(&Standing::Meshed),
            "neighbor census: silent partition (meshed but zero peer links)"
        );
        return;
    }

    // Always-on census reading: the cheap counts only (no `remote_info`
    // round-trips), at `info` so the file sink carries a per-tick
    // roster/link time series — the flap rate read directly, not
    // inferred from counting NeighborUp/Down lines. `peak_resident_memory_mb`
    // rides the same line as the leak gauge: peak resident memory is monotonic,
    // so a churn-proportional leak reads as a rising slope right next to the
    // flap counts — no external `ps` sampler needed (0 if it is unreadable on
    // this platform).
    //
    // The `idle_*` fields ride here rather than on lines of their own because
    // this one already fires on a fixed cadence at `info` under a pinned
    // target, so it survives a release build (base level `error`) with no
    // `RUST_LOG` surgery — and the arms being counted fire up to 150×/min,
    // which is far too often to afford a line each. Deltas, not totals: a
    // reader needs no arithmetic, and a rotated log cannot corrupt the series.
    let meshed = state.standing.contains(&Standing::Meshed);
    tracing::info!(
        target: "habilis_network::lifecycle",
        roster_len,
        link_len,
        meshed,
        relay_transport = state.relay_transport.relay_allowed(),
        links_direct = links.direct,
        links_relay_only = links.relay_only,
        links_pending = links.pending,
        peak_resident_memory_mb = resident_memory::peak_resident_memory_mb().unwrap_or(0),
        direct_units = state.webrtc_admission.direct_units(),
        over_ceiling = state.webrtc_admission.over_ceiling(),
        idle_wakeups = idle.wakeups,
        idle_prune = idle.prune,
        idle_alive = idle.alive,
        idle_sweep = idle.sweep,
        idle_heal = idle.heal,
        idle_reclaim = idle.reclaim,
        idle_antientropy = idle.antientropy,
        idle_state_refresh = idle.state_refresh,
        idle_linkstate = idle.linkstate,
        idle_external = ext.total(),
        idle_ext_gossip_rx = ext.gossip_rx,
        idle_ext_neighbor_up = ext.neighbor_up,
        idle_ext_neighbor_down = ext.neighbor_down,
        idle_ext_lagged = ext.lagged,
        idle_ext_gossip_end = ext.gossip_end,
        idle_ext_unicast = ext.unicast,
        idle_ext_path_rx = ext.path_rx,
        idle_ext_address = ext.address,
        idle_ext_direct_rx = ext.direct_rx,
        idle_ext_rung_change = ext.rung_change,
        idle_ext_rung_report = ext.rung_report,
        idle_ext_probe_verdict = ext.probe_verdict,
        idle_ext_ipc = ext.ipc,
        idle_ext_http = ext.http,
        idle_ext_session = ext.session,
        idle_ext_deadlines = ext.deadlines,
        idle_ext_other = ext.other,
        // Off the loop: their own tasks, so they are not in `idle_wakeups`.
        idle_ppid = reading.ppid,
        idle_sampler = reading.sampler,
        // Process CPU time of the interval, from `getrusage`; 0 where it is unreadable.
        cpu_user_ms = millis_saturating(cpu.user),
        cpu_sys_ms = millis_saturating(cpu.system),
        idle_duplicates = idle.duplicates,
        idle_resent_top = %top_requesters(&idle.resent_by),
        // The 1-minute load average of the host: a reading taken under load is void.
        load_1m = load_average_1m().unwrap_or(0.0),
        idle_broadcasts = idle.broadcasts,
        idle_resent = idle.resent,
        idle_resend_dropped = idle.resend_dropped,
        // A total since the process started, unlike the idle fields above, which are per interval.
        gossip_recursion_closes_total = payload_path::gossip_recursion_closes(),
        "mesh census"
    );

    // The per-peer conn classification feeds only the DEBUG census
    // below, and each `conn_path` is a `remote_info` actor round-trip.
    // `lifecycle` is pinned to `info` by default, so skip the whole loop
    // unless DEBUG is actually live — otherwise the tick pays N
    // round-trips every interval for output the subscriber discards.
    if !tracing::enabled!(target: "habilis_network::lifecycle", tracing::Level::DEBUG) {
        return;
    }
    let (mut direct, mut relay, mut other) = (0usize, 0usize, 0usize);
    let linked: Vec<_> = state.linked_endpoints.iter().copied().collect();
    for peer_id in linked {
        let (connection, relay_url) = net::conn_path(endpoint, peer_id).await;
        match connection {
            PathSummary::Direct => direct += 1,
            PathSummary::Relay => relay += 1,
            PathSummary::Mixed | PathSummary::Unknown => other += 1,
        }
        // A link that was relayed at `NeighborUp` and has since punched a
        // direct path: refresh the reading the roster and lanes consult.
        state.observe_path(peer_id, connection);
        tracing::debug!(
            target: "habilis_network::lifecycle",
            endpoint_id = %peer_id,
            connection = connection.label(),
            relay = relay_url.as_ref().map_or("-", |url| url.as_str()),
            "peer conn path"
        );
    }
    tracing::debug!(
        target: "habilis_network::lifecycle",
        roster_len,
        link_len,
        meshed,
        direct,
        relay,
        other,
        "neighbor census"
    );
}

/// Log a maintenance timer's interval fidelity and advance both its
/// monotonic and wall-clock anchors; returns `(mono_gap, wall_gap)` for
/// the heal arm, which drives the resume-edge re-bootstrap off them.
///
/// Two stall signatures are surfaced at `warn` (the prime suspects for
/// a silent mesh collapse): a monotonic gap far over `expected` (the
/// process was throttled), and a wall-vs-monotonic divergence far over
/// `expected` (the process was *suspended* — macOS sleep freezes the
/// monotonic clock in lockstep, so only the wall clock reveals it).
pub(crate) fn note_tick_gap(
    timer: &'static str,
    last: &mut Instant,
    last_wall: &mut unix_secs::UnixSecs,
    expected: Duration,
) -> (Duration, Duration) {
    let now = Instant::now();
    let mono_gap = now.duration_since(*last);
    *last = now;

    let now_wall = unix_secs::UnixSecs::now();
    let wall_gap = now_wall.since(*last_wall);
    *last_wall = now_wall;

    let mono_gap_ms = millis_saturating(mono_gap);
    let wall_gap_ms = millis_saturating(wall_gap);
    let expected_ms = millis_saturating(expected);
    let throttled = mono_gap > expected.saturating_mul(2);
    let suspended = wall_gap.saturating_sub(mono_gap) > expected.saturating_mul(2);
    if throttled || suspended {
        tracing::warn!(
            target: "habilis_network::lifecycle",
            timer,
            mono_gap_ms,
            wall_gap_ms,
            expected_ms,
            suspected = if suspended { "freeze/sleep" } else { "throttle" },
            "maintenance timer stalled"
        );
    } else {
        tracing::debug!(
            target: "habilis_network::lifecycle",
            timer,
            mono_gap_ms,
            wall_gap_ms,
            expected_ms,
            "maintenance tick"
        );
    }
    (mono_gap, wall_gap)
}

#[cfg(test)]
mod tests {
    use crate::daemon::state::Latch;
    use crate::testing;

    use crate::gossip::event::CountingSink;

    // The warn-only resident-memory leak signal: a threshold the live process
    // already exceeds (1 MiB) must fire exactly once and latch, never exit or
    // mutate anything else. A `0` threshold disables it entirely.
    #[test]
    fn resident_memory_warn_fires_once_then_latches() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::lifecycle",
            "resident memory crossed the warn threshold",
        );
        let sink = CountingSink::new();
        let mut state = testing::fresh_state();

        // Real resident memory is tens of MiB ≫ 1, so this crosses immediately.
        super::warn_on_high_resident_memory(&mut state, &sink, 1);
        assert!(
            state.latches.contains(&Latch::ResidentMemoryWarned),
            "first crossing latches the warn"
        );
        assert_eq!(sink.count(), 1, "an info event is emitted on the crossing");

        // Second tick: latched, so no second event (no per-tick spam).
        super::warn_on_high_resident_memory(&mut state, &sink, 1);
        assert_eq!(sink.count(), 1, "warn fires exactly once per process");
    }

    #[test]
    fn resident_memory_warn_disabled_by_zero_threshold() {
        let _guard = ::habilis_network_test_tracing::init();
        let sink = CountingSink::new();
        let mut state = testing::fresh_state();
        super::warn_on_high_resident_memory(&mut state, &sink, 0);
        assert!(
            !state.latches.contains(&Latch::ResidentMemoryWarned),
            "threshold 0 disables the warn"
        );
        assert_eq!(sink.count(), 0, "no event when disabled");
    }
}
