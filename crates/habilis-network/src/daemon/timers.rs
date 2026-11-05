//! Time-driven housekeeping ticks with no subsystem of their own: the
//! warn-only resident-memory leak check and the state-file liveness
//! heartbeat. The `Alive`/sweep heartbeat ticks live in
//! `lifecycle::heartbeat`; the gossip healer in `gossip::heal`.

use crate::daemon::state::{CollectionSizes, Latch, Standing};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use iroh::Endpoint;
use iroh_gossip::net::Gossip;

use super::state::{
    EventLoopState, GossipMsgs, GossipPathBytes, IdleCounters, SocketBytes, WireOut, by_arrival,
    by_class, by_variant, gossip_msgs_delta, gossip_path_delta, socket_delta, top_requesters,
};
use crate::gossip::event::{NodeEvent, NodeSink};
use crate::util::clock::{Instant, millis_saturating};
use crate::util::{resident_memory, tuning, unix_secs};

use crate::gossip::PathSummary;
use crate::net;
use crate::protocol::{Channel, Nickname};
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
/// Takes `&mut` because it also drains [`IdleCounters`]
/// onto the census line — this tick is the reporting interval for them.
pub(crate) async fn tick_state_refresh(
    state: &mut EventLoopState,
    endpoint: &Endpoint,
    gossip: &Gossip,
) {
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
    let (socket, gossip_path, gossip_msgs) = read_deltas(state, endpoint, gossip);
    let idle = reading.loop_arms;
    let ext = idle.ext;
    let cpu = reading.cpu.unwrap_or_default();
    let links = state.direct_counts();

    if state.silent_partition_due(roster_len, Instant::now()) {
        warn_silent_partition(state, roster_len, link_len);
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
    let relay_transport = state.relay_transport.relay_allowed();
    let direct_units = state.webrtc_admission.direct_units();
    let over_ceiling = state.webrtc_admission.over_ceiling();
    tracing::info!(
        target: "habilis_network::lifecycle",
        roster_len,
        link_len,
        meshed,
        relay_transport,
        links_direct = links.direct,
        links_relay_only = links.relay_only,
        links_pending = links.pending,
        peak_resident_memory_mb = resident_memory::peak_resident_memory_mb().unwrap_or(0),
        direct_units,
        over_ceiling,
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
        // Process CPU time of the interval, user and system together; 0 where it is unreadable.
        cpu_ms = millis_saturating(cpu),
        idle_duplicates = idle.duplicates,
        idle_fresh = idle.fresh,
        idle_fr_asks = idle.fr_asks,
        idle_fr_retries = idle.fr_retries,
        idle_state_answers = idle.state_answers,
        idle_state_frames_unicast = idle.state_frames_unicast,
        idle_state_frames_broadcast = idle.state_frames_broadcast,
        idle_state_rejected = idle.state_rejected,
        // A gauge, not a delta: the peers that a fast round still counts as ahead of us.
        idle_ahead_peers = state.fast_rounds.ahead_count(),
        idle_resent_top = %top_requesters(&idle.resent_by),
        idle_broadcasts = idle.broadcasts,
        idle_resent = idle.resent,
        idle_resend_dropped = idle.resend_dropped,
        // A total since the process started, unlike the idle fields above, which are per interval.
        gossip_recursion_closes_total = payload_path::gossip_recursion_closes(),
        "mesh census"
    );
    let join_phase = in_join_phase(state.joined_at, unix_secs::UnixSecs::now());
    log_wire_census(
        &idle,
        &reading.wire_out,
        socket,
        gossip_path,
        &gossip_msgs,
        join_phase,
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

/// How long after the join a node is in its join phase, the time of its backfill.
const JOIN_PHASE: Duration = Duration::from_mins(5);

/// Whether a node that joined at `joined_at` is still in its join phase at `now`.
fn in_join_phase(joined_at: unix_secs::UnixSecs, now: unix_secs::UnixSecs) -> bool {
    now.since(joined_at) < JOIN_PHASE
}

/// The entries of the per-peer map that belong to nobody on the roster and are not ours: members
/// that left and whose entry stays in the document for good.
fn absent_entries(nicks: &[String], roster: &HashSet<Nickname>, me: &Nickname) -> usize {
    let absent = |nick: &&String| {
        let owner = Nickname::try_new(nick);
        owner.is_ok_and(|owner| owner != *me && !roster.contains(&owner))
    };
    nicks.iter().filter(absent).count()
}

/// Every how many doc censuses the heavy part runs: the JSON, the save and the per-peer map cost
/// CPU in proportion to the document, and their size moves slowly. The light part is O(1).
const DOC_HEAVY_EVERY: u64 = 15;

static DOC_CENSUS_RUNS: AtomicU64 = AtomicU64::new(0);

fn is_heavy_run(run: u64) -> bool {
    run.is_multiple_of(DOC_HEAVY_EVERY)
}

/// What the socket, the gossip transport and the gossip actor of this loop moved since the last
/// census.
fn read_deltas(
    state: &mut EventLoopState,
    endpoint: &Endpoint,
    gossip: &Gossip,
) -> (SocketBytes, GossipPathBytes, GossipMsgs) {
    let idle = &mut state.idle;
    (
        socket_delta(&mut idle.socket_mark, endpoint),
        gossip_path_delta(&mut idle.gossip_path_mark, state.gossip_handle.as_ref()),
        gossip_msgs_delta(&mut idle.gossip_msgs_mark, gossip.metrics()),
    )
}

fn warn_silent_partition(state: &EventLoopState, roster_len: usize, link_len: usize) {
    tracing::warn!(
        target: "habilis_network::lifecycle",
        roster_len,
        link_len,
        meshed = state.standing.contains(&Standing::Meshed),
        "neighbor census: silent partition (meshed but zero peer links)"
    );
}

/// One tick of the minute timer for the epoch of the meta document: it adopts a higher epoch after
/// its wait, or starts a new one when its frames reach the threshold. The sweep tick writes the
/// entry of this node again.
pub(crate) fn tick_epoch(state: &mut EventLoopState, me: &Nickname) {
    let doc = state.doc_mut(Channel::Meta);
    let switch = doc.tick_epoch(me);
    for key in doc.take_dropped() {
        state.seen.remove(&key);
    }
    if let Some(switch) = switch {
        state.note_epoch_switch(switch);
    }
}

/// The sizes of the meta and the state document, on a line of their own, once per call (the
/// 1-minute tick): the changes and frames that the node keeps for good, their bytes, the JSON, the
/// save, and the entries of the per-peer map of members that are gone, every
/// [`DOC_HEAVY_EVERY`] runs; on the other runs those keys read 0. A reader of the numbers can tell
/// what a keyframe scheme would save.
pub(crate) fn tick_doc_census(state: &mut EventLoopState, me: &Nickname) {
    let run = DOC_CENSUS_RUNS.fetch_add(1, Ordering::Relaxed);
    let heavy = is_heavy_run(run);
    let meta = state.doc_mut(Channel::Meta).census(heavy);
    let shared = state.doc_mut(Channel::State).census(heavy);
    let peer_nicks = meta.peer_nicks.as_deref().unwrap_or_default();
    let absent = absent_entries(peer_nicks, &state.peers, me);
    let peer_entries = peer_nicks.len();
    tracing::info!(
        target: "habilis_network::lifecycle",
        doc_meta_epoch = meta.epoch,
        doc_meta_changes = meta.changes,
        doc_meta_frames = meta.frames,
        doc_meta_frame_bytes = meta.frame_bytes,
        doc_meta_save_bytes = meta.save_bytes.unwrap_or(0),
        doc_meta_json_bytes = meta.json_bytes.unwrap_or(0),
        doc_meta_peer_entries = peer_entries,
        doc_meta_absent_entries = absent,
        doc_state_changes = shared.changes,
        doc_state_frames = shared.frames,
        doc_state_frame_bytes = shared.frame_bytes,
        doc_state_save_bytes = shared.save_bytes.unwrap_or(0),
        doc_state_json_bytes = shared.json_bytes.unwrap_or(0),
        doc_state_refused_time = shared.refused_time,
        doc_state_unstamped_paths = shared.unstamped_paths,
        doc_state_dropped_restores = shared.dropped_restores,
        doc_state_replay_unsettled = shared.replay_unsettled,
        doc_save_taken = heavy,
        "doc census"
    );
}

/// The size of each long-lived collection, on a line of their own, once per call (the 1-minute
/// tick). The keys are `col_<name>` and `col_<name>_bytes`.
pub(crate) fn tick_collection_census(state: &EventLoopState) {
    let sizes = CollectionSizes::read(state);
    tracing::info!(
        target: "habilis_network::lifecycle",
        col_seen = sizes.seen,
        col_known_endpoints = sizes.known_endpoints,
        col_quiet = sizes.quiet,
        col_left = sizes.left,
        col_left_keys = sizes.left_keys,
        col_reassembled_groups = sizes.reassembled_groups,
        col_pending_outbound = sizes.pending_outbound,
        col_message_log = sizes.message_log,
        col_message_log_bytes = sizes.message_log_bytes,
        col_reassembly = sizes.reassembly,
        col_reassembly_bytes = sizes.reassembly_bytes,
        col_shard_cache = sizes.shard_cache,
        col_shard_cache_bytes = sizes.shard_cache_bytes,
        col_author_seqs = sizes.author_seqs,
        col_author_seq_entries = sizes.author_seq_entries,
        col_forked = sizes.forked,
        col_by_hash = sizes.by_hash,
        col_dag_heads = sizes.dag_heads,
        col_peers = sizes.peers,
        col_last_seen = sizes.last_seen,
        col_peer_endpoints = sizes.peer_endpoints,
        col_left_at = sizes.left_at,
        col_quiet_since = sizes.quiet_since,
        col_surfaced = sizes.surfaced,
        col_direct = sizes.direct,
        col_linked_endpoints = sizes.linked_endpoints,
        "collection census"
    );
}

/// The wire bytes of the interval by kind of frame, on a line of their own: the census line is at
/// the limit of one function, and a reader of that line takes the last line that names it.
/// `idle_bin_*` are frames received (first sightings and repeats), `idle_bout*` frames handed to the
/// transport. The wire total less the body total is the cost of the envelope.
fn log_wire_census(
    idle: &IdleCounters,
    sent: &WireOut,
    socket: SocketBytes,
    gossip_path: GossipPathBytes,
    msgs: &GossipMsgs,
    join_phase: bool,
) {
    tracing::info!(
        target: "habilis_network::lifecycle",
        idle_join_phase = join_phase,
        idle_bin_fresh = %by_class(&idle.wire_in.fresh),
        idle_bin_dup = %by_class(&idle.wire_in.dup),
        idle_bin_dup_path = %by_arrival(&idle.wire_in.dup_by_arrival),
        idle_bin_cdup = %by_class(&idle.wire_in.cdup),
        idle_bin_tags = %idle.wire_in.tags.top(),
        idle_bout = %by_class(&sent.bytes),
        idle_bout_tags = %sent.tags.top(),
        idle_wire_in = idle.wire_in.wire,
        idle_body_in = idle.wire_in.body,
        idle_frames_in = idle.wire_in.frames,
        idle_wire_out = sent.wire,
        idle_body_out = sent.body,
        idle_frames_out = sent.frames,
        // What the iroh socket moved: the UDP payload of all of QUIC, and the IP and UDP headers of the
        // received datagrams, which only the host sees. The first census of a process covers the time
        // since its endpoint started.
        idle_net_send_ip = socket.send_ip,
        idle_net_send_relay = socket.send_relay,
        idle_net_recv_ip = socket.recv_ip,
        idle_net_recv_relay = socket.recv_relay,
        idle_net_recv_custom = socket.recv_custom,
        idle_net_recv_dgrams = socket.recv_datagrams,
        idle_net_hdr_in = socket.header_bytes_in(),
        // Paths opened and closed by kind, and the custom paths made: a registered custom path can be
        // probed and kept alive, so these say whether the mesh has any.
        idle_net_paths_custom = socket.paths_custom,
        idle_net_ip_added = socket.ip_paths_added,
        idle_net_ip_removed = socket.ip_paths_removed,
        idle_net_relay_added = socket.relay_paths_added,
        idle_net_relay_removed = socket.relay_paths_removed,
        idle_net_custom_added = socket.custom_paths_added,
        idle_net_custom_removed = socket.custom_paths_removed,
        // The gossip transport: QUIC packets carried as frames on the mesh topic, for a pair with no
        // other path. All zero when the mesh has none.
        idle_gt_frames_out = gossip_path.frames_out,
        idle_gt_bytes_out = gossip_path.bytes_out,
        idle_gt_frames_in = gossip_path.frames_in,
        idle_gt_bytes_in = gossip_path.bytes_in,
        idle_gt_not_for_us = gossip_path.not_for_us,
        idle_gt_dropped = gossip_path.dropped,
        // The messages of the iroh-gossip protocol, by variant: the number and the bytes of what the
        // actor wrote and read, with the 4 bytes of length prefix of each. `gossip` carries our
        // frames; the others are the membership and the control of the broadcast layer.
        idle_gm_nout = %by_variant(&msgs.sent),
        idle_gm_bout = %by_variant(&msgs.sent_bytes),
        idle_gm_nin = %by_variant(&msgs.recv),
        idle_gm_bin = %by_variant(&msgs.recv_bytes),
        idle_gm_ctrl_out = msgs.ctrl_out,
        idle_gm_data_out = msgs.data_out,
        idle_gm_ctrl_in = msgs.ctrl_in,
        idle_gm_data_in = msgs.data_in,
        "wire census"
    );
}

#[cfg(test)]
mod tests {
    use crate::daemon::state::Latch;
    use crate::protocol::messages::Verified;
    use crate::testing;
    use crate::util::unix_secs::UnixSecs;
    use std::collections::HashSet;

    use crate::gossip::event::CountingSink;

    /// The join phase is the first 5 minutes after the join, and the census says so.
    #[test]
    fn the_join_phase_lasts_5_minutes() {
        let joined = UnixSecs::from_secs(1_700_000_000);
        let at = |secs: i64| UnixSecs::from_secs(1_700_000_000 + secs);
        assert!(super::in_join_phase(joined, at(0)), "at the join");
        assert!(
            super::in_join_phase(joined, at(299)),
            "just before 5 minutes"
        );
        assert!(!super::in_join_phase(joined, at(300)), "at 5 minutes");
        assert!(!super::in_join_phase(joined, at(3_600)), "an hour later");
    }

    /// An entry of the per-peer map is absent when its owner is neither on the roster nor us.
    #[test]
    fn an_entry_of_a_member_off_the_roster_is_absent() {
        let me = testing::nick("me");
        let roster: HashSet<_> = [testing::nick("alice")].into_iter().collect();
        let entries: Vec<String> = ["me", "alice", "bob", "carol"].map(str::to_owned).into();

        assert_eq!(
            super::absent_entries(&entries, &roster, &me),
            2,
            "bob and carol"
        );
        assert_eq!(
            super::absent_entries(&[], &roster, &me),
            0,
            "no entry, none absent"
        );
    }

    /// The heavy part of the doc census runs on the first call and then once in
    /// `DOC_HEAVY_EVERY`, so that its cost is spread over many ticks.
    /// A root frame of `epoch`, as a node that went through `epoch` resets sends it.
    fn root_frame(epoch: u64, name: &str) -> Verified {
        use crate::doc::{MeshDoc, SelfWriteGate};
        use crate::protocol::identity::Identity;
        use crate::protocol::{Channel, MeshId, Message};

        let author = testing::nick(name);
        let identity = Identity::generate();
        let gate = SelfWriteGate::new("peers".to_owned(), "card");
        let mut writer = MeshDoc::new_gated(gate).epoch_cap(0);
        for _ in 0..epoch {
            assert!(writer.tick_epoch(&author).is_some(), "a reset");
        }
        let seed = *identity.public().as_bytes();
        let merge = serde_json::json!({"peers": {name: {"card": "mine"}}});
        let change = writer
            .build_change(&merge, &seed)
            .expect("a JSON object merges")
            .expect("a non-empty merge yields a change");
        let (body, _plain) = writer
            .compose_wire_body(&change, None)
            .expect("compose the wire body");
        Message::new_channel_event(&MeshId::from("test"), &author, body, Channel::Meta)
            .sign(&identity)
    }

    /// The tick drains the dropped keys as a guard. No tick path pushes one today, and the receive
    /// path drains after each frame, so this test fills the keys by hand: a candidate that a higher
    /// one beat, with no frame between the two that would drain it.
    #[test]
    fn a_tick_of_the_epoch_forgets_the_keys_that_the_document_dropped() {
        use crate::doc::{MeshDoc, SelfWriteGate};
        use crate::protocol::Channel;

        let mut state = testing::fresh_state();
        state.meta_doc = MeshDoc::new_gated(SelfWriteGate::new("peers".to_owned(), "card"));
        let first = root_frame(1, "alice");
        let second = root_frame(2, "bob");
        state.doc_mut(Channel::Meta).ingest(&first);
        state.doc_mut(Channel::Meta).ingest(&second);
        state.seen.insert(first.dedup_key());

        super::tick_epoch(&mut state, &testing::nick("me"));

        assert!(
            !state.seen.contains(&first.dedup_key()),
            "the key of the beaten candidate is forgotten"
        );
    }

    #[test]
    fn the_heavy_doc_census_runs_once_in_fifteen_ticks() {
        let heavy: Vec<u64> = (0..31).filter(|run| super::is_heavy_run(*run)).collect();

        assert_eq!(
            heavy,
            [0, 15, 30],
            "the heavy census runs on the first call and then every 15th"
        );
    }

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
