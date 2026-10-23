//! Behavioural knobs. Changing these affects timing, capacity, and
//! policy but never the on-the-wire format — the size cap belongs in
//! `protocol::message` (`MAX_MESSAGE_SIZE`).
//!
//! **The split with `crate::consts` is by who may change a value.** A `pub
//! const` here is fixed at build time; a `pub fn` reads the process [`Tuning`]
//! and so honours a CLI override. `crate::consts` keeps only what every member
//! of a mesh must agree on bit-for-bit — the wire contracts.

use std::time::Duration;

/// In-memory message-log capacity: how many recent messages each member
/// retains as the anti-entropy recovery source and poll/fetch history. A
/// bigger log lets a reconnecting peer recover a longer gap. It also anchors
/// the shared IPC response cap.
pub const MESSAGE_LOG_SIZE: usize = 1000;
const _: () = assert!(MESSAGE_LOG_SIZE >= 1, "a zero-length log retains nothing");

/// How many recently-seen message ids are retained for duplicate
/// suppression. Kept at **2× the message log** so it always covers the
/// retention window with margin: anti-entropy resends any message still
/// in the log, and a resend whose id had scrolled out of this set would be
/// reprocessed and **re-surfaced**. Derived, so the two cannot drift.
pub const SEEN_IDS_CAP: usize = MESSAGE_LOG_SIZE * 2;
const _: () = assert!(
    SEEN_IDS_CAP >= MESSAGE_LOG_SIZE,
    "the dedup set must outlive the message log"
);

/// How many outbound frames are buffered while the node has no gossip link
/// yet (sent before the first `NeighborUp`). Flushed in order once connected;
/// oldest dropped past this cap so a node that spams while offline can't grow
/// memory unbounded. Sized in **frames** (≤ `MAX_MESSAGE_SIZE` each, so ~4 `MiB`
/// worst case): with the shard-count cap gone, a multipart body needs one
/// slot per shard and is admitted all-or-nothing, so this also bounds the
/// largest body sendable before the mesh forms (~3.7 MB) — bigger ones are
/// refused with a retry-after-connect error rather than half-buffered.
pub const PENDING_OUTBOUND_CAP: usize = 1024;

/// How many distinct peer endpoint ids we remember for the
/// rendezvous-independent re-bridge (`gossip::heal::rebridge_known`).
/// Survives `NeighborDown` (unlike `linked_endpoints`) so a node that
/// lost every link can still re-dial peers directly when the
/// rendezvous/relay is the bottleneck. Bounded FIFO (oldest evicted)
/// so long-lived meshes with churn can't grow it unbounded; sized well
/// above a typical mesh so recent peers are always retained.
pub const KNOWN_ENDPOINTS_CAP: usize = 64;

/// Anti-entropy: how often a member broadcasts its digest (recent
/// message ids it holds) so peers can re-send anything it missed
/// while partitioned/asleep. Short enough that a returning peer
/// recovers within a couple of cycles; digests are small and a
/// re-send only happens when there is an actual gap, so steady-state
/// cost is one tiny message per interval. Hidden flag
/// `--antientropy-interval-secs` so the backfill tests reconcile in
/// seconds. Clamped to `>= 1 s`.
pub const ANTIENTROPY_INTERVAL: Duration = Duration::from_secs(10);

/// The live value, after any CLI override of [`ANTIENTROPY_INTERVAL`].
#[must_use]
pub fn antientropy_interval() -> Duration {
    current().antientropy_interval.max(Duration::from_secs(1))
}

/// How often a node re-broadcasts its relay **link-state** vector (its own
/// measured links) so every peer keeps a fresh routing graph. Steady-state cost
/// is one small message per interval; churn triggers a fresh vector out-of-band
/// is not yet wired, so this cadence bounds convergence time.
pub const LINKSTATE_INTERVAL: Duration = Duration::from_secs(15);

/// How long a peer's link-vector stays in the routing graph without a newer one,
/// and how old a vector may be when it arrives. Three missed advertisements: a
/// peer that crashed, or left without a word, then leaves no edge behind.
///
/// The trade: a node that is degraded, or whose loop missed ticks under load, is
/// dropped by every peer and its routes go until its next vector (it comes back
/// with that vector). That costs a backup path for up to one interval. A longer
/// age keeps a crashed peer's routes longer instead. A peer's clock more than
/// this behind ours has its vectors refused, because a vector's `seq` is the
/// sender's wall-clock time in milliseconds.
pub const LINKSTATE_MAX_AGE: Duration = LINKSTATE_INTERVAL.saturating_mul(3);

/// How long a next hop's underlay may stay on the relay, refused by the relay
/// gate, before the hop stops being advertised as a link. A connection starts on
/// the relay until a direct path opens, so the deadline must outlast a normal
/// hole punch.
pub const MULTIHOP_RELAY_STUCK: Duration = Duration::from_secs(20);

/// Max ids advertised per digest **window**. A digest carries up to two
/// windows: an **open-ended newest** one (`[lo, i64::MAX]`, which drives
/// reconnect recovery — holders re-send every *newer* message the sender
/// lacks) and a rolling **closed** older one (`[lo, hi]`, which reconciles
/// deep interior gaps without re-sending the out-of-window remainder). At
/// 70 ids each (~140 total) the body packs the 16-byte dedup keys
/// Base58-encoded (~22 chars/id) to ~3.1 KB; plus the `{windows:[…]}` and
/// message envelope (the mesh id alone is ~80 chars) it stays under
/// `MAX_MESSAGE_SIZE` (3840) — guarded by the `digest_fits_gossip_cap`
/// test. Sized to a single gossip message, **not** the (larger,
/// configurable) log, which the rolling cursor sweeps across rounds.
pub const ANTIENTROPY_DIGEST_WINDOW_IDS: usize = 70;

/// Max messages re-broadcast in response to one received digest, so a
/// far-behind peer can't trigger an unbounded burst. This throttles
/// deep-backfill throughput (~`this × peers` messages per
/// `ANTIENTROPY_INTERVAL`). Hidden flag `--antientropy-max-resend` (tests raise it for deep backfill).
pub const ANTIENTROPY_MAX_RESEND: usize = 64;

/// The live value, after any CLI override of [`ANTIENTROPY_MAX_RESEND`].
#[must_use]
pub fn antientropy_max_resend() -> usize {
    current().antientropy_max_resend.max(1)
}

/// Capacity of a `habilis-network`'s `Node`'s inbound push channel
/// (`DriverMode::InProcess::msg_tx`). Bounded so a slow consumer never
/// backpressures the gossip/membership loop; under sustained lag the oldest
/// buffered messages are dropped and the consumer observes `RecvError::Lagged`.
pub const NODE_INBOUND_CAP: usize = 1024;

/// Depth of the typed session-request channel a `habilis-network`'s `Node`'s
/// driver drains. Pure backpressure: every request carries its own `oneshot`
/// reply, so one caller has at most one in flight — the queue only grows when
/// several tasks share a session.
pub const SESSION_REQUEST_CAP: usize = 64;

/// Soft resident-memory threshold (`MiB`) above which the daemon emits a
/// one-shot `warn` (log + JSON `info` event) on its slow prune tick — the
/// in-process leak-visibility signal the distributed soak lacked. **Warn-only**:
/// it never exits; host safety is the deployment runbook's OS resource caps.
/// Well above a healthy node's tens of `MiB`; `0` disables it.
pub const RESIDENT_MEMORY_WARN_MB: u64 = 1024;

/// How often an idle daemon broadcasts a `Presence::Alive` keepalive.
/// Active talkers never emit one — any sent gossip message resets the
/// timer, so chatty meshes pay zero heartbeat cost.
pub const ALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// How long a peer can go unheard before the sweeper evicts it.
/// Must exceed `ALIVE_INTERVAL` comfortably — 3x absorbs one or
/// two lost gossip rounds. Worst-case ghost window is
/// `alive_timeout + sweep_interval`.
///
/// Hidden flag
/// `--alive-timeout-secs` so integration tests exercise eviction in
/// seconds instead of minutes.
pub const ALIVE_TIMEOUT: Duration = Duration::from_secs(90);

/// The live value, after any CLI override of [`ALIVE_TIMEOUT`].
#[must_use]
pub fn alive_timeout() -> Duration {
    current().alive_timeout
}

/// How often the sweeper walks `last_seen` looking for expired peers.
/// Bounds the maximum statusline staleness from a peer's true
/// disappearance to its eviction. Hidden flag `--sweep-interval-secs`.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// The live value, after any CLI override of [`SWEEP_INTERVAL`].
#[must_use]
pub fn sweep_interval() -> Duration {
    current().sweep_interval
}

/// Grace before an **unmeshed joiner** co-hosts the rendezvous anyway
/// (empty mesh ⇒ become the beacon for the next joiner). Rationale:
/// `EventLoopConfig::cohost`. Non-blocking — only consulted
/// on heal ticks, never delays `ready`; a joiner that meshes co-hosts
/// the moment it has a neighbor, well before this. Hidden flag
/// `--beacon-cohost-grace-secs`.
pub const BEACON_COHOST_GRACE: Duration = Duration::from_secs(10);

/// The live value, after any CLI override of [`BEACON_COHOST_GRACE`].
#[must_use]
pub fn cohost_grace() -> Duration {
    current().cohost_grace
}

/// How long a ping round collects pongs before the daemon
/// emits its `ping_report`. Long enough for a relayed round-trip
/// across the mesh; hidden flag `--ping-window-secs` so tests don't
/// wait the full window.
pub const PING_WINDOW: Duration = Duration::from_secs(10);

/// The live value, after any CLI override of [`PING_WINDOW`].
#[must_use]
pub fn ping_window() -> Duration {
    current().ping_window
}

/// How often the CLI daemon re-reads its parent pid to detect orphaning.
/// Hidden flag `--ppid-watch-interval-ms` so the subprocess test sees the
/// self-exit in milliseconds instead of the production seconds.
///
/// Ungated, unlike its accessor: [`Tuning::DEFAULTS`] is one `const` for every
/// target and cannot name a field that disappears off a host.
pub const PPID_WATCH_INTERVAL: Duration = Duration::from_millis(1500);

/// The live value, after any CLI override of [`PPID_WATCH_INTERVAL`].
///
/// Gated with its only caller (`daemon::event_loop::spawn_orphan_watch`): the
/// orphan watch is `libc::getppid`, which arrives with `host`.
#[cfg(all(unix, feature = "host"))]
#[must_use]
pub fn ppid_watch_interval() -> Duration {
    current().ppid_watch_interval.max(Duration::from_millis(1))
}

/// Process tuning sourced **once** at daemon startup from the hidden CLI
/// flags (`--alive-timeout-secs`, …). Replaces the former env-var reads: an
/// experiment is now an edit-the-const + commit, and a subprocess test passes
/// the flag. Production runs on [`Tuning::DEFAULTS`] (the `crate::consts`
/// values) when [`init`] is never called (the in-process path).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Tuning {
    /// How long a peer may stay silent before it is quiet.
    pub alive_timeout: Duration,
    /// How often the sweeper looks for expired peers.
    pub sweep_interval: Duration,
    /// How often the mesh checks its links and heals them.
    pub heal_interval: Duration,
    /// How often a node sends its digest to look for missing messages.
    pub antientropy_interval: Duration,
    /// How long an unmeshed joiner waits before it co-hosts the rendezvous anyway.
    pub cohost_grace: Duration,
    /// How long a ping round collects pongs before it reports.
    pub ping_window: Duration,
    /// How often the daemon checks that its parent process is alive.
    pub ppid_watch_interval: Duration,
    /// How long the mesh may stay unhealthy before it re-bootstraps.
    pub heal_stall_threshold: Duration,
    /// How long without traffic before the node recovers from starvation.
    pub starvation_threshold: Duration,
    /// How often a directory advertiser re-broadcasts its mesh.
    pub advertise_interval: Duration,
    /// How long a directory entry stays listed without a new advertisement.
    pub directory_expiry: Duration,
    /// How many messages one received digest may re-broadcast.
    pub antientropy_max_resend: usize,
    /// Whether a directory advertiser keeps its mesh unlisted.
    pub directory_private: bool,
    /// How soon the first rival check runs after a probed claim.
    pub rival_recheck_first: Duration,
    /// How often a lone public beacon holder rechecks for a rival.
    pub rival_recheck: Duration,
    /// How often a meshed public beacon holder rechecks for a rival.
    pub rival_recheck_meshed: Duration,
    /// How often a lone beacon holder rechecks, with a ramping interval.
    pub rival_recheck_alone: Duration,
    /// How often a node revisits the rendezvous to meet split islands.
    pub rendezvous_periodic_return: Duration,
    /// Whether a topic mesh looks up peers over mDNS only.
    pub topic_mdns_only: bool,
}

impl Tuning {
    /// Set how often anti-entropy runs.
    #[must_use]
    pub fn with_antientropy_interval(mut self, antientropy_interval: Duration) -> Self {
        self.antientropy_interval = antientropy_interval;
        self
    }

    /// Set how long the first rival recheck waits.
    #[must_use]
    pub fn with_rival_recheck_first(mut self, rival_recheck_first: Duration) -> Self {
        self.rival_recheck_first = rival_recheck_first;
        self
    }

    /// Set how long each rival recheck waits.
    #[must_use]
    pub fn with_rival_recheck(mut self, rival_recheck: Duration) -> Self {
        self.rival_recheck = rival_recheck;
        self
    }

    /// Set how long each rival recheck waits once meshed.
    #[must_use]
    pub fn with_rival_recheck_meshed(mut self, rival_recheck_meshed: Duration) -> Self {
        self.rival_recheck_meshed = rival_recheck_meshed;
        self
    }

    /// Set how often the heal tick runs.
    #[must_use]
    pub fn with_heal_interval(mut self, heal_interval: Duration) -> Self {
        self.heal_interval = heal_interval;
        self
    }

    /// Set the co-host grace period.
    #[must_use]
    pub fn with_cohost_grace(mut self, cohost_grace: Duration) -> Self {
        self.cohost_grace = cohost_grace;
        self
    }

    /// Set how long a member waits before it asks for the rendezvous again.
    #[must_use]
    pub fn with_rendezvous_periodic_return(mut self, rendezvous_periodic_return: Duration) -> Self {
        self.rendezvous_periodic_return = rendezvous_periodic_return;
        self
    }

    /// Set the rival recheck interval for a lone member.
    #[must_use]
    pub fn with_rival_recheck_alone(mut self, rival_recheck_alone: Duration) -> Self {
        self.rival_recheck_alone = rival_recheck_alone;
        self
    }
}

impl Tuning {
    /// The production defaults, all from `crate::consts`.
    pub const DEFAULTS: Self = Self {
        alive_timeout: ALIVE_TIMEOUT,
        sweep_interval: SWEEP_INTERVAL,
        heal_interval: HEAL_INTERVAL,
        antientropy_interval: ANTIENTROPY_INTERVAL,
        cohost_grace: BEACON_COHOST_GRACE,
        ping_window: PING_WINDOW,
        ppid_watch_interval: PPID_WATCH_INTERVAL,
        heal_stall_threshold: HEAL_STALL_THRESHOLD,
        starvation_threshold: STARVATION_THRESHOLD,
        advertise_interval: ADVERTISE_INTERVAL,
        directory_expiry: DIRECTORY_EXPIRY,
        antientropy_max_resend: ANTIENTROPY_MAX_RESEND,
        directory_private: false,
        rival_recheck_first: RIVAL_RECHECK_FIRST,
        rival_recheck: RIVAL_RECHECK,
        rival_recheck_meshed: RIVAL_RECHECK_MESHED,
        rival_recheck_alone: RIVAL_RECHECK_ALONE,
        rendezvous_periodic_return: RENDEZVOUS_PERIODIC_RETURN,
        topic_mdns_only: false,
    };
}

impl Default for Tuning {
    fn default() -> Self {
        Self::DEFAULTS
    }
}

static TUNING: std::sync::OnceLock<Tuning> = std::sync::OnceLock::new();

/// Install the process tuning, once, at daemon startup (from the parsed CLI
/// flags). A second call is ignored; if never called (in-process: library API or MCP), `current`
/// returns [`Tuning::DEFAULTS`].
pub fn init(tuning: Tuning) {
    let _ = TUNING.set(tuning);
}

fn current() -> Tuning {
    TUNING.get().copied().unwrap_or(Tuning::DEFAULTS)
}

/// How often the daemon re-asserts `peer_count` +
/// `last_updated` into the session state file even when membership is
/// unchanged. A fresh `last_updated` is what external readers (the
/// shell statusline) treat as liveness — file presence alone would
/// show a false pill after a hard crash. Coupled to the statusline's
/// staleness window, which must stay >= ~3x this value (currently 30s
/// for a 10s cadence); change both together.
pub const STATE_REFRESH: Duration = Duration::from_secs(10);

/// Cadence of the unconditional gossip healer (`gossip::heal::tick_heal`).
/// The default balances fast re-mesh after a partition against
/// steady-state cost — one detached rendezvous connect-probe plus one
/// `HyParView` control message per tick when already healthy. Hidden flag
/// `--heal-interval-secs` so the subprocess reliability tests collapse the
/// multi-cycle rendezvous-handoff floor to seconds. Clamped to `>= 1 s`.
pub const HEAL_INTERVAL: Duration = Duration::from_secs(15);

/// The live value, after any CLI override of [`HEAL_INTERVAL`].
#[must_use]
pub fn heal_interval() -> Duration {
    current().heal_interval.max(Duration::from_secs(1))
}

/// How long a meshed member may hold no gossip link before the census calls it a silent
/// partition: one heal and one census tick. The heal arm re-bridges a member that lost its
/// links, so a shorter gap is a heal that is on its way, or a link that was closed on purpose;
/// a longer one is a heal that did not work.
#[must_use]
pub fn silent_partition_after() -> Duration {
    heal_interval().saturating_add(STATE_REFRESH)
}

/// Consecutive failed gossip-topic resubscribe attempts (one per heal
/// tick after the stream terminally ends) before the daemon gives up
/// and shuts down. A subscribe error means the gossip actor itself is
/// gone — endpoint closed, unrecoverable — so 8 (~2 min at the default
/// heal cadence) is generosity, not hope; a deaf daemon must not pose as
/// a live member forever.
pub const RESUBSCRIBE_MAX_ATTEMPTS: u32 = 8;

/// Backoff bounds between failed IPC `accept`s. An accept error is
/// almost always transient (fd exhaustion under load, an aborted
/// handshake), so the listener retries forever instead of dying — the
/// backoff (doubling MIN→MAX, reset on any successful accept) just
/// keeps a persistently failing listener from spinning hot.
///
/// `host`-only with the listener itself — a browser binds no socket.
#[cfg(feature = "host")]
pub const IPC_ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(100);
#[cfg(feature = "host")]
/// The longest wait between two tries to accept an IPC connection.
pub const IPC_ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Per-connection IPC I/O deadline: how long the daemon waits for a
/// connected client to send its command line, and for the response
/// write to complete. A client that connects and goes silent would
/// otherwise pin a task + fd for the daemon's lifetime; well above any
/// real `msg`/`poll` round-trip, so only a hung client ever hits it.
#[cfg(feature = "host")]
pub const IPC_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Readiness gate: how long to wait for the daemon's `--state-file` to
/// report `ready: true` before giving up (the `--timeout-secs` default),
/// and the fixed interval between file reads while waiting. 30s covers a
/// cold daemon start (the file appears sub-second once the process is up).
/// Client-side, so these are not part of the daemon `Tuning` struct.
pub const READY_MAX: Duration = Duration::from_secs(30);
/// How often the readiness gate reads the state file while it waits.
pub const READY_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// How fresh a `ready: true` state-file write must be for the gate to trust
/// it. A live daemon rewrites the file every `STATE_REFRESH` (10s), so
/// a `last_updated` older than this window means the writer is gone — e.g. a
/// `ready: true` file left behind by a prior daemon killed with SIGKILL (which
/// skips the file-removing shutdown path). Two heartbeats of slack absorbs a
/// missed refresh without trusting a truly stale file.
pub const READY_FRESH: Duration = STATE_REFRESH.saturating_mul(2);

/// Floor on one long-poll re-issue cycle. Normally dormant — a parked
/// read returns at the ~60s cap, far above it — it only engages when the
/// daemon degrades a long read to an immediate empty (waiter registry at
/// `POLL_WAITERS_CAP`), keeping the CLI's re-poll loop from spinning hot.
/// Client-side, so not part of the daemon `Tuning` struct.
pub const POLL_LONG_MIN_CYCLE: Duration = Duration::from_secs(1);

/// Upper bound on the healer's detached rendezvous connect-probe.
/// Generous enough to absorb a public relay/lookup warmup after a
/// real network change, capped well under the default heal interval so
/// at most one probe task is ever outstanding (probe sites clamp to
/// `heal_interval()` to preserve that when tests shorten the
/// cadence).
pub const HEAL_PROBE: Duration = Duration::from_secs(5);

/// Probe budget for the resume-edge hard heal. Longer than
/// `HEAL_PROBE` because a cold relay re-home after a freeze
/// routinely exceeds the steady-state 5s; the path is rare so a probe
/// that briefly outlives one heal interval (still detached) is fine.
pub const HEAL_HARD_PROBE: Duration = Duration::from_secs(20);

/// The longest wait between two rival probes of a member that keeps finding the rival.
/// A probe is a throwaway endpoint and a relay registration, and without a back-off every
/// member that holds no rendezvous starts one at each heal tick. The wait doubles with each
/// probe that finds the rival, from one heal interval up to this value (or 8 heal intervals,
/// if that is less: tests shorten the heal interval and must keep their cadence).
///
/// Cost: when the host of the rendezvous dies, the first probe after the death comes sooner
/// than this wait. The members that hold a link to the rendezvous do not wait: the
/// reclaim window opens at the `NeighborDown` and is not held back. The members that hold
/// none probe on their own phases. With N such members at the longest wait, the first probe
/// comes after about 120 / N s on average: 40 s at N = 4, 5 s at N = 24. The worst case, with
/// all phases aligned, is the full 120 s; a new joiner then waits that long, plus the two
/// free readings and the claim, as it does today. The jitter on the wait keeps the phases apart.
pub const HEAL_PROBE_BACKOFF_MAX: Duration = Duration::from_mins(2);

/// A heal inter-tick gap above this length means the process was
/// frozen between ticks (App Nap / coalescing / sleep) and must hard
/// re-bootstrap. Safely above the default heal interval (15s) so normal
/// slack never trips it. Hidden flag `--heal-stall-threshold-secs` so subprocess
/// tests drive it in seconds; a test shortening `--heal-interval-secs`
/// must keep this comfortably above the cadence it injects.
pub const HEAL_STALL_THRESHOLD: Duration = Duration::from_mins(1);

/// The live value, after any CLI override of [`HEAL_STALL_THRESHOLD`].
#[must_use]
pub fn heal_stall_threshold() -> Duration {
    current().heal_stall_threshold
}

/// No verified inbound gossip for this long, while real peers are known,
/// trips the heal arm's starvation watchdog (re-bridge + re-announce; see
/// `gossip::heal::recover_from_starvation`). Keyed on traffic, not the link
/// view — links can look alive while nothing flows (the roster-collapse
/// signature). Hidden flag `--starvation-threshold-secs`, its own knob so
/// the tests' short-evict profile doesn't arm it everywhere.
pub const STARVATION_THRESHOLD: Duration = ALIVE_TIMEOUT.saturating_mul(2);

/// The live value, after any CLI override of [`STARVATION_THRESHOLD`].
#[must_use]
pub fn starvation_threshold() -> Duration {
    current().starvation_threshold
}

/// How long the event-driven failover burst keeps retrying
/// `beacon::ensure` after a beacon-loss `NeighborDown`. Must
/// comfortably exceed the departing beacon's graceful-shutdown grace
/// (it broadcasts `Left`, sleeps, then exits and releases the UDP
/// socket) so the survivor is still retrying when the port frees.
pub const RECLAIM_WINDOW: Duration = Duration::from_secs(6);

/// Cadence of the fast reclaim burst while the window (above) is open.
pub const RECLAIM_INTERVAL: Duration = Duration::from_millis(400);

/// How often a member repeats that every port of its room's ladder is held by other processes
/// (`daemon::beacon_arm`: the warning and the event of the app).
///
/// The walk runs at every heal tick and at every tick of the reclaim burst, and the state does
/// not change in between. A line every heal tick is 240 lines an hour in the log and in the
/// terminal of the user, who can do nothing about it but free a port. Five minutes says it again
/// often enough for a session that was started later or a scrolled screen.
pub const NO_RUNG_REPEAT: Duration = Duration::from_mins(5);

/// Max remembered `quiet` (silence-evicted but maybe-returning) peers.
/// `quiet` is drained only when a peer returns, so without a cap a churn / sybil
/// stream of one-shot nicknames would grow it without bound — the one unbounded
/// collection we own. Evicting a long-departed peer that never came back costs
/// only a missed `peer_return` surface — acceptable. Generously above any
/// realistic live roster.
pub const QUIET_CAP: usize = 1024;

/// Minimum gap between our own re-dial + `PeerInfo` re-flood of the *same*
/// peer learned via `PeerInfo` (`gossip::recv::handle_peer_info`). Caps the
/// membership amplifier so a flapping/unstable peer is re-linked at most once
/// per window instead of once per flap — the fix for the mesh-wide CPU
/// runaway. `10s`: exceeds the QUIC idle timeout (a truly-gone peer isn't
/// aggressively re-dialed) and is ≤ the default heal interval (15s), so the
/// healer stays the backstop for legitimate re-bridge. iroh-gossip's own membership
/// still maintains links independently — this only throttles *our* piling-on.
pub const RELINK_COOLDOWN: Duration = Duration::from_secs(10);

/// How long after a proven pair loses its gossip link it is grafted again, before the
/// jitter of 30 %. The heal tick would take 10 to 15 s. The relink cooldown above paces a pair
/// that flaps. Both ends of a pair plan it, so the two grafts can cross: the tie-break of the
/// fork keeps one of the two links.
pub const REGRAFT_AFTER: Duration = Duration::from_secs(1);

/// How many session rounds a node holds in flight when it offers a lane session. The rounds that
/// it answers count too: the budget is the rounds of the admission table. A browser pays an ICE
/// gathering budget per round, and at formation a node would start one round per member. The
/// members left out of a pass are picked by the next one, and by the end of any round.
pub const LANE_OFFERS_IN_FLIGHT: usize = 4;

/// How many events the mesh topic may queue for the splitter before iroh-gossip reports a lag
/// and keeps the subscription (the engine counts the lag). It is also the size of the queue of
/// mesh messages to the event loop. This is iroh's default, 2048: at most 8 MB of queued events
/// (each holds a message of up to 3840 bytes).
///
/// The load run on real gossip (`docs/perf/benchmark.md`, "The split of the mesh topic under
/// load") found no difference in the frames lost between 2048 and 8192 at 64 or 128 MiB/s. The
/// topic does not lag below about 64 MiB/s with the split (about 16 MiB/s before it), and at
/// 128 MiB/s the split cuts the frames lost from 22% to 0.1% to 0.4%.
pub const MESH_TOPIC_EVENTS_CAP: usize = 2048;

/// How long a node may hold two or more links fewer than G, and how long it waits
/// between two fallbacks, before a graft asks with a `Join` instead of a low
/// priority request. A low priority request evicts nobody, so a member that arrives
/// when every other member is full gets no link from it. A `Join` evicts a random
/// neighbor of the peer, and that peer lands at G - 1, so one fallback per 300 s per
/// member bounds the churn to 0.2 link-ups per member per minute, and a fallback
/// starts no chain.
pub const STARVED: Duration = Duration::from_mins(5);

/// How often an advertising `create` re-broadcasts its mesh id into
/// the directory. Short enough that a fresh discoverer sees every live
/// mesh within one cycle (the join-horizon only surfaces ads stamped
/// after the discoverer joined), long enough that the directory stays
/// quiet — directory traffic is one tiny message per advertiser per
/// interval. Hidden flag `--advertise-interval-secs` so the subprocess directory test re-ads
/// quickly.
pub const ADVERTISE_INTERVAL: Duration = Duration::from_secs(20);

/// The live value, after any CLI override of [`ADVERTISE_INTERVAL`].
#[must_use]
pub fn advertise_interval() -> Duration {
    current().advertise_interval
}

/// How long a discoverer keeps showing a mesh after its last ad. A
/// publisher that exits stops re-broadcasting, so its listing ages out
/// within this window. ~3× `ADVERTISE_INTERVAL` so one or two lost
/// gossip rounds don't flicker a live mesh out of the list. Hidden flag
/// `--directory-expiry-secs` so the subprocess directory test can shorten the
/// `mesh_lost` window.
pub const DIRECTORY_EXPIRY: Duration = Duration::from_mins(1);

/// The live value, after any CLI override of [`DIRECTORY_EXPIRY`].
#[must_use]
pub fn directory_expiry() -> Duration {
    current().directory_expiry
}

/// First shed of an `EagerProbed` public beacon after a probed claim — see
/// [`RIVAL_RECHECK_FIRST`] for the rationale.
/// Hidden flag `--rival-recheck-first-secs` (tests converge in seconds).
/// Clamped to `>= 1 s`.
pub const RIVAL_RECHECK_FIRST: Duration = Duration::from_secs(12);

/// The live value, after any CLI override of [`RIVAL_RECHECK_FIRST`].
#[must_use]
pub fn rival_recheck_first() -> Duration {
    current().rival_recheck_first.max(Duration::from_secs(1))
}

/// Steady shed cadence for a lone `EagerProbed` public beacon holder —
/// see [`RIVAL_RECHECK`]. Hidden flag
/// `--rival-recheck-secs`. Clamped to `>= 1 s`.
pub const RIVAL_RECHECK: Duration = Duration::from_secs(30);

/// The live value, after any CLI override of [`RIVAL_RECHECK`].
#[must_use]
pub fn rival_recheck() -> Duration {
    current().rival_recheck.max(Duration::from_secs(1))
}

/// Steady shed cadence while meshed (island-vs-island backstop) — see
/// [`RIVAL_RECHECK_MESHED`]. Hidden flag
/// `--rival-recheck-meshed-secs`. Clamped to `>= 1 s`.
pub const RIVAL_RECHECK_MESHED: Duration = Duration::from_mins(5);

/// The live value, after any CLI override of [`RIVAL_RECHECK_MESHED`].
#[must_use]
pub fn rival_recheck_meshed() -> Duration {
    current().rival_recheck_meshed.max(Duration::from_secs(1))
}

/// Shed cadence ceiling for a holder with an **empty roster** — the tier
/// `daemon::beacon_arm::next_recheck_delay` picks when `roster == 0`.
///
/// [`RIVAL_RECHECK_MESHED`] is priced for two multi-member islands, and
/// the geometric ramp caps there for every small roster. A node that knows no
/// peer at all has nothing to reconcile: the brisk early rounds still run,
/// and they are what repairs a double-claim, but once a run of probes has
/// found no rival the only thing a 300s cap buys is a public-endpoint rebind
/// every ~7 minutes, forever. Measured on a permanently-alone topic peer:
/// ~138 rebinds/hour before the ramp existed, ~8/hour with the 300s cap, and
/// the rebind is the suspected road into a `recvmsg` spin. At 3600 the ramp
/// converges to a ~1.5h mean interval.
///
/// Hidden flag `--rival-recheck-alone-secs`. Clamped to `>= 1 s`.
pub const RIVAL_RECHECK_ALONE: Duration = Duration::from_hours(1);

/// The live value, after any CLI override of [`RIVAL_RECHECK_ALONE`].
#[must_use]
pub fn rival_recheck_alone() -> Duration {
    current().rival_recheck_alone.max(Duration::from_secs(1))
}

/// Topic meshes are the public preset; the `--topic-mdns-only` flag narrows
/// their lookups to mDNS (no DHT, no relay). **Test-only** (hidden flag): the
/// beacon-claim race is otherwise unreachable in CI (no public relay), same
/// rationale as `--directory-private` — see `tests/topic_split.rs`.
#[must_use]
pub fn topic_mdns_only_for_test() -> bool {
    current().topic_mdns_only
}

/// Directories are public by default; the `--directory-private` flag flips
/// `directory_mesh` to the loopback ladder and relaxes the `--advertise`
/// requires-`--public` guard. **Test-only** (hidden flag): the live
/// advertise→discover path is otherwise unreachable in CI (no public relay) —
/// see `tests/directory.rs`.
#[must_use]
pub fn directory_private_for_test() -> bool {
    current().directory_private
}

/// Per-rung timeout when selecting the public-mode bootstrap relay
/// (`habilis_network::net`'s bootstrap-rung selection) and when the beacon polls
/// its own rung's liveness. The selector walks the relay ladder and
/// homes on the first rung whose pinned endpoint reaches `online()`
/// within this budget; a rung that does not answer in time is treated
/// as unreachable and the next is tried.
///
/// Set to iroh's `NET_REPORT_TIMEOUT` (10s): `online()`'s own docs say
/// to use a timeout close to it so at least one net-report has been
/// attempted — a shorter budget can misjudge a healthy-but-slow relay
/// as down and trigger a spurious fall-through.
pub const RELAY_RUNG_PROBE: Duration = Duration::from_secs(10);

/// How often the beacon polls whether its current relay rung is still
/// connected (`timeout(RELAY_RUNG_PROBE, online())` on its own
/// endpoint). Off the event loop, inside the beacon co-host task.
pub const RELAY_LIVENESS_INTERVAL: Duration = Duration::from_secs(10);

/// Debounce: consecutive failed liveness polls before the beacon
/// concludes its rung is gone and re-walks the ladder. >1 so a single
/// transient blip (iroh auto-reconnects its home relay within a tick)
/// does not thrash the beacon between rungs.
pub const RELAY_LIVENESS_FAILS_TO_EVICT: u32 = 2;

/// Relay-less rediscovery backoff bounds. When the beacon holds **no**
/// rung (every ladder rung was unreachable), it keeps re-walking the
/// ladder to rediscover a recovered rung — but backs off between
/// rounds (`crate::lookup::next_relay_backoff`, doubling from MIN to
/// MAX) so an all-down ladder isn't hammered. The MIN is the first
/// inter-round wait; MAX caps it (still re-walking forever, just
/// sparsely). Distinct from `RELAY_LIVENESS_INTERVAL`, which is the
/// *homed* poll cadence (cheap, no backoff).
pub const RELAY_REPROBE_BACKOFF_MIN: Duration = Duration::from_secs(30);
/// The longest wait between two re-probes of a relay rung.
pub const RELAY_REPROBE_BACKOFF_MAX: Duration = Duration::from_mins(5);

/// Timeout for *one attempt* of the private-mode rendezvous identity
/// probe. When a ladder rung is `AddrInUse`, a member probes it to tell
/// *our* mesh's beacon (→ stay a peer) from an unrelated mesh squatting
/// the rung (→ try the next rung), or a rung that says nothing (→ stay a
/// peer, and bind it only once it has said nothing for
/// [`RECLAIM_WINDOW`] across walks).
///
/// The probe is a loopback connect to a live listener, so it resolves in
/// milliseconds; this is the cost of a walk that meets a silent rung, and
/// the walk stops at the first one. Kept tight so a contended-rung walk
/// cannot stall the event loop for long.
///
/// One attempt is enough because a silence no longer binds: the answer that
/// authorizes an irreversible bind is a failed identity check
/// (`ProbeAnswer::Foreign`: a key that the verifier rejected, or an identity
/// that iroh reads as another), or a rung that has stayed silent for the whole
/// window. A refusal (`ProbeAnswer::Refused`) reads as silence, and so does a
/// host that is too loaded to answer: for a few walks, and it binds nothing.
pub const RENDEZVOUS_PROBE: Duration = Duration::from_secs(1);

/// How long a departing member waits for its co-hosted rendezvous endpoint,
/// and for an outstanding rival probe's endpoint, to close
/// (`beacon::Rendezvous::shed_and_wait`, `beacon::RivalProbe::abort_and_close`).
///
/// Bounded because shutdown must not hang on a relay that stopped answering.
/// Exceeding the bound abandons the endpoint exactly as it was abandoned
/// before this wait existed — a fallback to the old behaviour, never worse
/// than it. [`NODE_LEAVE`] is derived from this, so the two cannot drift.
///
/// **Not a round number picked for looks.** At 1s it timed out on a live
/// three-peer share: an endpoint homed on two relay rungs spends most of a
/// second shutting its relay actors down (measured ~770ms under
/// `iroh=debug`). At 2s it timed out on every departure that landed while a
/// rival probe was still in its handshake: the probe's close frame is never
/// acknowledged, so iroh's close waits out the QUIC drain, which it documents
/// as "usually 3 seconds". 4s clears that with headroom.
pub const RENDEZVOUS_CLOSE: Duration = Duration::from_secs(4);

/// How long `Node::leave` waits for the event loop to wind down before it
/// detaches it: the 500ms `Left` propagation sleep, then the endpoint closes,
/// which run concurrently and so cost one [`RENDEZVOUS_CLOSE`], plus
/// headroom. A shorter budget let `serve` return and drop the runtime while a
/// close was still in flight, which aborts that close.
pub const NODE_LEAVE: Duration = RENDEZVOUS_CLOSE.saturating_add(Duration::from_secs(2));

/// Roster size (known live members) at or below which a *meshed* holder uses
/// the brisk lone cadence ([`RIVAL_RECHECK`]) instead of the slow
/// [`RIVAL_RECHECK_MESHED`] backstop.
///
/// The slow cadence is priced for the case it was written for: two
/// **multi-member** islands, where a shed's beacon blip costs a healthy gossip
/// something and the split is rare. A two-tab mesh left behind by a departed
/// origin is neither — the split is the routine outcome of that departure, and
/// a shed there disturbs almost nobody. So the tier is chosen by how much a
/// shed actually costs, which is roster size, not by the meshed flag alone.
///
/// A pure const with no flag, like [`RIVAL_RECHECK_OFFSET_SPAN`]: it
/// picks between two cadences that already have their own knobs.
pub const RIVAL_RECHECK_SMALL_ROSTER: usize = 4;

/// Span of the deterministic per-node phase offset added to the first shed,
/// derived from the peer endpoint id. Orders simultaneous claimants so
/// the earlier-offset node sheds first, finds the other's still-held beacon,
/// and yields — a tie-break, not a delay knob, so no flag.
pub const RIVAL_RECHECK_OFFSET_SPAN: Duration = Duration::from_secs(8);

/// How often one peer's digest may be *served*.
///
/// Answering a digest costs up to [`ANTIENTROPY_MAX_RESEND`] mesh-wide
/// broadcasts, and the budget was per digest with nothing per peer, so one
/// small crafted frame bought that from every member at once. Comfortably under
/// [`ANTIENTROPY_INTERVAL`], so the honest cadence is never refused.
pub const ANTIENTROPY_SERVE_COOLDOWN: Duration = Duration::from_secs(5);

/// How many members answer one chat digest.
///
/// Every member that holds a message the asker lacks used to answer, so one
/// digest bought up to `ANTIENTROPY_MAX_RESEND` broadcasts from each of the N - 1
/// others, and each broadcast reaches N - 1 links: about N^3 deliveries per
/// digest round. Of those, all but the first copy of a message are wasted. A
/// few answerers cover a lost answer and a holder that lacks the message, and
/// the answerers change with every digest (see `answers_digest`), so a message
/// that only one member holds still comes back within a few rounds.
pub const ANTIENTROPY_ANSWERERS: usize = 3;

/// How many resends the outbox of the event loop holds. A digest answer is at
/// most `ANTIENTROPY_MAX_RESEND` messages, so this is a few answers. When it is
/// full the resend is dropped and counted: the next digest asks again.
pub const RESEND_OUTBOX_CAP: usize = 256;

/// How many state digest answers one asker may get per channel on the unicast
/// plane in one [`ANTIENTROPY_SERVE_COOLDOWN`] window; the same heads get
/// an answer again only after [`FAST_ROUND_MIN_INTERVAL`]. A backfilling
/// node asks again as long as a peer's heads show it is behind (a fast round),
/// so it needs several per window; eight answers of
/// [`ANTIENTROPY_MAX_RESEND`] frames cover 512 changes, and still bound a node
/// whose fast rounds misbehave.
pub const ANTIENTROPY_SERVES_PER_WINDOW: usize = 8;

/// The shortest time between two direct fast-round digests to one peer, for
/// one channel. A peer that advertises heads nobody can hold then costs one
/// small frame per interval.
pub const FAST_ROUND_MIN_INTERVAL: Duration = Duration::from_millis(200);

/// How long after a direct fast-round digest a node holds back its own
/// broadcast digests for that channel.
pub const FAST_ROUND_ACTIVE: Duration = Duration::from_secs(1);

/// How long a stalled fast round waits before it asks a peer that is still
/// ahead again: a lost request, a lost answer, or a refusal costs this, not an
/// anti-entropy tick. The reclaim timer drives the check, so this matches it.
pub const FAST_ROUND_RETRY: Duration = Duration::from_millis(400);

/// How many peers a node remembers as ahead of it, per channel.
pub const FAST_ROUND_AHEAD_MAX: usize = 16;

/// How long a peer stays remembered as ahead after its heads last showed it:
/// a peer whose heads we can never hold must not hold a place for ever.
pub const FAST_ROUND_AHEAD_TTL: Duration = Duration::from_mins(1);

/// `HyParView` **active view** capacity (G): the number of direct gossip
/// neighbors (open QUIC links) each member keeps per topic. A mesh of G + 1
/// members or fewer forms a **full mesh** with nothing to shuffle, so it has
/// **zero membership churn** (and none of the per-connection-churn memory leak).
/// Past that the overlay is partial and keeps promoting and demoting peers.
///
/// The default is **32**, chosen together with D, the `WebRTC` session cap
/// (`MAX_DIRECT_PEERS`): the memory of a node follows both, see "Choosing G and
/// D from a memory budget" in `docs/perf/direct-peer-memory.md`. It was 64,
/// which kept meshes of up to 65 free of churn at 50 to 100 MB per node. G is a
/// count bound only: `HyParView` still accepts a high-priority join at a full
/// view and drops a random member. This is the default for the public
/// `--max-peers` cap, and `0` asks for it. The passive (healing/shuffle) pool is
/// derived as 2x the live view. Set `--max-peers` *small* to deliberately
/// reproduce the gossip-churn leak at any node count.
pub const GOSSIP_ACTIVE_VIEW_CAPACITY: usize = 32;

/// How often the direct-peer slot table drops the connections that are gone and
/// the peers that nothing holds. One timer per admission table, not one task
/// per connection.
pub const SLOT_SWEEP: Duration = Duration::from_secs(5);

/// How many gossip links to other members make a node let go of the
/// rendezvous. The rendezvous is where a node enters the mesh and where split
/// islands meet again; it is not a peer to hold for ever. A node below this
/// many links keeps it (or comes back to it); at this many it releases it, so
/// that the rendezvous has room for the next joiner (its direct-peer slots and
/// its gossip view are finite).
pub const RENDEZVOUS_RELEASE_LINKS: usize = 3;

/// How long a node that a peer refused at its cap leaves that peer alone, the
/// first time. Each further refusal in a row doubles it, up to
/// [`CAP_REFUSAL_COOLDOWN_MAX`]; a success resets it. A refusal at the
/// rendezvous frees up fast, so the first wait is short. A refusal at a member
/// does not: its sessions are gossip links and stay busy, so the wait grows to
/// the size that keeps the cost of a refused round (a full candidate gathering
/// on our side) low.
pub const CAP_REFUSAL_COOLDOWN: Duration = Duration::from_secs(30);

/// The longest a node leaves a peer alone after repeated refusals at its cap.
pub const CAP_REFUSAL_COOLDOWN_MAX: Duration = Duration::from_mins(5);

/// How long a node that comes back to the rendezvous stays, at least, before
/// it may let go again. The beacon introduces a visitor to the members in its
/// gossip view, and the introduction takes a few round trips; a visit shorter
/// than that would find no one.
pub const RENDEZVOUS_DWELL: Duration = Duration::from_secs(30);

/// How long a node that let go of the rendezvous on purpose waits before it wants it again, at
/// the least. Islands of a split mesh that each hold links enough have no other reason to visit the
/// rendezvous, where they meet. A node adds up to half of this from its id, so that n members cost
/// about n / period visits a minute, and not n at once. A wider spread for very large rooms is a
/// tuning choice: raise this value.
pub const RENDEZVOUS_PERIODIC_RETURN: Duration = Duration::from_mins(10);

/// The live value, after any override of [`RENDEZVOUS_PERIODIC_RETURN`]. Clamped to `>= 1 s`.
#[must_use]
pub fn rendezvous_periodic_return() -> Duration {
    current()
        .rendezvous_periodic_return
        .max(Duration::from_secs(1))
}

/// How long an owed return to the rendezvous lasts. A node that is refused at
/// the rendezvous, or finds it gone, offers again for this long and then stops:
/// the owed return is a debt with an end, not a state.
pub const RENDEZVOUS_COMEBACK: Duration = Duration::from_mins(2);

/// How long the session of a lane peer stays wanted after a frame was held for it. The offer
/// that the held frame asks for must start within this time, or the want lapses. A frame that stays
/// parked after the want lapsed does not mark the peer again by itself: the next send to the peer
/// does.
pub const LANE_WANTED: Duration = Duration::from_mins(1);

/// How many bytes of one QUIC stream a node buffers for a peer that sends faster than the node
/// reads (decision D11): 16 `MiB`, the same as the window of the connection, so that one blob
/// stream can use the whole window. Far above the iroh default, and a bound all the same.
pub const QUIC_STREAM_RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;

/// How many bytes of all the streams of one QUIC connection together a node buffers for a peer
/// (decision D11): 16 `MiB`. One connection cannot grow without bound, and at 100 ms of round trip
/// the window still allows about 1.3 Gbit/s.
pub const QUIC_CONNECTION_RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;

/// How many bytes a node sends to a peer before the peer acknowledges them (decision D11): 16 `MiB`.
pub const QUIC_SEND_WINDOW: u64 = 16 * 1024 * 1024;

/// How long after a `Neighbor` request a node reads "no link came up" as a refusal: the longer of
/// the relink cooldown (10 s) and the probe deadline (15 s), plus 5 s. A link that comes up later
/// than this is not a reply to the request.
pub const GRAFT_REFUSED_AFTER: Duration = Duration::from_secs(20);

/// The first wait before a peer that refused a `Neighbor` request is asked again. Each refusal in
/// a row doubles it, up to [`GRAFT_BACKOFF_MAX`]. A `NeighborUp` or a new address of the peer
/// starts it over.
pub const GRAFT_BACKOFF_FIRST: Duration = Duration::from_mins(1);

/// The longest wait before a peer that keeps refusing is asked again, 15 minutes.
pub const GRAFT_BACKOFF_MAX: Duration = Duration::from_mins(15);

/// The one idle backstop of the direct connections (decision D11). The ceiling frees a place
/// when a newcomer needs it; this only closes what nobody used for a quarter of an hour, so
/// that a quiet node holds nothing for ever. It is the idle close of a pooled connection and of
/// an accepted one, and the wait before an unheld session is detached.
pub const DIRECT_IDLE_BACKSTOP: Duration = Duration::from_mins(15);

/// How long the pooled connection of a direct-path probe stays after the probe
/// ends, when no send takes it (decision D4: direct connections are on demand).
/// The graft that follows a proven path forms its gossip link inside this
/// window, and iroh keeps the proven path for the peer while any connection to
/// it is open. Longer than that, the probe connection would be a pre-warmed
/// unicast connection for a pair that never sent.
pub const PROBE_HOLD: Duration = Duration::from_secs(15);

/// Max bytes a per-member log file grows before rotating to `<file>.1`
/// (active + one backup ⇒ bounded at `2 ×` this). The `--log-max-bytes` flag
/// overrides; `0` disables rotation. Resolved by [`crate::logs::log_max_bytes`].
///
/// `host`-only with the file sink: a browser has no log file to rotate.
#[cfg(feature = "host")]
pub const LOG_FILE_MAX_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB
