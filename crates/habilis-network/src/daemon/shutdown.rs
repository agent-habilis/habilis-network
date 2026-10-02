//! Leaving the mesh: the graceful shutdown path and the signals that trigger it.
//!
//! Split out of `event_loop` because none of it is the loop — it is what runs
//! once, on the way out, and it was the largest block of the file that never
//! touched a tick.

use std::time::Duration;

use tokio::sync::mpsc;

use crate::{gossip, lifecycle};

use super::app::NodeDriver;
use super::ctx::HandlerCtx;
use super::state::EventLoopState;
use crate::gossip::event::NodeEvent;
use crate::protocol::{MeshName, Message};
#[cfg(all(unix, feature = "host"))]
use crate::util::tuning::ppid_watch_interval_ms;

/// Graceful shutdown: remove the statusline state file first, then
/// announce `Left` and give the broadcast a moment to reach peers.
/// Shared by both the external-quit and ctrl-c/SIGTERM/SIGHUP paths so
/// they can't drift apart.
///
/// The state-file removal is the time-critical step: an external reader
/// (the shell statusline) shows the mesh pill while the file is fresh,
/// so a leaver must clear it *immediately*. It runs before the
/// best-effort `Left` broadcast and its 500 ms propagation sleep so a
/// kill landing during that window can't strand the file with a still-fresh
/// `last_updated`, leaving a ghost pill on the statusline.
pub(super) async fn shutdown<A: NodeDriver>(
    state: &mut EventLoopState,
    app: &mut A,
    ctx: &HandlerCtx<'_>,
    quit: &QuitParams<'_>,
) {
    // Release app-owned resources (fail parked app waiters, close the
    // blob-serving endpoint whose store spool is dropped with it).
    app.on_shutdown(state, ctx).await;
    #[cfg(feature = "host")]
    if let Some(sf) = state.state_file.as_ref() {
        sf.remove();
    }
    ctx.sink
        .emit(NodeEvent::Info(format!("left {}", quit.leave_label)));
    // The `Left` rides gossip only — deliberately NOT mirrored over unicast
    // (unlike the meta retraction in `on_shutdown`): presence drives the
    // survivors' rendezvous fast-reclaim, and a `Left` that lands while a
    // survivor's gossip still holds the dying beacon's link re-stands the
    // beacon into a stale connection and stalls (iroh-gossip#10; see the
    // post-departure-join test's SIGKILL choreography).
    gossip::broadcast_msg(
        ctx.sender,
        &Message::new_left(ctx.mesh, ctx.author).signed(&state.identity),
    )
    .await;
    // After the broadcast, so peers get the `Left` even when logging fails.
    lifecycle::log_leaving(quit.name.as_str());
    n0_future::time::sleep(Duration::from_millis(500)).await;
}
/// The mesh name (for the departure log line), the user-facing departure
/// label (the raw topic string for a topic gossip, `#name` otherwise), and
/// whether this quit should hard-exit the process — the plain values
/// [`announce_and_maybe_exit`] needs beyond the loop state and the shared
/// handler context.
pub(super) struct QuitParams<'a> {
    pub(super) name: &'a MeshName,
    pub(super) leave_label: &'a str,
    pub(super) exit_on_quit: bool,
}
/// Announce departure, then decide whether to hard-exit the process.
///
/// `exit_on_quit` is the CLI hard-exit: the CLI process exits immediately on
/// quit rather than tearing down its background tasks (advertiser,
/// localhost HTTP server, iroh) and unwinding. In-process quits pass `false`
/// and unwind cleanly instead. Under the `dhat-heap` profiling build we
/// *never* `process::exit` regardless — it skips destructors, so the heap
/// profiler would never flush `dhat-heap.json`; we fall through so `main`
/// unwinds and the profiler drops.
pub(super) async fn announce_and_maybe_exit<A: NodeDriver>(
    state: &mut EventLoopState,
    app: &mut A,
    ctx: &HandlerCtx<'_>,
    quit: QuitParams<'_>,
) {
    // Empty out any parked long-poll waiters first, so a held call returns a
    // clean timeout (empty) rather than a dropped-channel error — and before
    // the `exit_on_quit` path below may `std::process::exit`. Other app-owned
    // waiters (app RPC calls) are failed in `on_shutdown` (inside `shutdown`).
    app.close_poll_waiters();
    shutdown(state, app, ctx, &quit).await;
    #[cfg(not(feature = "dhat-heap"))]
    if quit.exit_on_quit {
        std::process::exit(0);
    }
    #[cfg(feature = "dhat-heap")]
    let _ = quit.exit_on_quit;
}
/// Spawn ctrl-c (all platforms) plus SIGTERM/SIGHUP/SIGQUIT (unix)
/// listener tasks feeding a single internal quit channel.
/// `tokio::signal::ctrl_c()` inside a `select!` branch doesn't reliably
/// interrupt a blocking stdin read, so we offload signal listening to
/// dedicated tasks.
///
/// Every catchable termination signal routes through the graceful
/// `shutdown()` path so the statusline state file is removed. SIGHUP in
/// particular is what a closing parent (e.g. the Monitor that hosts the
/// daemon for a `/gossip-*` session) tends to send; without catching it
/// the default action terminated the daemon without cleanup, stranding a
/// ghost pill on the statusline. Only SIGKILL stays uncatchable.
#[cfg(feature = "host")]
pub(super) fn spawn_quit_signal_tasks(
    exit_on_quit: bool,
    owner: Option<Owner>,
) -> mpsc::Receiver<()> {
    let (quit_tx, quit_rx) = mpsc::channel::<()>(1);
    let ctrl_c_tx = quit_tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = ctrl_c_tx.send(()).await;
    });
    #[cfg(unix)]
    for kind in [
        tokio::signal::unix::SignalKind::terminate(),
        tokio::signal::unix::SignalKind::hangup(),
        tokio::signal::unix::SignalKind::quit(),
    ] {
        let signal_tx = quit_tx.clone();
        tokio::spawn(async move {
            let mut signal =
                tokio::signal::unix::signal(kind).expect("failed to register termination handler");
            signal.recv().await;
            let _ = signal_tx.send(()).await;
        });
    }
    // Only the CLI daemon owns a process to exit; the in-process driver runs
    // in-process with no parent of its own to lose, so it must never self-quit
    // on a host reparent.
    #[cfg(unix)]
    if exit_on_quit {
        spawn_orphan_watch(quit_tx, owner);
    }
    quit_rx
}
/// Whether `pid` can own a daemon, with the checks and messages of
/// `EventLoopConfig::with_owner_pid`. For a launcher that must refuse a bad
/// pid in the foreground, before it re-spawns the daemon detached.
///
/// # Errors
/// `pid` is 0 or 1, the calling process's own pid, or no live process has it
/// (a zombie counts as dead). The message is one line.
#[cfg(feature = "host")]
pub fn validate_owner_pid(pid: u32) -> anyhow::Result<()> {
    owner_start(pid).map(drop)
}
/// The start time of a valid owner, the one home of the owner checks.
#[cfg(feature = "host")]
fn owner_start(pid: u32) -> anyhow::Result<u64> {
    anyhow::ensure!(
        pid > 1,
        "owner pid {pid} is init or invalid. Give a live process id greater than 1"
    );
    anyhow::ensure!(
        pid != std::process::id(),
        "owner pid {pid} is this process itself"
    );
    crate::util::process::live_start_time(pid)
        .ok_or_else(|| anyhow::anyhow!("owner pid {pid} is not running"))
}
/// The process a detached daemon lives for, in place of its parent. The pid
/// alone cannot tell the owner from a later process that reuses the pid, so
/// the start time captured at startup is what identifies it.
#[cfg(feature = "host")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Owner {
    pid: u32,
    start: u64,
}

#[cfg(feature = "host")]
impl Owner {
    /// # Errors
    /// See [`validate_owner_pid`].
    pub(crate) fn new(pid: u32) -> anyhow::Result<Self> {
        Ok(Self {
            pid,
            start: owner_start(pid)?,
        })
    }

    pub(crate) fn pid(self) -> u32 {
        self.pid
    }

    fn lost(self) -> bool {
        crate::util::process::live_start_time(self.pid) != Some(self.start)
    }
}
/// Detect orphaning by the spawning agent and route it through the same quit
/// channel as a signal. A hard-killed parent (`kill -9`, a reinstall, an IDE
/// restart) can't run any cleanup, so the spawned daemon is reparented instead
/// of terminated and would otherwise linger in the mesh forever. The daemon
/// watches its *own* parent — the only mechanism that survives SIGKILL and is
/// identical on macOS and Linux (`PR_SET_PDEATHSIG` and kqueue `NOTE_EXIT` are
/// each platform-specific). When the parent vanishes we feed `quit_tx`, reusing
/// the SIGTERM path that broadcasts `left` and exits cleanly.
// `unix` alone is not enough: `libc` arrives with the `host` feature.
#[cfg(all(unix, feature = "host"))]
#[expect(
    unsafe_code,
    reason = "libc::getppid FFI; no safe wrapper, always succeeds"
)]
fn spawn_orphan_watch(quit_tx: mpsc::Sender<()>, owner: Option<Owner>) {
    let interval = Duration::from_millis(ppid_watch_interval_ms());
    if let Some(owner) = owner {
        tokio::spawn(watch_owner(owner, interval, quit_tx));
        return;
    }
    let original_ppid = unsafe { libc::getppid() };
    if !orphan_watch_warranted(original_ppid) {
        return;
    }
    tokio::spawn(async move {
        loop {
            n0_future::time::sleep(interval).await;
            let current_ppid = unsafe { libc::getppid() };
            if parent_lost(original_ppid, current_ppid) {
                let _ = quit_tx.send(()).await;
                return;
            }
        }
    });
}
/// The orphan watch of a daemon with an [`Owner`]: its parent is init, so the
/// owner's exit is the one event that ends it.
#[cfg(all(unix, feature = "host"))]
async fn watch_owner(owner: Owner, interval: Duration, quit_tx: mpsc::Sender<()>) {
    loop {
        n0_future::time::sleep(interval).await;
        if owner.lost() {
            let _ = quit_tx.send(()).await;
            return;
        }
    }
}
/// Whether the orphan watch is worth running. Skip it when the daemon already
/// has no agent to lose — a parent pid of 1 means it was launched detached
/// straight from init/launchd, so it must never self-terminate.
#[cfg(all(unix, feature = "host"))]
pub(super) fn orphan_watch_warranted(original_ppid: i32) -> bool {
    original_ppid > 1
}
/// The orphaning test: the parent pid changed from the one captured at startup.
/// Comparing against the *original* (not against `1`) is what makes this correct
/// on both platforms — macOS reparents an orphan to launchd (1), but under
/// systemd Linux reparents to a subreaper at some other pid. Pid reuse can't
/// fool it: the reaper's pid won't coincidentally equal the original parent's.
#[cfg(all(unix, feature = "host"))]
pub(super) fn parent_lost(original_ppid: i32, current_ppid: i32) -> bool {
    original_ppid != current_ppid
}
/// A quit channel whose sender is deliberately leaked, so the receiver parks
/// forever. The loop's quit arm then only ever fires from `external_quit_rx`.
pub(super) fn never_quit() -> mpsc::Receiver<()> {
    let (quit_tx, quit_rx) = mpsc::channel::<()>(1);
    std::mem::forget(quit_tx);
    quit_rx
}

#[cfg(all(unix, feature = "host"))]
#[cfg(test)]
mod tests {
    use std::process::{Child, Command};
    use std::time::Duration;

    use tokio::sync::mpsc;

    use super::{Owner, orphan_watch_warranted, parent_lost, validate_owner_pid, watch_owner};

    const TICK: Duration = Duration::from_millis(10);

    fn spawn_owner() -> Child {
        Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep")
    }

    /// Run the owner watch; `true` when it quit within `within`.
    async fn watch_quits(owner: Owner, within: Duration) -> bool {
        let (quit_tx, mut quit_rx) = mpsc::channel(1);
        let watch = tokio::spawn(watch_owner(owner, TICK, quit_tx));
        let quit = tokio::time::timeout(within, quit_rx.recv()).await.is_ok();
        watch.abort();
        quit
    }

    #[tokio::test]
    async fn owner_watch_stays_while_the_owner_lives() {
        let mut child = spawn_owner();
        let owner = Owner::new(child.id()).expect("live owner accepted");
        assert!(!watch_quits(owner, Duration::from_millis(300)).await);
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[tokio::test]
    async fn owner_watch_quits_when_the_owner_exits() {
        let mut child = spawn_owner();
        let owner = Owner::new(child.id()).expect("live owner accepted");
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(watch_quits(owner, Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn owner_watch_quits_when_the_owner_is_an_unreaped_zombie() {
        let mut child = spawn_owner();
        let owner = Owner::new(child.id()).expect("live owner accepted");
        child.kill().unwrap();
        assert!(watch_quits(owner, Duration::from_secs(2)).await);
        child.wait().unwrap();
    }

    /// Simulates reuse with `start + 1`: that a real reissue changes the start
    /// time is a property of the OS, not something this test can show.
    #[tokio::test]
    async fn owner_watch_quits_when_the_pid_is_reissued() {
        let mut child = spawn_owner();
        let owner = Owner::new(child.id()).expect("live owner accepted");
        let reissued = Owner {
            start: owner.start + 1,
            ..owner
        };
        assert!(watch_quits(reissued, Duration::from_secs(2)).await);
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn validate_owner_pid_accepts_only_a_live_other_process() {
        let mut child = spawn_owner();
        let pid = child.id();
        assert!(validate_owner_pid(pid).is_ok());
        for refused in [0, 1, std::process::id()] {
            let error = validate_owner_pid(refused)
                .expect_err("refused")
                .to_string();
            assert!(!error.contains('\n'), "one error line: {error}");
        }
        child.kill().unwrap();
        // SIGKILL lands asynchronously, so poll until the unreaped child is a
        // zombie; it stays one until the `wait` below.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while validate_owner_pid(pid).is_ok() {
            assert!(std::time::Instant::now() < deadline, "a zombie is refused");
            std::thread::sleep(TICK);
        }
        child.wait().unwrap();
        assert!(validate_owner_pid(pid).is_err(), "a dead pid is refused");
    }

    #[test]
    fn owner_refuses_init_self_and_a_dead_pid() {
        assert!(Owner::new(0).is_err());
        assert!(Owner::new(std::process::id()).is_err(), "self is no owner");
        let init = Owner::new(1).expect_err("init refused").to_string();
        assert!(!init.contains('\n'), "one error line: {init}");
        assert!(!init.contains("agent"), "engine vocabulary only: {init}");
        let mut child = spawn_owner();
        let pid = child.id();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(Owner::new(pid).is_err());
    }

    #[test]
    fn orphan_watch_fires_only_on_a_parent_change() {
        // The agent that spawned us is alive ⇒ same ppid ⇒ stay running.
        assert!(!parent_lost(4242, 4242));
        // The agent died ⇒ reparented to launchd (1) ⇒ orphaned, quit.
        assert!(parent_lost(4242, 1));
        // …or, under a systemd subreaper, to some other pid ⇒ still orphaned.
        assert!(parent_lost(4242, 990));
    }

    #[test]
    fn orphan_watch_skips_an_already_detached_daemon() {
        // Spawned by a normal agent ⇒ worth watching.
        assert!(orphan_watch_warranted(4242));
        // Launched detached straight from init/launchd ⇒ no parent to lose.
        assert!(!orphan_watch_warranted(1));
    }
}
