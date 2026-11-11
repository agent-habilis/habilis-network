//! Leaving the mesh: the graceful shutdown path and the signals that trigger it.
//!
//! Split out of `event_loop` because none of it is the loop — it is what runs
//! once, on the way out, and it was the largest block of the file that never
//! touched a tick.

use std::mem;
#[cfg(all(not(windows), feature = "host"))]
use tokio::signal;

mod owned_endpoints;
#[cfg(feature = "host")]
mod owner;
#[cfg(feature = "host")]
mod owner_pid_error;
mod quit_params;

use std::time::Duration;

use tokio::sync::mpsc;

use crate::{gossip, lifecycle};

use super::app::NodeDriver;
use super::handler_ctx::HandlerCtx;
use super::state::EventLoopState;
use crate::gossip::event::NodeEvent;
use crate::protocol::Message;
#[cfg(feature = "host")]
use crate::util::tuning;

#[cfg(feature = "host")]
use crate::util::process;
use n0_future::time as n0future_time;
#[cfg(feature = "host")]
use std::process as std_process;
#[cfg(feature = "host")]
#[cfg(unix)]
use tokio::signal::unix;

pub(super) use owned_endpoints::OwnedEndpoints;
#[cfg(feature = "host")]
pub(crate) use owner::Owner;
#[cfg(feature = "host")]
pub use owner_pid_error::OwnerPidError;
pub(super) use quit_params::QuitParams;
/// Graceful shutdown: remove the statusline state file first, then
/// announce `Left` and give the broadcast a moment to reach peers.
/// Shared by the external-quit path and the quit channel (ctrl-c, SIGTERM,
/// SIGHUP, the console events and the end of the session on Windows, the
/// owner watch, the IPC `quit` on Windows) so they can't drift apart.
///
/// The state-file removal is the time-critical step: an external reader
/// (the shell statusline) shows the mesh pill while the file is fresh,
/// so a leaver must clear it *immediately*. It runs before the
/// best-effort `Left` broadcast and its 500 ms propagation sleep so a
/// kill landing during that window can't strand the file with a still-fresh
/// `last_updated`, leaving a ghost pill on the statusline.
pub(super) async fn shutdown<Driver: NodeDriver>(
    state: &mut EventLoopState,
    app: &mut Driver,
    context: &HandlerCtx<'_>,
    quit: &QuitParams<'_>,
) {
    // Release app-owned resources (fail parked app waiters, close the
    // blob-serving endpoint whose store spool is dropped with it).
    app.on_shutdown(state, context).await;
    #[cfg(feature = "host")]
    if let Some(sf) = state.state_file.as_ref() {
        sf.remove();
    }
    // Explicit, not a `Drop`: in CLI mode the process leaves through
    // `std::process::exit`, which runs no destructor.
    #[cfg(all(windows, feature = "host"))]
    if let Some(marker) = state.ipc_marker.as_ref() {
        marker.remove_if_ours();
    }
    context
        .sink
        .emit(NodeEvent::Info(format!("left {}", quit.leave_label)));
    // The `Left` rides gossip only — deliberately NOT mirrored over unicast
    // (unlike the meta retraction in `on_shutdown`): presence drives the
    // survivors' rendezvous fast-reclaim, and a `Left` that lands while a
    // survivor's gossip still holds the dying beacon's link re-stands the
    // beacon into a stale connection and stalls (iroh-gossip#10; see the
    // post-departure-join test's SIGKILL choreography).
    gossip::broadcast_msg(
        context.sender,
        &Message::new_left(context.mesh, context.author).sign(&state.identity),
    )
    .await;
    // After the broadcast, so peers get the `Left` even when logging fails.
    lifecycle::log_leaving(quit.name.as_str());
    n0future_time::sleep(Duration::from_millis(500)).await;
}
/// Announce departure, and say whether the loop must hard-exit the process once it has ended.
///
/// `exit_on_quit` is the CLI hard-exit: the CLI process exits on quit rather than tearing down
/// its background tasks (advertiser, localhost HTTP server, iroh) and unwinding. In-process
/// quits pass `false` and unwind cleanly instead. The exit is the loop's to make, after
/// `release_rendezvous` has shed the beacon and closed the endpoints that the loop owns: an exit
/// from here skips both, and the peers of the beacon wait for its idle timeout. Under the
/// `dhat-heap` profiling build we *never* hard-exit regardless: it skips destructors, so the
/// heap profiler would never flush `dhat-heap.json`; `main` unwinds and the profiler drops.
pub(super) async fn announce_departure<Driver: NodeDriver>(
    state: &mut EventLoopState,
    app: &mut Driver,
    context: &HandlerCtx<'_>,
    quit: QuitParams<'_>,
) -> bool {
    // Empty out any parked long-poll waiters first, so a held call returns a
    // clean timeout (empty) rather than a dropped-channel error. Other app-owned
    // waiters (app RPC calls) are failed in `on_shutdown` (inside `shutdown`).
    app.close_poll_waiters();
    shutdown(state, app, context, &quit).await;
    quit.exit_on_quit && !cfg!(feature = "dhat-heap")
}
/// Spawn ctrl-c (all platforms) plus SIGTERM/SIGHUP/SIGQUIT (unix) or the
/// console events (Windows, `spawn_console_event_tasks`) listener tasks,
/// and for the CLI daemon the owner or parent watch
/// ([`spawn_orphan_watch`]) and on Windows the window of the end of the
/// session (`spawn_session_end_watch`), all feeding a single internal quit
/// channel.
/// On Windows it returns both ends: the sender also goes to the IPC accept
/// loop, whose `quit` feeds the same channel. On Unix it returns the receiver,
/// as before the port.
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
pub(super) fn spawn_quit_signal_tasks(exit_on_quit: bool, owner: Option<Owner>) -> QuitChannel {
    let (quit_tx, quit_rx): (mpsc::Sender<()>, mpsc::Receiver<()>) = mpsc::channel(1);
    #[cfg(not(windows))]
    {
        let ctrl_c_tx = quit_tx.clone();
        tokio::spawn(async move {
            let _ = signal::ctrl_c().await;
            let _ = ctrl_c_tx.send(()).await;
        });
    }
    #[cfg(windows)]
    spawn_console_event_tasks(&quit_tx);
    #[cfg(unix)]
    for kind in [
        unix::SignalKind::terminate(),
        unix::SignalKind::hangup(),
        unix::SignalKind::quit(),
    ] {
        let signal_tx = quit_tx.clone();
        tokio::spawn(async move {
            let mut signal = unix::signal(kind).expect("failed to register termination handler");
            signal.recv().await;
            let _ = signal_tx.send(()).await;
        });
    }
    // Only the CLI daemon owns a process to exit; the in-process driver runs
    // in-process with no parent of its own to lose, so it must never self-quit
    // on a host reparent.
    if exit_on_quit {
        spawn_orphan_watch(quit_tx.clone(), owner);
        #[cfg(windows)]
        spawn_session_end_watch(&quit_tx);
    }
    #[cfg(windows)]
    let channel = (quit_tx, quit_rx);
    #[cfg(not(windows))]
    let channel = {
        drop(quit_tx);
        quit_rx
    };
    channel
}

/// What [`spawn_quit_signal_tasks`] and [`never_quit`] give: on Windows the
/// sender and the receiver of the quit channel, because the IPC `quit` feeds
/// it too; on other OSes the receiver alone.
#[cfg(all(windows, feature = "host"))]
pub(super) type QuitChannel = (mpsc::Sender<()>, mpsc::Receiver<()>);
/// What [`never_quit`] gives off Windows: the receiver alone.
#[cfg(not(all(windows, feature = "host")))]
pub(super) type QuitChannel = mpsc::Receiver<()>;

/// The console events of Windows (R7 of `docs/windows.md`): ctrl-c,
/// ctrl-break, the close of the console, a logoff and a shutdown all feed the
/// quit channel, so they take the path of SIGTERM.
///
/// The listeners are made here, before the `tokio::spawn`, so the handler of
/// tokio and its receivers exist when the node is ready. An event with no live
/// receiver goes to the default handler, which ends the process with no
/// `Left`. On a close, a logoff or a shutdown the handler of tokio never
/// returns, because Windows ends the process when it does; the process lives
/// until the `std::process::exit` of the quit path, or until the deadline of
/// Windows (about 5 s).
///
/// A logoff and a shutdown do not reach these listeners. Windows does not give
/// them to the console handler of a process that loaded `user32.dll`, and a
/// node loads it: iroh's `netwatch` uses COM through `wmi`, and the runtime
/// base uses `SHGetKnownFolderPath`. A CLI daemon gets them through the window
/// of [`spawn_session_end_watch`]. The listeners stay, at no cost, for a build
/// that does not load it. A process with no console gets no console event at
/// all, and a process in a new process group ignores ctrl-c.
#[cfg(all(windows, feature = "host"))]
fn spawn_console_event_tasks(quit_tx: &mpsc::Sender<()>) {
    use tokio::signal::windows;

    let register = "failed to register a console event handler";
    let mut ctrl_c = windows::ctrl_c().expect(register);
    let mut ctrl_break = windows::ctrl_break().expect(register);
    let mut ctrl_close = windows::ctrl_close().expect(register);
    let mut ctrl_logoff = windows::ctrl_logoff().expect(register);
    let mut ctrl_shutdown = windows::ctrl_shutdown().expect(register);
    spawn_console_event(quit_tx, "ctrl_c", async move {
        ctrl_c.recv().await;
    });
    spawn_console_event(quit_tx, "ctrl_break", async move {
        ctrl_break.recv().await;
    });
    spawn_console_event(quit_tx, "ctrl_close", async move {
        ctrl_close.recv().await;
    });
    spawn_console_event(quit_tx, "ctrl_logoff", async move {
        ctrl_logoff.recv().await;
    });
    spawn_console_event(quit_tx, "ctrl_shutdown", async move {
        ctrl_shutdown.recv().await;
    });
}
/// Wait for one console event, log it, and feed the quit channel.
#[cfg(all(windows, feature = "host"))]
fn spawn_console_event(
    quit_tx: &mpsc::Sender<()>,
    event: &'static str,
    received: impl Future<Output = ()> + Send + 'static,
) {
    let quit_tx = quit_tx.clone();
    tokio::spawn(async move {
        received.await;
        tracing::info!(
            target: "habilis_network::lifecycle",
            event,
            "console event; leaving"
        );
        let _ = quit_tx.send(()).await;
    });
}
/// The end of the Windows session (R13 of `docs/windows.md`): a logoff, a
/// shutdown, or a close by the Restart Manager, and a `WM_CLOSE`, which
/// `taskkill /PID` without `/F` sends. Each feeds the quit channel. Windows
/// does not give the end of the session to the console handler of a process
/// that loaded `user32.dll`, only to its windows, so the daemon has a hidden
/// one ([`crate::util::win_session`]). Only the CLI daemon has it: it alone
/// exits the process, and it must hold the end of the session until it does.
///
/// Windows ends the process when the window procedure returns from
/// `WM_ENDSESSION`, so on the end of the session the window thread never
/// returns: it parks until the `std::process::exit` of the quit path, or until
/// the deadline of Windows (`WaitToKillAppTimeout`, 5 s by default). A
/// `WM_CLOSE` has no deadline, so the window thread returns from it and still
/// gets a later end of the session.
///
/// With no window, the daemon runs on, and a logoff or a shutdown ends it with
/// no `Left`, as before R13.
#[cfg(all(windows, feature = "host"))]
fn spawn_session_end_watch(quit_tx: &mpsc::Sender<()>) {
    use std::thread;

    use crate::util::win_session::{SessionEvent, watch_session_end};

    let quit_tx = quit_tx.clone();
    // `try_send`: the window thread is not a task of tokio. A full channel is a
    // quit already on its way, and a closed one is a loop that has ended. The
    // send comes before the log, so the quit does not wait for it. The call
    // blocks this worker until the window exists: a few milliseconds, once.
    let watched = watch_session_end(move |event| match event {
        SessionEvent::End(kind) => {
            let _ = quit_tx.try_send(());
            tracing::info!(
                target: "habilis_network::lifecycle",
                ?kind,
                "session end; leaving"
            );
            loop {
                thread::park();
            }
        }
        SessionEvent::Close => {
            let _ = quit_tx.try_send(());
            tracing::info!(
                target: "habilis_network::lifecycle",
                "window close; leaving"
            );
        }
        // A later kind of event of the window stops nothing.
        _ => {}
    });
    if let Err(error) = watched {
        tracing::warn!(
            target: "habilis_network::lifecycle",
            %error,
            "no window for the end of the session; a logoff or a shutdown ends this daemon with no Left"
        );
    }
}
/// Whether `pid` can own a daemon, with the checks and messages of
/// `EventLoopConfig::owner_pid`. For a launcher that must refuse a bad
/// pid in the foreground, before it re-spawns the daemon detached.
///
/// # Errors
/// `pid` is 0 or 1, the calling process's own pid, or no live process has it
/// (a zombie counts as dead), or this process cannot read it (on Windows, an
/// owner of another account). The message is one line.
///
/// # Examples
///
/// The pids 0 and 1 are never a valid owner.
///
/// ```
/// use habilis_network::runtime::validate_owner_pid;
///
/// assert!(validate_owner_pid(0).is_err());
/// assert!(validate_owner_pid(1).is_err());
/// ```
#[cfg(feature = "host")]
pub fn validate_owner_pid(pid: u32) -> Result<(), OwnerPidError> {
    owner_start(pid).map(drop)
}

/// The start time of a valid owner, the one home of the owner checks.
#[cfg(feature = "host")]
fn owner_start(pid: u32) -> Result<u64, OwnerPidError> {
    if pid <= 1 {
        return Err(OwnerPidError::Reserved(pid));
    }
    if pid == std_process::id() {
        return Err(OwnerPidError::OwnSelf(pid));
    }
    process::live_start_time(pid).ok_or(OwnerPidError::NotRunning(pid))
}
/// Detect orphaning by the spawning agent and route it through the same quit
/// channel as a signal. A hard-killed parent (`kill -9`, a reinstall, an IDE
/// restart) can't run any cleanup, so the spawned daemon is reparented instead
/// of terminated and would otherwise linger in the mesh forever. When the
/// owner or the parent vanishes we feed `quit_tx`, reusing the SIGTERM path
/// that broadcasts `left` and exits cleanly.
///
/// With an [`Owner`], every OS watches the owner. Without one, Unix watches
/// the parent (`spawn_parent_watch`), and Windows watches nothing: it does
/// not reparent an orphan, and the pid of a dead parent can be reused, so
/// there is nothing to compare. A Windows launcher passes `--owner-pid`.
#[cfg(feature = "host")]
fn spawn_orphan_watch(quit_tx: mpsc::Sender<()>, owner: Option<Owner>) {
    let interval = tuning::ppid_watch_interval();
    if let Some(owner) = owner {
        tokio::spawn(watch_owner(owner, interval, quit_tx));
        return;
    }
    #[cfg(unix)]
    spawn_parent_watch(quit_tx, interval);
    #[cfg(not(unix))]
    drop(quit_tx);
}
/// The watch of a daemon with no [`Owner`]: its *own* parent — the only
/// mechanism that survives SIGKILL and is identical on macOS and Linux
/// (`PR_SET_PDEATHSIG` and kqueue `NOTE_EXIT` are each platform-specific).
// `unix` alone is not enough: `rustix` arrives with the `host` feature.
#[cfg(all(unix, feature = "host"))]
fn spawn_parent_watch(quit_tx: mpsc::Sender<()>, interval: Duration) {
    let original_ppid = parent_pid();
    if !orphan_watch_warranted(original_ppid) {
        return;
    }
    tokio::spawn(async move {
        loop {
            n0future_time::sleep(interval).await;
            super::state::note_ppid_wake();
            let current_ppid = parent_pid();
            if parent_lost(original_ppid, current_ppid) {
                let _ = quit_tx.send(()).await;
                return;
            }
        }
    });
}
/// The orphan watch of a daemon with an [`Owner`], on every OS: its parent is
/// init (or, on Windows, of no use), so the owner's exit is the one event that
/// ends it. The start time of [`Owner::lost`] guards against pid reuse.
#[cfg(feature = "host")]
async fn watch_owner(owner: Owner, interval: Duration, quit_tx: mpsc::Sender<()>) {
    loop {
        n0future_time::sleep(interval).await;
        super::state::note_ppid_wake();
        if owner.lost() {
            #[cfg(windows)]
            tracing::info!(
                target: "habilis_network::lifecycle",
                owner_pid = owner.pid(),
                "owner exited; leaving"
            );
            let _ = quit_tx.send(()).await;
            return;
        }
    }
}
/// The parent pid, or 0 when the kernel reports none.
#[cfg(all(unix, feature = "host"))]
fn parent_pid() -> i32 {
    use rustix::process::getppid;

    getppid().map_or(0, |pid| pid.as_raw_nonzero().get())
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
/// A quit channel that no signal feeds. Its sender is leaked, so the receiver
/// never reads `None` (the loop's quit arm fires on one). On Windows a clone is
/// leaked and the sender goes back to the caller, so the arm fires only from
/// `external_quit_rx` or an IPC `quit`; only a CLI session binds an IPC
/// endpoint, and it always has its signals. Elsewhere the arm fires only from
/// `external_quit_rx`.
pub(super) fn never_quit() -> QuitChannel {
    let (quit_tx, quit_rx): (mpsc::Sender<()>, mpsc::Receiver<()>) = mpsc::channel(1);
    #[cfg(all(windows, feature = "host"))]
    let channel = {
        mem::forget(quit_tx.clone());
        (quit_tx, quit_rx)
    };
    #[cfg(not(all(windows, feature = "host")))]
    let channel = {
        mem::forget(quit_tx);
        quit_rx
    };
    channel
}

#[cfg(all(test, windows, feature = "host"))]
mod never_quit_tests {
    use std::time::Duration;

    use tokio::time;

    #[test]
    fn a_never_quit_channel_stays_open_when_its_sender_drops() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (quit_tx, mut quit_rx) = super::never_quit();
            drop(quit_tx);
            // A closed channel would give `None` at once, and the quit arm fires on it.
            let read = time::timeout(Duration::from_millis(100), quit_rx.recv()).await;
            assert!(read.is_err(), "the channel closed: {read:?}");
        });
    }
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    use tokio::sync::mpsc;

    use super::{Owner, validate_owner_pid, watch_owner};

    #[cfg(unix)]
    use crate::{membership, protocol};
    #[cfg(unix)]
    use std::env;
    use std::time::{Instant, Instant as std_Instant};
    use std::{process, thread};
    use tokio::time;
    const TICK: Duration = Duration::from_millis(10);

    /// A process that lives for about 30 s. Each OS has its own idle command,
    /// as in the `idle_child` of the util crate.
    fn spawn_owner() -> Child {
        #[cfg(unix)]
        let mut command = {
            let mut command = Command::new("sleep");
            command.arg("30");
            command
        };
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("ping");
            command.args(["-n", "30", "127.0.0.1"]);
            command
        };
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.spawn().expect("spawn an idle owner")
    }

    /// Run the owner watch; `true` when it quit within `within`.
    async fn watch_quits(owner: Owner, within: Duration) -> bool {
        let (quit_tx, mut quit_rx) = mpsc::channel(1);
        let watch = tokio::spawn(watch_owner(owner, TICK, quit_tx));
        let quit = time::timeout(within, quit_rx.recv()).await.is_ok();
        watch.abort();
        quit
    }

    #[test]
    fn owner_watch_stays_while_the_owner_lives() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut child = spawn_owner();
            let owner = Owner::try_new(child.id()).expect("live owner accepted");
            assert!(
                !watch_quits(owner, Duration::from_millis(300)).await,
                "an owner watch stays while the owner lives"
            );
            child
                .kill()
                .expect("the spawned owner process can be killed");
            child
                .wait()
                .expect("the killed owner process can be reaped");
        });
    }

    #[test]
    fn owner_watch_quits_when_the_owner_exits() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut child = spawn_owner();
            let owner = Owner::try_new(child.id()).expect("live owner accepted");
            child
                .kill()
                .expect("the spawned owner process can be killed");
            child
                .wait()
                .expect("the killed owner process can be reaped");
            assert!(
                watch_quits(owner, Duration::from_secs(2)).await,
                "an owner watch quits when the owner exits"
            );
        });
    }

    /// On Windows the killed child is held open by its `Child`, which is the
    /// case "exited, but still open" of `live_start_time`.
    #[test]
    fn owner_watch_quits_when_the_owner_is_an_unreaped_zombie() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut child = spawn_owner();
            let owner = Owner::try_new(child.id()).expect("live owner accepted");
            child
                .kill()
                .expect("the spawned owner process can be killed");
            assert!(
                watch_quits(owner, Duration::from_secs(2)).await,
                "an owner watch quits for an unreaped zombie owner"
            );
            child
                .wait()
                .expect("the killed owner process can be reaped");
        });
    }

    /// Simulates reuse with `start + 1`: that a real reissue changes the start
    /// time is a property of the OS, not something this test can show.
    #[test]
    fn owner_watch_quits_when_the_pid_is_reissued() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut child = spawn_owner();
            let owner = Owner::try_new(child.id()).expect("live owner accepted");
            let reissued = Owner {
                start: owner.start + 1,
                ..owner
            };
            assert!(
                watch_quits(reissued, Duration::from_secs(2)).await,
                "an owner watch quits when the pid is reissued"
            );
            child
                .kill()
                .expect("the spawned owner process can be killed");
            child
                .wait()
                .expect("the killed owner process can be reaped");
        });
    }

    #[test]
    fn validate_owner_pid_accepts_only_a_live_other_process() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut child = spawn_owner();
        let pid = child.id();
        assert!(
            validate_owner_pid(pid).is_ok(),
            "a live other process is an accepted owner pid"
        );
        for refused in [0, 1, process::id()] {
            let error = validate_owner_pid(refused)
                .expect_err("refused")
                .to_string();
            assert!(!error.contains('\n'), "one error line: {error}");
        }
        child
            .kill()
            .expect("the spawned owner process can be killed");
        // SIGKILL lands asynchronously, so poll until the unreaped child is a
        // zombie; it stays one until the `wait` below.
        let deadline = std_Instant::now() + Duration::from_secs(2);
        while validate_owner_pid(pid).is_ok() {
            assert!(Instant::now() < deadline, "a zombie is refused");
            thread::sleep(TICK);
        }
        child
            .wait()
            .expect("the killed owner process can be reaped");
        assert!(validate_owner_pid(pid).is_err(), "a dead pid is refused");
    }

    #[test]
    fn owner_refuses_init_self_and_a_dead_pid() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(Owner::try_new(0).is_err(), "pid 0 is refused as an owner");
        assert!(Owner::try_new(process::id()).is_err(), "self is no owner");
        let init = Owner::try_new(1).expect_err("init refused").to_string();
        assert!(!init.contains('\n'), "one error line: {init}");
        assert!(!init.contains("agent"), "engine vocabulary only: {init}");
        let mut child = spawn_owner();
        let pid = child.id();
        child
            .kill()
            .expect("the spawned owner process can be killed");
        child
            .wait()
            .expect("the killed owner process can be reaped");
        assert!(
            Owner::try_new(pid).is_err(),
            "a dead pid is refused as an owner"
        );
    }

    /// The test binary runs this test again, in a process of its own, with this variable set.
    #[cfg(unix)]
    const QUIT_CHILD: &str = "HABILIS_TEST_CLI_QUIT_CHILD";

    /// A CLI quit announces the departure and asks the loop to exit the process, which it does
    /// only after it has released the beacon and closed the endpoints that it owns. A process
    /// that exits inside the announcement skips both: the peers of the beacon wait for its idle
    /// timeout, and its endpoints are never closed. The check runs in a child process, because
    /// an exit inside the announcement ends the process.
    #[cfg(unix)]
    #[test]
    fn a_cli_quit_leaves_the_exit_to_the_loop() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use super::{QuitParams, announce_departure};
            use crate::testing::LaneNode;

            if env::var_os(QUIT_CHILD).is_some() {
                let node = LaneNode::start().await;
                let context = node.context();
                let mut state = node.state();
                let (inbound, _unread) = mpsc::channel(1);
                let mut app = membership::MembershipApp::new(inbound);
                let name = protocol::MeshName::try_new("test").expect("a name");
                let exit = announce_departure(
                    &mut state,
                    &mut app,
                    &context,
                    QuitParams {
                        name: &name,
                        leave_label: "#test",
                        exit_on_quit: true,
                    },
                )
                .await;
                println!("QUIT_ANNOUNCED exit={exit}");
                node.endpoint.close().await;
                return;
            }
            let mut command = Command::new(env::current_exe().expect("the test binary"));
            command
                .args([
                    "--exact",
                    "daemon::shutdown::tests::a_cli_quit_leaves_the_exit_to_the_loop",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(QUIT_CHILD, "1");
            let output = command.output().expect("run the test binary");
            let stdout = String::from_utf8_lossy(&output.stdout);
            // A `dhat-heap` build does not exit the process on a quit, so that dhat can write its
            // profile: the loop then gets `false`.
            let exit = !cfg!(feature = "dhat-heap");
            assert!(
                stdout.contains(&format!("QUIT_ANNOUNCED exit={exit}")),
                "the process exited inside the quit, before the loop released its endpoints: {stdout}"
            );
        });
    }
}

/// The watch of the parent pid, which only Unix has.
#[cfg(all(test, unix, feature = "host"))]
mod parent_watch_tests {
    use super::{orphan_watch_warranted, parent_lost};

    #[test]
    fn orphan_watch_fires_only_on_a_parent_change() {
        // The agent that spawned us is alive ⇒ same ppid ⇒ stay running.
        let _guard = ::habilis_network_test_tracing::init();
        assert!(!parent_lost(4242, 4242), "an unchanged parent is not lost");
        // The agent died ⇒ reparented to launchd (1) ⇒ orphaned, quit.
        assert!(
            parent_lost(4242, 1),
            "a parent change to init counts as lost"
        );
        // …or, under a systemd subreaper, to some other pid ⇒ still orphaned.
        assert!(
            parent_lost(4242, 990),
            "a parent change to another pid counts as lost"
        );
    }

    #[test]
    fn orphan_watch_skips_an_already_detached_daemon() {
        // Spawned by a normal agent ⇒ worth watching.
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            orphan_watch_warranted(4242),
            "a daemon attached to a parent warrants the orphan watch"
        );
        // Launched detached straight from init/launchd ⇒ no parent to lose.
        assert!(
            !orphan_watch_warranted(1),
            "a detached daemon under init does not warrant the orphan watch"
        );
    }
}
