//! The life of a CLI daemon on the host, on every OS (R11 of `docs/windows.md`).
//!
//! Part 1, the runtime base and the IPC: a node in CLI mode, in a child
//! process, with a runtime base in a temporary folder, binds its endpoint
//! before it is ready, `active_endpoints` finds it, an `Info` command answers,
//! and the state file is in the mesh folder. On Windows the endpoint is the
//! named pipe of R3, found through its marker; on Unix it is the socket, found
//! by its path. The child itself checks that the endpoint is there when it
//! reports ready.
//!
//! Part 2, the quit (R5): a node in a child process stops on an IPC `quit` on
//! Windows, and on the `SIGTERM` of `terminate` on Unix. The child exits with
//! 0, and its state file and its endpoint are gone, and on Windows its marker.
//!
//! Part 3, the owner watch (R6): a node in a child process, with the pid of a
//! second child process as its owner, stops when that owner is killed. The
//! node exits with 0, and its state file is gone, and on Windows its marker, so
//! the watch took the graceful path.
//!
//! Part 4, the console events (R7), on Windows only: a node in a child process,
//! in a console of its own, stops on ctrl-break and on ctrl-c. The node exits
//! with 0, and its state file and its marker are gone. A third process, the
//! test binary with only `console_sender` selected, attaches to the console of
//! the node and raises the event there, so the test does not depend on the
//! console of the runner.
//!
//! Part 5, the end of the session (R13), on Windows only: a node in a child
//! process stops on a logoff and on a `WM_CLOSE`. The test sends the messages
//! that Windows sends to the hidden window of the node, as `taskkill /PID`
//! without `/F` and a logoff do. The node exits with 0, it logs the line of the
//! event, and its state file and its marker are gone. No process can end the
//! session of the runner, and in the test nothing ends the node when its
//! window procedure returns, so the wait of the node until its `Left` is
//! tested by hand (T6).
//!
//! In CLI mode a quit ends the process with `std::process::exit`, and a node
//! whose task is aborted drops its endpoint with no `Endpoint::close`, which
//! iroh logs as an ERROR that fails the test. So every part runs its node in a
//! child process: the test binary itself, with only `child_node` selected.
//! Part 1 kills its child at the end. The owner of part 3 is the test binary too, with only
//! `owner_process` selected, so the test needs no `sleep` or `ping` of the OS.
//! (The unit tests of the owner watch in `daemon/shutdown.rs` use them, because
//! a lib test binary is too large to start as an idle process.)

#![cfg(feature = "host")]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, IpcRequest, NodeApp, NodeDriver, NodeEvent,
    NodeSink,
};
use habilis_network::net::TransportOpts;
use habilis_network::protocol::message::Authored;
use habilis_network::protocol::{LookupOpts, MeshId, Nickname};
#[cfg(windows)]
use habilis_network::runtime::ipc::quit;
#[cfg(unix)]
use habilis_network::runtime::ipc::terminate;
use habilis_network::runtime::ipc::{IpcName, QuitTarget, active_endpoints, send_to_endpoint};
use habilis_network::runtime::{
    EventLoopConfig, SetupKind, SetupParams, derive_topic_mesh_with, run, setup_mesh,
};
use habilis_network_test_tracing::test;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::Notify;

/// The nickname of the test node. A valid Windows file stem too.
const NICKNAME: &str = "host-test";

/// The variable that makes [`child_node`] run a node: the runtime base, the
/// topic, and, for part 3, the pid of the owner, one per line.
const CHILD_ENV: &str = "HABILIS_HOST_LIFECYCLE_CHILD";

/// The variable that makes [`owner_process`] wait.
const OWNER_ENV: &str = "HABILIS_HOST_LIFECYCLE_OWNER";

/// The variable that makes [`child_node`] turn ctrl-c on before it starts the
/// node, for part 4: a parent that ignores ctrl-c gives the flag to its child.
#[cfg(windows)]
const CTRL_C_ENV: &str = "HABILIS_HOST_LIFECYCLE_CTRL_C";

/// The variable that makes [`console_sender`] send an event: the pid of the
/// node and `c` or `break`.
#[cfg(windows)]
const SENDER_ENV: &str = "HABILIS_HOST_LIFECYCLE_SENDER";

/// An app with no frames of its own that answers every IPC command with its
/// nickname and its mesh, as the `Info` command of a real consumer does.
struct InfoApp;

#[habilis_network::async_trait]
impl NodeApp for InfoApp {
    fn classify(&self, _message: &Authored) -> AppClass {
        AppClass {
            loggable: false,
            beat: true,
            valid: true,
            chained: false,
            sealed: false,
        }
    }

    async fn on_app_frame(
        &mut self,
        _frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        _ctx: &HandlerCtx<'_>,
    ) -> bool {
        false
    }
}

#[habilis_network::async_trait]
impl NodeDriver for InfoApp {
    type Session = ();
    type Http = ();
    type Ipc = serde_json::Value;

    async fn handle_ipc(
        &mut self,
        req: IpcRequest<'_, Self::Ipc>,
        _state: &mut EventLoopState,
        ctx: &HandlerCtx<'_>,
    ) -> bool {
        let answer = if req.cmd["command"] == "info" {
            serde_json::json!({ "ok": true, "nickname": NICKNAME, "mesh": ctx.mesh.as_str() })
        } else {
            serde_json::json!({ "ok": false, "error": "unknown command" })
        };
        let _ = req.resp.send(answer.to_string());
        false
    }
}

/// A sink that wakes the test when the node reports ready, and keeps the
/// error texts: a failed bind gives an error and never `Ready`, and the test
/// shows the error instead of a bare timeout. The child also writes each error
/// to stderr, which the parent shows when it fails.
#[derive(Default)]
struct ReadySink {
    ready: Notify,
    errors: Mutex<Vec<String>>,
}

impl NodeSink for ReadySink {
    fn emit(&self, event: NodeEvent) {
        if let NodeEvent::Error(text) = event {
            eprintln!("node error: {text}");
            self.errors.lock().expect("no poison").push(text);
        } else if matches!(event, NodeEvent::Ready { .. }) {
            self.ready.notify_one();
        }
    }
}

/// A runtime base of this run alone, removed at the end, also when an assert
/// fails. On Unix it is under `/tmp`: a socket path must stay inside the
/// `sun_path` limit, and the macOS temp directory is long. `tag` keeps the
/// bases of the two parts apart, because they run at the same time.
struct TempBase(PathBuf);

impl TempBase {
    fn new(tag: &str) -> Self {
        let name = format!("hn-{tag}-{}", std::process::id());
        #[cfg(unix)]
        let path = Path::new("/tmp").join(name);
        #[cfg(not(unix))]
        let path = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }
}

impl Drop for TempBase {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The CLI config of a test node on a loopback topic mesh, with its runtime
/// base at `base` and no state file of its own: in CLI mode it writes one into
/// the mesh folder.
async fn cli_config(base: &Path, topic: &str, sink: Arc<dyn NodeSink>) -> EventLoopConfig {
    let mesh = derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("a loopback mesh");
    setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic.to_owned(),
        },
        SetupParams {
            author: Nickname::new(NICKNAME).expect("a valid nickname"),
            max_peers: 16,
            max_direct: 0,
            endpoint: None,
            protocols: Vec::new(),
            transports: TransportOpts::default(),
            runtime_base: Some(base.to_path_buf()),
            state_file: None,
            sink,
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network")
}

/// Each file under `base`, one mesh folder deep, whose name ends with `suffix`.
fn files_ending_with(base: &Path, suffix: &str) -> Vec<PathBuf> {
    let Ok(mesh_dirs) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    mesh_dirs
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .flat_map(|dir| std::fs::read_dir(dir).into_iter().flatten().flatten())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(suffix))
        })
        .collect()
}

#[test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cli_node_is_found_and_answers_info() {
    let base = TempBase::new("host");
    let topic = format!("host-lifecycle-{}", std::process::id());
    // The child exits with 3 when it reports ready before its endpoint exists.
    let mut child = ChildNode::spawn(&base.0, &topic, None);
    let name = match child.endpoint(&base.0).await {
        Ok((name, _)) => name,
        Err(what) => child.fail(&what).await,
    };

    let names = active_endpoints(&base.0);
    assert_eq!(names, vec![name.clone()], "one endpoint under the base");
    let reply = send_to_endpoint(&name, &serde_json::json!({ "command": "info" }))
        .await
        .expect("the Info command answers");
    let reply: serde_json::Value = serde_json::from_str(&reply).expect("JSON");
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["nickname"], NICKNAME, "{reply}");

    // In CLI mode the node also writes its state file into the mesh folder.
    let state_files = files_ending_with(&base.0, &format!("{NICKNAME}.state.json"));
    assert_eq!(state_files.len(), 1, "one state file: {state_files:?}");

    if let Ok(Some(status)) = child.process.try_wait() {
        child
            .fail(&format!("the child exited during the checks: {status}"))
            .await;
    }
    let _ = child.process.kill().await;
}

/// The node of every part, in the child process that [`ChildNode`] starts.
/// With no [`CHILD_ENV`] it does nothing, so a run with `--include-ignored`
/// passes it at once.
///
/// A quit, or the exit of its owner, ends this process with 0. It does not
/// remove the base: the parent owns it.
#[test]
#[ignore = "the child process of every part"]
fn child_node() {
    let Ok(spec) = std::env::var(CHILD_ENV) else {
        return;
    };
    #[cfg(windows)]
    if std::env::var_os(CTRL_C_ENV).is_some() {
        habilis_network_util::win_console::allow_ctrl_c().expect("ctrl-c on");
    }
    let mut lines = spec.splitn(3, '\n');
    let base = lines.next().expect("the base");
    let topic = lines.next().expect("the topic");
    let owner = lines
        .next()
        .map(|pid| pid.parse::<u32>().expect("the pid of the owner"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let sink = Arc::new(ReadySink::default());
        // Ready implies the endpoint (part 1): it is there when the node
        // reports ready, with no wait.
        let watched = Arc::clone(&sink);
        let marker_base = PathBuf::from(base);
        tokio::spawn(async move {
            watched.ready.notified().await;
            if active_endpoints(&marker_base).is_empty() {
                eprintln!("the node reported ready before its endpoint existed");
                std::process::exit(3);
            }
        });
        let mut config = cli_config(Path::new(base), topic, sink as Arc<dyn NodeSink>).await;
        if let Some(owner) = owner {
            config = config.with_owner_pid(owner).expect("a live owner");
        }
        let ran = tokio::time::timeout(
            Duration::from_mins(1),
            Box::pin(run(config, InfoApp, None, None)),
        )
        .await;
        panic!("the node did not exit within 60 s: {ran:?}");
    });
}

/// The owner of part 3, in its own child process: it only waits, until the
/// test kills it. With no [`OWNER_ENV`] it does nothing.
#[test]
#[ignore = "the owner process of part 3"]
fn owner_process() {
    if std::env::var_os(OWNER_ENV).is_none() {
        return;
    }
    std::thread::sleep(Duration::from_mins(2));
}

/// The sender of part 4, in its own child process, because it leaves its
/// console. It panics, and so exits with an error, when the send fails. With
/// no [`SENDER_ENV`] it does nothing.
#[cfg(windows)]
#[test]
#[ignore = "the sender process of part 4"]
fn console_sender() {
    use habilis_network_util::win_console::{ConsoleEvent, send_console_event};

    let Ok(spec) = std::env::var(SENDER_ENV) else {
        return;
    };
    let (pid, event) = spec.split_once(' ').expect("a pid and an event");
    let event = match event {
        "c" => ConsoleEvent::CtrlC,
        "break" => ConsoleEvent::CtrlBreak,
        other => panic!("unknown event {other}"),
    };
    send_console_event(pid.parse().expect("a pid"), event).expect("the console event");
}

/// Start the test binary with only `entry` selected. The process is killed on
/// drop, so a test that fails leaves no child behind.
fn spawn_entry(entry: &str, env: (&str, &str), stdout: Stdio) -> tokio::process::Command {
    let mut command =
        tokio::process::Command::new(std::env::current_exe().expect("the path of the test binary"));
    command
        .args([entry, "--exact", "--ignored", "--nocapture"])
        .env(env.0, env.1)
        .stdin(Stdio::null())
        .stdout(stdout)
        .kill_on_drop(true);
    command
}

/// The child process of every part, with its output read from the start, so
/// a child that writes much never blocks on a full pipe.
struct ChildNode {
    process: tokio::process::Child,
    stdout: tokio::task::JoinHandle<String>,
    stderr: tokio::task::JoinHandle<String>,
}

impl ChildNode {
    fn spawn(base: &Path, topic: &str, owner: Option<u32>) -> Self {
        Self::start(Self::command(base, topic, owner))
    }

    /// The command of the child, before its stderr is piped.
    fn command(base: &Path, topic: &str, owner: Option<u32>) -> tokio::process::Command {
        let spec = match owner {
            Some(owner) => format!("{}\n{topic}\n{owner}", base.display()),
            None => format!("{}\n{topic}", base.display()),
        };
        spawn_entry("child_node", (CHILD_ENV, &spec), Stdio::piped())
    }

    /// The child of part 5, which logs the lines of `habilis_network::lifecycle`
    /// to its stderr. Without `RUST_LOG` the tracing of the test shows only
    /// ERROR.
    #[cfg(windows)]
    fn spawn_with_lifecycle_log(base: &Path, topic: &str) -> Self {
        let mut command = Self::command(base, topic, None);
        command.env("RUST_LOG", "habilis_network::lifecycle=info");
        Self::start(command)
    }

    /// The child of part 4, in a console of its own (`CREATE_NO_WINDOW`), with
    /// the other creation `flags`. With `ctrl_c` it turns ctrl-c on first.
    #[cfg(windows)]
    fn spawn_in_console(base: &Path, topic: &str, flags: u32, ctrl_c: bool) -> Self {
        use habilis_network_util::win_console::CREATE_NO_WINDOW;

        let mut command = Self::command(base, topic, None);
        command.creation_flags(CREATE_NO_WINDOW | flags);
        if ctrl_c {
            command.env(CTRL_C_ENV, "1");
        }
        Self::start(command)
    }

    fn start(mut command: tokio::process::Command) -> Self {
        let mut process = command
            .stderr(Stdio::piped())
            .spawn()
            .expect("the child starts");
        let stdout = tokio::spawn(read_all(process.stdout.take().expect("piped")));
        let stderr = tokio::spawn(read_all(process.stderr.take().expect("piped")));
        Self {
            process,
            stdout,
            stderr,
        }
    }

    /// Kill the child, and panic with `what` and the output of the child.
    async fn fail(mut self, what: &str) -> ! {
        let _ = self.process.kill().await;
        let stdout = self.stdout.await.unwrap_or_default();
        let stderr = self.stderr.await.unwrap_or_default();
        panic!("{what}\n--- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}");
    }

    /// The endpoint of the child and its mesh, from its `Info` answer. The
    /// endpoint is there once the child has bound it. A slow first start (an
    /// antivirus scan of the binary on Windows) is covered by the 30 s.
    async fn endpoint(&mut self, base: &Path) -> Result<(IpcName, MeshId), String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let name = loop {
            if let Some(name) = active_endpoints(base).into_iter().next() {
                break name;
            }
            if let Ok(Some(status)) = self.process.try_wait() {
                return Err(format!("the child exited before its endpoint: {status}"));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("the child bound no endpoint within 30 s".to_owned());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let reply = send_to_endpoint(&name, &serde_json::json!({ "command": "info" }))
            .await
            .map_err(|error| format!("the Info command: {error}"))?;
        let reply: serde_json::Value = serde_json::from_str(&reply).expect("JSON");
        let mesh = MeshId::new(reply["mesh"].as_str().expect("the mesh in the answer"))
            .expect("a valid mesh id");
        Ok((name, mesh))
    }

    /// Wait up to 10 s for the child to exit with 0.
    async fn exits_with_zero(&mut self) -> Result<(), String> {
        match tokio::time::timeout(Duration::from_secs(10), self.process.wait()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(status)) => Err(format!("the child exited with {status}, not 0")),
            Ok(Err(error)) => Err(format!("wait for the child: {error}")),
            Err(_) => Err("the child did not exit within 10 s".to_owned()),
        }
    }
}

async fn read_all(mut pipe: impl AsyncRead + Unpin) -> String {
    let mut bytes = Vec::new();
    let _ = pipe.read_to_end(&mut bytes).await;
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The node left by the graceful path: the shutdown removed the state file,
/// and on Windows the marker. On Unix the socket file stays, as after a
/// SIGTERM, and nothing accepts on it.
async fn assert_left_cleanly(base: &Path, name: &IpcName) {
    let state_files = files_ending_with(base, ".state.json");
    assert!(
        state_files.is_empty(),
        "the state file stays: {state_files:?}"
    );
    #[cfg(windows)]
    {
        let markers = files_ending_with(base, ".ipc");
        assert!(markers.is_empty(), "the marker stays: {markers:?}");
        assert!(active_endpoints(base).is_empty());
    }
    assert!(
        send_to_endpoint(name, &serde_json::json!({ "command": "info" }))
            .await
            .is_err(),
        "the old endpoint still answers"
    );
}

#[test(flavor = "multi_thread", worker_threads = 4)]
async fn quit_stops_a_cli_node_in_a_child_process() {
    let base = TempBase::new("quit");
    let topic = format!("host-lifecycle-quit-{}", std::process::id());
    let mut child = ChildNode::spawn(&base.0, &topic, None);
    let (name, mesh) = match child.endpoint(&base.0).await {
        Ok(found) => found,
        Err(what) => child.fail(&what).await,
    };
    let nickname = Nickname::new(NICKNAME).expect("a valid nickname");

    // On Windows the IPC quit. On Unix the IPC quit does not exist, and
    // `terminate` sends `SIGTERM`.
    let target = QuitTarget {
        base: &base.0,
        mesh: &mesh,
        nickname: &nickname,
    };
    #[cfg(windows)]
    let stopped = quit(&target).await.map_err(anyhow::Error::from);
    #[cfg(unix)]
    let stopped = terminate(&target, child.process.id().expect("the pid of the child")).await;
    if let Err(error) = stopped {
        child.fail(&format!("the stop: {error}")).await;
    }
    if let Err(what) = child.exits_with_zero().await {
        child.fail(&what).await;
    }
    assert_left_cleanly(&base.0, &name).await;
}

#[test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_watch_stops_a_cli_node_when_its_owner_dies() {
    let base = TempBase::new("owner");
    let topic = format!("host-lifecycle-owner-{}", std::process::id());
    // The owner first: `with_owner_pid` refuses an owner that is not running.
    let mut owner = spawn_entry("owner_process", (OWNER_ENV, "1"), Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the owner starts");
    let owner_pid = owner.id().expect("the owner runs");
    let mut child = ChildNode::spawn(&base.0, &topic, Some(owner_pid));
    let name = match child.endpoint(&base.0).await {
        Ok((name, _)) => name,
        Err(what) => child.fail(&what).await,
    };

    // `kill` waits for the owner, so the node watches an owner that is gone.
    // Then one watch interval (1.5 s) and the `Left` delay (500 ms) pass.
    owner.kill().await.expect("kill the owner");
    if let Err(what) = child.exits_with_zero().await {
        child.fail(&what).await;
    }
    assert_left_cleanly(&base.0, &name).await;
}

/// Part 4: start a node in a console of its own, send it `event` from a third
/// process, and check that it left by the graceful path.
#[cfg(windows)]
async fn assert_console_event_stops_a_cli_node(tag: &str, event: &str, flags: u32, ctrl_c: bool) {
    let base = TempBase::new(tag);
    let topic = format!("host-lifecycle-{tag}-{}", std::process::id());
    let mut child = ChildNode::spawn_in_console(&base.0, &topic, flags, ctrl_c);
    let name = match child.endpoint(&base.0).await {
        Ok((name, _)) => name,
        Err(what) => child.fail(&what).await,
    };
    let pid = child.process.id().expect("the child runs");
    // `CREATE_NO_WINDOW` shows no window on a runner with no console; the
    // sender leaves that console at once.
    let sent = spawn_entry(
        "console_sender",
        (SENDER_ENV, &format!("{pid} {event}")),
        Stdio::piped(),
    )
    .stderr(Stdio::piped())
    .creation_flags(habilis_network_util::win_console::CREATE_NO_WINDOW)
    .output()
    .await
    .expect("the sender runs");
    if !sent.status.success() {
        let output = format!(
            "{}{}",
            String::from_utf8_lossy(&sent.stdout),
            String::from_utf8_lossy(&sent.stderr)
        );
        child
            .fail(&format!("the sender failed: {}\n{output}", sent.status))
            .await;
    }
    if let Err(what) = child.exits_with_zero().await {
        child.fail(&what).await;
    }
    assert_left_cleanly(&base.0, &name).await;
}

/// Without the listener of R7, the default handler ends the node with
/// `STATUS_CONTROL_C_EXIT`, and this test fails.
#[cfg(windows)]
#[test(flavor = "multi_thread", worker_threads = 4)]
async fn ctrl_break_stops_a_cli_node() {
    use habilis_network_util::win_console::CREATE_NEW_PROCESS_GROUP;

    // Ctrl-break goes to a process group, so the node is the root of its own.
    assert_console_event_stops_a_cli_node("ctrl-break", "break", CREATE_NEW_PROCESS_GROUP, false)
        .await;
}

/// A regression test: ctrl-c took the graceful path before R7 too.
#[cfg(windows)]
#[test(flavor = "multi_thread", worker_threads = 4)]
async fn ctrl_c_stops_a_cli_node() {
    // Not in a new process group: a node in one ignores ctrl-c.
    assert_console_event_stops_a_cli_node("ctrl-c", "c", 0, true).await;
}

/// Part 5: start a node, `send` it a message of the end of the session from a
/// blocking thread, and check that it logged `line` and left by the graceful
/// path.
#[cfg(windows)]
async fn assert_window_message_stops_a_cli_node(
    tag: &str,
    send: fn(u32) -> std::io::Result<()>,
    line: &str,
) {
    let base = TempBase::new(tag);
    let topic = format!("host-lifecycle-{tag}-{}", std::process::id());
    let mut child = ChildNode::spawn_with_lifecycle_log(&base.0, &topic);
    let name = match child.endpoint(&base.0).await {
        Ok((name, _)) => name,
        Err(what) => child.fail(&what).await,
    };
    let pid = child.process.id().expect("the child runs");
    let delivered = tokio::task::spawn_blocking(move || send(pid))
        .await
        .expect("the send thread");
    if let Err(error) = delivered {
        child
            .fail(&format!("the message to the window: {error}"))
            .await;
    }
    if let Err(what) = child.exits_with_zero().await {
        child.fail(&what).await;
    }
    let stderr = (&mut child.stderr).await.unwrap_or_default();
    assert!(
        stderr.contains(line),
        "the child did not log {line:?}
--- child stderr ---
{stderr}"
    );
    assert_left_cleanly(&base.0, &name).await;
}

/// Without the window of R13, the node has no window to find, and this test
/// fails.
#[cfg(windows)]
#[test(flavor = "multi_thread", worker_threads = 4)]
async fn a_logoff_stops_a_cli_node() {
    use habilis_network_util::win_session::send_session_end;

    assert_window_message_stops_a_cli_node("logoff", send_session_end, "session end; leaving")
        .await;
}

/// `taskkill /PID` without `/F` sends `WM_CLOSE` to the windows of the process.
#[cfg(windows)]
#[test(flavor = "multi_thread", worker_threads = 4)]
async fn a_window_close_stops_a_cli_node() {
    use habilis_network_util::win_session::post_window_close;

    assert_window_message_stops_a_cli_node("close", post_window_close, "window close; leaving")
        .await;
}
