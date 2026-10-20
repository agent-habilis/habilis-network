//! The life of a CLI daemon on the host, on every OS (R11 of `docs/windows.md`).
//!
//! Part 1, the runtime base and the IPC: a node in CLI mode with a runtime base
//! in a temporary folder binds its endpoint and writes its marker before it is
//! ready, `active_endpoints` finds it, an `Info` command answers, and the state
//! file is in the mesh folder. On Windows the endpoint is the named pipe of R3,
//! on Unix the socket.
//!
//! The node is never sent `Quit`: in CLI mode a quit ends the process with
//! `std::process::exit`, which would end the test binary. The test aborts the
//! task instead, and awaits it, so the loop is gone before the folder is
//! removed. The tasks that the loop spawned (the IPC accept loop, the signal
//! tasks, iroh) stay until the test runtime ends, which is harmless. Part 2 (`Quit` and the owner watch, R5 and R6) needs the node
//! in a child process. This file holds one test, so no other test shares the
//! process with a node that could exit it.

#![cfg(feature = "host")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, IpcRequest, NodeApp, NodeDriver, NodeEvent,
    NodeSink,
};
use habilis_network::net::TransportOpts;
use habilis_network::protocol::message::Authored;
use habilis_network::protocol::{LookupOpts, Nickname};
use habilis_network::runtime::ipc::{active_endpoints, send_to_endpoint};
use habilis_network::runtime::{SetupKind, SetupParams, derive_topic_mesh_with, run, setup_mesh};
use tokio::sync::Notify;

/// The nickname of the test node. A valid Windows file stem too.
const NICKNAME: &str = "host-test";

/// An app with no frames of its own that answers every IPC command with its
/// nickname, as the `Info` command of a real consumer does.
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
        _ctx: &HandlerCtx<'_>,
    ) -> bool {
        let answer = if req.cmd["command"] == "info" {
            serde_json::json!({ "ok": true, "nickname": NICKNAME })
        } else {
            serde_json::json!({ "ok": false, "error": "unknown command" })
        };
        let _ = req.resp.send(answer.to_string());
        false
    }
}

/// A sink that wakes the test when the node reports ready, and keeps the
/// error texts: a failed bind gives an error and never `Ready`, and the test
/// shows the error instead of a bare timeout.
#[derive(Default)]
struct ReadySink {
    ready: Notify,
    errors: Mutex<Vec<String>>,
}

impl NodeSink for ReadySink {
    fn emit(&self, event: NodeEvent) {
        if let NodeEvent::Error(text) = event {
            self.errors.lock().expect("no poison").push(text);
        } else if matches!(event, NodeEvent::Ready { .. }) {
            self.ready.notify_one();
        }
    }
}

/// A runtime base of this run alone, removed at the end, also when an assert
/// fails. On Unix it is under `/tmp`: a socket path must stay inside the
/// `sun_path` limit, and the macOS temp directory is long.
struct TempBase(std::path::PathBuf);

impl TempBase {
    fn new() -> Self {
        let name = format!("hn-host-{}", std::process::id());
        #[cfg(unix)]
        let path = std::path::Path::new("/tmp").join(name);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cli_node_is_found_through_its_marker_and_answers_info() {
    let base = TempBase::new();
    let topic = format!("host-lifecycle-{}", std::process::id());
    let mesh = derive_topic_mesh_with(&topic, LookupOpts::loopback()).expect("a loopback mesh");
    let sink = Arc::new(ReadySink::default());
    let config = setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic,
        },
        SetupParams {
            author: Nickname::new(NICKNAME).expect("a valid nickname"),
            max_peers: 16,
            max_direct: 0,
            endpoint: None,
            protocols: Vec::new(),
            transports: TransportOpts::default(),
            runtime_base: Some(base.0.clone()),
            state_file: None,
            sink: Arc::clone(&sink) as Arc<dyn NodeSink>,
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network");

    // `setup_mesh` gives a CLI config. `Node::spawn` would make it in-process,
    // which binds no endpoint, so the test runs the loop itself.
    let ready = sink.ready.notified();
    let node = tokio::spawn(Box::pin(run(config, InfoApp, None, None)));
    if tokio::time::timeout(Duration::from_secs(30), ready)
        .await
        .is_err()
    {
        let errors = sink.errors.lock().expect("no poison").clone();
        panic!("the node did not report ready within 30 s; its errors: {errors:?}");
    }

    // Ready implies the marker: the endpoint is found at once, with no wait.
    let names = active_endpoints(&base.0);
    assert_eq!(names.len(), 1, "one endpoint under the base: {names:?}");
    let reply = send_to_endpoint(&names[0], &serde_json::json!({ "command": "info" }))
        .await
        .expect("the Info command answers");
    let reply: serde_json::Value = serde_json::from_str(&reply).expect("JSON");
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["nickname"], NICKNAME, "{reply}");

    // In CLI mode the node also writes its state file into the mesh folder.
    let state_files: Vec<_> = std::fs::read_dir(&base.0)
        .expect("the base exists")
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.path().join(format!("{NICKNAME}.state.json")))
        .filter(|path| path.is_file())
        .collect();
    assert_eq!(state_files.len(), 1, "one state file: {state_files:?}");

    node.abort();
    let _ = node.await;
}
