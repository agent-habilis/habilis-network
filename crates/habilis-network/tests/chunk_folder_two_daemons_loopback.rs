//! A second daemon of one nickname, on the same mesh and runtime base, leaves the chunks of the first.
//!
//! Two daemons that share a nickname, a mesh and a runtime base share one chunk folder,
//! `<base>/<mesh>/<nickname>.chunks`, when their state files differ (so no key lock keeps them apart). The
//! first member writes a value of the cap: its slice is a pointer, and its chunks are files in that folder. A
//! second daemon of the same nickname then starts on the same base. The chunk files of the first must still be
//! there, the same ones: before the folder had a lock, the second daemon cleared it when its loop started.
//!
//! The test reads the files, not a fetch by a third member: two members of one nickname race for the
//! nickname, and the loser's slices are refused, so what a third member shows depends on that race and not on
//! the chunks.

#![cfg(all(unix, feature = "host"))]

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, SilentSink,
};
use habilis_network::ops::{StateMergeParams, broadcast_state_merge};
use habilis_network::protocol::messages::Authored;
use habilis_network::protocol::{AuthorKey, Channel, LookupOpts, Nickname};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{env, fs, process};
use tokio::sync::oneshot;
use tokio::time;

/// The cap of one value: the encoded value takes `1 MiB` at most.
const CAP: usize = 1024 * 1024;

/// Wide enough for a loaded machine.
const WITHIN: Duration = Duration::from_secs(30);

enum Request {
    Merge(Value, oneshot::Sender<Result<(), String>>),
    Key(oneshot::Sender<AuthorKey>),
}

struct Member;

#[habilis_network::async_trait]
impl NodeApp for Member {
    fn classify(&self, _message: &Authored) -> AppClass {
        AppClass::NONE
    }

    async fn on_app_frame(
        &mut self,
        _frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        _context: &HandlerCtx<'_>,
    ) -> bool {
        true
    }
}

#[habilis_network::async_trait]
impl NodeDriver for Member {
    type Session = Request;
    type Http = ();
    type Ipc = Value;

    async fn handle_session(
        &mut self,
        request: Self::Session,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            Request::Merge(merge, done) => {
                let params =
                    StateMergeParams::new(context.into(), Channel::State, merge).surface(false);
                let sent = broadcast_state_merge(state, params).await;
                let written: Result<(), String> =
                    sent.map(|_sent| ()).map_err(|error| error.to_string());
                let _ = done.send(written);
                true
            }
            Request::Key(response) => {
                let _ = response.send(state.identity().author_key());
                false
            }
        }
    }
}

/// A member of the topic `topic` under the nickname `name`, with its chunk folder under the runtime base
/// `base`, as it is for a daemon.
async fn spawn(topic: &str, name: &str, base: &Path) -> Node<Member> {
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
    let kind = SetupKind::Topic {
        mesh,
        topic_string: topic.to_owned(),
    };
    let nickname = Nickname::try_new(name).expect("a nickname");
    let capped = SetupParams::new(nickname, SilentSink::default()).max_connections(16);
    let params = capped.runtime_base(base.to_path_buf());
    let loop_config = setup_mesh(kind, params).await.expect("a joined mesh");
    Node::spawn(loop_config, Member, None, SignalHandling::Leave)
}

async fn merge(node: &Node<Member>, value: Value) -> Result<(), String> {
    let (done, written) = oneshot::channel();
    node.send(Request::Merge(value, done))
        .await
        .expect("the request reaches the loop");
    written.await.expect("the loop answers")
}

/// Merge on `node` until it goes through or `WITHIN` has passed.
async fn merge_within(node: &Node<Member>, value: &Value) -> Result<(), String> {
    let started = Instant::now();
    let mut last = merge(node, value.clone()).await;
    while last.is_err() && started.elapsed() < WITHIN {
        time::sleep(Duration::from_millis(100)).await;
        last = merge(node, value.clone()).await;
    }
    last
}

/// An answer from the loop of `node`: the loop clears its chunk folder before it serves any request.
async fn answered(node: &Node<Member>) -> AuthorKey {
    let (response, read) = oneshot::channel();
    node.send(Request::Key(response))
        .await
        .expect("the request reaches the loop");
    read.await.expect("the loop answers")
}

/// An object of one key whose text varies, so that no two chunks of its encoding are equal. Its encoding takes
/// exactly `encoded` bytes.
fn value_of(encoded: usize) -> Value {
    let mut seed = 17_u32;
    let text: String = (0..encoded - 8)
        .map(|_| {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let index = u8::try_from((seed >> 16) % 26).expect("a letter index");
            char::from(b'a' + index)
        })
        .collect();
    let mut object = Map::new();
    object.insert("k".to_owned(), Value::String(text));
    Value::Object(object)
}

/// The files under every chunk folder (a folder whose name ends in `.chunks`) below `base`, sorted.
fn chunk_files(base: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let mut pending: Vec<(PathBuf, bool)> = vec![(base.to_path_buf(), false)];
    while let Some((folder, inside)) = pending.pop() {
        let Ok(entries) = fs::read_dir(&folder) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_chunk_folder = path.extension().is_some_and(|name| name == "chunks");
            if path.is_dir() {
                pending.push((path, inside || is_chunk_folder));
            } else if inside {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

#[test]
fn a_second_daemon_of_one_nickname_leaves_the_chunk_files_of_the_first() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        // A topic and a base of their own, so two runs on one host share neither a mesh nor a folder.
        let nonce: u64 = rand::random();
        let topic = format!("chunk-folder-two-daemons-{nonce}");
        let base = env::temp_dir().join(format!("habilis-chunk-folder-{}-{nonce}", process::id()));

        let first = spawn(&topic, "twin", &base).await;
        let big = value_of(CAP);
        let merged = merge_within(&first, &json!({ "k": big["k"].clone() })).await;
        assert_eq!(merged, Ok(()), "the first member keeps a value at the cap");
        let before = chunk_files(&base);
        assert!(
            !before.is_empty(),
            "a value at the cap is chunks on disk under {}",
            base.display()
        );

        // The second daemon takes the nickname, the mesh and the base of the first. It clears the chunk
        // folder when its loop starts, so an answer from that loop shows that the clearing has happened.
        let second = spawn(&topic, "twin", &base).await;
        let _ = answered(&second).await;

        let after = chunk_files(&base);
        for node in [first, second] {
            let _ = node.leave().await;
        }
        let _ = fs::remove_dir_all(&base);
        assert_eq!(
            after, before,
            "the second daemon must leave the chunk files that the first serves"
        );
    });
}
