//! A late joiner gets the slice of an author that wrote before it arrived. The
//! author's own slice is sent to the newcomer, once a path exists, so the
//! newcomer does not wait for a tick.
//!
//! The author writes its whole log as one slice. The test waits past the
//! retention of the gossip cache first, so that the cache cannot be the path.

#![cfg(feature = "host")]

use habilis_network::protocol::messages::Authored;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::ops::{StateMergeParams, broadcast_state_merge};
use habilis_network::protocol::{Channel, LookupOpts, MessageKind, Nickname, PresenceSubtype};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use tokio::sync::{Notify, oneshot};

use habilis_network::runtime::tuning;
use tokio::time::{self, Instant};
/// The keys of the log. One slice carries the whole log, so it must fit one frame.
const WRITES: usize = 80;
/// The retention of the payload cache of iroh-gossip (`PlumtreeConfig::message_cache_retention`). The
/// same value as in `missed_chat_backfill_loopback.rs`. A joiner that meets an author within it can get
/// the author's frame from that cache, which is no backfill.
const GOSSIP_CACHE_RETENTION: Duration = Duration::from_secs(30);
/// How long a test waits for the slice of an author. With the tick pinned away it can only be the
/// backfill on meeting the author, so this only bounds a slow join.
const BUDGET: Duration = Duration::from_secs(15);

enum Request {
    Write(serde_json::Value, oneshot::Sender<()>),
    Read(oneshot::Sender<serde_json::Value>),
    WriteMeta(serde_json::Value, oneshot::Sender<()>),
    ReadMeta(oneshot::Sender<serde_json::Value>),
}

/// Presence alone forms the mesh; sessions write and read the state document.
struct Store;

#[habilis_network::async_trait]
impl NodeApp for Store {
    fn classify(&self, _message: &Authored) -> AppClass {
        AppClass::BEAT.union(AppClass::VALID)
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
impl NodeDriver for Store {
    type Session = Request;
    type Http = ();
    type Ipc = serde_json::Value;

    async fn handle_session(
        &mut self,
        request: Self::Session,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            Request::Write(merge, done) => {
                broadcast_state_merge(
                    state,
                    StateMergeParams::new(context.into(), Channel::State, merge).surface(false),
                )
                .await
                .expect("a small merge is accepted");
                let _ = done.send(());
                true
            }
            Request::Read(response) => {
                let _ = response.send(state.view(Channel::State));
                false
            }
            Request::WriteMeta(merge, done) => {
                broadcast_state_merge(
                    state,
                    StateMergeParams::new(context.into(), Channel::Meta, merge).surface(false),
                )
                .await
                .expect("a small merge is accepted");
                let _ = done.send(());
                true
            }
            Request::ReadMeta(response) => {
                let _ = response.send(state.view(Channel::Meta));
                false
            }
        }
    }
}

/// Records every `joined` presence the engine surfaces.
#[derive(Default)]
struct Joined {
    peers: Mutex<Vec<Nickname>>,
    changed: Notify,
}

impl NodeSink for Joined {
    fn emit(&self, event: NodeEvent) {
        if let NodeEvent::Presence { message, .. } = event
            && let MessageKind::Presence {
                subtype: PresenceSubtype::Joined,
            } = message.kind
        {
            self.peers
                .lock()
                .expect("no poison")
                .push(message.author.clone());
            self.changed.notify_waiters();
        }
    }
}

impl Joined {
    async fn wait_for(&self, nick: &Nickname, deadline: Duration) -> bool {
        let seen = || self.peers.lock().expect("no poison").contains(nick);
        let wait = async {
            loop {
                let changed = self.changed.notified();
                if seen() {
                    return;
                }
                changed.await;
            }
        };
        time::timeout(deadline, wait).await.is_ok() || seen()
    }
}

/// Only the immediate pull on meeting the mesh can backfill inside a test, so
/// a slow join cannot let a tick pass it instead. Per process, and every test
/// here wants the same value.
fn pin_backfill_tick() {
    tuning::init(tuning::Tuning::DEFAULTS.backfill_interval(Duration::from_hours(1)));
}

fn nick(name: &str) -> Nickname {
    Nickname::try_new(name).expect("valid nickname")
}

// each member's sink is shared with the node that writes to it, and the test reads it
async fn spawn(topic: &str, name: &str) -> (Node<Store>, Arc<Joined>) {
    // each member's sink is shared with the node that writes to it, and the test reads it
    let sink = Arc::new(Joined::default());
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
    let config = setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic.to_owned(),
        },
        SetupParams::new(nick(name), Arc::clone(&sink)).max_peers(16),
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network");
    (
        Node::spawn(config, Store, None, SignalHandling::Leave),
        sink,
    )
}

/// The whole log is one merge, so it is one slice of the writer.
async fn write_log(node: &Node<Store>, writes: usize) {
    let merge: serde_json::Map<String, serde_json::Value> = (0..writes)
        .map(|index| (format!("k{index}"), serde_json::json!(index)))
        .collect();
    let (done_tx, done_rx) = oneshot::channel();
    node.send(Request::Write(serde_json::Value::Object(merge), done_tx))
        .await
        .expect("the write reaches the loop");
    done_rx.await.expect("the write is applied");
}

async fn read(node: &Node<Store>) -> serde_json::Value {
    let (tx, rx) = oneshot::channel();
    node.send(Request::Read(tx))
        .await
        .expect("the read reaches the loop");
    rx.await.expect("the loop answers")
}

/// The whole meta log is one merge too, so it is one meta slice of the writer.
async fn write_meta_log(node: &Node<Store>, writes: usize) {
    let merge: serde_json::Map<String, serde_json::Value> = (0..writes)
        .map(|index| (format!("m{index}"), serde_json::json!(index)))
        .collect();
    let (done_tx, done_rx) = oneshot::channel();
    node.send(Request::WriteMeta(
        serde_json::Value::Object(merge),
        done_tx,
    ))
    .await
    .expect("the meta write reaches the loop");
    done_rx.await.expect("the meta write is applied");
}

async fn read_meta(node: &Node<Store>) -> serde_json::Value {
    let (tx, rx) = oneshot::channel();
    node.send(Request::ReadMeta(tx))
        .await
        .expect("the meta read reaches the loop");
    rx.await.expect("the loop answers")
}

/// The meta log keys in every author's slice of the meta document.
fn meta_key_count(document: &serde_json::Value) -> usize {
    let mut count = 0;
    if let Some(authors) = document.as_object() {
        for slice in authors.values() {
            if let Some(fields) = slice.as_object() {
                count += fields.keys().filter(|key| key.starts_with('m')).count();
            }
        }
    }
    count
}

/// The log keys in every author's slice of the state document.
fn key_count(document: &serde_json::Value) -> usize {
    let mut count = 0;
    if let Some(authors) = document.as_object() {
        for slice in authors.values() {
            if let Some(fields) = slice.as_object() {
                count += fields.keys().filter(|key| key.starts_with('k')).count();
            }
        }
    }
    count
}

/// How many of the log keys of each document `node` holds, state first, once it has both whole slices, or when
/// [`BUDGET`] runs out.
async fn held_after_backfill(node: &Node<Store>) -> (usize, usize) {
    let started = Instant::now();
    loop {
        let held = key_count(&read(node).await);
        let held_meta = meta_key_count(&read_meta(node).await);
        if (held >= WRITES && held_meta >= WRITES) || started.elapsed() > BUDGET {
            return (held, held_meta);
        }
        time::sleep(Duration::from_millis(100)).await;
    }
}

/// The author writes its log before a second peer and the late joiner arrive.
/// The late joiner meets the author and the second peer, and it must hold the
/// whole slice of the author.
#[test]
fn a_late_joiner_backfills_on_meeting_a_meshed_pair() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        pin_backfill_tick();
        let nonce: u64 = rand::random();
        let topic = format!("late-joiner-trio-{nonce}");

        let (alice, _) = spawn(&topic, "alice").await;
        write_log(&alice, WRITES).await;
        write_meta_log(&alice, WRITES).await;
        time::sleep(GOSSIP_CACHE_RETENTION + Duration::from_secs(1)).await;
        let (early, early_saw) = spawn(&topic, "early").await;
        assert!(
            early_saw
                .wait_for(&nick("alice"), Duration::from_secs(45))
                .await,
            "early never saw alice join"
        );

        let (late, late_saw) = spawn(&topic, "late").await;
        for peer in ["alice", "early"] {
            assert!(
                late_saw
                    .wait_for(&nick(peer), Duration::from_secs(45))
                    .await,
                "late never saw {peer} join"
            );
        }

        let (held, held_meta) = held_after_backfill(&late).await;
        assert_eq!(
            (held, held_meta),
            (WRITES, WRITES),
            "late holds {held} state keys and {held_meta} meta keys of alice's {WRITES} of each {BUDGET:?} after meeting the pair"
        );

        alice.leave().await.expect("alice leaves");
        early.leave().await.expect("early leaves");
        late.leave().await.expect("late leaves");
    });
}
