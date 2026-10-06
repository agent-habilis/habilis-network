//! A late joiner pulls the state already written before it arrived within one
//! round trip of meeting the mesh, not on its next anti-entropy tick.
//!
//! The pull is the newcomer's own digest. It used to be sent only when an
//! existing peer's `joined` was the first frame the newcomer saw from it, so a
//! `PeerInfo` arriving first — from the `NeighborUp` re-send, or the re-flood
//! every `joined` triggers — pushed the whole backfill back an interval.

#![cfg(feature = "host")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::net::TransportOpts;
use habilis_network::ops::{StateMergeParams, broadcast_state_merge};
use habilis_network::protocol::{
    Channel, LookupOpts, Message, MessageKind, Nickname, PresenceSubtype,
};
use habilis_network::runtime::{Node, SetupKind, SetupParams, derive_topic_mesh_with, setup_mesh};
use tokio::sync::{Notify, oneshot};

/// The agent-gossip late-joiner test's log size: two and a half answers.
const WRITES: usize = 160;
/// Changes one digest answer carries (the default `ANTIENTROPY_MAX_RESEND`).
const ONE_ANSWER: usize = 64;
/// How long a test waits for the first answer. With the tick pinned away it
/// can only be the immediate pull, so this only bounds a slow join.
const BUDGET: Duration = Duration::from_secs(15);

enum Request {
    Write(serde_json::Value, oneshot::Sender<()>),
    Read(oneshot::Sender<serde_json::Value>),
}

/// Presence alone forms the mesh; sessions write and read the state document.
struct Store;

#[habilis_network::async_trait]
impl NodeApp for Store {
    fn classify(&self, _message: &Message) -> AppClass {
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
impl NodeDriver for Store {
    type Session = Request;
    type Http = ();
    type Ipc = serde_json::Value;

    async fn handle_session(
        &mut self,
        req: Self::Session,
        state: &mut EventLoopState,
        ctx: &HandlerCtx<'_>,
    ) -> bool {
        match req {
            Request::Write(merge, done) => {
                broadcast_state_merge(
                    state,
                    StateMergeParams {
                        mesh: ctx.mesh,
                        author: ctx.author,
                        merge,
                        sender: ctx.sender,
                        sink: ctx.sink,
                        channel: Channel::State,
                        surface: false,
                    },
                )
                .await
                .expect("a small merge is accepted");
                let _ = done.send(());
                true
            }
            Request::Read(resp) => {
                let _ = resp.send(state.doc(Channel::State).to_json());
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
        if let NodeEvent::Presence { msg } = event
            && let MessageKind::Presence {
                subtype: PresenceSubtype::Joined,
            } = msg.kind
        {
            self.peers
                .lock()
                .expect("no poison")
                .push(msg.author.clone());
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
        tokio::time::timeout(deadline, wait).await.is_ok() || seen()
    }
}

/// Only the immediate pull on meeting the mesh can backfill inside a test, so
/// a slow join cannot let a tick pass it instead. Per process, and every test
/// here wants the same value.
fn pin_antientropy_tick() {
    habilis_network::runtime::tuning::init(habilis_network::runtime::tuning::Tuning {
        antientropy_interval_secs: 3600,
        ..habilis_network::runtime::tuning::Tuning::DEFAULTS
    });
}

fn nick(name: &str) -> Nickname {
    Nickname::new(name).expect("valid nickname")
}

async fn spawn(topic: &str, name: &str) -> (Node<Store>, Arc<Joined>) {
    let sink = Arc::new(Joined::default());
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
    let config = setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic.to_owned(),
        },
        SetupParams {
            author: nick(name),
            max_peers: 16,
            endpoint: None,
            protocols: Vec::new(),
            transports: TransportOpts::default(),
            runtime_base: None,
            state_file: None,
            sink: Arc::clone(&sink) as Arc<dyn NodeSink>,
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network");
    (Node::spawn(config, Store, None, false), sink)
}

/// More changes than one digest answer carries, so the backfill takes several
/// rounds and the first one is visible on its own.
async fn write_log(node: &Node<Store>, writes: usize) {
    for index in 0..writes {
        let (done_tx, done_rx) = oneshot::channel();
        node.send(Request::Write(
            serde_json::json!({ format!("k{index}"): index }),
            done_tx,
        ))
        .await
        .expect("the write reaches the loop");
        done_rx.await.expect("the write is applied");
    }
}

async fn read(node: &Node<Store>) -> serde_json::Value {
    let (tx, rx) = oneshot::channel();
    node.send(Request::Read(tx))
        .await
        .expect("the read reaches the loop");
    rx.await.expect("the loop answers")
}

fn key_count(document: &serde_json::Value) -> usize {
    document.as_object().map_or(0, |fields| {
        fields.keys().filter(|key| key.starts_with('k')).count()
    })
}

/// How many of the log's changes `node` holds once it has a full answer, or
/// when [`BUDGET`] runs out.
async fn held_after_first_answer(node: &Node<Store>) -> usize {
    let started = tokio::time::Instant::now();
    loop {
        let held = key_count(&read(node).await);
        if held >= ONE_ANSWER || started.elapsed() > BUDGET {
            return held;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_joiner_backfills_on_meeting_its_only_peer() {
    pin_antientropy_tick();
    let topic = format!("late-joiner-pair-{}", rand::random::<u64>());
    let (alice, _) = spawn(&topic, "alice").await;
    write_log(&alice, WRITES).await;

    let (bob, bob_saw) = spawn(&topic, "bob").await;
    assert!(
        bob_saw
            .wait_for(&nick("alice"), Duration::from_secs(45))
            .await,
        "bob never saw alice join"
    );

    let held = held_after_first_answer(&bob).await;
    assert!(
        held >= ONE_ANSWER,
        "bob held {held} of alice's {WRITES} changes {BUDGET:?} after seeing her join; \
         the first digest answer carries {ONE_ANSWER}"
    );

    alice.leave().await.expect("alice leaves");
    bob.leave().await.expect("bob leaves");
}

/// The agent-gossip shape: the late joiner meets two peers that already hold
/// the log. Before the fix whether it passed turned on which frame each peer's
/// first one happened to be, so it failed only some of the time; with the
/// digest sent on any first frame the digest itself goes out every run. Under
/// load it still missed when the joiner met both peers over the rendezvous
/// before its first real-peer link: both answers re-sent frames the
/// rendezvous had just carried in alice's flush, iroh-gossip dropped them as
/// seen, and with the tick pinned nothing asked again. It also missed when the
/// joiner had the lowest endpoint id and its first frame at a peer was not its
/// `joined`: no `PeerInfo` re-flood reached it, and both peers deferred the
/// first dial to it. The joiner now asks again on its first real-peer link,
/// and a new peer's first frame of any kind floods our address. The test waits
/// for the first answer only; it does not show that all 160 changes arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_joiner_backfills_on_meeting_a_meshed_pair() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    pin_antientropy_tick();
    let topic = format!("late-joiner-trio-{}", rand::random::<u64>());
    let (alice, _) = spawn(&topic, "alice").await;
    write_log(&alice, WRITES).await;
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

    let held = held_after_first_answer(&late).await;
    assert!(
        held >= ONE_ANSWER,
        "late held {held} of alice's {WRITES} changes {BUDGET:?} after meeting the pair; \
         the first digest answer carries {ONE_ANSWER}"
    );

    alice.leave().await.expect("alice leaves");
    early.leave().await.expect("early leaves");
    late.leave().await.expect("late leaves");
}

/// A long history reaches a late joiner in rounds of one answer budget each.
/// With the anti-entropy tick pinned far away, only the joiner's own fast
/// rounds can pull more than the first answer: it asks again, point-to-point,
/// each time it applied a full answer or still holds orphans.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_joiner_pulls_a_long_history_in_fast_rounds() {
    const LONG: usize = 300;
    const FAST: Duration = Duration::from_secs(5);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    pin_antientropy_tick();
    let topic = format!("late-joiner-long-{}", rand::random::<u64>());
    let (alice, _) = spawn(&topic, "alice").await;
    write_log(&alice, LONG).await;
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

    let started = tokio::time::Instant::now();
    let mut held = 0;
    while started.elapsed() < FAST {
        held = key_count(&read(&late).await);
        if held >= LONG {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        held, LONG,
        "late held {held} of alice's {LONG} changes {FAST:?} after meeting the pair"
    );

    alice.leave().await.expect("alice leaves");
    early.leave().await.expect("early leaves");
    late.leave().await.expect("late leaves");
}
