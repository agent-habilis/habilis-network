//! A late joiner pulls the state already written before it arrived within one
//! round trip of meeting the mesh, not on its next anti-entropy tick.
//!
//! The pull is the newcomer's own digest. It used to be sent only when an
//! existing peer's `joined` was the first frame the newcomer saw from it, so a
//! `PeerInfo` arriving first — from the `NeighborUp` re-send, or the re-flood
//! every `joined` triggers — pushed the whole backfill back an interval.

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
/// The retention of the message ids of iroh-gossip. A joiner that meets an author within it can get the
/// author's frame from the gossip cache, which is no backfill. Each test waits past it before a joiner starts.
const GOSSIP_MESSAGE_RETENTION: Duration = Duration::from_secs(90);
/// How long a test waits for the slice of an author. With the tick pinned away it can only be the
/// backfill on meeting the author, so this only bounds a slow join.
const BUDGET: Duration = Duration::from_secs(15);

enum Request {
    Write(serde_json::Value, oneshot::Sender<()>),
    Read(oneshot::Sender<serde_json::Value>),
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
fn pin_antientropy_tick() {
    tuning::init(tuning::Tuning::DEFAULTS.antientropy_interval(Duration::from_hours(1)));
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

/// How many of the log's keys `node` holds once it has the whole slice, or when [`BUDGET`] runs out.
async fn held_after_backfill(node: &Node<Store>) -> usize {
    let started = Instant::now();
    loop {
        let held = key_count(&read(node).await);
        if held >= WRITES || started.elapsed() > BUDGET {
            return held;
        }
        time::sleep(Duration::from_millis(100)).await;
    }
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
#[test]
fn a_late_joiner_backfills_on_meeting_a_meshed_pair() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        pin_antientropy_tick();
        let nonce: u64 = rand::random();
        let topic = format!("late-joiner-trio-{nonce}");

        let (alice, _) = spawn(&topic, "alice").await;
        write_log(&alice, WRITES).await;
        time::sleep(GOSSIP_MESSAGE_RETENTION + Duration::from_secs(1)).await;
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

        let held = held_after_backfill(&late).await;
        assert_eq!(
            held, WRITES,
            "late holds {held} of alice's {WRITES} keys {BUDGET:?} after meeting the pair"
        );

        alice.leave().await.expect("alice leaves");
        early.leave().await.expect("early leaves");
        late.leave().await.expect("late leaves");
    });
}
