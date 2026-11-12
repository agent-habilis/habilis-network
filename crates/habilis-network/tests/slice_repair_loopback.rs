//! A member that misses a slice of an author pulls it from a neighbour on the digest round, without a new
//! write from the author.
//!
//! Alice writes her whole log as one slice. Carol drops Alice's State and Meta frames after the dedup gate,
//! so the frame is seen and lost, as on a real network. The hook goes off and Alice writes nothing more. The
//! digest round of the tick then pulls the slice to Carol within the bound.

#![cfg(feature = "host")]

use habilis_network::protocol::messages::Authored;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::ops::{StateMergeParams, broadcast_state_merge};
use habilis_network::protocol::{
    AuthorKey, Channel, LookupOpts, MessageKind, Nickname, PresenceSubtype,
};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use tokio::sync::{Notify, oneshot};

use tokio::time::{self, Instant};

/// The keys of Alice's log. One slice carries the whole log, so it must fit one frame.
const WRITES: usize = 80;

/// The bound of the repair: the backfill tick, the settle delay with its jitter, and a margin of 5 s.
const REPAIR_BOUND: Duration = Duration::from_millis(21_500);

enum Request {
    Write(serde_json::Value, oneshot::Sender<()>),
    Read(oneshot::Sender<serde_json::Value>),
    Key(oneshot::Sender<AuthorKey>),
    DropFrom(Option<AuthorKey>, oneshot::Sender<()>),
}

/// Presence alone forms the mesh; members write and read the state document, and drop frames on request.
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
            Request::Key(response) => {
                let _ = response.send(state.identity().author_key());
                false
            }
            Request::DropFrom(author, done) => {
                state.drop_slices_from(author);
                let _ = done.send(());
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

fn nick(name: &str) -> Nickname {
    Nickname::try_new(name).expect("valid nickname")
}

// The sink is shared: the node holds it, and the test reads what the node emitted into it.
async fn spawn(topic: &str, name: &str) -> (Node<Store>, Arc<Joined>) {
    // shared with the node that emits into it, and read by the test
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

async fn key_of(node: &Node<Store>) -> AuthorKey {
    let (tx, rx) = oneshot::channel();
    node.send(Request::Key(tx))
        .await
        .expect("the key request reaches the loop");
    rx.await.expect("the loop answers")
}

async fn drop_frames_from(node: &Node<Store>, author: Option<AuthorKey>) {
    let (tx, rx) = oneshot::channel();
    node.send(Request::DropFrom(author, tx))
        .await
        .expect("the drop request reaches the loop");
    rx.await.expect("the loop answers");
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

/// Alice's log is held by Carol once Carol has all of its keys, or the bound runs out.
async fn held_within(node: &Node<Store>, bound: Duration) -> usize {
    let started = Instant::now();
    loop {
        let held = key_count(&read(node).await);
        if held >= WRITES || started.elapsed() > bound {
            return held;
        }
        time::sleep(Duration::from_millis(250)).await;
    }
}

/// Carol misses Alice's write, then pulls it from a neighbour on the digest round, within the bound.
#[test]
fn a_member_that_missed_a_write_pulls_it_from_a_neighbor() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let nonce: u64 = rand::random();
        let topic = format!("slice-repair-{nonce}");

        let (alice, _) = spawn(&topic, "alice").await;
        let (bob, bob_saw) = spawn(&topic, "bob").await;
        let (carol, carol_saw) = spawn(&topic, "carol").await;
        assert!(
            bob_saw
                .wait_for(&nick("alice"), Duration::from_secs(45))
                .await,
            "bob never saw alice join"
        );
        assert!(
            carol_saw
                .wait_for(&nick("alice"), Duration::from_secs(45))
                .await,
            "carol never saw alice join"
        );

        let alice_key = key_of(&alice).await;
        drop_frames_from(&carol, Some(alice_key)).await;
        write_log(&alice, WRITES).await;
        time::sleep(Duration::from_secs(3)).await;
        drop_frames_from(&carol, None).await;

        let held = held_within(&carol, REPAIR_BOUND).await;
        assert!(
            held >= WRITES,
            "carol holds {held} of alice's {WRITES} keys within the repair bound"
        );

        alice.leave().await.expect("alice leaves");
        bob.leave().await.expect("bob leaves");
        carol.leave().await.expect("carol leaves");
    });
}
