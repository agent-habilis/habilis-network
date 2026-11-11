//! The time that a seed of the state channel takes to reach a peer over a real link: a node that
//! holds a state of 20 000 paths (the cut ceiling of the path line) cuts, signs and sends the
//! chain, and the test times the wait until the other node holds the whole chain as a candidate.
//! A candidate is adopted at the end of a wait of `DOC_EPOCH_ADOPT_WAIT_TICKS` ticks, and an
//! adopter drops a candidate whose chain is not whole by then, so the chain must arrive in less
//! than that wait. It is a measurement and it is ignored by default. Run it in release mode with
//! `--ignored --nocapture`.

#![cfg(feature = "host")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::ops::doc::MeshDoc;
use habilis_network::ops::{StateMergeParams, broadcast_state_merge, state_cut_now};
use habilis_network::protocol::messages::Authored;
use habilis_network::protocol::{Channel, LookupOpts, MessageKind, Nickname, PresenceSubtype};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh, tuning,
};
use tokio::sync::{Notify, oneshot};
use tokio::time::{self, Instant};

/// The paths of the state: the cut ceiling of the path line.
const PATHS: usize = 20_000;
/// The leaves that one write carries.
const PER_WRITE: usize = 100;
/// The wait of an adopter, less one tick, in seconds: the chain must be whole before it.
const ADOPT_BUDGET: Duration = Duration::from_mins(4);

enum Request {
    Enable(oneshot::Sender<()>),
    Write(serde_json::Value, oneshot::Sender<()>),
    Cut(oneshot::Sender<(usize, Duration)>),
    Candidate(oneshot::Sender<(bool, bool)>),
    Read(oneshot::Sender<usize>),
}

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
            Request::Enable(done) => {
                let mut doc = MeshDoc::new_state(None);
                doc.finish_sync();
                *state.doc_mut(Channel::State) = doc;
                let _ = done.send(());
                false
            }
            Request::Write(merge, done) => {
                let params =
                    StateMergeParams::new(context.into(), Channel::State, merge).surface(false);
                broadcast_state_merge(state, params)
                    .await
                    .expect("a merge of 100 leaves is accepted");
                let _ = done.send(());
                true
            }
            Request::Cut(done) => {
                let started = Instant::now();
                let frames = state_cut_now(state, context)
                    .await
                    .expect("the state is cut and the seed sent");
                let _ = done.send((frames, started.elapsed()));
                true
            }
            Request::Candidate(done) => {
                let doc = state.doc(Channel::State);
                let _ = done.send((doc.has_candidate(), doc.candidate_whole()));
                false
            }
            Request::Read(done) => {
                let json = state.doc(Channel::State).to_json();
                let live = json.get("live").and_then(serde_json::Value::as_object);
                let _ = done.send(live.map_or(0, serde_json::Map::len));
                false
            }
        }
    }
}

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

// The sink is shared with the node that writes to it, and the test reads it.
async fn spawn(topic: &str, name: &str) -> (Node<Store>, Arc<Joined>) {
    // The sink is shared with the node that writes to it, and the test reads it.
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

async fn ask<Answer>(
    node: &Node<Store>,
    build: impl FnOnce(oneshot::Sender<Answer>) -> Request,
) -> Answer {
    let (tx, rx) = oneshot::channel();
    node.send(build(tx))
        .await
        .expect("the request reaches the loop");
    rx.await.expect("the loop answers")
}

#[test]
#[ignore = "a measurement: run it in release mode with --ignored"]
fn the_chain_of_a_cut_of_20000_paths_reaches_a_peer_whole_before_it_adopts() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        tuning::init(tuning::Tuning::DEFAULTS.antientropy_interval(Duration::from_hours(1)));
        let nonce: u64 = rand::random();
        let topic = format!("state-seed-send-{nonce}");
        let (alice, _) = spawn(&topic, "alice").await;
        let (bob, bob_saw) = spawn(&topic, "bob").await;
        assert!(
            bob_saw
                .wait_for(&nick("alice"), Duration::from_secs(45))
                .await,
            "bob never saw alice join"
        );
        ask(&alice, Request::Enable).await;
        ask(&bob, Request::Enable).await;

        let filling = Instant::now();
        for write in 0..(PATHS / PER_WRITE) {
            let mut leaves = serde_json::Map::new();
            for leaf in 0..PER_WRITE {
                let index = write * PER_WRITE + leaf;
                leaves.insert(format!("l{index:06}"), serde_json::json!(index % 10));
            }
            let merge = serde_json::json!({ "live": serde_json::Value::Object(leaves) });
            ask(&alice, |done| Request::Write(merge, done)).await;
        }
        // Bob holds the same leaves before the cut, so the time below is the chain and no history.
        while ask(&bob, Request::Read).await < PATHS {
            assert!(
                filling.elapsed() < Duration::from_secs(600),
                "bob never held the state"
            );
            time::sleep(Duration::from_millis(200)).await;
        }
        eprintln!(
            "SENDTEST state of {PATHS} paths held by both nodes after {:?}",
            filling.elapsed()
        );

        let started = Instant::now();
        let (frames, alice_took) = ask(&alice, Request::Cut).await;
        let whole = loop {
            let (has, whole) = ask(&bob, Request::Candidate).await;
            if has && whole {
                break started.elapsed();
            }
            assert!(
                started.elapsed() < ADOPT_BUDGET,
                "the chain of {frames} frames was not whole at bob after {:?}",
                started.elapsed()
            );
            time::sleep(Duration::from_millis(100)).await;
        };
        eprintln!(
            "SENDTEST chain of {frames} frames: alice cut and sent in {alice_took:?}, bob held the whole chain {whole:?} after the start; the budget is {ADOPT_BUDGET:?}"
        );
        assert!(
            whole < ADOPT_BUDGET,
            "the chain must be whole before the wait of an adopter ends"
        );

        alice.leave().await.expect("alice leaves");
        bob.leave().await.expect("bob leaves");
    });
}
