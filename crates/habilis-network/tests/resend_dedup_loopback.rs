//! A frame that the gossip layer delivered and the app dropped comes again by anti-entropy.
//!
//! The gossip layer names a message by the hash of its payload and drops a payload it has seen
//! for 90 s. A resend of the same bytes therefore cannot repair a frame that a full queue
//! between the gossip layer and the loop made the app drop. A resend carries a nonce, so it is
//! a new gossip message, and the app drops it only where it already knows the frame inside.
//!
//! Two nodes on a loopback mesh. The app logs what it reads, so the log can be repaired. Two
//! sites send a resend on gossip: the answer to a chat digest (`resend_one`), and the answer to a
//! state digest when the asker's endpoint is not proven. One test for each.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use habilis_network::protocol::message::Authored;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeSink, SilentSink,
    TestDrop,
};
use habilis_network::ops::{StateMergeParams, app_frame, broadcast_state_merge, send_app};
use habilis_network::protocol::{
    AppFrameParams, AppTag, Channel, LookupOpts, MessageBody, Nickname,
};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use tokio::sync::oneshot;

/// Two anti-entropy cycles (10 s each) and margin, less than the 90 s dedup of the gossip layer.
const REPAIR: Duration = Duration::from_secs(40);
const MEETING: Duration = Duration::from_mins(1);
/// The window of the state test: two digest rounds and the cooldown of an answer, and less than the
/// 30 s of the alive tick, whose deferred `PeerInfo` gives alice the proof of bob back and turns the
/// answer point-to-point (seen at 29 s in the run without the nonce).
const REPAIR_STATE: Duration = Duration::from_secs(20);

fn serial() -> &'static tokio::sync::Mutex<()> {
    static SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn logs() -> String {
    habilis_network_test_tracing::captured_logs()
}

/// The lines that say how a state change travelled, from `before` on.
fn lines_since(before: usize) -> String {
    logs()[before..]
        .lines()
        .filter(|line| {
            ["peerinfo received", "state anti-entropy", "state digest"]
                .iter()
                .any(|needle| line.contains(needle))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

enum Request {
    Say(String, oneshot::Sender<()>),
    Drop(TestDrop, oneshot::Sender<()>),
    Fired(oneshot::Sender<u32>),
    Merge(serde_json::Value, oneshot::Sender<()>),
    Read(oneshot::Sender<serde_json::Value>),
    ForgetProof(String, oneshot::Sender<()>),
}

/// An app that logs every frame it reads and keeps what it read.
struct Chat {
    read: Arc<Mutex<Vec<String>>>,
}

#[habilis_network::async_trait]
impl NodeApp for Chat {
    fn classify(&self, _message: &Authored) -> AppClass {
        AppClass::NONE
            .union(AppClass::LOGGABLE)
            .union(AppClass::VALID)
    }

    async fn on_app_frame(
        &mut self,
        frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        _ctx: &HandlerCtx<'_>,
    ) -> bool {
        self.read
            .lock()
            .expect("no poison")
            .push(frame.message.body.as_str().to_owned());
        true
    }
}

#[habilis_network::async_trait]
impl NodeDriver for Chat {
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
            Request::Say(text, done) => {
                let frame = app_frame(
                    ctx,
                    AppFrameParams::new(
                        AppTag::try_new("app_msg").expect("a valid app tag"),
                        None,
                        None,
                        MessageBody::from(text.as_str()),
                    ),
                );
                let class = self.classify(&frame.authored());
                let _ = send_app(state, ctx, frame, class)
                    .await
                    .expect("a small frame is accepted");
                let _ = done.send(());
                true
            }
            Request::Drop(what, done) => {
                state.drop_inbound(what);
                let _ = done.send(());
                false
            }
            Request::Fired(resp) => {
                let _ = resp.send(state.inbound_drops_fired());
                false
            }
            Request::Merge(merge, done) => {
                broadcast_state_merge(
                    state,
                    StateMergeParams::new(ctx.into(), Channel::State, merge).with_surface(false),
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
            Request::ForgetProof(peer, done) => {
                state.forget_endpoint_proof(&nick(&peer));
                let _ = done.send(());
                false
            }
        }
    }
}

fn nick(name: &str) -> Nickname {
    Nickname::try_new(name).expect("valid nickname")
}

async fn spawn(topic: &str, name: &str) -> (Node<Chat>, Arc<Mutex<Vec<String>>>) {
    let read = Arc::new(Mutex::new(Vec::new()));
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
    let config = setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic.to_owned(),
        },
        SetupParams::new(
            nick(name),
            Arc::new(SilentSink::default()) as Arc<dyn NodeSink>,
        )
        .with_max_peers(16),
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network");
    let node = Node::spawn(
        config,
        Chat {
            read: Arc::clone(&read),
        },
        None,
        SignalHandling::Leave,
    );
    (node, read)
}

async fn say(node: &Node<Chat>, text: &str) {
    let (done, sent) = oneshot::channel();
    node.send(Request::Say(text.to_owned(), done))
        .await
        .expect("the request reaches the loop");
    sent.await.expect("the loop answers");
}

async fn drop_inbound(node: &Node<Chat>, what: TestDrop) {
    let (done, armed) = oneshot::channel();
    node.send(Request::Drop(what, done))
        .await
        .expect("the request reaches the loop");
    armed.await.expect("the loop answers");
}

/// The hook must have dropped its frame, exactly once, before a repair counts: a run in which the
/// drop did not happen proves nothing.
async fn assert_dropped_once(node: &Node<Chat>) {
    let started = Instant::now();
    loop {
        let (resp, fired) = oneshot::channel();
        node.send(Request::Fired(resp))
            .await
            .expect("the request reaches the loop");
        let count = fired.await.expect("the loop answers");
        if count == 1 {
            return;
        }
        assert!(
            count == 0 && started.elapsed() < Duration::from_secs(10),
            "the hook dropped {count} frames, not one"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn merge(node: &Node<Chat>, merge: serde_json::Value) {
    let (done, merged) = oneshot::channel();
    node.send(Request::Merge(merge, done))
        .await
        .expect("the request reaches the loop");
    merged.await.expect("the loop answers");
}

async fn forget_proof(node: &Node<Chat>, peer: &str) {
    let (done, armed) = oneshot::channel();
    node.send(Request::ForgetProof(peer.to_owned(), done))
        .await
        .expect("the request reaches the loop");
    armed.await.expect("the loop answers");
}

async fn state_has(node: &Node<Chat>, key: &str) -> bool {
    let (resp, document) = oneshot::channel();
    node.send(Request::Read(resp))
        .await
        .expect("the request reaches the loop");
    document.await.expect("the loop answers").get(key).is_some()
}

fn has_read(read: &Arc<Mutex<Vec<String>>>, text: &str) -> bool {
    read.lock()
        .expect("no poison")
        .iter()
        .any(|got| got == text)
}

/// Wait until `text` is in `read`; the time it took, or `None`.
async fn waits_for(
    read: &Arc<Mutex<Vec<String>>>,
    text: &str,
    deadline: Duration,
) -> Option<Duration> {
    let started = Instant::now();
    while started.elapsed() < deadline {
        if has_read(read, text) {
            return Some(started.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    has_read(read, text).then(|| started.elapsed())
}

/// A frame that the author sent, one member read and bob dropped comes again from the member that
/// holds it. The author logs no app frame of her own (`send_app` keeps none), so a third member
/// that ingested the frame is the one that has it to resend: carol answers bob's digest. Her
/// resend has the payload that bob's gossip layer already named, unless it carries a nonce.
#[test]
fn a_frame_the_app_dropped_is_repaired_by_anti_entropy() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network::gossip=debug");
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let _one_at_a_time = serial().lock().await;
        let topic = format!("resend-dedup-{}", rand::random::<u64>());

        let (alice, _alice_read) = spawn(&topic, "alice").await;
        let (bob, bob_read) = spawn(&topic, "bob").await;
        let (carol, carol_read) = spawn(&topic, "carol").await;

        // A first frame that reaches both proves that the three are meshed.
        let meeting = Instant::now();
        while !(has_read(&bob_read, "hello") && has_read(&carol_read, "hello")) {
            assert!(meeting.elapsed() < MEETING, "the three never meshed");
            say(&alice, "hello").await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        drop_inbound(&bob, TestDrop::AppBody("dropped-once".to_owned())).await;
        say(&alice, "dropped-once").await;
        assert_dropped_once(&bob).await;
        assert!(
            waits_for(&carol_read, "dropped-once", Duration::from_secs(10))
                .await
                .is_some(),
            "carol never read the frame, so nobody holds it to resend"
        );

        let after = waits_for(&bob_read, "dropped-once", REPAIR).await;
        eprintln!("the dropped frame reached the app after: {after:?}");
        assert!(
            after.is_some(),
            "a frame the app dropped never came again inside {REPAIR:?}: the resend has the \
         payload that the gossip layer already named"
        );

        alice.leave().await.expect("alice leaves");
        bob.leave().await.expect("bob leaves");
        carol.leave().await.expect("carol leaves");
    });
}

#[test]
fn a_state_change_the_app_dropped_is_repaired_by_the_state_digest_answer() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network::gossip=debug");
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let _one_at_a_time = serial().lock().await;
        let topic = format!("resend-dedup-state-{}", rand::random::<u64>());

        let (alice, _alice_read) = spawn(&topic, "alice").await;
        let (bob, bob_read) = spawn(&topic, "bob").await;

        let meeting = Instant::now();
        while !has_read(&bob_read, "hello") {
            assert!(meeting.elapsed() < MEETING, "the pair never meshed");
            say(&alice, "hello").await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // Alice must hold the proof of bob before she forgets it, or the first `PeerInfo` of bob, late,
        // would put it back after the forget. The line says that she took his `PeerInfo`.
        let waiting = Instant::now();
        while !logs()
            .lines()
            .any(|line| line.contains("peerinfo received") && line.contains("author=bob"))
        {
            assert!(
                waiting.elapsed() < MEETING,
                "alice never took the PeerInfo of bob"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        // The forget models a member whose `PeerInfo` does not reach the asker side, the state the
        // gossip answer exists for; the wait below forgets again after every poll.
        forget_proof(&alice, "bob").await;
        drop_inbound(&bob, TestDrop::StateChange).await;
        let before = logs().len();
        merge(&alice, serde_json::json!({ "dropped-once": 1 })).await;
        assert_dropped_once(&bob).await;

        let started = Instant::now();
        while !state_has(&bob, "dropped-once").await {
            assert!(
                started.elapsed() < REPAIR_STATE,
                "a state change the app dropped never came again inside {REPAIR_STATE:?}: the answer has \
             the payload that the gossip layer already named\n{}",
                lines_since(before)
            );
            // A PeerInfo of bob restores the proof; forgetting it again keeps the answer on gossip.
            forget_proof(&alice, "bob").await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        eprintln!(
            "the dropped state change reached the app after: {:?}",
            started.elapsed()
        );
        let answers: Vec<String> = lines_since(before)
            .lines()
            .filter(|line| line.contains("state anti-entropy: resent frames a peer lacked"))
            .map(str::to_owned)
            .collect();
        for line in &answers {
            eprintln!("state digest answer: {line}");
        }
        assert!(
            !answers.is_empty() && answers.iter().all(|line| !line.contains("broadcast=0")),
            "a state digest was answered point-to-point, so the dedup was not what the repair beat\n{}",
            lines_since(before)
        );

        alice.leave().await.expect("alice leaves");
        bob.leave().await.expect("bob leaves");
    });
}

/// The author holds what she broadcast. A peer that holds her frame then has nothing to resend to
/// her: her digest names it. Without it the peer answers every digest round of hers with a resend
/// of her own frame, forever.
#[test]
fn a_peer_does_not_resend_to_its_author_the_frame_she_kept() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network::gossip=debug");
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let _one_at_a_time = serial().lock().await;
        let topic = format!("resend-author-{}", rand::random::<u64>());

        let (alice, _alice_read) = spawn(&topic, "alice").await;
        let (bob, bob_read) = spawn(&topic, "bob").await;

        let meeting = Instant::now();
        while !has_read(&bob_read, "hello") {
            assert!(meeting.elapsed() < MEETING, "the pair never meshed");
            say(&alice, "hello").await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        // One digest round of each node to settle, then two rounds in which nothing may be resent.
        tokio::time::sleep(Duration::from_secs(12)).await;
        let before = logs().len();
        tokio::time::sleep(Duration::from_secs(25)).await;
        let log = logs();
        let resends: Vec<&str> = log[before..]
            .lines()
            .filter(|line| line.contains("anti-entropy: resent messages a peer was missing"))
            .collect();
        for line in &resends {
            eprintln!("resend: {line}");
        }
        assert!(
            resends.is_empty(),
            "{} resends in two digest rounds although every frame was delivered",
            resends.len()
        );

        alice.leave().await.expect("alice leaves");
        bob.leave().await.expect("bob leaves");
    });
}

/// The acceptance of the dedup and of the author's log together, with two members: alice sends,
/// bob drops the frame, and alice is the only member that can resend it. With the nonce alone
/// there is no holder (she kept nothing); with her log alone her resend has the payload that
/// bob's gossip layer already named. Only both bring the frame back.
#[test]
fn a_frame_the_app_dropped_comes_back_from_its_author_when_she_kept_it() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network::gossip=debug");
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let _one_at_a_time = serial().lock().await;
        let topic = format!("resend-author-dedup-{}", rand::random::<u64>());

        let (alice, _alice_read) = spawn(&topic, "alice").await;
        let (bob, bob_read) = spawn(&topic, "bob").await;

        let meeting = Instant::now();
        while !has_read(&bob_read, "hello") {
            assert!(meeting.elapsed() < MEETING, "the pair never meshed");
            say(&alice, "hello").await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        drop_inbound(&bob, TestDrop::AppBody("dropped-once".to_owned())).await;
        say(&alice, "dropped-once").await;
        assert_dropped_once(&bob).await;

        let after = waits_for(&bob_read, "dropped-once", REPAIR).await;
        eprintln!("the dropped frame reached the app after: {after:?}");
        assert!(
            after.is_some(),
            "a frame the app dropped never came back from its author inside {REPAIR:?}"
        );

        alice.leave().await.expect("alice leaves");
        bob.leave().await.expect("bob leaves");
    });
}
