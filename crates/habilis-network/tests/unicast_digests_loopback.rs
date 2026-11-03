//! A member that missed traffic catches up by anti-entropy, with the unicast form of the digests
//! on and off.
//!
//! Three nodes on a loopback mesh. One node is frozen, its event loop blocked, while the others
//! send chat and state changes, and one sender leaves before the frozen node wakes. Each test runs
//! in both forms: the repair must not depend on the form.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, SilentSink,
};
use habilis_network::ops::{StateMergeParams, app_frame, broadcast_state_merge, send_app};
use habilis_network::protocol::messages::Authored;
use habilis_network::protocol::{
    AppFrameParams, AppTag, Channel, LookupOpts, MessageBody, Nickname,
};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use tokio::sync::oneshot;
use tokio::{sync, time};

const MEETING: Duration = Duration::from_mins(1);
/// The time a member is frozen: longer than the 60 s of the quiet timeout.
const FROZEN: Duration = Duration::from_secs(75);
/// The time to catch up after the wake: several digest rounds.
const CATCH_UP: Duration = Duration::from_secs(90);

fn serial() -> &'static sync::Mutex<()> {
    static SERIAL: OnceLock<sync::Mutex<()>> = OnceLock::new();
    SERIAL.get_or_init(|| sync::Mutex::new(()))
}

enum Request {
    Say(String, oneshot::Sender<()>),
    Merge(serde_json::Value, oneshot::Sender<()>),
    Read(oneshot::Sender<serde_json::Value>),
    Freeze(Duration, oneshot::Sender<()>),
    Unicast(oneshot::Sender<()>),
}

/// An app that keeps every frame it reads.
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
        let body = frame.message.body.as_str().to_owned();
        self.read.lock().expect("no poison").push(body);
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
        request: Self::Session,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            Request::Say(text, done) => {
                let frame = app_frame(
                    context,
                    AppFrameParams::new(
                        AppTag::try_new("app_msg").expect("a valid app tag"),
                        None,
                        None,
                        MessageBody::from(text.as_str()),
                    ),
                );
                let class = self.classify(&frame.authored());
                let _ = send_app(state, context, frame, class)
                    .await
                    .expect("a small frame is accepted");
                let _ = done.send(());
                true
            }
            Request::Merge(merge, done) => {
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
                let _ = response.send(state.doc(Channel::State).to_json());
                false
            }
            Request::Freeze(span, done) => {
                let _ = done.send(());
                // A blocked loop is the frozen process: nothing is read or sent meanwhile.
                thread::sleep(span);
                false
            }
            Request::Unicast(done) => {
                state.set_unicast_digests(true);
                let _ = done.send(());
                false
            }
        }
    }
}

fn nick(name: &str) -> Nickname {
    Nickname::try_new(name).expect("valid nickname")
}

async fn spawn(topic: &str, name: &str, unicast: bool) -> (Node<Chat>, Arc<Mutex<Vec<String>>>) {
    let read = Arc::new(Mutex::new(Vec::new()));
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
    let config = setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic.to_owned(),
        },
        SetupParams::new(nick(name), SilentSink::default()).max_peers(16),
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
    if unicast {
        ask(&node, Request::Unicast).await;
    }
    (node, read)
}

/// Send a request that carries a `oneshot` of `()` and wait for the loop to answer.
async fn ask(node: &Node<Chat>, request: impl FnOnce(oneshot::Sender<()>) -> Request) {
    let (done, answered) = oneshot::channel();
    node.send(request(done))
        .await
        .expect("the request reaches the loop");
    answered.await.expect("the loop answers");
}

async fn say(node: &Node<Chat>, text: &str) {
    ask(node, |done| Request::Say(text.to_owned(), done)).await;
}

async fn merge(node: &Node<Chat>, merge: serde_json::Value) {
    ask(node, |done| Request::Merge(merge, done)).await;
}

fn has_read(read: &Arc<Mutex<Vec<String>>>, text: &str) -> bool {
    read.lock()
        .expect("no poison")
        .iter()
        .any(|got| got == text)
}

async fn state_has(node: &Node<Chat>, key: &str) -> bool {
    let (response, document) = oneshot::channel();
    node.send(Request::Read(response))
        .await
        .expect("the request reaches the loop");
    let document = document.await.expect("the loop answers");
    document.get(key).is_some()
}

async fn waits(deadline: Duration, mut done: impl AsyncFnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < deadline {
        if done().await {
            return true;
        }
        time::sleep(Duration::from_millis(250)).await;
    }
    done().await
}

/// Three members, all meshed: the first chat of alice reaches bob and carol.
async fn trio(
    topic: &str,
    unicast: bool,
) -> (
    (Node<Chat>, Arc<Mutex<Vec<String>>>),
    (Node<Chat>, Arc<Mutex<Vec<String>>>),
    (Node<Chat>, Arc<Mutex<Vec<String>>>),
) {
    let alice = spawn(topic, "alice", unicast).await;
    let bob = spawn(topic, "bob", unicast).await;
    let carol = spawn(topic, "carol", unicast).await;
    let meeting = Instant::now();
    while !(has_read(&bob.1, "hello") && has_read(&carol.1, "hello")) {
        assert!(meeting.elapsed() < MEETING, "the trio never meshed");
        say(&alice.0, "hello").await;
        time::sleep(Duration::from_secs(1)).await;
    }
    (alice, bob, carol)
}

fn frozen_member_catches_up(unicast: bool) {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network::gossip=debug");
    // The freeze is the subject: the stalled maintenance timers are what a frozen process logs.
    guard.expect_warn("habilis_network::lifecycle", "maintenance timer stalled");
    // A freeze longer than the quiet timeout also makes the node heal itself, and its clock gap
    // makes the others refuse its link state until the clocks agree again.
    guard.expect_warn("habilis_network::gossip", "heal: hard re-bootstrap");
    guard.allow_warn(
        "habilis_network_iroh_multihop_transport::topology",
        "link-state refused",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let _one_at_a_time = serial().lock().await;
        let nonce: u64 = rand::random();
        let topic = format!("unicast-frozen-{nonce}-{unicast}");
        let (alice, bob, carol) = trio(&topic, unicast).await;

        ask(&carol.0, |done| Request::Freeze(FROZEN, done)).await;
        for index in 0..5 {
            say(&alice.0, &format!("while-frozen-{index}")).await;
        }
        merge(&alice.0, serde_json::json!({ "while-frozen": 1 })).await;
        time::sleep(FROZEN).await;

        let chats = waits(CATCH_UP, async || {
            (0..5).all(|index| has_read(&carol.1, &format!("while-frozen-{index}")))
        })
        .await;
        assert!(chats, "carol did not read the chat she missed while frozen");
        let state = waits(CATCH_UP, async || state_has(&carol.0, "while-frozen").await).await;
        assert!(state, "carol did not get the state she missed while frozen");
        assert!(has_read(&bob.1, "while-frozen-4"), "bob read it live");

        alice.0.leave().await.expect("alice leaves");
        bob.0.leave().await.expect("bob leaves");
        carol.0.leave().await.expect("carol leaves");
    });
}

fn sender_that_left_is_repaired_by_the_others(unicast: bool) {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network::gossip=debug");
    // The freeze is the subject: the stalled maintenance timers are what a frozen process logs.
    guard.expect_warn("habilis_network::lifecycle", "maintenance timer stalled");
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let _one_at_a_time = serial().lock().await;
        let nonce: u64 = rand::random();
        let topic = format!("unicast-left-{nonce}-{unicast}");
        let (alice, bob, carol) = trio(&topic, unicast).await;

        ask(&carol.0, |done| {
            Request::Freeze(Duration::from_secs(20), done)
        })
        .await;
        say(&alice.0, "last-words").await;
        merge(&alice.0, serde_json::json!({ "last-key": 1 })).await;
        assert!(
            waits(Duration::from_secs(15), async || {
                has_read(&bob.1, "last-words") && state_has(&bob.0, "last-key").await
            })
            .await,
            "bob never got what alice sent"
        );
        alice.0.leave().await.expect("alice leaves");

        let chat = waits(CATCH_UP, async || has_read(&carol.1, "last-words")).await;
        assert!(chat, "carol never got the chat of the sender that left");
        let state = waits(CATCH_UP, async || state_has(&carol.0, "last-key").await).await;
        assert!(state, "carol never got the state of the sender that left");

        bob.0.leave().await.expect("bob leaves");
        carol.0.leave().await.expect("carol leaves");
    });
}

#[test]
fn a_member_frozen_75_s_catches_up_chat_and_state() {
    frozen_member_catches_up(false);
}

#[test]
fn a_member_frozen_75_s_catches_up_chat_and_state_by_unicast_digests() {
    frozen_member_catches_up(true);
}

#[test]
fn a_sender_that_left_is_repaired_by_the_others() {
    sender_that_left_is_repaired_by_the_others(false);
}

#[test]
fn a_sender_that_left_is_repaired_by_the_others_by_unicast_digests() {
    sender_that_left_is_repaired_by_the_others(true);
}
