//! A chat broadcast that a late joiner missed is not delivered to it after the late joiner meets
//! the mesh. Chat has no backfill now: no digest, tick or resend carries it. The tick runs at one
//! second, so a tick-driven chat resend would have time to act, and the test waits five ticks
//! before it asserts that the frame did not arrive.

#![cfg(feature = "host")]

use habilis_network::protocol::messages::Authored;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::protocol::{
    AppFrameParams, AppTag, LookupOpts, Message, MessageBody, MessageId, MessageKind, Nickname,
    PresenceSubtype,
};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use tokio::sync::{Notify, oneshot};

use habilis_network::ops;
use habilis_network::runtime::tuning;
use tokio::time::{self, Instant};
/// Bounds a slow join only: with the tick pinned away, nothing but the ask on
/// the first link can deliver.
const BUDGET: Duration = Duration::from_secs(15);

/// A frame stamped this far ahead stays inside a node's window even when the
/// node joins after it was sent, so the only way to get it is to ask.
const AHEAD: Duration = Duration::from_secs(30);

/// Logs every chat frame and records the surfaceable ones it receives.
#[derive(Clone, Default)]
struct Chat {
    // the chat shares the received list with the test, which reads it
    received: Arc<Mutex<Vec<MessageId>>>,
    // the chat and the test share the notify that wakes the reader
    changed: Arc<Notify>,
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
        if frame.surfaceable {
            self.received
                .lock()
                .expect("no poison")
                .push(frame.message.id.clone());
            self.changed.notify_waiters();
        }
        true
    }
}

#[habilis_network::async_trait]
impl NodeDriver for Chat {
    type Session = oneshot::Sender<MessageId>;
    type Http = ();
    type Ipc = serde_json::Value;

    /// Broadcast one chat frame stamped [`AHEAD`] ahead.
    async fn handle_session(
        &mut self,
        sent: Self::Session,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        let mut frame = Message::new_app(
            context.mesh,
            context.author,
            AppFrameParams::new(
                AppTag::try_new("chat").expect("a valid app tag"),
                None,
                None,
                MessageBody::try_new("\"hello\"").expect("a JSON body"),
            ),
        );
        frame.timestamp = frame.timestamp + AHEAD;
        let frame = frame.sign(context.identity);
        let bytes = frame.serialize().expect("serialize");
        let _ = ops::deliver(&frame, bytes.clone(), state, context.sender)
            .await
            .expect("a meshed node broadcasts");
        let _ = sent.send(frame.id.clone());
        false
    }
}

impl Chat {
    async fn wait_for(&self, id: &MessageId, deadline: Duration) -> bool {
        let seen = || self.received.lock().expect("no poison").contains(id);
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

fn pin_antientropy_tick() {
    tuning::init(tuning::Tuning::DEFAULTS.antientropy_interval(Duration::from_secs(1)));
}

fn nick(name: &str) -> Nickname {
    Nickname::try_new(name).expect("valid nickname")
}

// each member's sink is shared with the node that writes to it, and the test reads it
async fn spawn(topic: &str, name: &str) -> (Node<Chat>, Chat, Arc<Joined>) {
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
    let chat = Chat::default();
    (
        Node::spawn(config, chat.clone(), None, SignalHandling::Leave),
        chat,
        sink,
    )
}

#[test]
fn a_chat_broadcast_missed_by_a_late_joiner_is_not_delivered() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        pin_antientropy_tick();
        let nonce: u64 = rand::random();
        let topic = format!("missed-chat-{nonce}");

        let (alice, _, alice_saw) = spawn(&topic, "alice").await;
        let (early, early_chat, _) = spawn(&topic, "early").await;
        assert!(
            alice_saw.wait_for(&nick("early"), BUDGET).await,
            "alice and early never meshed"
        );

        let (sent_tx, sent_rx) = oneshot::channel();
        alice
            .send(sent_tx)
            .await
            .expect("the send reaches the loop");
        let sent = sent_rx.await.expect("alice broadcast the frame");
        assert!(
            early_chat.wait_for(&sent, BUDGET).await,
            "early never got the frame, so it cannot hold it for late"
        );

        let started = Instant::now();
        let (late, late_chat, late_saw) = spawn(&topic, "late").await;
        assert!(
            late_saw.wait_for(&nick("early"), BUDGET).await,
            "late never met the mesh"
        );
        let got = late_chat.wait_for(&sent, Duration::from_secs(5)).await;
        eprintln!(
            "late got the missed frame: {got} after {:?}",
            started.elapsed()
        );
        assert!(
            !got,
            "late got a chat frame it missed: chat is no longer backfilled"
        );

        alice.leave().await.expect("alice leaves");
        early.leave().await.expect("early leaves");
        late.leave().await.expect("late leaves");
    });
}
