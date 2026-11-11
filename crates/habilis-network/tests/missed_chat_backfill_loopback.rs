//! A chat broadcast that a late joiner missed is not delivered to it after the late joiner meets
//! the mesh. Chat has no backfill now: no digest, tick or resend carries it. The late joiner starts
//! only after iroh-gossip's payload cache (30 s) lets go of the frame, so a graft cannot answer from
//! that cache; the frame is stamped `AHEAD` so that it stays surfaceable for the late joiner, which
//! makes the assertion test the engine and not the join horizon.

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
/// The retention of the payload cache of iroh-gossip (`PlumtreeConfig::message_cache_retention`).
const GOSSIP_CACHE_RETENTION: Duration = Duration::from_secs(30);
/// Bounds a slow join: the late joiner must mesh with `early` within this time.
const BUDGET: Duration = Duration::from_secs(15);

/// A frame stamped this far ahead stays surfaceable for the late joiner, so the assertion below
/// reaches the engine. It must exceed the wait before the late joiner starts (31 s) plus the join
/// budget (15 s) plus the 5 s read, which is 51 s: 120 s leaves room. Less than that and the join
/// horizon hides the frame, and the assertion proves nothing.
const AHEAD: Duration = GOSSIP_CACHE_RETENTION.saturating_mul(4);

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
        AppClass::NONE.union(AppClass::PUSH).union(AppClass::VALID)
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

fn pin_backfill_tick() {
    tuning::init(tuning::Tuning::DEFAULTS.backfill_interval(Duration::from_secs(1)));
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
        pin_backfill_tick();
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

        // Cheap insurance: iroh-gossip answers a graft from its payload cache, which keeps a message
        // for `message_cache_retention` (30 s). It was observed once in a failing run log with AHEAD =
        // 30 s (8 Graft messages, then a Gossip message), and not in 5 runs without this wait at
        // AHEAD = 120 s. Wait past the retention so that the cache cannot be the path.
        time::sleep(GOSSIP_CACHE_RETENTION + Duration::from_secs(1)).await;
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
