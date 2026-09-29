//! A node gets the chat it missed before its first real-peer link within one
//! round trip of that link, not on its next anti-entropy tick.
//!
//! Every node has a window from its join to its first real-peer link in which
//! a broadcast cannot reach it; the mesh creator's own rendezvous leaves it
//! alone for up to one reclaim tick. The state channels ask again on that link.
//! This pins the tick away so only the chat log's own ask can deliver.

#![cfg(feature = "host")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fofoca::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use fofoca::net::TransportOpts;
use fofoca::protocol::{
    AppFrameParams, AppTag, LookupOpts, Message, MessageBody, MessageId, MessageKind, Nickname,
    PresenceSubtype,
};
use fofoca::runtime::{Node, SetupKind, SetupParams, derive_topic_mesh_with, setup_mesh};
use tokio::sync::{Notify, oneshot};

/// Bounds a slow join only: with the tick pinned away, nothing but the ask on
/// the first link can deliver.
const BUDGET: Duration = Duration::from_secs(15);

/// A frame stamped this far ahead stays inside a node's window even when the
/// node joins after it was sent, so the only way to get it is to ask.
const AHEAD_SECS: i64 = 30;

/// Logs every chat frame and records the surfaceable ones it receives.
#[derive(Clone, Default)]
struct Chat {
    received: Arc<Mutex<Vec<MessageId>>>,
    changed: Arc<Notify>,
}

#[fofoca::async_trait]
impl NodeApp for Chat {
    fn classify(&self, _message: &Message) -> AppClass {
        AppClass {
            loggable: true,
            beat: false,
            valid: true,
            chained: false,
            sealed: false,
        }
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

#[fofoca::async_trait]
impl NodeDriver for Chat {
    type Session = oneshot::Sender<MessageId>;
    type Http = ();
    type Ipc = serde_json::Value;

    /// Broadcast one chat frame stamped [`AHEAD_SECS`] ahead.
    async fn handle_session(
        &mut self,
        sent: Self::Session,
        state: &mut EventLoopState,
        ctx: &HandlerCtx<'_>,
    ) -> bool {
        let mut frame = Message::new_app(
            ctx.mesh,
            ctx.author,
            AppFrameParams {
                tag: AppTag::from("chat"),
                to: None,
                corr: None,
                body: MessageBody::new("\"hello\"").expect("a JSON body"),
            },
        );
        frame.timestamp += AHEAD_SECS;
        let frame = frame.signed(ctx.identity);
        let bytes = bytes::Bytes::from(frame.serialize().expect("serialize"));
        fofoca::ops::deliver(&frame, bytes, state, ctx.sender)
            .await
            .expect("a meshed node broadcasts");
        // The sender keeps its own frame, as a chat app does, so any peer late
        // meets first can answer it.
        let _ = state.message_log_mut().push(frame.clone());
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
        tokio::time::timeout(deadline, wait).await.is_ok() || seen()
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

fn pin_antientropy_tick() {
    fofoca::runtime::tuning::init(fofoca::runtime::tuning::Tuning {
        antientropy_interval_secs: 3600,
        ..fofoca::runtime::tuning::Tuning::DEFAULTS
    });
}

fn nick(name: &str) -> Nickname {
    Nickname::new(name).expect("valid nickname")
}

async fn spawn(topic: &str, name: &str) -> (Node<Chat>, Chat, Arc<Joined>) {
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
            multihop: false,
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network");
    let chat = Chat::default();
    (Node::spawn(config, chat.clone(), None, false), chat, sink)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_gets_the_chat_it_missed_on_its_first_real_peer_link() {
    pin_antientropy_tick();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let topic = format!("missed-chat-{}", rand::random::<u64>());
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

    let started = tokio::time::Instant::now();
    let (late, late_chat, late_saw) = spawn(&topic, "late").await;
    assert!(
        late_saw.wait_for(&nick("early"), BUDGET).await,
        "late never met the mesh"
    );
    let got = late_chat.wait_for(&sent, BUDGET).await;
    eprintln!(
        "late got the missed frame: {got} after {:?}",
        started.elapsed()
    );
    assert!(got, "late never got the frame it missed");

    alice.leave().await.expect("alice leaves");
    early.leave().await.expect("early leaves");
    late.leave().await.expect("late leaves");
}
