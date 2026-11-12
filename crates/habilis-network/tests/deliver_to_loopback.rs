//! A frame that a node signed reaches one member by `deliver_to`, and no other member receives it.
//!
//! Alice splits a body into 2 shards. She broadcasts shard 0, so Bob and Carol hold the first half. Bob
//! misses shard 1: Alice never sends it to the mesh. She then repairs it for Bob alone with `deliver_to`.
//! Bob completes the group and surfaces the message once. Carol never gets shard 1, so she never completes
//! the group and surfaces nothing. A repair by `deliver` would flood shard 1, and Carol would surface the
//! message too.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::ops::{deliver_to, send_app};
use habilis_network::protocol::messages::Authored;
use habilis_network::protocol::{
    AppFrameParams, AppTag, AuthorKey, LookupOpts, Message, MessageBody, MessageKind, Nickname,
    PresenceSubtype, Shard, ShardGroup, Verified,
};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use tokio::sync::{Notify, oneshot};
use tokio::time::{self, Instant};

/// How long Bob has to complete the group after the repair.
const REPAIR_BOUND: Duration = Duration::from_secs(20);

/// How long the test waits after Bob completes the group, for a copy that a flood would deliver late.
const FLOOD_WAIT: Duration = Duration::from_secs(5);

const GROUP: &str = "550e8400-e29b-41d4-a716-446655440000";

enum Request {
    Key(oneshot::Sender<AuthorKey>),
    /// Broadcast shard 0, then repair shard 1 for the member with this key alone.
    SplitSend(AuthorKey, oneshot::Sender<()>),
}

/// Records the body of each message that the engine surfaces to the app, after the reassembly.
struct Recorder {
    // The node's loop writes it, and the test reads it.
    received: Arc<Mutex<Vec<String>>>,
}

#[habilis_network::async_trait]
impl NodeApp for Recorder {
    fn classify(&self, _message: &Authored) -> AppClass {
        AppClass::BEAT.union(AppClass::VALID)
    }

    async fn on_app_frame(
        &mut self,
        frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        _ctx: &HandlerCtx<'_>,
    ) -> bool {
        self.received
            .lock()
            .expect("no poison")
            .push(frame.message.body.to_string());
        false
    }
}

fn shard_frame(context: &HandlerCtx<'_>, index: u32, text: &str) -> Verified {
    let group = ShardGroup::parse_uuid(GROUP).expect("a valid group");
    Message::new_app(
        context.mesh,
        context.author,
        AppFrameParams::new(
            AppTag::try_new("app_msg").expect("a valid app tag"),
            None,
            None,
            MessageBody::from(text),
        ),
    )
    .shard(Some(Shard::new(group, 2).index(index)))
    .sign(context.identity)
}

#[habilis_network::async_trait]
impl NodeDriver for Recorder {
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
            Request::Key(response) => {
                let _ = response.send(state.identity().author_key());
                false
            }
            Request::SplitSend(requester, done) => {
                let _flood = send_app(state, context, shard_frame(context, 0, "first half, "))
                    .await
                    .expect("shard 0 is broadcast");
                let second = shard_frame(context, 1, "second half");
                let bytes = second.serialize().expect("a shard serializes");
                // The verdict of the repair is Bob's surfacing, which the test reads.
                let _repair = deliver_to(&requester, &second, bytes, state)
                    .await
                    .expect("shard 1 is repaired for the requester");
                let _ = done.send(());
                true
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

/// A member, the sink that it emits into, and the bodies that it surfaced.
struct Member {
    node: Node<Recorder>,
    // The node emits into the sink, and the test reads it.
    saw: Arc<Joined>,
    // The node's app writes the bodies, and the test reads them.
    received: Arc<Mutex<Vec<String>>>,
}

impl Member {
    async fn spawn(topic: &str, name: &str) -> Self {
        // Shared with the node that emits into it, and read by the test.
        let saw = Arc::new(Joined::default());
        // Shared with the app of the node, and read by the test.
        let received = Arc::new(Mutex::new(Vec::new()));
        let mesh =
            derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
        let config = setup_mesh(
            SetupKind::Topic {
                mesh,
                topic_string: topic.to_owned(),
            },
            SetupParams::new(nick(name), Arc::clone(&saw)).max_peers(16),
        )
        .await
        .expect("setup_mesh on a loopback mesh must not touch the network");
        let app = Recorder {
            received: Arc::clone(&received),
        };
        Self {
            node: Node::spawn(config, app, None, SignalHandling::Leave),
            saw,
            received,
        }
    }

    async fn key(&self) -> AuthorKey {
        let (tx, rx) = oneshot::channel();
        self.node
            .send(Request::Key(tx))
            .await
            .expect("the key request reaches the loop");
        rx.await.expect("the loop answers")
    }

    fn surfaced(&self) -> Vec<String> {
        self.received.lock().expect("no poison").clone()
    }
}

/// The count of surfaced messages once it is at least `want`, or when the bound runs out.
async fn surfaced_within(member: &Member, want: usize, bound: Duration) -> usize {
    let started = Instant::now();
    loop {
        let count = member.surfaced().len();
        if count >= want || started.elapsed() > bound {
            return count;
        }
        time::sleep(Duration::from_millis(100)).await;
    }
}

#[test]
fn a_repaired_shard_reaches_the_requester_alone() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let nonce: u64 = rand::random();
        let topic = format!("deliver-to-{nonce}");

        let alice = Member::spawn(&topic, "alice").await;
        let bob = Member::spawn(&topic, "bob").await;
        let carol = Member::spawn(&topic, "carol").await;
        for (member, name) in [(&bob, "bob"), (&carol, "carol")] {
            assert!(
                member
                    .saw
                    .wait_for(&nick("alice"), Duration::from_secs(45))
                    .await,
                "{name} never saw alice join"
            );
        }
        assert!(
            alice
                .saw
                .wait_for(&nick("bob"), Duration::from_secs(45))
                .await,
            "alice never saw bob join"
        );

        let (done_tx, done_rx) = oneshot::channel();
        alice
            .node
            .send(Request::SplitSend(bob.key().await, done_tx))
            .await
            .expect("the split send reaches the loop");
        done_rx.await.expect("alice sends both shards");

        let at_bob = surfaced_within(&bob, 1, REPAIR_BOUND).await;
        assert_eq!(
            at_bob, 1,
            "bob surfaces the repaired message within the bound"
        );
        time::sleep(FLOOD_WAIT).await;

        assert_eq!(
            bob.surfaced(),
            ["first half, second half"],
            "bob surfaces the whole body once, and a late copy adds none"
        );
        assert!(
            carol.surfaced().is_empty(),
            "carol never gets shard 1, so she surfaces nothing: {:?}",
            carol.surfaced()
        );

        alice.node.leave().await.expect("alice leaves");
        bob.node.leave().await.expect("bob leaves");
        carol.node.leave().await.expect("carol leaves");
    });
}
