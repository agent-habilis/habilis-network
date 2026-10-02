//! Two real habilis-network nodes on a loopback mesh with the default transport policy
//! — the relay is lookup only — must still form a mesh.
//!
//! Loopback has no relay at all, so every path is direct: this proves the
//! probe-then-graft gate never *blocks* a pair that has a direct path. It
//! cannot prove the refusal side (that needs a relay and a NAT); that is the
//! manual `mesh_peer` run in the plan.

#![cfg(feature = "host")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::net::TransportOpts;
use habilis_network::protocol::{LookupOpts, Message, MessageKind, Nickname, PresenceSubtype};
use habilis_network::runtime::{Node, SetupKind, SetupParams, derive_topic_mesh_with, setup_mesh};
use tokio::sync::Notify;

/// The do-nothing application: presence alone forms a mesh.
struct Probe;

#[habilis_network::async_trait]
impl NodeApp for Probe {
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
impl NodeDriver for Probe {
    type Session = ();
    type Http = ();
    type Ipc = serde_json::Value;
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

async fn spawn(topic: &str, nick: &str, sink: Arc<Joined>) -> Node<Probe> {
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
    assert!(
        !mesh.transport().relay_transport,
        "the default policy keeps the relay for lookup only"
    );
    let author = Nickname::new(nick).expect("valid nickname");
    let config = setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic.to_owned(),
        },
        SetupParams {
            author,
            max_peers: 16,
            endpoint: None,
            protocols: Vec::new(),
            transports: TransportOpts::default(),
            runtime_base: None,
            state_file: None,
            sink,
            multihop: false,
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network");
    Node::spawn(config, Probe, None, false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_loopback_nodes_mesh_with_the_relay_lookup_only() {
    let topic = format!("relay-lookup-only-{}", rand::random::<u64>());
    let alice_saw = Arc::new(Joined::default());
    let bob_saw = Arc::new(Joined::default());
    let alice = spawn(&topic, "alice", Arc::clone(&alice_saw)).await;
    let bob = spawn(&topic, "bob", Arc::clone(&bob_saw)).await;

    let deadline = Duration::from_secs(45);
    let bob_nick = Nickname::new("bob").expect("valid");
    let alice_nick = Nickname::new("alice").expect("valid");
    assert!(
        alice_saw.wait_for(&bob_nick, deadline).await,
        "alice never saw bob join: the graft gate held a direct pair"
    );
    assert!(
        bob_saw.wait_for(&alice_nick, deadline).await,
        "bob never saw alice join: the graft gate held a direct pair"
    );

    alice.leave().await.expect("alice leaves");
    bob.leave().await.expect("bob leaves");
}
