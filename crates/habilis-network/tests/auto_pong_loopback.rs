//! Two real habilis-network nodes linked only by gossip must each answer the other's
//! ping.
//!
//! The auto-pong goes out over a warm unicast connection or not at all, so a
//! receive arm never dials inline. Only the side that grafted through the
//! direct-path probe holds such a connection; the side that accepted the link
//! never dialed, and its pongs were skipped until something else warmed the
//! pool. Pinging in both directions covers whichever side accepted.

#![cfg(feature = "host")]

use habilis_network::protocol::message::Authored;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::protocol::{LookupOpts, MessageKind, Nickname, PresenceSubtype};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use tokio::sync::{Notify, oneshot};

type Rtts = Vec<(Nickname, u64)>;

/// The last lines of the log, for the message of a failed assertion. The log is
/// also written to the file that `HABILIS_TEST_LOG_DUMP` names, if set.
fn trace() -> String {
    let log = habilis_network_test_tracing::captured_logs();
    if let Ok(path) = std::env::var("HABILIS_TEST_LOG_DUMP") {
        let _ = std::fs::write(path, &log);
    }
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(200)..].join("\n")
}

/// Presence alone forms the mesh; a session request runs one ping round.
struct Pinger;

#[habilis_network::async_trait]
impl NodeApp for Pinger {
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
impl NodeDriver for Pinger {
    type Session = oneshot::Sender<Rtts>;
    type Http = ();
    type Ipc = serde_json::Value;

    async fn handle_session(
        &mut self,
        response: Self::Session,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        habilis_network::ops::start_ping_round(state, context, Some(response)).await;
        true
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
        tokio::time::timeout(deadline, wait).await.is_ok() || seen()
    }
}

// each member's sink is shared with the node that writes to it, and the test reads it
async fn spawn(topic: &str, nick: &str, sink: Arc<Joined>) -> Node<Pinger> {
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
    let author = Nickname::try_new(nick).expect("valid nickname");
    let config = setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic.to_owned(),
        },
        SetupParams::new(author, sink).max_peers(16),
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network");
    Node::spawn(config, Pinger, None, SignalHandling::Leave)
}

async fn ping(node: &Node<Pinger>) -> Rtts {
    let (tx, rx) = oneshot::channel();
    node.send(tx)
        .await
        .expect("the ping request reaches the loop");
    rx.await.expect("the round is finalized")
}

#[test]
fn each_peer_linked_only_by_gossip_answers_the_others_ping() {
    let guard = habilis_network_test_tracing::init_capturing(
        "habilis_network=info,habilis_network::transport=debug",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let topic = format!("auto-pong-{}", rand::random::<u64>());
        // each member's sink is shared with the node that writes to it, and the test reads it
        let alice_saw = Arc::new(Joined::default());
        // each member's sink is shared with the node that writes to it, and the test reads it
        let bob_saw = Arc::new(Joined::default());

        let alice = spawn(&topic, "alice", Arc::clone(&alice_saw)).await;
        let bob = spawn(&topic, "bob", Arc::clone(&bob_saw)).await;

        let deadline = Duration::from_secs(45);
        let alice_nick = Nickname::try_new("alice").expect("valid");
        let bob_nick = Nickname::try_new("bob").expect("valid");
        assert!(
            alice_saw.wait_for(&bob_nick, deadline).await,
            "alice never saw bob join\n{}",
            trace()
        );
        assert!(
            bob_saw.wait_for(&alice_nick, deadline).await,
            "bob never saw alice join\n{}",
            trace()
        );

        let (alice_rtts, bob_rtts) = tokio::join!(ping(&alice), ping(&bob));
        let answered = |rtts: &Rtts, nick: &Nickname| rtts.iter().any(|(peer, _)| peer == nick);
        assert!(
            answered(&alice_rtts, &bob_nick),
            "bob never answered alice's ping: {alice_rtts:?}\n{}",
            trace()
        );
        assert!(
            answered(&bob_rtts, &alice_nick),
            "alice never answered bob's ping: {bob_rtts:?}\n{}",
            trace()
        );

        alice.leave().await.expect("alice leaves");
        bob.leave().await.expect("bob leaves");
    });
}

/// A probe sent while no link exists reaches nobody, so the first probe of a round is lost. The
/// second one, sent at the middle of the window, meets a linked peer, and the round holds it.
#[test]
fn a_ping_sent_before_any_link_exists_is_answered_after_the_second_probe() {
    let guard = habilis_network_test_tracing::init_capturing(
        "habilis_network=info,habilis_network::transport=debug",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let topic = format!("auto-pong-early-{}", rand::random::<u64>());

        // each member's sink is shared with the node that writes to it, and the test reads it
        let alice = spawn(&topic, "alice", Arc::new(Joined::default())).await;
        // each member's sink is shared with the node that writes to it, and the test reads it
        let bob = spawn(&topic, "bob", Arc::new(Joined::default())).await;
        let bob_nick = Nickname::try_new("bob").expect("valid");

        // No wait for `joined`: the round starts before the pair is linked.
        let rtts = ping(&alice).await;

        assert!(
            rtts.iter().any(|(peer, _)| *peer == bob_nick),
            "bob never answered alice's early ping: {rtts:?}\n{}",
            trace()
        );
        alice.leave().await.expect("alice leaves");
        bob.leave().await.expect("bob leaves");
    });
}
