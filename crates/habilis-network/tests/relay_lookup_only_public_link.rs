//! Two peers on a **public** lookup-only mesh — a relay-homed rendezvous,
//! probe-before-claim beacon arbitration, the accept gate on every link —
//! must still mesh. The loopback twin cannot cover this: a loopback mesh
//! has no relay, no beacon claim race, and direct addresses known up front.
//!
//! The webrtc-lane variant is `#[ignore]`d: it needs a real JSEP round and
//! rides the beacon's shed cadence, which makes it timing-sensitive under a
//! parallel suite. Run it solo; the mesh e2e suite exercises the same path
//! against a real browser.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use habilis_network::protocol::message::Authored;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::iroh::RelayUrl;
use habilis_network::net::TransportOpts;
use habilis_network::protocol::{LookupOpts, MeshConfig, Nickname, RelayChoice, TransportPolicy};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_config, setup_mesh,
};
use tokio::sync::Notify;

use habilis_network::net::test_relay;
struct Probe;

#[habilis_network::async_trait]
impl NodeApp for Probe {
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
impl NodeDriver for Probe {
    type Session = ();
    type Http = ();
    type Ipc = serde_json::Value;
}

#[derive(Default)]
struct Joined {
    peers: Mutex<Vec<Nickname>>,
    changed: Notify,
}

impl NodeSink for Joined {
    fn emit(&self, event: NodeEvent) {
        if let NodeEvent::Presence { message, .. } = event {
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

async fn wait_for_log(needle: &str, deadline: Duration) -> bool {
    let started = std::time::Instant::now();
    loop {
        if habilis_network_test_tracing::captured_logs().contains(needle) {
            return true;
        }
        if started.elapsed() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn dump_log_tail() {
    let logs = habilis_network_test_tracing::captured_logs();
    let tail: Vec<&str> = logs.lines().rev().take(60).collect();
    eprintln!("--- engine log tail ---");
    for line in tail.into_iter().rev() {
        eprintln!("{line}");
    }
}

async fn spawn_with(
    topic: &str,
    nick: &str,
    relay: &RelayUrl,
    // each member's sink is shared with the node that writes to it, and the test reads it
    sink: Arc<Joined>,
    transports: TransportOpts,
) -> Node<Probe> {
    let mesh = derive_topic_mesh_config(
        topic,
        MeshConfig::new(
            LookupOpts::new(RelayChoice::Custom(vec![relay.clone()])),
            None,
            None,
            TransportPolicy::default().relay_transport(false),
        ),
    )
    .expect("derive");
    let author = Nickname::try_new(nick).expect("valid nickname");
    let topic_string = topic.to_owned();
    let config = setup_mesh(
        SetupKind::Topic { mesh, topic_string },
        SetupParams::new(author, sink)
            .max_peers(16)
            .transports(transports),
    )
    .await
    .expect("setup_mesh");
    Node::spawn(config, Probe, None, SignalHandling::Leave)
}

#[test]
fn two_ip_peers_link_through_the_gated_rendezvous() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network=info");
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let topic = format!("scratch-link-{}", rand::random::<u64>());
        // each member's sink is shared with the node that writes to it, and the test reads it
        let alice_saw = Arc::new(Joined::default());
        // each member's sink is shared with the node that writes to it, and the test reads it
        let bob_saw = Arc::new(Joined::default());
        let ip_only: TransportOpts = TransportOpts::default()
            .udp(true)
            .relay(true)
            .webrtc(false)
            .gossip(false);
        let alice = spawn_with(&topic, "alice", &relay, Arc::clone(&alice_saw), ip_only).await;
        assert!(
            wait_for_log("beacon role active", Duration::from_mins(1)).await,
            "alice never claimed the beacon; nothing for bob to find"
        );
        let bob = spawn_with(&topic, "bob", &relay, Arc::clone(&bob_saw), ip_only).await;

        let deadline = Duration::from_secs(75);
        let alice_nick = Nickname::try_new("alice").expect("valid");
        let bob_nick = Nickname::try_new("bob").expect("valid");
        let alice_ok = alice_saw.wait_for(&bob_nick, deadline).await;
        let bob_ok = bob_saw.wait_for(&alice_nick, deadline).await;
        let _ = alice.leave().await;
        let _ = bob.leave().await;
        if !(alice_ok && bob_ok) {
            dump_log_tail();
        }
        assert!(
            alice_ok && bob_ok,
            "two IP peers must link through the gated rendezvous (alice saw bob: {alice_ok}, bob saw alice: {bob_ok})"
        );
    });
}

/// The browser-shaped case, natively: a peer with no IP transports must
/// still link — its rendezvous link rides the beacon's `WebRTC` lane.
#[ignore = "timing-sensitive: a JSEP round per beacon shed; run solo with --ignored"]
#[test]
fn a_webrtc_only_peer_links_through_the_beacon_lane() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network=info");
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let topic = format!("scratch-lane-{}", rand::random::<u64>());
        // each member's sink is shared with the node that writes to it, and the test reads it
        let alice_saw = Arc::new(Joined::default());
        // each member's sink is shared with the node that writes to it, and the test reads it
        let bob_saw = Arc::new(Joined::default());
        let alice_transports: TransportOpts = TransportOpts::default()
            .udp(true)
            .relay(true)
            .webrtc(true)
            .gossip(false);
        let alice = spawn_with(
            &topic,
            "alice",
            &relay,
            Arc::clone(&alice_saw),
            alice_transports,
        )
        .await;
        // Stagger like a real join: the first node claims the beacon, the second
        // finds it held. Simultaneous starts race both into the claim and leave
        // two same-id rendezvous copies shedding each other for the whole test.
        tokio::time::sleep(Duration::from_secs(10)).await;
        let bob_transports: TransportOpts = TransportOpts::default()
            .udp(false)
            .relay(true)
            .webrtc(true)
            .gossip(false);
        let bob = spawn_with(&topic, "bob", &relay, Arc::clone(&bob_saw), bob_transports).await;

        let deadline = Duration::from_secs(75);
        let alice_nick = Nickname::try_new("alice").expect("valid");
        let bob_nick = Nickname::try_new("bob").expect("valid");
        let alice_ok = alice_saw.wait_for(&bob_nick, deadline).await;
        let bob_ok = bob_saw.wait_for(&alice_nick, deadline).await;
        let _ = alice.leave().await;
        let _ = bob.leave().await;
        assert!(
            alice_ok && bob_ok,
            "a webrtc-only peer must link through the beacon lane (alice saw bob: {alice_ok}, bob saw alice: {bob_ok})"
        );
    });
}
