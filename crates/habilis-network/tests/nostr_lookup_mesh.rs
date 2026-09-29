//! A mesh whose only lookup is Nostr forms with no iroh relay and no IP: the
//! members find each other over a Nostr relay, exchange the `WebRTC` offer and
//! answer over it, and graft gossip onto the data channel.
//!
//! Run with `cargo test -p habilis-network --test nostr_lookup_mesh`.

#![cfg(feature = "host")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::net::TransportOpts;
use habilis_network::protocol::mesh::NostrChoice;
use habilis_network::protocol::{
    LookupOpts, MeshConfig, Message, MessageKind, Nickname, PresenceSubtype, TransportPolicy,
};
use habilis_network::runtime::{Node, SetupKind, SetupParams, derive_topic_mesh_config, setup_mesh};
use habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay;
use tokio::sync::Notify;

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
    async fn wait_for(&self, nick: &str, deadline: Duration) -> bool {
        let nick = Nickname::new(nick).expect("valid nickname");
        let seen = || self.peers.lock().expect("no poison").contains(&nick);
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

/// A node on a Nostr-only mesh. `ip` off leaves the data channel as its only
/// path; the relay transport is always off, and there is no relay lookup.
async fn spawn(
    topic: &str,
    nick: &str,
    relay: &TestRelay,
    ip: bool,
    sink: Arc<Joined>,
) -> Node<Probe> {
    spawn_on(topic, nick, &[relay], ip, sink).await
}

async fn spawn_on(
    topic: &str,
    nick: &str,
    relays: &[&TestRelay],
    ip: bool,
    sink: Arc<Joined>,
) -> Node<Probe> {
    let mesh = derive_topic_mesh_config(
        topic,
        MeshConfig {
            lookups: LookupOpts {
                nostr: NostrChoice::Custom(relays.iter().map(|relay| relay.url()).collect()),
                ..LookupOpts::loopback()
            },
            password: None,
            issuer_pubkey: None,
            transport: TransportPolicy::default(),
        },
    )
    .expect("derive a nostr-only mesh");
    let config = setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic.to_owned(),
        },
        SetupParams {
            author: Nickname::new(nick).expect("valid nickname"),
            max_peers: 16,
            endpoint: None,
            protocols: Vec::new(),
            transports: TransportOpts {
                udp: ip,
                relay: false,
                webrtc: true,
                multihop: false,
            },
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
    .expect("setup a nostr-only mesh");
    Node::spawn(config, Probe, None, false)
}

const DEADLINE: Duration = Duration::from_secs(40);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_webrtc_only_nodes_mesh_over_nostr_alone() {
    let relay = TestRelay::spawn().await.expect("test relay");
    let topic = format!("nostr-pair-{}", rand::random::<u64>());
    let alice_saw = Arc::new(Joined::default());
    let bob_saw = Arc::new(Joined::default());
    let alice = spawn(&topic, "alice", &relay, false, Arc::clone(&alice_saw)).await;
    let bob = spawn(&topic, "bob", &relay, false, Arc::clone(&bob_saw)).await;

    let linked =
        alice_saw.wait_for("bob", DEADLINE).await && bob_saw.wait_for("alice", DEADLINE).await;
    alice.leave().await.expect("alice leaves");
    bob.leave().await.expect("bob leaves");
    assert!(
        linked,
        "two nodes with only Nostr, no IP and no relay, must mesh"
    );
}

/// A third member joins a formed mesh, whose members hold one relay each by
/// then, and links with no beacon to find.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_third_member_joins_a_formed_nostr_mesh() {
    let relay = TestRelay::spawn().await.expect("test relay");
    let topic = format!("nostr-trio-{}", rand::random::<u64>());
    let alice_saw = Arc::new(Joined::default());
    let bob_saw = Arc::new(Joined::default());
    let carol_saw = Arc::new(Joined::default());
    let alice = spawn(&topic, "alice", &relay, false, Arc::clone(&alice_saw)).await;
    let bob = spawn(&topic, "bob", &relay, false, Arc::clone(&bob_saw)).await;
    assert!(
        alice_saw.wait_for("bob", DEADLINE).await,
        "the pair forms first"
    );

    let carol = spawn(&topic, "carol", &relay, false, Arc::clone(&carol_saw)).await;
    let joined =
        carol_saw.wait_for("alice", DEADLINE).await || carol_saw.wait_for("bob", DEADLINE).await;
    for node in [alice, bob, carol] {
        node.leave().await.expect("leave");
    }
    assert!(joined, "the third member links into the formed mesh");
}

/// Two nodes with IP find each other over Nostr and link on the IP path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_ip_nodes_mesh_over_nostr_by_ip() {
    let relay = TestRelay::spawn().await.expect("test relay");
    let topic = format!("nostr-ip-{}", rand::random::<u64>());
    let alice_saw = Arc::new(Joined::default());
    let bob_saw = Arc::new(Joined::default());
    let alice = spawn(&topic, "alice", &relay, true, Arc::clone(&alice_saw)).await;
    let bob = spawn(&topic, "bob", &relay, true, Arc::clone(&bob_saw)).await;

    let linked =
        alice_saw.wait_for("bob", DEADLINE).await && bob_saw.wait_for("alice", DEADLINE).await;
    alice.leave().await.expect("alice leaves");
    bob.leave().await.expect("bob leaves");
    assert!(linked, "two IP nodes with only Nostr must mesh");
}

/// While unlinked a node holds 3 relays; once linked and settled (10 s), 1.
/// Every member ranks the relays alike, so the linked pair shares that one
/// socket, and holds it: the check is that it stays at one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_linked_pair_holds_one_relay_socket() {
    let relays = [
        TestRelay::spawn().await.expect("test relay"),
        TestRelay::spawn().await.expect("test relay"),
        TestRelay::spawn().await.expect("test relay"),
    ];
    let refs: Vec<&TestRelay> = relays.iter().collect();
    let topic = format!("nostr-width-{}", rand::random::<u64>());
    let alice_saw = Arc::new(Joined::default());
    let bob_saw = Arc::new(Joined::default());
    let alice = spawn_on(&topic, "alice", &refs, false, Arc::clone(&alice_saw)).await;
    let bob = spawn_on(&topic, "bob", &refs, false, Arc::clone(&bob_saw)).await;
    let open = || relays.iter().map(TestRelay::connections).sum::<usize>();
    assert!(alice_saw.wait_for("bob", DEADLINE).await, "the pair forms");

    let mut narrowed = false;
    for _ in 0..400 {
        if open() == 1 {
            narrowed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Steady, not a passing moment of reconnect churn.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let seen = open();
    narrowed &= seen == 1;
    alice.leave().await.expect("leave");
    bob.leave().await.expect("leave");
    assert!(narrowed, "a linked pair holds one relay socket, not {seen}");
}
