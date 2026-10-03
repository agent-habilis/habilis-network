//! Two nodes with IP on a Nostr-only mesh find each other over Nostr and link
//! over IP: the IP probe runs first, and no data channel is made.
//!
//! Its own test binary because it installs a global log subscriber to read
//! which path the pair took.

#![cfg(feature = "host")]

use std::io::Write;
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
use habilis_network_nostr::test_relay::TestRelay;

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

#[derive(Default)]
struct Joined(Mutex<Vec<Nickname>>);

impl NodeSink for Joined {
    fn emit(&self, event: NodeEvent) {
        if let NodeEvent::Presence { msg } = event
            && let MessageKind::Presence {
                subtype: PresenceSubtype::Joined,
            } = msg.kind
        {
            self.0.lock().expect("no poison").push(msg.author.clone());
        }
    }
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("no poison").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn spawn(topic: &str, nick: &str, relay: &TestRelay, sink: Arc<Joined>) -> Node<Probe> {
    let mesh = derive_topic_mesh_config(
        topic,
        MeshConfig {
            lookups: LookupOpts {
                nostr: NostrChoice::Custom(vec![relay.url()]),
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
                udp: true,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ip_pair_found_over_nostr_links_over_ip_with_no_data_channel() {
    let logs = Captured::default();
    let writer = logs.clone();
    tracing_subscriber::fmt()
        .with_env_filter("habilis_network=debug")
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .init();

    let relay = TestRelay::spawn().await.expect("test relay");
    let topic = format!("nostr-ip-path-{}", rand::random::<u64>());
    let alice_saw = Arc::new(Joined::default());
    let bob_saw = Arc::new(Joined::default());
    let alice = spawn(&topic, "alice", &relay, Arc::clone(&alice_saw)).await;
    let bob = spawn(&topic, "bob", &relay, Arc::clone(&bob_saw)).await;

    let bob_nick = Nickname::new("bob").expect("valid");
    let mut linked = false;
    for _ in 0..400 {
        if alice_saw.0.lock().expect("no poison").contains(&bob_nick) {
            linked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    alice.leave().await.expect("leave");
    bob.leave().await.expect("leave");
    assert!(linked, "the pair must link");

    let text = String::from_utf8_lossy(&logs.0.lock().expect("no poison")).into_owned();
    assert!(
        text.contains("linked over IP, found through nostr"),
        "the IP probe must win:\n{text}"
    );
    assert!(
        !text.contains("webrtc session attached"),
        "no data channel between two IP peers:\n{text}"
    );
}
