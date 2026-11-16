//! Two nodes with IP on a Nostr-only mesh find each other over Nostr and link
//! over IP: the IP probe runs first, and no data channel is made.
//!
//! Its own test binary because it installs a global log subscriber to read
//! which path the pair took.

#![cfg(feature = "host")]

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::net::TransportOpts;
use habilis_network::protocol::meshes::{Mesh, NostrChoice};
use habilis_network::protocol::messages::Authored;
use habilis_network::protocol::{LookupOpts, MeshConfig, Nickname, TransportPolicy};
use habilis_network::runtime::{
    EventLoopConfig, Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_config,
    setup_mesh,
};
use habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay;
use url::Url;

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
struct Joined(Mutex<Vec<Nickname>>);

impl NodeSink for Joined {
    fn emit(&self, event: NodeEvent) {
        if let NodeEvent::Presence { message, .. } = event {
            self.0
                .lock()
                .expect("no poison")
                .push(message.author.clone());
        }
    }
}

// each member's sink is shared with the node that writes to it, and the test reads it
async fn spawn(topic: &str, nick: &str, relay: &TestRelay, sink: Arc<Joined>) -> Node<Probe> {
    let urls: Vec<Url> = vec![relay.url()];
    let lookups = LookupOpts::loopback().nostr(NostrChoice::Custom(urls));
    let mesh_config = MeshConfig::new(lookups, None, None, TransportPolicy::default());
    let mesh: Mesh =
        derive_topic_mesh_config(topic, mesh_config).expect("derive a nostr-only mesh");
    let author = Nickname::try_new(nick).expect("valid nickname");
    let transports: TransportOpts = TransportOpts::default()
        .udp(true)
        .relay(false)
        .webrtc(true)
        .gossip(false);
    let params = SetupParams::new(author, sink)
        .max_peers(16)
        .transports(transports);
    let kind = SetupKind::Topic {
        mesh,
        topic_string: topic.to_owned(),
    };
    let config: EventLoopConfig = setup_mesh(kind, params)
        .await
        .expect("setup a nostr-only mesh");
    Node::spawn(config, Probe, None, SignalHandling::Leave)
}

#[test]
fn an_ip_pair_found_over_nostr_links_over_ip_with_no_data_channel() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network=debug");
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let relay = TestRelay::spawn().await.expect("test relay");
        let nonce: u64 = rand::random();
        let topic = format!("nostr-ip-path-{nonce}");
        // each member's sink is shared with the node that writes to it, and the test reads it
        let alice_saw = Arc::new(Joined::default());
        // each member's sink is shared with the node that writes to it, and the test reads it
        let bob_saw = Arc::new(Joined::default());
        let alice = spawn(&topic, "alice", &relay, Arc::clone(&alice_saw)).await;
        let bob = spawn(&topic, "bob", &relay, Arc::clone(&bob_saw)).await;

        let bob_nick = Nickname::try_new("bob").expect("valid");
        let mut linked = false;
        for _ in 0..400 {
            if alice_saw.0.lock().expect("no poison").contains(&bob_nick) {
                linked = true;
                break;
            }
            time::sleep(Duration::from_millis(100)).await;
        }
        alice.leave().await.expect("leave");
        bob.leave().await.expect("leave");
        assert!(linked, "the pair must link");

        let text = habilis_network_test_tracing::captured_logs();
        assert!(
            text.contains("linked over IP, found through nostr"),
            "the IP probe must win:\n{text}"
        );
        assert!(
            !text.contains("webrtc session attached"),
            "no data channel between two IP peers:\n{text}"
        );
    });
}
