//! The refusal side of the relay transport policy, on a real relay.
//!
//! Two nodes whose only path is a local iroh relay — IP transports cleared,
//! `WebRTC` off — never link on a mesh whose relay is lookup only: the
//! beacon's accept gate holds each inbound gossip connection until iroh
//! selects a direct path, and here none can ever be selected. The same two
//! nodes on a mesh that lets the relay carry payload link within seconds,
//! which is what proves the first run failed for the right reason.
//!
//! Run with `cargo test -p habilis-network --features iroh-test-utils --test
//! relay_lookup_only_refusal`.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::iroh::RelayUrl;
use habilis_network::net::TransportOpts;
use habilis_network::protocol::{
    LookupOpts, MeshConfig, Message, MessageKind, Nickname, PresenceSubtype, RelayChoice,
    TransportPolicy,
};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, derive_topic_mesh_config, setup_mesh,
};
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

/// A node that can reach the other only through `relay`: no IP transports,
/// no `WebRTC`, no mDNS or DHT.
async fn spawn(
    topic: &str,
    nick: &str,
    relay: &RelayUrl,
    relay_transport: bool,
    sink: Arc<Joined>,
) -> Node<Probe> {
    let mesh = derive_topic_mesh_config(
        topic,
        MeshConfig {
            lookups: LookupOpts {
                mdns: false,
                dht: false,
                relay_lookup: RelayChoice::Custom(vec![relay.clone()]),
            },
            password: None,
            issuer_pubkey: None,
            transport: TransportPolicy {
                relay_transport,
                ..TransportPolicy::default()
            },
        },
    )
    .expect("derive a relay-only mesh");
    let author = Nickname::new(nick).expect("valid nickname");
    let config = setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic.to_owned(),
        },
        SetupParams {
            author,
            max_peers: 16,
            max_sessions: 0,
            endpoint: None,
            protocols: Vec::new(),
            transports: TransportOpts {
                udp: false,
                relay: true,
                webrtc: false,
            },
            runtime_base: None,
            state_file: None,
            sink,
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await
    .expect("setup_mesh against a local relay");
    Node::spawn(config, Probe, None, false)
}

/// Whether two relay-only nodes see each other join within `deadline`.
async fn pair_links(relay: &RelayUrl, relay_transport: bool, deadline: Duration) -> bool {
    let topic = format!("relay-refusal-{relay_transport}-{}", rand::random::<u64>());
    let alice_saw = Arc::new(Joined::default());
    let bob_saw = Arc::new(Joined::default());
    let alice = spawn(
        &topic,
        "alice",
        relay,
        relay_transport,
        Arc::clone(&alice_saw),
    )
    .await;
    // Let alice's probe-before-claim finish and the beacon come up before
    // bob joins, as a creator does in practice; two simultaneous starts
    // both claim the beacon and spend the run shedding the rival copy.
    tokio::time::sleep(Duration::from_secs(12)).await;
    let bob = spawn(&topic, "bob", relay, relay_transport, Arc::clone(&bob_saw)).await;

    let bob_nick = Nickname::new("bob").expect("valid");
    let alice_nick = Nickname::new("alice").expect("valid");
    let linked = alice_saw.wait_for(&bob_nick, deadline).await
        && bob_saw.wait_for(&alice_nick, deadline).await;

    alice.leave().await.expect("alice leaves");
    bob.leave().await.expect("bob leaves");
    linked
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_only_pair_links_only_when_the_relay_may_carry_payload() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    // Plain HTTP, the same relay flavour the browser matrix uses.
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay server");

    // The control first: the pair *can* meet through this relay.
    assert!(
        pair_links(&relay, true, Duration::from_mins(1)).await,
        "with the relay as a transport the pair must link through it"
    );

    // The gate holds each inbound gossip connection for `PROBE_DEADLINE`
    // (15 s) and then closes it; the deadline here outlasts that plus one
    // heal-tick retry, so a link would have had every chance to form.
    assert!(
        !pair_links(&relay, false, Duration::from_secs(40)).await,
        "with the relay lookup only a relay-only pair must never link"
    );
}
