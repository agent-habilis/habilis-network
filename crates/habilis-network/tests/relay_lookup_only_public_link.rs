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

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::iroh::RelayUrl;
use habilis_network::net::TransportOpts;
use habilis_network::protocol::{
    LookupOpts, MeshConfig, Message, Nickname, RelayChoice, TransportPolicy,
};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, derive_topic_mesh_config, setup_mesh,
};
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

#[derive(Default)]
struct Joined {
    peers: Mutex<Vec<Nickname>>,
    changed: Notify,
}

impl NodeSink for Joined {
    fn emit(&self, event: NodeEvent) {
        if let NodeEvent::Presence { msg } = event {
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

/// Both tests must start their second peer only after the first has claimed
/// the beacon. Two peers spawned back-to-back probe the same (deterministic)
/// beacon key on the same cadence, both find it free, and both claim it in
/// the same tick — two rival rendezvous, roster stuck at zero. The mesh e2e
/// matrix staggers on the same log line; this buffer is how a test sees it.
fn log_buffer() -> &'static Mutex<String> {
    static BUFFER: OnceLock<Mutex<String>> = OnceLock::new();
    BUFFER.get_or_init(|| Mutex::new(String::new()))
}

struct BufferWriter;

impl std::io::Write for BufferWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        log_buffer()
            .lock()
            .expect("no poison")
            .push_str(&String::from_utf8_lossy(bytes));
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("habilis_network=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(|| BufferWriter)
        .with_ansi(false)
        .try_init();
}

async fn wait_for_log(needle: &str, deadline: Duration) -> bool {
    let started = std::time::Instant::now();
    loop {
        if log_buffer().lock().expect("no poison").contains(needle) {
            return true;
        }
        if started.elapsed() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn dump_log_tail() {
    let logs = log_buffer().lock().expect("no poison").clone();
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
    sink: Arc<Joined>,
    transports: TransportOpts,
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
                relay_transport: false,
                ..TransportPolicy::default()
            },
        },
    )
    .expect("derive");
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
            transports,
            runtime_base: None,
            state_file: None,
            sink,
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await
    .expect("setup_mesh");
    Node::spawn(config, Probe, None, false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_ip_peers_link_through_the_gated_rendezvous() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let topic = format!("scratch-link-{}", rand::random::<u64>());
    let alice_saw = Arc::new(Joined::default());
    let bob_saw = Arc::new(Joined::default());
    let ip_only = TransportOpts {
        udp: true,
        relay: true,
        webrtc: false,
    };
    let alice = spawn_with(&topic, "alice", &relay, Arc::clone(&alice_saw), ip_only).await;
    assert!(
        wait_for_log("beacon role active", Duration::from_mins(1)).await,
        "alice never claimed the beacon; nothing for bob to find"
    );
    let bob = spawn_with(&topic, "bob", &relay, Arc::clone(&bob_saw), ip_only).await;

    let deadline = Duration::from_secs(75);
    let alice_nick = Nickname::new("alice").expect("valid");
    let bob_nick = Nickname::new("bob").expect("valid");
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
}

/// The browser-shaped case, natively: a peer with no IP transports must
/// still link — its rendezvous link rides the beacon's `WebRTC` lane.
#[ignore = "timing-sensitive: a JSEP round per beacon shed; run solo with --ignored"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_webrtc_only_peer_links_through_the_beacon_lane() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let topic = format!("scratch-lane-{}", rand::random::<u64>());
    let alice_saw = Arc::new(Joined::default());
    let bob_saw = Arc::new(Joined::default());
    let alice = spawn_with(
        &topic,
        "alice",
        &relay,
        Arc::clone(&alice_saw),
        TransportOpts {
            udp: true,
            relay: true,
            webrtc: true,
        },
    )
    .await;
    // Stagger like a real join: the first node claims the beacon, the second
    // finds it held. Simultaneous starts race both into the claim and leave
    // two same-id rendezvous copies shedding each other for the whole test.
    tokio::time::sleep(Duration::from_secs(10)).await;
    let bob = spawn_with(
        &topic,
        "bob",
        &relay,
        Arc::clone(&bob_saw),
        TransportOpts {
            udp: false,
            relay: true,
            webrtc: true,
        },
    )
    .await;

    let deadline = Duration::from_secs(75);
    let alice_nick = Nickname::new("alice").expect("valid");
    let bob_nick = Nickname::new("bob").expect("valid");
    let alice_ok = alice_saw.wait_for(&bob_nick, deadline).await;
    let bob_ok = bob_saw.wait_for(&alice_nick, deadline).await;
    let _ = alice.leave().await;
    let _ = bob.leave().await;
    assert!(
        alice_ok && bob_ok,
        "a webrtc-only peer must link through the beacon lane (alice saw bob: {alice_ok}, bob saw alice: {bob_ok})"
    );
}
