//! A **public** mesh whose beacon is homed on rung 1 while rung 0 is down. Rung 0 comes back and
//! answers for the hold, and the beacon returns to it **in place**: the same beacon, no new claim,
//! and a joiner that starts after the return meshes with it. The times of the relay follower come
//! from the process tuning, so the hold is seconds here.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use habilis_network::protocol::messages::Authored;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::iroh::RelayUrl;
use habilis_network::net::{TransportOpts, test_relay};
use habilis_network::protocol::{LookupOpts, MeshConfig, Nickname, RelayChoice, TransportPolicy};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_config, setup_mesh,
};
use habilis_network::util::tuning::{self, Tuning};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::time;

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
        time::timeout(deadline, wait).await.is_ok() || seen()
    }
}

/// How many lines of the capture hold `needle`.
fn count_logs(needle: &str) -> usize {
    habilis_network_test_tracing::captured_logs()
        .lines()
        .filter(|line| line.contains(needle))
        .count()
}

/// Print the lines of the capture that name the beacon, for a failure.
fn dump_beacon_log() {
    eprintln!("--- beacon log ---");
    let logs = habilis_network_test_tracing::captured_logs();
    for line in logs.lines() {
        if line.contains("beacon") || line.contains("rung") {
            eprintln!("{line}");
        }
    }
}

async fn wait_for_logs(needle: &str, count: usize, deadline: Duration) -> bool {
    let started = Instant::now();
    loop {
        if count_logs(needle) >= count {
            return true;
        }
        if started.elapsed() >= deadline {
            return false;
        }
        time::sleep(Duration::from_millis(250)).await;
    }
}

/// A relay URL in front of `real`: while the gate is shut it drops every connection, and once it
/// is open it forwards them.
// The test opens the gate and the proxy task reads it, so both own the flag.
async fn spawn_gated_relay(real: &RelayUrl) -> (RelayUrl, Arc<AtomicBool>) {
    let host = real.host_str().expect("the relay URL has a host");
    let upstream = format!("{host}:{}", real.port().expect("the relay URL has a port"));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a free loopback port");
    let port = listener.local_addr().expect("the bound address").port();
    // The proxy task reads the gate that the test opens.
    let open = Arc::new(AtomicBool::new(false));
    let gate = Arc::clone(&open);
    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            if !gate.load(Ordering::SeqCst) {
                continue;
            }
            let upstream = upstream.clone();
            tokio::spawn(async move {
                if let Ok(mut onward) = TcpStream::connect(&upstream).await {
                    drop(copy_bidirectional(&mut stream, &mut onward).await);
                }
            });
        }
    });
    let url = format!("http://127.0.0.1:{port}/")
        .parse()
        .expect("a literal http URL parses");
    (url, open)
}

async fn spawn_with(
    topic: &str,
    nick: &str,
    ladder: &[RelayUrl],
    // The node app writes into the set that the test reads.
    sink: Arc<Joined>,
) -> Node<Probe> {
    let mesh = derive_topic_mesh_config(
        topic,
        MeshConfig::new(
            LookupOpts::new(RelayChoice::Custom(ladder.to_vec())),
            None,
            None,
            TransportPolicy::default().relay_transport(false),
        ),
    )
    .expect("derive");
    let author = Nickname::try_new(nick).expect("valid nickname");
    let topic_string = topic.to_owned();
    let transports: TransportOpts = TransportOpts::default()
        .udp(true)
        .relay(true)
        .webrtc(false)
        .gossip(false);
    let config = setup_mesh(
        SetupKind::Topic { mesh, topic_string },
        SetupParams::new(author, sink)
            .max_connections(16)
            .transports(transports),
    )
    .await
    .expect("setup_mesh");
    Node::spawn(config, Probe, None, SignalHandling::Leave)
}

#[test]
fn a_beacon_returns_to_rung_0_in_place_and_a_joiner_meshes_with_it() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network=info");
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        // Rung 0 drops every connection until the gate opens, so iroh warns of it.
        habilis_network_test_tracing::allow_warn("iroh::net_report::reportgen", "probe failed");
        habilis_network_test_tracing::allow_warn(
            "iroh::socket::transports::relay::actor",
            "Failed to connect to relay server",
        );
        habilis_network_test_tracing::allow_warn(
            "iroh::socket::transports::relay::actor",
            "Lost connection to relay server",
        );
        tuning::init(
            Tuning::default()
                .relay_liveness_interval(Duration::from_secs(1))
                .relay_return_probe_interval(Duration::from_secs(1))
                .relay_return_hold(Duration::from_secs(3))
                .relay_reprobe_backoff_max(Duration::from_secs(2)),
        );
        let (real_one, _real_one_server) = test_relay::spawn_plain().await.expect("local relay");
        let (rung_1, _rung_1_server) = test_relay::spawn_plain().await.expect("local relay");
        let (rung_0, rung_0_open) = spawn_gated_relay(&real_one).await;
        let ladder = [rung_0, rung_1];
        let suffix: u64 = rand::random();
        let topic = format!("scratch-return-{suffix}");

        // The node app of alice writes into the set that the test reads.
        let alice_saw = Arc::new(Joined::default());
        let alice = spawn_with(&topic, "alice", &ladder, Arc::clone(&alice_saw)).await;
        // Rung 0 is down: the startup probe moves the rung to rung 1, and the beacon is claimed
        // on it.
        assert!(
            wait_for_logs("bootstrap relay rung changed", 1, Duration::from_mins(1)).await,
            "the beacon never moved to rung 1"
        );
        let claimed = wait_for_logs("beacon role active", 1, Duration::from_mins(2)).await;
        if !claimed {
            dump_beacon_log();
        }
        assert!(claimed, "the beacon was never claimed on rung 1");
        let claims = count_logs("beacon role active");
        let rehomes = count_logs("bootstrap relay rung changed");

        rung_0_open.store(true, Ordering::SeqCst);
        let moved = wait_for_logs(
            "the beacon moved to another relay rung in place",
            1,
            Duration::from_mins(1),
        )
        .await;
        time::sleep(Duration::from_secs(3)).await;
        let claims_after = count_logs("beacon role active");
        let rehomes_after = count_logs("bootstrap relay rung changed");

        // The node app of bob writes into the set that the test reads.
        let bob_saw = Arc::new(Joined::default());
        let bob = spawn_with(&topic, "bob", &ladder, Arc::clone(&bob_saw)).await;
        let bob_nick = Nickname::try_new("bob").expect("valid");
        let alice_nick = Nickname::try_new("alice").expect("valid");
        let alice_ok = alice_saw.wait_for(&bob_nick, Duration::from_secs(75)).await;
        let bob_ok = bob_saw.wait_for(&alice_nick, Duration::from_secs(75)).await;
        let _ = alice.leave().await;
        let _ = bob.leave().await;

        assert!(moved, "the beacon never returned to rung 0 in place");
        assert_eq!(claims_after, claims, "the return claimed a new beacon");
        assert_eq!(rehomes_after, rehomes, "the return re-homed the beacon");
        assert!(
            alice_ok && bob_ok,
            "a joiner after the return did not mesh with the beacon (alice saw bob: {alice_ok}, bob saw alice: {bob_ok})"
        );
    });
}
