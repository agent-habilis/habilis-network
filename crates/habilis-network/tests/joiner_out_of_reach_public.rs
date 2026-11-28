//! A **public** mesh with a live creator, and a joiner whose relay is out of reach when it starts.
//!
//! The joiner has no address to dial, and the engine reads a rendezvous with nothing to dial as
//! held: the joiner does not claim it. So a joiner that cannot reach the relay never makes a second
//! holder beside the live creator, and when the relay is back the joiner meshes with the creator.
//! Two ways to be out of reach are tried: a relay that refuses every new connection (the gate drops
//! it), and a relay that accepts and says nothing (the gate holds it open).
//!
//! This test was written to make the pair "a live creator and a later claim" by cutting the relay.
//! It cannot: 8 runs showed that no claim comes, and the pair needs a probe that has an address and
//! times out twice (a loaded host, lost datagrams). The pair is covered by the tests of the cause
//! (`a_creator_arms_the_ask_of_the_holder`, `a_mesh_with_a_creator_ends_with_one_holder`).

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inspect, Membership, Request};
use habilis_network::net::{Bind, test_relay};
use habilis_network::protocol::{Lookup, Transport};
use habilis_network::topology::TopologySnapshot;
use habilis_network::util::tuning::MIN_MAX_CONNECTIONS;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time;

/// How long the joiner is watched while its relay is out of reach: past 2 heal ticks and the
/// co-host grace, so that a claim, if it came, would have come.
const WATCH: Duration = Duration::from_secs(75);

/// How long the joiner has to mesh with the creator once the relay is back.
const MESH_DEADLINE: Duration = Duration::from_secs(90);

/// How the relay is out of reach.
#[derive(Debug, Clone, Copy)]
enum Cut {
    /// The proxy drops each new connection at once.
    Refuse,
    /// The proxy accepts each new connection and says nothing.
    Silent,
}

/// A relay URL in front of `real`. While the gate is shut, a new connection is dropped (`Refuse`) or
/// held open and silent (`Silent`). Once the gate is open it forwards new connections. A connection
/// that was made while the gate was open goes on.
// The test opens the gate and the proxy task reads it, so both own the flag.
async fn spawn_gated_relay(real: &RelayUrl, cut: Cut) -> (RelayUrl, Arc<AtomicBool>) {
    let host = real.host_str().expect("the relay URL has a host");
    let upstream = format!("{host}:{}", real.port().expect("the relay URL has a port"));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a free loopback port");
    let port = listener.local_addr().expect("the bound address").port();
    // The proxy task reads the gate that the test opens.
    let open = Arc::new(AtomicBool::new(true));
    let gate = Arc::clone(&open);
    tokio::spawn(async move {
        let mut held: Vec<TcpStream> = Vec::new();
        while let Ok((mut stream, _peer)) = listener.accept().await {
            if !gate.load(Ordering::SeqCst) {
                if matches!(cut, Cut::Silent) {
                    held.push(stream);
                }
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

struct Member {
    membership: Membership,
    _events: UnboundedReceiver<String>,
}

impl Member {
    async fn open(options: &membership::JoinOptions) -> Self {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(options, sink)
            .await
            .expect("open a member");
        Self {
            membership,
            _events: events,
        }
    }

    /// The creator of a mesh whose lookup is the relay `relay`: the policy `Eager`.
    async fn create(nick: &str, relay: &RelayUrl) -> Self {
        let options: membership::JoinOptions = membership::JoinOptions::default()
            .bind(Bind::Loopback)
            .nick(Some(nick.to_owned()))
            .lookup(vec![Lookup::Relay]);
        let options: membership::JoinOptions = options.transport(vec![
            Transport::Udp,
            Transport::WebRtc,
            Transport::Multihop,
            Transport::Relay,
        ]);
        let options: membership::JoinOptions = options
            .relay_urls(vec![relay.to_string()])
            .max_connections(MIN_MAX_CONNECTIONS);
        Self::open(&options).await
    }

    /// A joiner by the mesh id alone: the lookups come from the id, which names the relay.
    async fn join_mesh(nick: &str, mesh: &str) -> Self {
        let options: membership::JoinOptions = membership::JoinOptions::default()
            .bind(Bind::Loopback)
            .nick(Some(nick.to_owned()));
        let options = options.mesh(Some(mesh.to_owned()));
        Self::open(&options.max_connections(MIN_MAX_CONNECTIONS)).await
    }

    /// The short id that the beacon lines of the log name this member by.
    fn short_id(&self) -> String {
        self.membership.node.endpoint_id().fmt_short().to_string()
    }

    async fn snapshot(&self) -> TopologySnapshot {
        self.membership
            .request(|reply| Request::Inspect(Inspect::Topology { reply }))
            .await
            .expect("the loop answers")
    }

    /// Whether this member has a gossip neighbor with the nickname `nick`.
    async fn has_neighbor(&self, nick: &str) -> bool {
        let snapshot = self.snapshot().await;
        let mut links = snapshot.peers.iter().filter(|link| link.neighbor);
        links.any(|link| link.nickname.as_deref() == Some(nick))
    }
}

/// Whether the capture holds a line with `needle` and the short id `node`.
fn logged(node: &str, needle: &str) -> bool {
    let logs = habilis_network_test_tracing::captured_logs();
    logs.lines()
        .any(|line| line.contains(needle) && line.contains(node))
}

async fn a_joiner_whose_relay_is_out_of_reach(cut: Cut) {
    // The cut relay makes iroh warn.
    habilis_network_test_tracing::allow_warn("iroh::net_report::reportgen", "probe failed");
    habilis_network_test_tracing::allow_warn(
        "iroh::socket::transports::relay::actor",
        "Failed to connect to relay server",
    );
    habilis_network_test_tracing::allow_warn(
        "iroh::socket::transports::relay::actor",
        "Lost connection to relay server",
    );
    let (real, _server) = test_relay::spawn_plain().await.expect("local relay");
    let (relay, gate) = spawn_gated_relay(&real, cut).await;

    // The creator makes its connections to the relay while the gate is open.
    let creator = Member::create("creator", &relay).await;
    let mesh = creator.membership.node.mesh_id().to_string();
    let creator_id = creator.short_id();
    let creator_holds = wait_for_claim(&creator_id, Duration::from_mins(1)).await;
    assert!(creator_holds, "the creator never held the rendezvous");

    gate.store(false, Ordering::SeqCst);
    let joiner = Member::join_mesh("joiner", &mesh).await;
    let joiner_id = joiner.short_id();
    let watched = Instant::now();
    let mut claimed = false;
    while watched.elapsed() < WATCH {
        if logged(&joiner_id, "beacon assumed") {
            claimed = true;
            break;
        }
        time::sleep(Duration::from_secs(2)).await;
    }

    gate.store(true, Ordering::SeqCst);
    let opened = Instant::now();
    let mut meshed = false;
    while opened.elapsed() < MESH_DEADLINE {
        if joiner.has_neighbor("creator").await {
            meshed = true;
            break;
        }
        time::sleep(Duration::from_secs(2)).await;
    }
    let _ = joiner.membership.node.leave().await;
    let _ = creator.membership.node.leave().await;

    assert!(
        !claimed,
        "{cut:?}: the joiner claimed the rendezvous while its relay was out of reach: a second holder beside the live creator"
    );
    assert!(
        meshed,
        "{cut:?}: the joiner has no gossip neighbor in the mesh of the creator {MESH_DEADLINE:?} after the relay came back"
    );
}

/// Wait until the capture holds a claim line of `node`, or the deadline passes.
async fn wait_for_claim(node: &str, deadline: Duration) -> bool {
    let started = Instant::now();
    loop {
        if logged(node, "beacon assumed") {
            return true;
        }
        if started.elapsed() >= deadline {
            return false;
        }
        time::sleep(Duration::from_millis(250)).await;
    }
}

/// **A joiner whose relay refuses every connection does not claim.** It has no address to dial, the
/// engine reads that as a held rendezvous, and when the relay is back the joiner meshes with the
/// creator.
#[test]
fn a_joiner_whose_relay_refuses_does_not_claim_and_meshes_when_it_is_back() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network=info");
    habilis_network_test_tracing::run_multi_thread(
        guard,
        4,
        a_joiner_whose_relay_is_out_of_reach(Cut::Refuse),
    );
}

/// **A joiner whose relay accepts and says nothing does not claim.** Its first probe times out and
/// reads free; every later probe has no address to dial and reads held, so 2 free readings in a row
/// never come. When the relay is back the joiner meshes with the creator.
#[test]
fn a_joiner_whose_relay_is_silent_does_not_claim_and_meshes_when_it_is_back() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network=info");
    habilis_network_test_tracing::run_multi_thread(
        guard,
        4,
        a_joiner_whose_relay_is_out_of_reach(Cut::Silent),
    );
}
