//! The multihop underlay gets a `WebRTC` session to a gossip neighbor that has no
//! IP path to it, and to no other neighbor.
//!
//! Two real members on a local relay, with the transport list
//! `udp,webrtc,multihop,relay`. While IP works between them the underlay needs no
//! session of its own: it reaches the neighbor over IP. When both lose IP to each
//! other, their application pair rides `WebRTC`, and the underlay opens a session
//! to the same neighbor, so that a cell can be forwarded over it.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Membership, Request, Rung};
use habilis_network::protocol::{Lookup, Transport};
use tokio::sync::mpsc::UnboundedReceiver;

/// Long enough for an ICE round on the application pair, then for the alive tick
/// that offers the underlay session, then for a second ICE round.
const STEP_DEADLINE: Duration = Duration::from_mins(3);

struct Member {
    membership: Membership,
    _events: UnboundedReceiver<String>,
}

impl Member {
    async fn open(opts: &membership::Opts) -> Self {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(opts, sink).await.expect("open a member");
        Self {
            membership,
            _events: events,
        }
    }

    async fn create(nick: &str, relay: &RelayUrl) -> Self {
        Self::create_with(
            nick,
            relay,
            vec![
                Transport::Udp,
                Transport::WebRtc,
                Transport::Multihop,
                Transport::Relay,
            ],
        )
        .await
    }

    async fn create_with(nick: &str, relay: &RelayUrl, transport: Vec<Transport>) -> Self {
        Self::open(&membership::Opts {
            nick: Some(nick.to_owned()),
            lookup: vec![Lookup::Relay],
            transport,
            relay_urls: vec![relay.to_string()],
            ..membership::Opts::default()
        })
        .await
    }

    async fn join(nick: &str, creator: &Self) -> Self {
        Self::open(&membership::Opts {
            nick: Some(nick.to_owned()),
            mesh: Some(creator.membership.node.mesh_id().to_string()),
            ..membership::Opts::default()
        })
        .await
    }

    async fn roster_len(&self) -> usize {
        let json = self
            .membership
            .request(|reply| Request::Peers { reply })
            .await
            .unwrap_or_default();
        serde_json::from_str::<serde_json::Value>(&json)
            .ok()
            .and_then(|roster| roster["peers"].as_array().map(Vec::len))
            .unwrap_or(0)
    }

    fn ports(&self) -> Vec<u16> {
        self.membership.node.bound_ports().to_vec()
    }

    async fn block_ip_to(&self, ports: Vec<u16>) {
        self.membership
            .request(|reply| Request::BlockIpTo {
                remote_ports: ports,
                reply,
            })
            .await
            .expect("the loop answers");
    }

    /// The rung of the selected path on this member's pooled connection to `peer`.
    async fn rung_to(&self, peer: &str) -> Option<&'static str> {
        self.membership
            .request(|reply| Request::SelectedRung {
                peer: peer.to_owned(),
                reply,
            })
            .await
            .ok()
            .flatten()
    }

    async fn block_rung_to(&self, rung: Rung, peer: &str, blocked: bool) {
        self.membership
            .request(|reply| Request::BlockRungTo {
                rung,
                peer: peer.to_owned(),
                blocked,
                reply,
            })
            .await
            .expect("the loop answers");
    }

    async fn forwarded_cells(&self) -> u64 {
        self.membership
            .request(|reply| Request::ForwardedCells { reply })
            .await
            .expect("the loop answers")
    }

    fn underlay_id(&self) -> iroh::EndpointId {
        self.membership.node.underlay_id().expect("multihop is on")
    }

    fn underlay_ports(&self) -> Vec<u16> {
        self.membership.node.underlay_ports().to_vec()
    }

    /// How many `WebRTC` sessions the underlay of this member holds.
    async fn underlay_sessions(&self) -> usize {
        self.membership
            .request(|reply| Request::UnderlaySessions { reply })
            .await
            .expect("the loop answers")
    }

    /// Send a directed message. A refusal is an answer, not a failure.
    async fn send(&self, to: &str, text: &str) -> Result<(), String> {
        let to = membership::parse_to(Some(to)).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Send { to, body, reply })
            .await
            .expect("the loop answers")
    }

    /// Wait until the selected rung to `peer` is `expected`. A probe goes out each
    /// second, because since sessions open on demand a pair that sends nothing
    /// stays on the relay: it is traffic that makes the engine try a better path.
    async fn wait_for_rung(&self, peer: &str, expected: &str, step: &str) {
        let started = Instant::now();
        let mut seen = None;
        let mut probes = 0_u32;
        while started.elapsed() < STEP_DEADLINE {
            probes += 1;
            let _ = self.send(peer, &format!("probe {step} {probes}")).await;
            seen = self.rung_to(peer).await;
            if seen == Some(expected) {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        panic!(
            "{step}: expected the rung {expected}, the last rung read was {seen:?} \
             after {probes} probes"
        );
    }

    async fn wait_for_underlay_session(&self, peer: &str, step: &str) {
        let started = Instant::now();
        let mut probes = 0_u32;
        while started.elapsed() < STEP_DEADLINE {
            probes += 1;
            let _ = self.send(peer, &format!("probe {step} {probes}")).await;
            if self.underlay_sessions().await >= 1 {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        panic!("{step}: the underlay never opened a WebRTC session");
    }
}

/// With `RUST_LOG` set, a failing run prints the engine's log.
fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
}

async fn rosters_hold(members: &[&Member], peers: usize, deadline: Duration) -> bool {
    let started = Instant::now();
    loop {
        let mut all = true;
        for member in members {
            all &= member.roster_len().await == peers;
        }
        if all {
            return true;
        }
        if started.elapsed() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_underlay_opens_a_webrtc_session_to_a_neighbor_that_has_no_ip_path() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let alice = Member::create("alice", &relay).await;
    let bob = Member::join("bob", &alice).await;
    assert!(
        rosters_hold(&[&alice, &bob], 1, Duration::from_mins(1)).await,
        "the two members never formed a mesh"
    );

    // IP works: the underlay reaches the neighbor over IP, so it holds no session.
    alice.wait_for_rung("bob", "ip", "nothing blocked").await;
    assert_eq!(alice.underlay_sessions().await, 0, "IP works, no session");
    assert_eq!(bob.underlay_sessions().await, 0, "IP works, no session");

    // Both ends lose IP to each other: the application pair rides WebRTC, and the
    // underlay opens a session to the same neighbor.
    alice.block_ip_to(bob.ports()).await;
    bob.block_ip_to(alice.ports()).await;
    alice.wait_for_rung("bob", "webrtc", "IP blocked").await;
    alice
        .wait_for_underlay_session("bob", "alice, IP blocked")
        .await;
    bob.wait_for_underlay_session("alice", "bob, IP blocked")
        .await;

    for member in [alice, bob] {
        let _ = member.membership.node.leave().await;
    }
}

/// The proof of the leg of the underlay: a cell is forwarded over a `WebRTC` edge
/// of the underlay, through a third member.
///
/// Alice has `WebRTC` and no IP to carol, on the application endpoint and on the
/// underlay. Carol and bob keep IP. Alice and bob are cut entirely: no IP, and no
/// `WebRTC` to each other (one remote of each, so that the other pair keeps it).
/// The list is `udp,webrtc,multihop`, with no relay for payload, so the relay
/// gate keeps cells off the relay and the only way from alice to bob is carol. The
/// edge from alice to carol is a `WebRTC` session of the underlays, which exists
/// only since the underlay has a leg of its own. Carol's count of forwarded cells
/// shows that she was a hop, and not that the pair used a direct link.
/// Three members on a local relay, with the list `udp,webrtc,multihop`: no relay
/// carries payload.
async fn three_members(relay: &RelayUrl) -> (Member, Member, Member) {
    let list = vec![Transport::Udp, Transport::WebRtc, Transport::Multihop];
    let alice = Member::create_with("alice", relay, list).await;
    let bob = Member::join("bob", &alice).await;
    let carol = Member::join("carol", &alice).await;
    assert!(
        rosters_hold(&[&alice, &bob, &carol], 2, Duration::from_mins(1)).await,
        "the three members never formed a mesh"
    );
    alice.wait_for_rung("bob", "ip", "nothing blocked").await;
    (alice, bob, carol)
}

/// IP: alice to carol and alice to bob, on the application endpoint of each member
/// and, with `underlay`, on its underlay too. Carol and bob keep it.
async fn cut_ip_from_alice(alice: &Member, bob: &Member, carol: &Member, underlay: bool) {
    if underlay {
        habilis_network_iroh_webrtc_transport::block_ip_to(
            alice.underlay_id(),
            bob.underlay_ports()
                .into_iter()
                .chain(carol.underlay_ports()),
        );
        habilis_network_iroh_webrtc_transport::block_ip_to(
            bob.underlay_id(),
            alice.underlay_ports(),
        );
        habilis_network_iroh_webrtc_transport::block_ip_to(
            carol.underlay_id(),
            alice.underlay_ports(),
        );
    }
    alice
        .block_ip_to(bob.ports().into_iter().chain(carol.ports()).collect())
        .await;
    bob.block_ip_to(alice.ports()).await;
    carol.block_ip_to(alice.ports()).await;
}

/// The same mesh of three, with IP cut on the application endpoints only: the
/// underlays keep IP to each other. It tells a session that the cut of the
/// underlay stops from a session that three members stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_underlay_opens_a_session_to_carol_when_only_the_application_ip_is_cut() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let (alice, bob, carol) = three_members(&relay).await;
    cut_ip_from_alice(&alice, &bob, &carol, false).await;
    alice
        .wait_for_rung("carol", "webrtc", "alice to carol")
        .await;
    alice
        .wait_for_underlay_session("carol", "application IP cut")
        .await;
    for member in [alice, bob, carol] {
        let _ = member.membership.node.leave().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cell_is_forwarded_over_a_webrtc_underlay_edge_through_a_third_member() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let (alice, bob, carol) = three_members(&relay).await;
    cut_ip_from_alice(&alice, &bob, &carol, true).await;

    // WebRTC: alice and bob lose it to each other only, on both endpoints.
    alice.block_rung_to(Rung::WebRtc, "bob", true).await;
    bob.block_rung_to(Rung::WebRtc, "alice", true).await;
    habilis_network_iroh_webrtc_transport::block_rung_to(
        alice.underlay_id(),
        Rung::WebRtc,
        bob.underlay_id(),
        true,
    );
    habilis_network_iroh_webrtc_transport::block_rung_to(
        bob.underlay_id(),
        Rung::WebRtc,
        alice.underlay_id(),
        true,
    );

    alice
        .wait_for_rung("carol", "webrtc", "alice to carol")
        .await;
    alice
        .wait_for_underlay_session("carol", "alice, IP blocked to carol")
        .await;
    alice
        .wait_for_rung("bob", "multihop", "IP and WebRTC cut between alice and bob")
        .await;

    let started = Instant::now();
    while carol.forwarded_cells().await == 0 {
        assert!(
            started.elapsed() < STEP_DEADLINE,
            "alice reached bob on the multihop rung, but carol forwarded no cell"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    for member in [alice, bob, carol] {
        let _ = member.membership.node.leave().await;
    }
}
