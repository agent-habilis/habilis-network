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
use habilis_network::membership::{self, Membership, Request};
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
        Self::open(&membership::Opts {
            nick: Some(nick.to_owned()),
            lookup: vec![Lookup::Relay],
            transport: vec![
                Transport::Udp,
                Transport::WebRtc,
                Transport::Multihop,
                Transport::Relay,
            ],
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

    /// How many `WebRTC` sessions the underlay of this member holds.
    async fn underlay_sessions(&self) -> usize {
        self.membership
            .request(|reply| Request::UnderlaySessions { reply })
            .await
            .expect("the loop answers")
    }

    async fn wait_for_rung(&self, peer: &str, expected: &str, step: &str) {
        let started = Instant::now();
        let mut seen = None;
        while started.elapsed() < STEP_DEADLINE {
            seen = self.rung_to(peer).await;
            if seen == Some(expected) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        panic!("{step}: expected the rung {expected}, the last rung read was {seen:?}");
    }

    async fn wait_for_underlay_session(&self, step: &str) {
        let started = Instant::now();
        while started.elapsed() < STEP_DEADLINE {
            if self.underlay_sessions().await >= 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
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
    alice.wait_for_underlay_session("alice, IP blocked").await;
    bob.wait_for_underlay_session("bob, IP blocked").await;

    for member in [alice, bob] {
        let _ = member.membership.node.leave().await;
    }
}
