//! A node steps down the path ladder one rung at a time: a direct IP path, then
//! `WebRTC`, then multihop, then the relay. Each step is
//! shown with a test hook that takes one rung away from one node, and the node
//! climbs back when the rungs return.
//!
//! Three real members on a local relay, with the transport list
//! `udp,webrtc,multihop,relay`. Every assertion reads the selected path of the
//! **pooled unicast connection** from `alice` to `bob` (`Request::SelectedRung`).
//! It is not the gossip link: the relay policy closes a gossip link that stays on
//! the relay, so the last rung could not be read on it without a race.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Membership, Request, Rung};
use habilis_network::protocol::{Lookup, Transport};
use tokio::sync::mpsc::UnboundedReceiver;

/// Long enough for an ICE round, or for a multihop route to be advertised once
/// (every 15 s) and then used.
const STEP_DEADLINE: Duration = Duration::from_mins(2);

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

    async fn block_rung(&self, rung: Rung, blocked: bool) {
        self.membership
            .request(|reply| Request::BlockRung {
                rung,
                blocked,
                reply,
            })
            .await
            .expect("the loop answers");
    }

    /// Forget that `peer` is proven direct and offer it a `WebRTC` session now.
    async fn offer_session(&self, peer: &str) {
        self.membership
            .request(|reply| Request::OfferSession {
                peer: peer.to_owned(),
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

    /// Wait until the selected rung to `peer` is `expected`, or fail with the
    /// last rung read.
    async fn expect_rung(&self, peer: &str, expected: &str, step: &str) {
        tracing::info!(target: "ladder_test", "STEP {step}: waiting for {expected}");
        let started = Instant::now();
        let mut seen = None;
        while started.elapsed() < STEP_DEADLINE {
            let before = seen;
            seen = self.rung_to(peer).await;
            if seen != before {
                tracing::info!(target: "ladder_test", "STEP {step}: rung {seen:?} after {:?}", started.elapsed());
            }
            if seen == Some(expected) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        panic!("{step}: expected the rung {expected}, the last rung read was {seen:?}");
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
async fn a_node_steps_down_the_ladder_and_climbs_back() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let alice = Member::create("alice", &relay).await;
    let bob = Member::join("bob", &alice).await;
    let carol = Member::join("carol", &alice).await;
    assert!(
        rosters_hold(&[&alice, &bob, &carol], 2, Duration::from_mins(1)).await,
        "the three members never formed a mesh"
    );

    // Carol is a third member that keeps every rung to both. The multihop rung
    // between alice and bob needs her only as a possible hop: the shortest route
    // is the direct link between their multihop underlays, an endpoint of its
    // own, which the blocks on the application endpoint do not cut. In the runs
    // that I measured no hop forwarded a cell.
    alice.expect_rung("bob", "ip", "nothing blocked").await;

    // Both ends lose IP to each other: a WebRTC session that attaches while
    // the far side still has UDP is dropped by the far side.
    alice.block_ip_to(bob.ports()).await;
    bob.block_ip_to(alice.ports()).await;
    alice.expect_rung("bob", "webrtc", "IP blocked").await;

    alice.block_rung(Rung::WebRtc, true).await;
    alice
        .expect_rung("bob", "multihop", "IP and WebRTC blocked")
        .await;

    alice.block_rung(Rung::Multihop, true).await;
    alice
        .expect_rung("bob", "relay", "IP, WebRTC and multihop blocked")
        .await;

    // Back up, in the reverse order.
    alice.block_rung(Rung::Multihop, false).await;
    alice
        .expect_rung("bob", "multihop", "multihop returned")
        .await;
    alice.block_rung(Rung::WebRtc, false).await;
    alice.expect_rung("bob", "webrtc", "WebRTC returned").await;
    alice.block_ip_to(Vec::new()).await;
    bob.block_ip_to(Vec::new()).await;
    alice.expect_rung("bob", "ip", "IP returned").await;

    for member in [alice, bob, carol] {
        let _ = member.membership.node.leave().await;
    }
}

/// A pair whose `WebRTC` session ends before any member has advertised a route
/// must still climb to multihop once the route exists. This is the order that
/// failed one run in twenty: the session is attached, the `WebRTC` rung is lost
/// within seconds of the mesh forming, and the multihop address is learned by no
/// lookup, because iroh looks up only while no path or the relay is selected,
/// and the lookup answers only if the topology has a route at that moment (the
/// first link-state comes 15 s after a member starts). Nothing then dials the
/// pair, since it already has a session and so makes no offer.
///
/// The test forces the order instead of waiting for it: it attaches the session
/// at once with `Request::OfferSession`, then blocks `WebRTC`, all within the
/// first seconds. It needs the mesh to be young; on a host too loaded to form it
/// in about ten seconds the route may exist already and the test passes without
/// the fix.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pair_that_loses_webrtc_before_any_route_exists_climbs_to_multihop() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let alice = Member::create("alice", &relay).await;
    let bob = Member::join("bob", &alice).await;
    let carol = Member::join("carol", &alice).await;
    assert!(
        rosters_hold(&[&alice, &bob, &carol], 2, Duration::from_mins(1)).await,
        "the three members never formed a mesh"
    );
    alice.expect_rung("bob", "ip", "nothing blocked").await;

    alice.block_ip_to(bob.ports()).await;
    bob.block_ip_to(alice.ports()).await;
    // The offer decision reads the selected path, which is still IP for a moment
    // after the block: ask only once the pair is on the relay.
    alice
        .expect_rung("bob", "relay", "IP blocked, before the offer")
        .await;
    // Only the lower id offers; each side asks, so the right one does.
    alice.offer_session("bob").await;
    bob.offer_session("alice").await;
    alice
        .expect_rung("bob", "webrtc", "IP blocked, session offered")
        .await;

    alice.block_rung(Rung::WebRtc, true).await;
    alice
        .expect_rung("bob", "multihop", "WebRTC lost before any route")
        .await;

    for member in [alice, bob, carol] {
        let _ = member.membership.node.leave().await;
    }
}
