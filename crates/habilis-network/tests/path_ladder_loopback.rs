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

mod until_known;

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Membership, Request, Rung};
use habilis_network::protocol::{Lookup, Transport};
use tokio::sync::mpsc::UnboundedReceiver;
use until_known::until_peer_known;

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
        until_peer_known(&self.membership, peer, |reply| Request::OfferSession {
            peer: peer.to_owned(),
            reply,
        })
        .await;
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

    /// The multihop cells that this member has forwarded for others.
    async fn forwarded_cells(&self) -> u64 {
        self.membership
            .request(|reply| Request::ForwardedCells { reply })
            .await
            .expect("the loop answers")
    }

    /// Hold this member's link-vector back (`true`), which also withdraws its own vector from its
    /// routing table, or let it go (`false`), which advertises at once.
    async fn hold_link_state(&self, hold: bool) {
        self.membership
            .request(|reply| Request::HoldLinkState { hold, reply })
            .await
            .expect("the loop answers");
    }

    /// Whether this member's multihop topology has a route to `peer` now.
    async fn has_route(&self, peer: &str) -> bool {
        self.membership
            .request(|reply| Request::HasRoute {
                peer: peer.to_owned(),
                reply,
            })
            .await
            .expect("the loop answers")
    }

    /// Wait until the selected rung to `peer` is `expected`, or fail with the
    /// last rung read.
    async fn expect_rung(&self, peer: &str, expected: &str, step: &str) {
        self.expect_rung_in(peer, &[expected], step).await;
    }

    /// Wait until the selected rung to `peer` is one of `expected`, and say which one it was.
    /// A step that the engine passes through by itself, and whose resting rung is the next
    /// one, names both: a poll can miss a state that lasts a few hundred ms.
    async fn expect_rung_in(&self, peer: &str, expected: &[&str], step: &str) -> &'static str {
        tracing::info!(target: "ladder_test", "STEP {step}: waiting for one of {expected:?}");
        let started = Instant::now();
        let mut seen = None;
        while started.elapsed() < STEP_DEADLINE {
            let before = seen;
            seen = self.rung_to(peer).await;
            if seen != before {
                tracing::info!(target: "ladder_test", "STEP {step}: rung {seen:?} after {:?}", started.elapsed());
            }
            if let Some(rung) = seen
                && expected.contains(&rung)
            {
                return rung;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        panic!("{step}: expected one of the rungs {expected:?}, the last rung read was {seen:?}");
    }
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

#[test]
fn a_node_steps_down_the_ladder_and_climbs_back() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
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
    });
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
/// The test forces the order by construction: alice's link-vector is held back and
/// withdrawn from her own table (`Request::HoldLinkState`), so that she has no route for as
/// long as the hold lasts, however old the mesh is. It attaches the session with
/// `Request::OfferSession`, blocks `WebRTC`, and lets the vector go only after the loss
/// is observed. The two asserts that no route exists hold by construction: a failure of
/// either is a fault of the hook, not a reason to skip.
#[test]
fn a_pair_that_loses_webrtc_before_any_route_exists_climbs_to_multihop() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
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

        alice.hold_link_state(true).await;
        assert!(
            !alice.has_route("bob").await,
            "alice has a route to bob although her link-vector is withdrawn"
        );
        alice.block_ip_to(bob.ports()).await;
        bob.block_ip_to(alice.ports()).await;
        // The offer decision reads the selected path, which is still IP for a moment
        // after the block: ask only once the pair has left IP. The engine offers a session by
        // itself as soon as its watcher reports the relay, so the relay lasts a few hundred ms and
        // a poll can see WebRTC next: offer only when the relay was seen, and never again to a pair
        // that is already on WebRTC (an offer resets its proof and offers a second time).
        let left_ip = alice
            .expect_rung_in("bob", &["relay", "webrtc"], "IP blocked, before the offer")
            .await;
        if left_ip == "relay" {
            // Only the lower id offers; each side asks, so the right one does.
            alice.offer_session("bob").await;
            bob.offer_session("alice").await;
        }
        alice
            .expect_rung("bob", "webrtc", "IP blocked, session offered")
            .await;

        alice.block_rung(Rung::WebRtc, true).await;
        let lost_at = Instant::now();
        while !matches!(alice.rung_to("bob").await, Some("relay" | "multihop")) {
            assert!(
                lost_at.elapsed() < STEP_DEADLINE,
                "the pair never left WebRTC after the block"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            !alice.has_route("bob").await,
            "alice has a route to bob after the loss although her link-vector is withdrawn"
        );
        // The first link-vector comes now, after the loss: the order that failed one run in twenty.
        alice.hold_link_state(false).await;
        alice
            .expect_rung("bob", "multihop", "WebRTC lost before any route")
            .await;

        for member in [alice, bob, carol] {
            let _ = member.membership.node.leave().await;
        }
    });
}

/// Take every IP path between `first` and `second` away from both, on the application
/// endpoint and on the multihop underlay. The underlay is an endpoint of its
/// own: left alone, the direct link between the two underlays is the shortest
/// route, and no member would forward a cell.
async fn cut_ip_between(first: &Member, second: &Member) {
    first.block_ip_to(second.ports()).await;
    second.block_ip_to(first.ports()).await;
    for (from, to) in [(first, second), (second, first)] {
        let underlay = from.membership.node.underlay_id().expect("multihop is on");
        habilis_network_iroh_webrtc_transport::block_ip_to(
            underlay,
            to.membership.node.underlay_ports().iter().copied(),
        );
    }
}

/// Take the `WebRTC` rung away from both ends, on the application endpoint and on
/// the underlay, through the shared tables. Since an underlay may open a `WebRTC`
/// session to a neighbor of its own, as the lower underlay id offers one, cutting
/// only alice's application endpoint leaves a direct underlay edge on about half
/// of the draws of the two ids, and carol then forwards nothing.
async fn cut_webrtc_between(first: &Member, second: &Member) {
    first.block_rung(Rung::WebRtc, true).await;
    second.block_rung(Rung::WebRtc, true).await;
    for member in [first, second] {
        let underlay = member
            .membership
            .node
            .underlay_id()
            .expect("multihop is on");
        habilis_network_iroh_webrtc_transport::block_rung(underlay, Rung::WebRtc, true);
    }
}

/// With IP and `WebRTC` gone between alice and bob, the pair is carried by the
/// multihop rung through carol, the only member that can reach both. The proof is
/// carol's count of forwarded cells: a selected multihop rung alone does not show
/// a hop, since the direct link between the two underlays is a route too.
///
/// The list is `udp,webrtc,multihop`, with no relay for payload, so the relay
/// gate keeps cells off the relay and the only way left is the hop. The edge
/// between alice and bob ages out of the topology after the stuck time of 20 s
/// plus one link-state of 15 s, which is why the waits are long.
#[test]
fn the_multihop_rung_forwards_through_a_third_member() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
            .await
            .expect("local relay");
        let list = vec![Transport::Udp, Transport::WebRtc, Transport::Multihop];
        let alice = Member::create_with("alice", &relay, list).await;
        let bob = Member::join("bob", &alice).await;
        let carol = Member::join("carol", &alice).await;
        assert!(
            rosters_hold(&[&alice, &bob, &carol], 2, Duration::from_mins(1)).await,
            "the three members never formed a mesh"
        );
        alice.expect_rung("bob", "ip", "nothing blocked").await;

        // The lower underlay id offers an underlay session to its neighbor, so which
        // of alice and bob has it decides a draw: the line says which one it was.
        let (alice_underlay, bob_underlay) = (
            alice.membership.node.underlay_id().expect("multihop is on"),
            bob.membership.node.underlay_id().expect("multihop is on"),
        );
        eprintln!(
            "UNDERLAY IDS alice={} bob={} lower={}",
            alice_underlay.fmt_short(),
            bob_underlay.fmt_short(),
            if alice_underlay < bob_underlay {
                "alice"
            } else {
                "bob"
            }
        );
        cut_ip_between(&alice, &bob).await;
        cut_webrtc_between(&alice, &bob).await;
        alice
            .expect_rung("bob", "multihop", "IP and WebRTC cut between alice and bob")
            .await;

        let started = Instant::now();
        while carol.forwarded_cells().await == 0 {
            assert!(
                started.elapsed() < STEP_DEADLINE,
                "alice reached bob on the multihop rung, but carol forwarded no cell: \
             the pair used a link that is not a hop"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        for member in [alice, bob, carol] {
            let _ = member.membership.node.leave().await;
        }
    });
}
