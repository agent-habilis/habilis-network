//! A node at its cap of direct connections reaches a new peer through a connected peer, and it
//! evicts nobody.
//!
//! Four native members on a local relay, with the list `udp,webrtc,multihop`. Alice has a cap of 2
//! and holds bob and carol. Dave can reach bob only: IP and `WebRTC` are cut between dave and each of
//! alice and carol, on the application endpoints and on the underlays. A send from alice to dave
//! has no free unit, and the route alice > bob > dave exists, so the dial must take that route and
//! pin the peer. Dave answers over the same route.
//!
//! What the run shows:
//! - both frames arrive, and bob forwards cells for them;
//! - no member evicts a connection at its ceiling;
//! - alice counts 2 direct units, none over the cap, after the send. A direct dial to dave would
//!   take a third unit, and an eviction would take one of bob and carol.
//!
//! What it does not show: that the connection of alice to dave carries no IP path. The unit tests
//! of the pin set and of the selectors do. This test shows that the node does not dial direct.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

mod until_known;

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{
    self, Blocking, Inbound, Inspect, Membership, Messaging, Request, Routing,
};
use habilis_network::net;
use habilis_network::protocol::{Lookup, Transport};
use habilis_network_iroh_multihop_transport::MultihopCounters;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time;

/// Long enough for the cuts to take effect, for the gossip view to settle, and for the topology to
/// hold the route.
const STEP_DEADLINE: Duration = Duration::from_mins(3);
/// The WARN that the underlay logs for a hop that stays on the relay for longer than the stuck limit.
const STUCK_TARGET: &str = "habilis_network_iroh_multihop_transport::underlay";
const STUCK_TEXT: &str =
    "multihop underlay stays on the relay: this hop is not advertised as a link";
/// The line that an eviction at the ceiling logs, on the transport target.
const EVICTION_LINE: &str = "evicting a direct connection at the ceiling";
/// The WARN of a forwarder that gets a cell over the relay: a cut pair still has its relay path.
const RELAY_CELL_TEXT: &str = "multihop forwarder refusing cells";

struct Member {
    membership: Membership,
    _events: UnboundedReceiver<String>,
    seen_msgs: Vec<Inbound>,
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
            seen_msgs: Vec::new(),
        }
    }

    async fn create(
        nick: &str,
        relay: &RelayUrl,
        transport: Vec<Transport>,
        max_connections: usize,
    ) -> Self {
        let options = membership::JoinOptions::default()
            .nick(Some(nick.to_owned()))
            .lookup(vec![Lookup::Relay]);
        let options = options
            .transport(transport)
            .relay_urls(vec![relay.to_string()]);
        let options = options.max_connections(max_connections);
        Self::open(&options).await
    }

    async fn join(nick: &str, creator: &Self) -> Self {
        let mesh = creator.membership.node.mesh_id().to_string();
        let options = membership::JoinOptions::default()
            .nick(Some(nick.to_owned()))
            .mesh(Some(mesh));
        Self::open(&options).await
    }

    async fn roster_len(&self) -> usize {
        let json = self
            .membership
            .request(|reply| Request::Inspect(Inspect::Peers { reply }))
            .await
            .unwrap_or_default();
        let roster: Option<serde_json::Value> = serde_json::from_str(&json).ok();
        roster
            .and_then(|roster| roster["peers"].as_array().map(Vec::len))
            .unwrap_or(0)
    }

    fn ports(&self) -> Vec<u16> {
        self.membership.node.bound_ports().to_vec()
    }

    fn underlay_id(&self) -> iroh::EndpointId {
        self.membership.node.underlay_id().expect("multihop is on")
    }

    fn underlay_ports(&self) -> Vec<u16> {
        self.membership.node.underlay_ports().to_vec()
    }

    async fn block_ip_to(&self, ports: Vec<u16>) {
        self.membership
            .request(|reply| {
                Request::Blocking(Blocking::BlockIpTo {
                    remote_ports: ports,
                    reply,
                })
            })
            .await
            .expect("the loop answers");
    }

    /// Refuse every `WebRTC` session with `peer`, on the application endpoint and on the
    /// underlay.
    async fn deny_peer(&self, peer: &str) {
        until_known::until_peer_known(&self.membership, peer, |reply| {
            Request::Blocking(Blocking::DenyPeer {
                peer: peer.to_owned(),
                denied: true,
                reply,
            })
        })
        .await;
    }

    async fn forwarded_cells(&self) -> u64 {
        self.membership
            .request(|reply| Request::Routing(Routing::ForwardedCells { reply }))
            .await
            .expect("the loop answers")
    }

    async fn counters(&self) -> MultihopCounters {
        self.membership
            .request(|reply| Request::Routing(Routing::MultihopCounters { reply }))
            .await
            .expect("the loop answers")
    }

    /// The direct units that the ceiling counts, and by how many they are over the cap.
    async fn direct_units(&self) -> (usize, usize) {
        self.membership
            .request(|reply| Request::Routing(Routing::DirectUnits { reply }))
            .await
            .expect("the loop answers")
    }

    /// Send a directed message. A refusal is an answer, not a failure.
    async fn send(&self, to: &str, text: &str) -> Result<(), String> {
        let to = membership::parse_to(Some(to)).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Messaging(Messaging::Send { to, body, reply }))
            .await
            .expect("the loop answers")
    }

    /// Whether a directed message with this text has arrived at this member.
    fn saw_msg(&mut self, text: &str) -> bool {
        while let Ok(message) = self.membership.inbound.try_recv() {
            self.seen_msgs.push(message);
        }
        self.seen_msgs
            .iter()
            .any(|message| message.directed && message.text == text)
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
        time::sleep(Duration::from_millis(500)).await;
    }
}

/// IP between the two, on the application endpoints and on the underlays, both ways.
async fn cut_ip_between(first: &Member, second: &Member) {
    first.block_ip_to(second.ports()).await;
    second.block_ip_to(first.ports()).await;
    for (from, to) in [(first, second), (second, first)] {
        habilis_network_iroh_webrtc_transport::block_ip_to(from.underlay_id(), to.underlay_ports());
    }
}

/// `WebRTC` and IP both ways: the pair has no direct path left.
async fn cut_between(first: &Member, second: &Member, first_nick: &str, second_nick: &str) {
    first.deny_peer(second_nick).await;
    second.deny_peer(first_nick).await;
    cut_ip_between(first, second).await;
}

/// What the members counted, for the message of a failure.
async fn counters_of(members: &[(&str, &Member)]) -> String {
    let mut text = String::new();
    for (nick, member) in members {
        let units = member.direct_units().await;
        let counters = member.counters().await;
        let _ = write!(text, "{nick} units {units:?} {counters:?}; ");
    }
    text
}

/// Send `text` from `from` to `to` each second until `to` reads it, or the deadline ends.
async fn delivered(from: &Member, to: &mut Member, to_nick: &str, text: &str) -> bool {
    let started = Instant::now();
    loop {
        let _ = from.send(to_nick, text).await;
        if to.saw_msg(text) {
            return true;
        }
        if started.elapsed() >= STEP_DEADLINE {
            return false;
        }
        time::sleep(Duration::from_secs(1)).await;
    }
}

#[test]
fn a_node_at_its_cap_reaches_a_new_peer_through_a_connected_one_and_evicts_nobody() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network::transport=info");
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = net::test_relay::spawn_plain().await.expect("local relay");
        let list = vec![Transport::Udp, Transport::WebRtc, Transport::Multihop];
        let mut alice = Member::create("alice", &relay, list, 2).await;
        let bob = Member::join("bob", &alice).await;
        let carol = Member::join("carol", &alice).await;
        let mut dave = Member::join("dave", &alice).await;
        assert!(
            rosters_hold(&[&alice, &bob, &carol, &dave], 3, Duration::from_mins(1)).await,
            "the four members never formed a mesh"
        );

        // Dave keeps bob and loses the two others, so that the only way from alice to dave is
        // alice > bob > dave.
        cut_between(&alice, &dave, "alice", "dave").await;
        cut_between(&carol, &dave, "carol", "dave").await;
        habilis_network_test_tracing::allow_warn(STUCK_TARGET, STUCK_TEXT);
        habilis_network_test_tracing::allow_warn(STUCK_TARGET, RELAY_CELL_TEXT);

        // Alice holds a full ceiling: bob and carol, both neighbors, for 2 units.
        let started = Instant::now();
        loop {
            let (units, over) = alice.direct_units().await;
            if units == 2 && over == 0 {
                break;
            }
            assert!(
                started.elapsed() < STEP_DEADLINE,
                "alice never settled at 2 units: {}",
                counters_of(&[("alice", &alice), ("bob", &bob), ("dave", &dave)]).await
            );
            time::sleep(Duration::from_millis(500)).await;
        }

        // The first frame goes while no route may be known yet: a send that finds no route
        // dials as it always did, and the test waits for a route before it counts.
        assert!(
            delivered(&alice, &mut dave, "dave", "to dave through bob").await,
            "the frame of alice never reached dave: {}",
            counters_of(&[("alice", &alice), ("bob", &bob), ("dave", &dave)]).await
        );
        let after_send = alice.direct_units().await;
        assert_eq!(
            after_send,
            (2, 0),
            "alice took a unit or evicted a peer for dave: {}",
            counters_of(&[("alice", &alice), ("bob", &bob), ("dave", &dave)]).await
        );

        // Both ways. The cut takes a moment to remove a direct hop between alice and dave, and
        // until it does a frame goes the short way. Frames go on until bob has forwarded cells
        // for them.
        let before = bob.forwarded_cells().await;
        let forwarding_since = Instant::now();
        let mut round = 0_u32;
        while bob.forwarded_cells().await == before {
            assert!(
                forwarding_since.elapsed() < STEP_DEADLINE,
                "bob forwarded no cell for the frames of alice and dave: {}",
                counters_of(&[("alice", &alice), ("bob", &bob), ("dave", &dave)]).await
            );
            round += 1;
            let reply = format!("dave answers alice {round}");
            assert!(
                delivered(&dave, &mut alice, "alice", &reply).await,
                "the answer of dave never reached alice: {}",
                counters_of(&[("alice", &alice), ("bob", &bob), ("dave", &dave)]).await
            );
            let text = format!("alice to dave {round}");
            assert!(
                delivered(&alice, &mut dave, "dave", &text).await,
                "the frame of alice never reached dave: {}",
                counters_of(&[("alice", &alice), ("bob", &bob), ("dave", &dave)]).await
            );
            time::sleep(Duration::from_secs(1)).await;
        }
        let after_answer = alice.direct_units().await;
        assert_eq!(
            after_answer,
            (2, 0),
            "the answer of dave changed the units of alice: {}",
            counters_of(&[("alice", &alice), ("bob", &bob), ("dave", &dave)]).await
        );

        let logs = habilis_network_test_tracing::captured_logs();
        assert!(
            !logs.contains(EVICTION_LINE),
            "a node evicted a direct connection at its ceiling: {}",
            logs.lines()
                .filter(|line| line.contains(EVICTION_LINE))
                .collect::<Vec<_>>()
                .join("\n")
        );

        for member in [alice, bob, carol, dave] {
            let _ = member.membership.node.leave().await;
        }
    });
}
