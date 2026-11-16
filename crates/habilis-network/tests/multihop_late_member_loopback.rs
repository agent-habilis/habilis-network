//! A node at its cap learns a new member, and dials nobody and evicts nobody for it. A send to a
//! member that it holds no connection to then pins the peer on a multihop route.
//!
//! Four native members on a local relay, with the list `udp,webrtc,multihop`. Alice has a cap of 2.
//! Bob and carol join with her, and dave joins after her ceiling is full. No path is cut: the rule
//! does not depend on a path that is missing, only on the ceiling being full. The gossip view of
//! alice holds 2 of the 3 others, and the third is the peer of the test.
//!
//! The run shows, after the roster of alice holds the third member and a settle time:
//! - alice counts 2 direct units, none over the cap, and no connection beside them: a dial for the
//!   new member (a `PeerInfo` dial, a probe, a courtesy dial) would take a third unit or evict one;
//! - no member logged an eviction at its ceiling;
//! - a send of alice to the third member arrives, and her snapshot shows it pinned on the
//!   multihop path.
#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{
    self, Inbound, Inspect, InspectHost, Membership, Messaging, Request, Routing,
};
use habilis_network::net;
use habilis_network::protocol::{Lookup, Transport};
use habilis_network::topology::TopologySnapshot;
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
/// The cause that the eviction line carries when a gossip neighbor took the unit.
const NEIGHBOR_CAUSE: &str = "cause=\"a gossip neighbor\"";
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

    /// The connections of this member, the cap on them, and the multihop graph.
    async fn snapshot(&self) -> TopologySnapshot {
        self.membership
            .request(|reply| Request::Inspect(Inspect::Topology { reply }))
            .await
            .expect("the loop answers")
    }

    /// Whether this member's topology holds a multihop route to `peer`.
    async fn has_route(&self, peer: &str) -> bool {
        self.membership
            .request(|reply| {
                Request::InspectHost(InspectHost::HasRoute {
                    peer: peer.to_owned(),
                    reply,
                })
            })
            .await
            .unwrap_or(false)
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

/// What the members counted, for the message of a failure.
async fn counters_of(members: &[(&str, &Member)]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (nick, member) in members {
        let units = member.direct_units().await;
        let counters = member.counters().await;
        parts.push(format!("{nick} units {units:?} {counters:?}"));
    }
    parts.join("; ")
}

/// Wait until `from` holds a multihop route to `nick`: a send that finds none dials as it always
/// did, and the test is about the send that finds one.
async fn route_known(from: &Member, nick: &str) -> bool {
    let started = Instant::now();
    while !from.has_route(nick).await {
        if started.elapsed() >= STEP_DEADLINE {
            return false;
        }
        time::sleep(Duration::from_millis(500)).await;
    }
    true
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

/// The nicknames of the gossip neighbors in the snapshot, sorted.
fn neighbor_nicks(snapshot: &TopologySnapshot) -> Vec<&str> {
    let neighbors = snapshot.peers.iter().filter(|link| link.neighbor);
    let mut nicks: Vec<&str> = neighbors
        .filter_map(|link| link.nickname.as_deref())
        .collect();
    nicks.sort_unstable();
    nicks
}

/// Whether the snapshot shows `nick` pinned, with no unit for it: the units are the cap and none is
/// over it.
fn is_pinned_at_the_ceiling(snapshot: &TopologySnapshot, nick: &str) -> bool {
    let wanted = Some(nick);
    let found = snapshot
        .peers
        .iter()
        .find(|link| link.nickname.as_deref() == wanted);
    let pinned = found.is_some_and(|link| link.pinned && !link.neighbor);
    pinned && snapshot.direct_units == 2 && snapshot.over_ceiling == 0
}

/// How long the ledger may take to settle after the first frame of a send.
const LABEL_DEADLINE: Duration = Duration::from_secs(30);

/// How long the ledger of alice is watched once her view and her route are in place. A dial for the
/// new member (a `PeerInfo` dial, a probe, a courtesy dial) starts within seconds of the roster
/// entry, and no state shows that none will come, so the absence of a dial needs a window. The
/// ledger is read every 500 ms in it, and a connection beyond the units fails the run at once.
const WATCH: Duration = Duration::from_secs(10);

/// Why the ledger of a node at its cap of 2 holds a connection beyond its units, or `None` when it
/// holds none: no unit over the cap, no peer with a connection or a session that took no unit, and
/// no peer connected besides the units. A dial for the new member (a `PeerInfo` dial, a probe, a
/// courtesy dial) would take a third unit, or it would leave an extra.
fn beyond_the_units(snapshot: &TopologySnapshot) -> Option<String> {
    let flagged = snapshot.peers.iter().filter(|link| link.extra);
    let extras: Vec<&str> = flagged.map(|link| link.endpoint.as_str()).collect();
    let held = (
        snapshot.direct_units,
        snapshot.over_ceiling,
        snapshot.connected_peers,
    );
    if held == (2, 0, 2) && extras.is_empty() {
        None
    } else {
        Some(format!(
            "units, over the cap and connected peers are {held:?}, extras {extras:?}: {snapshot:?}"
        ))
    }
}

#[test]
fn a_node_at_its_cap_dials_nobody_for_a_new_member_and_pins_the_first_send() {
    let guard = habilis_network_test_tracing::init_capturing(
        "habilis_network::transport=debug,habilis_network::gossip=debug",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = net::test_relay::spawn_plain().await.expect("local relay");
        let list = vec![Transport::Udp, Transport::WebRtc, Transport::Multihop];
        let alice = Member::create("alice", &relay, list, 2).await;
        let bob = Member::join("bob", &alice).await;
        let carol = Member::join("carol", &alice).await;
        assert!(
            rosters_hold(&[&alice, &bob, &carol], 2, Duration::from_mins(1)).await,
            "the three members never formed a mesh"
        );
        let started = Instant::now();
        loop {
            let (units, over) = alice.direct_units().await;
            if units == 2 && over == 0 {
                break;
            }
            assert!(
                started.elapsed() < STEP_DEADLINE,
                "alice never filled her ceiling: {}",
                counters_of(&[("alice", &alice)]).await
            );
            time::sleep(Duration::from_millis(500)).await;
        }
        habilis_network_test_tracing::clear_captured_logs();

        // The new member comes after the ceiling of alice is full.
        let dave = Member::join("dave", &alice).await;
        assert!(
            rosters_hold(&[&alice, &bob, &carol, &dave], 3, Duration::from_mins(1)).await,
            "the four members never formed a mesh"
        );
        habilis_network_test_tracing::allow_warn(STUCK_TARGET, STUCK_TEXT);
        habilis_network_test_tracing::allow_warn(STUCK_TARGET, RELAY_CELL_TEXT);

        // The state to wait for is the one in which alice has done all that she does for the new
        // member: her gossip view holds 2 of the 3 others, and her topology holds a route to the
        // third. The ledger is read at each step of the wait, so a dial that takes a unit, or leaves
        // an extra, fails the run when it happens and not only at the end.
        let waiting_since = Instant::now();
        let target: String = loop {
            let snapshot = alice.snapshot().await;
            if let Some(why) = beyond_the_units(&snapshot) {
                panic!("alice holds a connection for the new member: {why}");
            }
            let neighbors = neighbor_nicks(&snapshot);
            let others = ["bob", "carol", "dave"]
                .into_iter()
                .filter(|nick| !neighbors.contains(nick));
            let others: Vec<&str> = others.collect();
            if let [only] = others[..]
                && alice.has_route(only).await
            {
                break only.to_owned();
            }
            assert!(
                waiting_since.elapsed() < STEP_DEADLINE,
                "alice never held a view of 2 neighbors and a route to the third: {}",
                counters_of(&[("alice", &alice)]).await
            );
            time::sleep(Duration::from_millis(500)).await;
        };
        let watching_since = Instant::now();
        while watching_since.elapsed() < WATCH {
            let snapshot = alice.snapshot().await;
            if let Some(why) = beyond_the_units(&snapshot) {
                panic!("alice holds a connection for the new member: {why}");
            }
            time::sleep(Duration::from_millis(500)).await;
        }
        let logs = habilis_network_test_tracing::captured_logs();
        // A new gossip neighbor takes the unit of a cached peer: that eviction is the design. An
        // eviction that a connection or a session caused is a dial that took a unit at the cap.
        let lines: Vec<&str> = logs.lines().collect();
        let by_dial = |line: &&str| line.contains(EVICTION_LINE) && !line.contains(NEIGHBOR_CAUSE);
        if let Some(index) = lines.iter().position(by_dial) {
            let from = index.saturating_sub(14);
            panic!(
                "a dial evicted a connection at a ceiling for the new member; the log before it:\n{}",
                lines[from..=index].join("\n")
            );
        }

        // The peer of the test is the one that alice holds no connection to: the member that is no
        // neighbor of hers.
        let mut members = [("bob", bob), ("carol", carol), ("dave", dave)];
        let (_, member) = members
            .iter_mut()
            .find(|(nick, _)| *nick == target)
            .unwrap_or_else(|| panic!("no member {target}"));
        assert!(
            route_known(&alice, &target).await,
            "alice never learned a route to {target}: {}",
            counters_of(&[("alice", &alice)]).await
        );
        assert!(
            delivered(&alice, member, &target, "to the third member").await,
            "the frame of alice never reached {target}: {}",
            counters_of(&[("alice", &alice)]).await
        );
        // The peer is pinned while its connection is open, and a send in flight keeps a unit
        // over the ceiling until it ends, so the state is read once it has settled. The path label
        // of the snapshot comes from a path watcher that a pair may not have, so it is not read.
        let settling_since = Instant::now();
        let mut after = alice.snapshot().await;
        while !is_pinned_at_the_ceiling(&after, &target)
            && settling_since.elapsed() < LABEL_DEADLINE
        {
            time::sleep(Duration::from_millis(500)).await;
            after = alice.snapshot().await;
        }
        assert!(
            is_pinned_at_the_ceiling(&after, &target),
            "the send of alice to {target} did not pin it with her units at 2 of 2: {after:?}"
        );

        for (_, held) in members {
            let _ = held.membership.node.leave().await;
        }
        let _ = alice.membership.node.leave().await;
    });
}
