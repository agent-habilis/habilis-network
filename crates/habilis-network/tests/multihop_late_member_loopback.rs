//! A node at its cap learns a new member, and dials nobody and evicts nobody for it. A send to a
//! member that it holds no connection to then pins the peer on a multihop route.
//!
//! Four native members on a local relay, with the list `udp,webrtc,multihop`. Alice has a cap of 2.
//! Bob and carol join with her, and dave joins after her ceiling is full. No path is cut: the rule
//! does not depend on a path that is missing, only on the ceiling being full. The gossip view of
//! alice holds 2 of the 3 others, and the third is the peer of the test.
//!
//! The run shows, after the roster of alice holds the third member and a settle time:
//! - alice counts 2 direct units, none over the cap, and no more connected peers than the total
//!   cap: a dial for the new member (a `PeerInfo` dial, a probe, a courtesy dial) would take a
//!   third unit or evict one. A connection that takes no unit is legal and is not checked, such as
//!   the connection of a former neighbor that the view change demoted to an extra;
//! - no member logged an eviction at its ceiling;
//! - a send of alice to the third member arrives, and her snapshot shows it pinned on the
//!   multihop path.
#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{
    self, Inbound, Inspect, InspectHost, InspectTest, Membership, Messaging, Request, Routing,
};
use habilis_network::net;
use habilis_network::net::Bind;
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
            .bind(Bind::Loopback)
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
            .bind(Bind::Loopback)
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

    /// How many dials this member made to `peer` since it started, direct or through a route.
    async fn dials_to(&self, peer: &str) -> u64 {
        self.membership
            .request(|reply| {
                Request::InspectTest(InspectTest::DialsTo {
                    peer: peer.to_owned(),
                    reply,
                })
            })
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

/// The member that is no gossip neighbor of alice in `snapshot`, when there is exactly one.
fn the_third_member(snapshot: &TopologySnapshot) -> Option<&'static str> {
    let neighbors = neighbor_nicks(snapshot);
    let others = ["bob", "carol", "dave"]
        .into_iter()
        .filter(|nick| !neighbors.contains(nick));
    let others: Vec<&'static str> = others.collect();
    match others[..] {
        [only] => Some(only),
        _ => None,
    }
}

/// Whether the snapshot shows `nick` held within the cap: pinned with no unit for it, or a gossip
/// neighbor, because the random view can make the third member a neighbor between the choice of the
/// peer and the send, and a neighbor needs no pin. The units are the cap and none is over it.
fn is_held_within_the_cap(snapshot: &TopologySnapshot, nick: &str) -> bool {
    let wanted = Some(nick);
    let found = snapshot
        .peers
        .iter()
        .find(|link| link.nickname.as_deref() == wanted);
    let held = found.is_some_and(|link| link.neighbor || link.pinned);
    held && snapshot.direct_units == 2 && snapshot.over_ceiling == 0
}

/// How long the ledger may take to settle after the first frame of a send.
const LABEL_DEADLINE: Duration = Duration::from_secs(30);

/// How long the ledger of alice is watched once her view and her route are in place. A dial for the
/// new member (a `PeerInfo` dial, a probe, a courtesy dial) starts within seconds of the roster
/// entry, and no state shows that none will come, so the absence of a dial needs a window. The
/// ledger is read every 500 ms in it, and a connection beyond the units fails the run at once.
const WATCH: Duration = Duration::from_secs(10);

/// The dials that `alice` made since she started, to each of the other three members, as a nickname
/// and a count. A gossip link to a neighbor is a dial too, and a unit: alice dialed bob and carol
/// for their links while her ceiling had room, and she dials a new neighbor that the view takes
/// in. So a test reads the counts once the ceiling is full, and a later dial is allowed only to a
/// member that she held as a neighbor or as a pinned peer.
async fn dials_made(alice: &Member) -> Vec<(&'static str, u64)> {
    let mut dials: Vec<(&'static str, u64)> = Vec::new();
    for nick in ["bob", "carol", "dave"] {
        dials.push((nick, alice.dials_to(nick).await));
    }
    dials
}

/// The members that `now` shows more dials to than `at_the_cap` did, and that alice holds now
/// as a `loose` connection: neither a gossip neighbor nor a pinned peer. A dial to a neighbor is a
/// link of the view, and a dial to a pinned peer is the dial of a send on a multihop route (the
/// engine's own unicast frames are sends too, and one comes about 10 s after a join). A dial that
/// ends in a connection of neither kind is a direct dial for a member that no send asked for. A dial
/// that has not connected yet, or that failed, holds nothing and is not counted.
fn dialed_strangers<'a>(
    now: &[(&'a str, u64)],
    at_the_cap: &[(&str, u64)],
    loose: &[&str],
) -> Vec<&'a str> {
    let pairs = now.iter().zip(at_the_cap);
    let grown = pairs.filter(|(after, before)| after.1 > before.1);
    let nicks = grown.map(|(after, _)| after.0);
    nicks.filter(|nick| loose.contains(nick)).collect()
}

/// The dials of alice now, and the members among them that she holds as a loose connection. A
/// pinned dial under load can take seconds to connect and show its flag, and a gossip link shows
/// after its connection, so a member must stay loose for 10 s to count.
async fn dialed_without_a_hold(
    alice: &Member,
    at_the_cap: &[(&str, u64)],
) -> (Vec<(&'static str, u64)>, Vec<&'static str>) {
    let started = Instant::now();
    loop {
        let dials = dials_made(alice).await;
        let snapshot = alice.snapshot().await;
        let loose = loose_nicks(&snapshot);
        let strangers = dialed_strangers(&dials, at_the_cap, &loose);
        if strangers.is_empty() || started.elapsed() >= Duration::from_secs(10) {
            return (dials, strangers);
        }
        time::sleep(Duration::from_millis(250)).await;
    }
}

/// The nicknames in `snapshot` that alice holds as a connection that is neither a gossip neighbor
/// nor a pinned peer.
fn loose_nicks(snapshot: &TopologySnapshot) -> Vec<&str> {
    let loose = snapshot
        .peers
        .iter()
        .filter(|link| !link.neighbor && !link.pinned);
    loose.filter_map(|link| link.nickname.as_deref()).collect()
}

/// Why the ledger of a node at its cap of 2 took a unit for the new member, or `None` when it did
/// not: the units and the units over the cap must be exactly 2 and 0, and the peers that hold any
/// connection must not pass the total cap. A connection that takes no unit is legal and is not
/// checked: the connection of a former gossip neighbor is demoted to an extra when the view changes
/// (CI saw bob so, when dave took his place), the newcomer may dial alice, and a dial with a route
/// pins its peer. A dial for the new member that takes a unit shows as a third unit, or as an
/// eviction in the log, and both fail the run.
fn took_a_unit(snapshot: &TopologySnapshot) -> Option<String> {
    let held = (snapshot.direct_units, snapshot.over_ceiling);
    let within = snapshot.connected_peers <= snapshot.connected_cap;
    if held == (2, 0) && within {
        None
    } else {
        Some(format!(
            "units and over the cap are {held:?}, connected peers {} of {}: {snapshot:?}",
            snapshot.connected_peers, snapshot.connected_cap
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
        let dials_at_the_cap = dials_made(&alice).await;

        // The new member comes after the ceiling of alice is full.
        let dave = Member::join("dave", &alice).await;
        assert!(
            rosters_hold(&[&alice, &bob, &carol, &dave], 3, Duration::from_mins(1)).await,
            "the four members never formed a mesh"
        );
        habilis_network_test_tracing::allow_warn(STUCK_TARGET, STUCK_TEXT);
        habilis_network_test_tracing::allow_relay_cell_refusal();

        // The state to wait for is the one in which alice has done all that she does for the new
        // member: her gossip view holds 2 of the 3 others, and her topology holds a route to the
        // third. The ledger is read at each step of the wait, so a dial that takes a unit fails the run when
        // it happens and not only at the end.
        let waiting_since = Instant::now();
        let target: String = loop {
            let snapshot = alice.snapshot().await;
            if let Some(why) = took_a_unit(&snapshot) {
                panic!("alice took a unit for the new member: {why}");
            }
            if let Some(only) = the_third_member(&snapshot)
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
            if let Some(why) = took_a_unit(&snapshot) {
                panic!("alice took a unit for the new member: {why}");
            }
            time::sleep(Duration::from_millis(500)).await;
        }
        let (dials_now, strangers) = dialed_without_a_hold(&alice, &dials_at_the_cap).await;
        assert!(
            strangers.is_empty(),
            "alice dialed members that she holds as neither a neighbor nor a pinned peer: {strangers:?}; dials {dials_now:?}, at the cap {dials_at_the_cap:?}"
        );
        // The random view can change while alice is watched: the peer of the send is the one that is
        // no neighbor now.
        let latest = alice.snapshot().await;
        let target: String = the_third_member(&latest).map_or(target, str::to_owned);
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
        while !is_held_within_the_cap(&after, &target) && settling_since.elapsed() < LABEL_DEADLINE
        {
            time::sleep(Duration::from_millis(500)).await;
            after = alice.snapshot().await;
        }
        assert!(
            is_held_within_the_cap(&after, &target),
            "the send of alice to {target} was neither pinned nor a neighbor, or her units are not 2 of 2: {after:?}"
        );

        for (_, held) in members {
            let _ = held.membership.node.leave().await;
        }
        let _ = alice.membership.node.leave().await;
    });
}

#[test]
fn a_dial_that_ends_in_a_loose_connection_is_a_stranger() {
    let at_the_cap = [("bob", 1), ("carol", 1), ("dave", 0)];
    let now = [("bob", 1), ("carol", 1), ("dave", 1)];
    assert_eq!(
        dialed_strangers(&now, &at_the_cap, &["dave"]),
        ["dave"],
        "a dial to dave that left a connection of neither kind is a direct dial that no send asked for"
    );
}

#[test]
fn a_dial_that_holds_nothing_loose_is_not_a_stranger() {
    let at_the_cap = [("bob", 1), ("carol", 1), ("dave", 0)];
    let now = [("bob", 1), ("carol", 2), ("dave", 1)];
    assert!(
        dialed_strangers(&now, &at_the_cap, &[]).is_empty(),
        "a link of the view, the dial of a send and a dial that has not connected yet are allowed"
    );
}
