//! A node at its cap of direct connections reaches a new peer through a connected peer, and it
//! evicts nobody.
//!
//! Ten native members on a local relay, with the list `udp,webrtc,multihop`. Every member has the
//! minimum cap of 8, so alice holds 8 gossip neighbors and one member is left out of her view. The
//! gossip view is random, so the test reads which 8: the member outside her view is the far one,
//! and a neighbor of alice that holds the far member in its own view is the hub. IP and `WebRTC`
//! are cut between the far member and each of alice and the 7 other neighbors, on the application
//! endpoints and on the underlays, and the relay too between alice and the far member. A send from
//! alice to the far member has no free unit, and the route alice > hub > far exists, so the dial
//! must take that route and pin the peer.
//!
//! The setup has up to 3 tries. A try is void only when the far member is a neighbor of alice at
//! the read before the send, while the frames go, or at the read of the snapshot that the asserts
//! use: the view of a node changes during a run, and a member that the hub reaches can enter it.
//! A void try prints both views and leaves all its members, and the next try builds a new mesh. The
//! asserts run in full on the first try that held, and the eviction assert reads the log of that
//! try only. Three void tries fail the test.
//!
//! What the run shows:
//! - both frames arrive, and bob forwards cells for them;
//! - no member evicts a connection at its ceiling;
//! - the snapshot of alice shows dave on the multihop path, pinned, with bob as the first hop, and
//!   9 connections of the 16 that twice the cap allows;
//! - alice counts 8 direct units, none over the cap, after the send. A direct dial to dave would
//!   take a ninth unit, and an eviction would take one of her neighbors.
//!
//! What it does not show: that the connection of alice to dave carries no IP path. The unit tests
//! of the pin set and of the selectors do. This test shows that the node does not dial direct.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

mod until_known;

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{
    self, Blocking, Inbound, Inspect, InspectHost, InspectTest, Membership, Messaging, Request,
    Routing,
};
use habilis_network::net;
use habilis_network::net::Bind;
use habilis_network::protocol::{Lookup, Transport};
use habilis_network::topology::{PathLabel, TopologySnapshot};
use habilis_network::util::tuning::MIN_MAX_CONNECTIONS;
use habilis_network_iroh_multihop_transport::MultihopCounters;
use habilis_network_iroh_webrtc_transport::Rung;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time;

/// The cap of every member: the minimum. It sets the size of the gossip view of each one, so alice
/// holds a full view when she has this many neighbors, and a mesh needs more members than the cap.
const CAP: usize = MIN_MAX_CONNECTIONS;
/// The joiners. Alice and these 9 make 10 members, one more than the cap plus the creator.
const JOINERS: [&str; 9] = [
    "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy",
];
/// Long enough for the cuts to take effect, for the gossip view to settle, and for the topology to
/// hold the route.
const STEP_DEADLINE: Duration = Duration::from_mins(3);
/// The WARN that the underlay logs for a hop that stays on the relay for longer than the stuck limit.
const STUCK_TARGET: &str = "habilis_network_iroh_multihop_transport::underlay";
const STUCK_TEXT: &str =
    "multihop underlay stays on the relay: this hop is not advertised as a link";
/// How long the snapshot may take to show the path of a peer after its first frame.
const LABEL_DEADLINE: Duration = Duration::from_secs(60);
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
        let options: membership::JoinOptions = membership::JoinOptions::default()
            .bind(Bind::Loopback)
            .nick(Some(nick.to_owned()))
            .lookup(vec![Lookup::Relay]);
        let options = options
            .transport(transport)
            .relay_urls(vec![relay.to_string()]);
        let options = options.max_connections(max_connections);
        Self::open(&options).await
    }

    async fn join(nick: &str, creator: &Self, max_connections: usize) -> Self {
        let mesh = creator.membership.node.mesh_id().to_string();
        let options: membership::JoinOptions = membership::JoinOptions::default()
            .bind(Bind::Loopback)
            .nick(Some(nick.to_owned()))
            .mesh(Some(mesh));
        let options = options.max_connections(max_connections);
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

    /// The endpoint id of this member on the application endpoint.
    async fn endpoint_id(&self) -> iroh::EndpointId {
        self.membership
            .request(|reply| Request::InspectTest(InspectTest::EndpointId { reply }))
            .await
            .expect("the loop answers")
    }

    /// The short endpoint id of this member, as the eviction lines of the transport name it.
    async fn short_id(&self) -> String {
        let id = self
            .membership
            .request(|reply| Request::InspectTest(InspectTest::EndpointId { reply }))
            .await
            .expect("the loop answers");
        id.fmt_short().to_string()
    }

    /// How many dials this member made to the member `peer`, direct or through a route.
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

/// The far member and each member of `others` have no direct path left: `WebRTC` refused on both
/// ends, and IP blocked on both ends, on the application endpoints and on the underlays. The block
/// of a node REPLACES its earlier set, so each node gets one call with every port it must not
/// reach: the far member the union of the ports of all `others`, and each other member the ports
/// of the far member.
async fn cut_far_from(far: &Member, far_nick: &str, others: &[(&str, &Member)]) {
    let mut far_app_ports: Vec<u16> = Vec::new();
    let mut far_underlay_ports: Vec<u16> = Vec::new();
    for (other_nick, other) in others {
        other.deny_peer(far_nick).await;
        far.deny_peer(other_nick).await;
        far_app_ports.extend(other.ports());
        far_underlay_ports.extend(other.underlay_ports());
        other.block_ip_to(far.ports()).await;
        habilis_network_iroh_webrtc_transport::block_ip_to(
            other.underlay_id(),
            far.underlay_ports(),
        );
    }
    far.block_ip_to(far_app_ports).await;
    habilis_network_iroh_webrtc_transport::block_ip_to(far.underlay_id(), far_underlay_ports);
}

/// The relay too, both ways, on the application endpoints and on the underlays: the pair has no
/// direct path and no relay path. The far member can still enter the view of alice over a route
/// through the hub, and then the try is void.
async fn cut_relay_between(first: &Member, second: &Member) {
    for (from, to) in [(first, second), (second, first)] {
        habilis_network_iroh_webrtc_transport::block_rung_to(
            from.endpoint_id().await,
            Rung::Relay,
            to.endpoint_id().await,
            true,
        );
        habilis_network_iroh_webrtc_transport::block_rung_to(
            from.underlay_id(),
            Rung::Relay,
            to.underlay_id(),
            true,
        );
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

/// Whether the first hop of the route to `far` is `hub`. The cut takes a moment to age the
/// multihop link between the far member and the other neighbor out of the topology, and until it
/// does the route can go through the other neighbor.
fn first_hop_is(snapshot: &TopologySnapshot, far: &str, hub: &str) -> bool {
    let find = |nick: &str| {
        let links = snapshot.peers.iter();
        links
            .into_iter()
            .find(|link| link.nickname.as_deref() == Some(nick))
    };
    match (find(far), find(hub)) {
        (Some(far_link), Some(hub_link)) => {
            far_link.via.as_deref() == Some(hub_link.endpoint.as_str())
        }
        _ => false,
    }
}

/// Whether the snapshot lists `nick` as a pinned peer.
fn is_pinned(snapshot: &TopologySnapshot, nick: &str) -> bool {
    let found = snapshot
        .peers
        .iter()
        .find(|link| link.nickname.as_deref() == Some(nick));
    found.is_some_and(|link| link.pinned)
}

/// Whether the snapshot lists `nick` on the multihop path.
fn is_on_multihop(snapshot: &TopologySnapshot, nick: &str) -> bool {
    let found = snapshot
        .peers
        .iter()
        .find(|link| link.nickname.as_deref() == Some(nick));
    found.is_some_and(|link| link.path == PathLabel::Multihop)
}

/// The snapshot of alice: dave is on the multihop path, pinned, with bob as the first hop, and the
/// pinned connection counts toward twice the cap and toward no direct unit.
fn assert_far_is_pinned_through_hub(snapshot: &TopologySnapshot, far: &str, hub: &str) {
    let link_of = |nick: &str| {
        let found = snapshot
            .peers
            .iter()
            .find(|link| link.nickname.as_deref() == Some(nick));
        found.unwrap_or_else(|| panic!("the snapshot of alice has no peer {nick}: {snapshot:?}"))
    };
    let (dave_link, bob_link) = (link_of(far), link_of(hub));
    assert_eq!(
        dave_link.path,
        PathLabel::Multihop,
        "dave is on the multihop path: {snapshot:?}"
    );
    assert!(dave_link.pinned, "dave is pinned: {snapshot:?}");
    assert_eq!(
        dave_link.via.as_deref(),
        Some(bob_link.endpoint.as_str()),
        "the first hop to dave is bob: {snapshot:?}"
    );
    assert_eq!(
        (
            snapshot.max_connections,
            snapshot.direct_units,
            snapshot.over_ceiling
        ),
        (CAP, CAP, 0),
        "alice is at its cap and not over it: {snapshot:?}"
    );
    assert_eq!(
        (snapshot.connected_peers, snapshot.connected_cap),
        (CAP + 1, 2 * CAP),
        "the pinned connection counts toward 2N: {snapshot:?}"
    );
}

/// Alice holds a full ceiling: `CAP` gossip neighbors for `CAP` units. The gossip view is random, so
/// the test waits until the same neighbors stay for three reads, and the member of `nicks` that is
/// not one of them is the far one.
async fn far_member(alice: &Member, nicks: &[&str]) -> String {
    let started = Instant::now();
    let mut previous: Vec<String> = Vec::new();
    let mut stable = 0_u32;
    loop {
        let snapshot = alice.snapshot().await;
        let names: Vec<&str> = neighbor_nicks(&snapshot);
        let neighbors: Vec<String> = names.iter().map(|nick| (*nick).to_owned()).collect();
        let settled = snapshot.direct_units == CAP
            && snapshot.over_ceiling == 0
            && neighbors.len() == CAP
            && neighbors == previous;
        stable = if settled { stable + 1 } else { 0 };
        if stable >= 3 {
            let far = nicks.iter().find(|nick| !names.contains(nick));
            return far
                .expect("nine joiners and eight neighbors leave one far")
                .to_string();
        }
        assert!(
            started.elapsed() < STEP_DEADLINE,
            "alice never settled with {CAP} neighbors ({neighbors:?})"
        );
        previous = neighbors;
        time::sleep(Duration::from_millis(500)).await;
    }
}

/// How long the test waits for a hub: a neighbor of alice that is also a gossip neighbor of the far
/// member. A mesh of 10 at cap 8 leaves each node one member outside its view, so the shape is not
/// fixed by the size and the run reads it.
const HUB_DEADLINE: Duration = Duration::from_mins(1);

/// A neighbor of alice that holds the far member in its own view. A run that never gets one fails,
/// with both views in the text: a skip in silence proves nothing.
async fn hub_of(alice: &Member, joined: &[(&str, Member)], far: &str) -> String {
    let started = Instant::now();
    loop {
        let alice_view = alice.snapshot().await;
        let alice_names: Vec<&str> = neighbor_nicks(&alice_view);
        let mut views: Vec<String> = Vec::new();
        for (nick, member) in joined {
            if *nick == far || !alice_names.contains(nick) {
                continue;
            }
            let view = member.snapshot().await;
            let names: Vec<&str> = neighbor_nicks(&view);
            if names.contains(&far) {
                return (*nick).to_owned();
            }
            views.push(format!("{nick}: {names:?}"));
        }
        assert!(
            started.elapsed() < HUB_DEADLINE,
            "no hub: no neighbor of alice holds {far} in its view. alice: {alice_names:?}; \
             neighbors of alice: {views:?}"
        );
        time::sleep(Duration::from_millis(500)).await;
    }
}

/// The premise at a read: the far member is no neighbor of alice, and the hub still holds it.
/// `Err` names both views: the try is void, not failed.
async fn premise_holds(
    alice: &Member,
    hub: &Member,
    far: &str,
    hub_nick: &str,
    when: &str,
) -> Result<(), String> {
    let alice_view = alice.snapshot().await;
    let hub_view = hub.snapshot().await;
    let alice_names: Vec<&str> = neighbor_nicks(&alice_view);
    let hub_names: Vec<&str> = neighbor_nicks(&hub_view);
    if !alice_names.contains(&far) && hub_names.contains(&far) {
        return Ok(());
    }
    Err(format!(
        "premise void {when}: {far} must be no neighbor of alice and a neighbor of {hub_nick}. \
         alice: {alice_names:?}; {hub_nick}: {hub_names:?}"
    ))
}

/// The most tries of the setup. A try is void only when the premise read finds the far member in
/// the view of alice: the view of a node changes during a run, and a member that a hub reaches
/// can be taken into it. A void try ends its members and the next try builds a new mesh.
const TRIES: u32 = 3;

/// Every member of a try leaves.
async fn end_try(alice: Member, hub: Member, far: Member, joined: Vec<(&str, Member)>) {
    let mut everyone: Vec<Member> = vec![alice, hub, far];
    everyone.extend(joined.into_iter().map(|(_, member)| member));
    for member in everyone {
        let _ = member.membership.node.leave().await;
    }
}

/// No dial for the far member took a unit at the ceiling of alice. A new gossip neighbor takes the
/// unit of a cached peer: that is the design. An eviction that a connection or a session caused is
/// a dial that took a unit at the cap. Only alice is bound by the rule: a joiner that sends to a
/// peer with no route dials direct and evicts, as a send always did.
async fn assert_no_dial_evicted(alice: &Member, logs: &str) {
    let evictions = logs.lines().filter(|line| line.contains(EVICTION_LINE));
    // Each eviction line names the victim and the newcomers that took the units.
    let eviction_lines = logs.lines().filter(|line| line.contains(EVICTION_LINE));
    for line in eviction_lines {
        assert!(
            line.contains("victim=") && line.contains("newcomers="),
            "an eviction line names the victim and the newcomers: {line}"
        );
    }
    let alice_local = format!("local={}", alice.short_id().await);
    let by_dial: Vec<&str> = evictions
        .filter(|line| line.contains(&alice_local) && !line.contains(NEIGHBOR_CAUSE))
        .collect();
    assert!(
        by_dial.is_empty(),
        "a dial evicted a direct connection at its ceiling: {}",
        by_dial.join("\n")
    );
}

/// The snapshot of alice once it shows the far member pinned on the multihop path through the hub,
/// or after the label deadline, or at once when the far member is a neighbor of alice.
async fn snapshot_with_the_pin(alice: &Member, far_nick: &str, hub_nick: &str) -> TopologySnapshot {
    // The path of a peer reaches the snapshot when its path watcher reports it, a moment after
    // the first frame arrives.
    // A frame that goes while alice holds no connection to dave dials through bob and pins dave,
    // so the frames go on until the snapshot shows the pin.
    let label_since = Instant::now();
    let mut snapshot = alice.snapshot().await;
    let mut nudge = 0_u32;
    while !(is_on_multihop(&snapshot, far_nick)
        && is_pinned(&snapshot, far_nick)
        && first_hop_is(&snapshot, far_nick, hub_nick))
        && label_since.elapsed() < LABEL_DEADLINE
        && !neighbor_nicks(&snapshot).contains(&far_nick)
    {
        nudge += 1;
        let text = format!("alice nudges dave {nudge}");
        let _ = alice.send(far_nick, &text).await;
        time::sleep(Duration::from_millis(500)).await;
        snapshot = alice.snapshot().await;
    }
    snapshot
}

/// One try of the setup and, when the premise held at both reads, all the asserts.
async fn run_try(relay: &RelayUrl) -> Result<(), String> {
    // The eviction assert judges the mesh of this try: the log before the mark belongs to a
    // mesh that an earlier void try threw away.
    let mark = habilis_network_test_tracing::captured_logs().len();
    let list = vec![Transport::Udp, Transport::WebRtc, Transport::Multihop];
    let mut alice = Member::create("alice", relay, list, CAP).await;
    let mut joined: Vec<(&str, Member)> = Vec::new();
    for nick in JOINERS {
        joined.push((nick, Member::join(nick, &alice, CAP).await));
    }
    let mut everyone: Vec<&Member> = vec![&alice];
    everyone.extend(joined.iter().map(|(_, member)| member));
    assert!(
        rosters_hold(&everyone, JOINERS.len(), Duration::from_mins(1)).await,
        "the ten members never formed a mesh"
    );
    let nicks: Vec<&str> = joined.iter().map(|(nick, _)| *nick).collect();
    let far_nick: String = far_member(&alice, &nicks).await;
    let far_nick: &str = &far_nick;
    let position = joined
        .iter()
        .position(|(nick, _)| *nick == far_nick)
        .expect("the far member joined");
    let hub_name: String = hub_of(&alice, &joined, far_nick).await;
    let (_, mut dave) = joined.remove(position);
    let hub_position = joined
        .iter()
        .position(|(nick, _)| *nick == hub_name)
        .expect("the hub joined");
    let (hub_nick, bob) = joined.remove(hub_position);

    // The far member keeps the hub and loses alice and the 7 other neighbors, so that the only
    // way from alice to it is alice > hub > far.
    let mut others: Vec<(&str, &Member)> = vec![("alice", &alice)];
    others.extend(joined.iter().map(|(nick, member)| (*nick, member)));
    cut_far_from(&dave, far_nick, &others).await;
    cut_relay_between(&alice, &dave).await;
    habilis_network_test_tracing::allow_warn(STUCK_TARGET, STUCK_TEXT);
    habilis_network_test_tracing::allow_relay_cell_refusal();

    // The first frame goes while no route may be known yet: a send that finds no route
    // dials as it always did, and the test waits for a route before it counts.
    if let Err(views) = premise_holds(&alice, &bob, far_nick, hub_nick, "at the send").await {
        end_try(alice, bob, dave, joined).await;
        return Err(views);
    }
    assert!(
        route_known(&alice, far_nick).await,
        "alice never learned a route to dave: {}",
        counters_of(&[("alice", &alice), (hub_nick, &bob), (far_nick, &dave)]).await
    );
    assert!(
        delivered(&alice, &mut dave, far_nick, "to dave through bob").await,
        "the frame of alice never reached dave: {}",
        counters_of(&[("alice", &alice), (hub_nick, &bob), (far_nick, &dave)]).await
    );
    let after_send = alice.direct_units().await;
    assert_eq!(
        after_send,
        (CAP, 0),
        "alice took a unit or evicted a peer for dave: {}",
        counters_of(&[("alice", &alice), (hub_nick, &bob), (far_nick, &dave)]).await
    );

    // Both ways. The cut takes a moment to remove a direct hop between alice and dave, and
    // until it does a frame goes the short way. Frames go on until bob has forwarded cells
    // for them.
    let before = bob.forwarded_cells().await;
    let forwarding_since = Instant::now();
    let mut round = 0_u32;
    while bob.forwarded_cells().await == before {
        // The far member in the view of alice sends the frames the short way: the same event as
        // before the send, so the try is void and not failed after the step limit.
        if let Err(views) =
            premise_holds(&alice, &bob, far_nick, hub_nick, "while the frames go").await
        {
            end_try(alice, bob, dave, joined).await;
            return Err(views);
        }
        assert!(
            forwarding_since.elapsed() < STEP_DEADLINE,
            "bob forwarded no cell for the frames of alice and dave: {}",
            counters_of(&[("alice", &alice), (hub_nick, &bob), (far_nick, &dave)]).await
        );
        round += 1;
        let reply = format!("dave answers alice {round}");
        assert!(
            delivered(&dave, &mut alice, "alice", &reply).await,
            "the answer of dave never reached alice: {}",
            counters_of(&[("alice", &alice), (hub_nick, &bob), (far_nick, &dave)]).await
        );
        let text = format!("alice to dave {round}");
        assert!(
            delivered(&alice, &mut dave, far_nick, &text).await,
            "the frame of alice never reached dave: {}",
            counters_of(&[("alice", &alice), (hub_nick, &bob), (far_nick, &dave)]).await
        );
        time::sleep(Duration::from_secs(1)).await;
    }
    let after_answer = alice.direct_units().await;
    assert_eq!(
        after_answer,
        (CAP, 0),
        "the answer of dave changed the units of alice: {}",
        counters_of(&[("alice", &alice), (hub_nick, &bob), (far_nick, &dave)]).await
    );

    let snapshot = snapshot_with_the_pin(&alice, far_nick, hub_nick).await;
    // The second premise read is the snapshot that the asserts read: a far member that the
    // view of alice took in during the run makes the try void.
    let alice_names: Vec<&str> = neighbor_nicks(&snapshot);
    if alice_names.contains(&far_nick) {
        let views = format!(
            "premise void at the arrival: {far_nick} is a neighbor of alice. alice: {alice_names:?}"
        );
        end_try(alice, bob, dave, joined).await;
        return Err(views);
    }
    assert_far_is_pinned_through_hub(&snapshot, far_nick, hub_nick);
    assert!(
        alice.dials_to(far_nick).await >= 1,
        "a pinned connection is the result of a dial of alice, and the pool counts it"
    );

    let captured = habilis_network_test_tracing::captured_logs();
    assert_no_dial_evicted(&alice, &captured[mark..]).await;

    end_try(alice, bob, dave, joined).await;
    Ok(())
}

#[test]
fn a_node_at_its_cap_reaches_a_new_peer_through_a_connected_one_and_evicts_nobody() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network::transport=info");
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = net::test_relay::spawn_plain().await.expect("local relay");
        let mut voids: Vec<String> = Vec::new();
        for attempt in 1..=TRIES {
            match run_try(&relay).await {
                Ok(()) => {
                    println!("TRIES this run needed: {attempt}");
                    return;
                }
                Err(views) => {
                    println!("TRY {attempt} void: {views}");
                    voids.push(views);
                }
            }
        }
        panic!("premise void in {TRIES} tries: {voids:?}");
    });
}
