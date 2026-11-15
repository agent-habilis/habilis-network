//! The send ladder matrix: one test per cell of transport list, blocked rungs and
//! path of the third member. Each cell runs three real members on a local relay
//! and asserts two things after the pair has settled:
//!
//! - the rung of the selected path of alice's pooled connection to bob is the one
//!   that `expected_rung` names for the cell (the ladder as a pure function of
//!   what the list allows and what the cell leaves available), and
//! - a directed message from alice arrives at bob, or, when no rung is left that
//!   may carry payload, does not.
//!
//! Every cell is `#[ignore]`, so that a plain `cargo test` never runs one next to
//! another test: each stands up three real members, and the cells must run one at
//! a time. The gate row of `cargo task ci` names two of them, the default list with
//! IP blocked and the cell that goes through carol, and runs them with
//! `--include-ignored --exact --test-threads=1`. `cargo task matrix` runs all of
//! them with `--include-ignored --test-threads=1`, and the nightly workflow runs
//! that task.
//!
//! The lists are the valid ones of the 16 subsets of `udp,webrtc,multihop,relay`
//! (`MeshConfig::resolve`); a test below keeps the two in step, so an invalid
//! list is never built. A cell is left out where blocking a rung that the list
//! does not have changes nothing, and `via_third` is set only where it changes
//! the path: with `IpWebRtc` blocked and `multihop` in the list but not `relay`,
//! since a selector block cannot take away a path that iroh has selected, and a hop
//! cannot be forced when the relay may carry payload. `target_full`
//! (a receiver at the cap of `WebRTC` sessions) has no cells until Phase 2.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

mod common;
use habilis_network::net;
use tokio::time;
mod until_known;

use std::time::{Duration, Instant};

use common::GOSSIP_INSTALLED;
use habilis_network::iroh::{EndpointId, RelayUrl};
use habilis_network::membership::{
    self, Blocking, Inbound, Inspect, InspectHost, InspectTest, Membership, Messaging, Request,
    Routing, Rung,
};
use habilis_network::protocol::{Lookup, MeshConfig, Transport};
use tokio::sync::mpsc::UnboundedReceiver;

/// Long enough for an ICE round, or for a multihop route to be advertised once
/// (every 15 s) and then used: the stuck edge of the pair ages out after 20 s.
const STEP_DEADLINE: Duration = Duration::from_mins(2);
const PAYLOAD_DEADLINE: Duration = Duration::from_secs(20);
/// How long the rung must stay as it is read, while the pair is being sent to, for
/// a cell to count as settled when the pair already stands on the best rung that
/// its list allows: nothing can be above it.
const SETTLE_AT_THE_TOP: Duration = Duration::from_secs(5);
/// The same for a cell whose list allows a rung above the expected one, which the
/// cell blocked. The pair leaves the relay for such a rung when the probe that goes
/// every second makes the engine open a session (`negotiate_session`) and the ICE
/// round, about 5 s, is done. That took more than 10 s in the runs that I made, with
/// a probe each second, so a lower rung that is read for less than 30 s proves
/// nothing: the engine may still be about to climb.
const SETTLE_BELOW_A_BLOCK: Duration = Duration::from_secs(30);
/// How long a message that must not arrive is given to arrive.
const REFUSAL_WINDOW: Duration = Duration::from_secs(8);

/// How long a cell that expects no rung waits for the cut to take the pair off the path it had.
const LEAVE_DIRECT_DEADLINE: Duration = Duration::from_secs(30);

/// Which rungs a cell takes away from alice, from the top of the ladder down.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Blocked {
    None,
    Ip,
    IpWebRtc,
    IpWebRtcMultihop,
    /// The gossip rung too. It can be blocked per node only, so the cut is made on every
    /// member.
    IpWebRtcMultihopGossip,
}

/// What a cell sends. Only a directed message for now; the gossip and stream
/// kinds join when their transports can be told apart in a cell.
#[derive(Clone, Copy, Debug)]
enum Kind {
    Unicast,
}

#[derive(Clone, Copy, Debug)]
struct Cell {
    transports: &'static [Transport],
    blocked: Blocked,
    kinds: &'static [Kind],
    /// Alice and bob also lose the direct link between their underlays, so a
    /// multihop path must go through carol.
    via_third: bool,
    /// The receiver is at the cap of `WebRTC` sessions. Phase 2.
    target_full: bool,
}

/// A member of the three that a cell starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Who {
    Alice,
    Bob,
    Carol,
}

impl Who {
    const ALL: [Self; 3] = [Self::Alice, Self::Bob, Self::Carol];

    fn name(self) -> &'static str {
        match self {
            Self::Alice => "alice",
            Self::Bob => "bob",
            Self::Carol => "carol",
        }
    }
}

/// One cut that a cell makes before it settles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cut {
    /// IP between the two application endpoints.
    IpApp,
    /// IP between the two multihop underlays.
    IpUnderlays,
    /// The whole `WebRTC` rung of alice's application endpoint.
    WebRtcAlice,
    /// The `WebRTC` rung of bob's application endpoint toward alice.
    WebRtcBobToAlice,
    /// The whole `WebRTC` rung of bob's application endpoint. Every cell that cuts alice's rung
    /// cuts bob's too (a cell through a third member cuts `WebRtcBobToAlice` instead).
    WebRtcBob,
    /// The whole `WebRTC` rung of carol's application endpoint. The block table is per node and
    /// rung, so the cut of alice and of bob also takes the rung toward carol. Carol is cut as
    /// well, or the pair keeps the rung at carol's end only: its ends select different paths, and
    /// the path that gets no return traffic times out after 15 s.
    WebRtcCarol,
    /// The `WebRTC` rung of carol's application endpoint toward alice: the cell through a third
    /// member lets carol keep the rung toward bob.
    WebRtcCarolToAlice,
    /// The `WebRTC` rung between the two underlays, in both directions.
    WebRtcUnderlays,
    /// The whole multihop rung of alice's application endpoint.
    MultihopAlice,
    /// The whole multihop rung of bob's application endpoint. With only alice cut, bob keeps the
    /// rung and alice's path gets no return traffic, and iroh drops it: the pair flaps. A
    /// selection block at one end exists only in our test hooks, so every cell cuts both ends.
    MultihopBob,
    /// The whole multihop rung of carol's application endpoint: see `WebRtcCarol`.
    MultihopCarol,
    /// The gossip rung of alice. The block table is per node and rung, not per remote, so bob
    /// and carol are cut too: see `GossipBob` and `GossipCarol`.
    GossipAlice,
    /// The gossip rung of bob.
    GossipBob,
    /// The gossip rung of carol.
    GossipCarol,
}

impl Cut {
    /// The rung that the cut takes from an application endpoint, and from whom: the member that
    /// loses it, and the one remote that it loses it toward (`None`: toward every remote). The
    /// cuts of IP and of the underlays take no rung from a member and answer `None`.
    fn rung_cut(self) -> Option<(Rung, Who, Option<Who>)> {
        match self {
            Self::IpApp | Self::IpUnderlays | Self::WebRtcUnderlays => None,
            Self::WebRtcAlice => Some((Rung::WebRtc, Who::Alice, None)),
            Self::WebRtcBob => Some((Rung::WebRtc, Who::Bob, None)),
            Self::WebRtcCarol => Some((Rung::WebRtc, Who::Carol, None)),
            Self::WebRtcBobToAlice => Some((Rung::WebRtc, Who::Bob, Some(Who::Alice))),
            Self::WebRtcCarolToAlice => Some((Rung::WebRtc, Who::Carol, Some(Who::Alice))),
            Self::MultihopAlice => Some((Rung::Multihop, Who::Alice, None)),
            Self::MultihopBob => Some((Rung::Multihop, Who::Bob, None)),
            Self::MultihopCarol => Some((Rung::Multihop, Who::Carol, None)),
            Self::GossipAlice => Some((Rung::Gossip, Who::Alice, None)),
            Self::GossipBob => Some((Rung::Gossip, Who::Bob, None)),
            Self::GossipCarol => Some((Rung::Gossip, Who::Carol, None)),
        }
    }
}

impl Cell {
    /// What the cell cuts, in order. A cell that goes through a third member cuts
    /// the direct underlay edge on every rung that could carry it: IP, and the
    /// `WebRTC` session that an underlay may open to a neighbor of its own (the
    /// lower underlay id offers one). Left open, that edge revives and carol
    /// forwards nothing. The list of such a cell has no relay: see
    /// `no_cell_through_a_third_member_has_the_relay_in_its_list`.
    fn cuts(self) -> Vec<Cut> {
        let mut cuts = Vec::new();
        if self.blocked >= Blocked::Ip {
            cuts.push(Cut::IpApp);
        }
        if self.blocked >= Blocked::IpWebRtc {
            cuts.push(Cut::WebRtcAlice);
            if !self.via_third {
                cuts.extend([Cut::WebRtcBob, Cut::WebRtcCarol]);
            }
        }
        if self.blocked >= Blocked::IpWebRtcMultihop {
            cuts.extend([Cut::MultihopAlice, Cut::MultihopBob, Cut::MultihopCarol]);
        }
        if self.blocked >= Blocked::IpWebRtcMultihopGossip {
            cuts.extend([Cut::GossipAlice, Cut::GossipBob, Cut::GossipCarol]);
        }
        if self.via_third {
            cuts.extend([
                Cut::IpUnderlays,
                Cut::WebRtcUnderlays,
                Cut::WebRtcBobToAlice,
                Cut::WebRtcCarolToAlice,
            ]);
        }
        cuts
    }

    fn has(self, transport: Transport) -> bool {
        self.transports.contains(&transport)
    }

    /// How long the expected rung must be read before the cell counts as settled.
    fn settle(self, expected: Rung) -> Duration {
        let allowed_above = [Rung::Ip, Rung::WebRtc, Rung::Multihop, Rung::Gossip]
            .into_iter()
            .any(|rung| rung < expected && self.allows(rung));
        if allowed_above {
            SETTLE_BELOW_A_BLOCK
        } else {
            SETTLE_AT_THE_TOP
        }
    }

    /// Whether the transport list lets `rung` carry payload.
    fn allows(self, rung: Rung) -> bool {
        let transport = match rung {
            Rung::Ip => Some(Transport::Udp),
            Rung::WebRtc => Some(Transport::WebRtc),
            Rung::Multihop => Some(Transport::Multihop),
            Rung::Gossip => Some(Transport::Gossip),
            Rung::Relay => Some(Transport::Relay),
            Rung::Other | _ => None,
        };
        transport.is_some_and(|transport| self.has(transport))
    }

    /// The rung of the ladder, as a pure function: the highest rung that the
    /// list allows and that the cell leaves available. `None`: no rung may carry
    /// payload, so the pair stays unlinked for it.
    fn expected(self) -> Option<Rung> {
        habilis_network_iroh_webrtc_transport::expected_rung(
            |rung| self.allows(rung),
            |rung| match rung {
                Rung::Ip => self.blocked < Blocked::Ip,
                Rung::WebRtc => self.blocked < Blocked::IpWebRtc,
                Rung::Multihop => self.blocked < Blocked::IpWebRtcMultihop,
                Rung::Gossip => self.blocked < Blocked::IpWebRtcMultihopGossip,
                Rung::Relay => true,
                Rung::Other | _ => false,
            },
        )
    }
}

fn rung_name(rung: Rung) -> &'static str {
    match rung {
        Rung::Ip => "ip",
        Rung::WebRtc => "webrtc",
        Rung::Multihop => "multihop",
        Rung::Gossip => "gossip",
        Rung::Relay => "relay",
        Rung::Other => "other",
        _ => "unknown",
    }
}

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

    async fn create(nick: &str, relay: &RelayUrl, transport: Vec<Transport>) -> Self {
        let options = membership::JoinOptions::default()
            .nick(Some(nick.to_owned()))
            .lookup(vec![Lookup::Relay]);
        let options = options
            .transport(transport)
            .relay_urls(vec![relay.to_string()]);
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

    /// Whether this member holds a live gossip link to `peer` now: the roster names
    /// the reach of a peer `direct` only while it does.
    async fn linked_to(&self, peer: &str) -> bool {
        let json = self
            .membership
            .request(|reply| Request::Inspect(Inspect::Peers { reply }))
            .await
            .unwrap_or_default();
        let roster: Option<serde_json::Value> = serde_json::from_str(&json).ok();
        roster
            .and_then(|roster| {
                roster["peers"].as_array().map(|peers| {
                    peers
                        .iter()
                        .any(|entry| entry["nickname"] == peer && entry["reach"] == "direct")
                })
            })
            .unwrap_or(false)
    }

    /// The lane that a directed frame to `peer` takes now, as the roster names it:
    /// `relay-only` is the one where the frame is parked until a direct path is proven.
    async fn lane_to(&self, peer: &str) -> Option<String> {
        let json = self
            .membership
            .request(|reply| Request::Inspect(Inspect::Peers { reply }))
            .await
            .expect("the loop answers");
        let roster: serde_json::Value = serde_json::from_str(&json).ok()?;
        let mut entries = roster["peers"].as_array()?.iter();
        let found = entries.find(|entry| entry["nickname"] == peer);
        found.and_then(|entry| entry["transport"].as_str().map(str::to_owned))
    }

    fn ports(&self) -> Vec<u16> {
        self.membership.node.bound_ports().to_vec()
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

    async fn block_rung(&self, rung: Rung, blocked: bool) {
        self.membership
            .request(|reply| {
                Request::Blocking(Blocking::BlockRung {
                    rung,
                    blocked,
                    reply,
                })
            })
            .await
            .expect("the loop answers");
    }

    async fn block_rung_to(&self, rung: Rung, peer: &str) {
        until_known::until_peer_known(&self.membership, peer, |reply| {
            Request::Blocking(Blocking::BlockRungTo {
                rung,
                peer: peer.to_owned(),
                blocked: true,
                reply,
            })
        })
        .await;
    }

    async fn endpoint_id(&self) -> EndpointId {
        self.membership
            .request(|reply| Request::InspectTest(InspectTest::EndpointId { reply }))
            .await
            .expect("the loop answers")
    }

    /// Whether this member's multihop topology has a route to `peer` now.
    async fn has_route(&self, peer: &str) -> bool {
        self.membership
            .request(|reply| {
                Request::InspectHost(InspectHost::HasRoute {
                    peer: peer.to_owned(),
                    reply,
                })
            })
            .await
            .expect("the loop answers")
    }

    /// The multihop view of this member for the run log: see `InspectHost::RouteDiag`.
    async fn route_diag(&self) -> String {
        self.membership
            .request(|reply| Request::InspectHost(InspectHost::RouteDiag { reply }))
            .await
            .expect("the loop answers")
    }

    /// Cells that this member refused to write on a hop that stays on the relay.
    async fn refused_on_relay(&self) -> u64 {
        self.membership
            .request(|reply| Request::Routing(Routing::MultihopCounters { reply }))
            .await
            .expect("the loop answers")
            .refused_on_relay
    }

    async fn forwarded_cells(&self) -> u64 {
        self.membership
            .request(|reply| Request::Routing(Routing::ForwardedCells { reply }))
            .await
            .expect("the loop answers")
    }

    /// The rung of the selected path on this member's pooled connection to `peer`.
    async fn rung_to(&self, peer: &str) -> Option<&'static str> {
        self.membership
            .request(|reply| {
                Request::InspectTest(InspectTest::SelectedRung {
                    peer: peer.to_owned(),
                    reply,
                })
            })
            .await
            .ok()
            .flatten()
    }

    /// Wait until the selected rung to `peer` is `expected`, or fail with the last
    /// rung read. For a healthy pair, that nobody has sent to yet.
    async fn expect_rung(&self, peer: &str, expected: &str, cell: &str) {
        let started = Instant::now();
        let mut seen = None;
        while started.elapsed() < STEP_DEADLINE {
            seen = self.rung_to(peer).await;
            if seen == Some(expected) {
                return;
            }
            time::sleep(Duration::from_millis(500)).await;
        }
        panic!("cell {cell}: expected the rung {expected}, the last rung read was {seen:?}");
    }

    /// Settle the pair on `expected`, driving it as production does. The engine
    /// opens a better path only for a pair that is sent to, so a pair that is
    /// only watched stays on the relay for as long as one cares to wait, and a
    /// rung read once says nothing. A probe goes every second (a refusal is an
    /// answer, not a failure: sending is what makes the engine try a better
    /// path), and the cell is settled when `expected` has been read for
    /// `hold` in a row.
    async fn settle_on(&self, peer: &str, expected: &str, hold: Duration, cell: &str) {
        let started = Instant::now();
        let mut seen = None;
        let mut held_since: Option<Instant> = None;
        let mut probes = 0u32;
        let mut logged = None;
        while started.elapsed() < STEP_DEADLINE {
            probes += 1;
            let _ = self.send(peer, &format!("probe {cell} {probes}")).await;
            seen = self.rung_to(peer).await;
            if logged != Some(seen) {
                eprintln!(
                    "DIAG {cell}: the rung read changed to {seen:?} at probe {probes}, {:.1} s",
                    started.elapsed().as_secs_f32()
                );
                logged = Some(seen);
            }
            if seen == Some(expected) {
                if held_since.get_or_insert_with(Instant::now).elapsed() >= hold {
                    return;
                }
            } else {
                held_since = None;
            }
            time::sleep(Duration::from_secs(1)).await;
        }
        panic!(
            "cell {cell}: expected the rung {expected}, the last rung read was {seen:?} \
             after {probes} probes"
        );
    }

    /// Send a directed message. A refusal (no rung may carry payload) is an
    /// answer, not a failure of the harness.
    async fn send(&self, to: &str, text: &str) -> Result<(), String> {
        let to = membership::parse_to(Some(to)).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Messaging(Messaging::Send { to, body, reply }))
            .await
            .expect("the loop answers")
    }

    fn saw_msg(&mut self, text: &str) -> bool {
        while let Ok(message) = self.membership.inbound.try_recv() {
            self.seen_msgs.push(message);
        }
        self.seen_msgs
            .iter()
            .any(|message| message.directed && message.text == text)
    }

    async fn leave(self) {
        let _ = self.membership.node.leave().await;
    }
}

/// Wait until every member holds a live gossip link to each of the other two, read
/// at both ends of every pair. A cell is built on that triangle: a pair that starts
/// without its link is in a state that the ladder does not describe, and a cut made
/// then reads as a fault of the ladder when it is a late link.
async fn triangle_linked(members: [(&str, &Member); 3], deadline: Duration) -> bool {
    let started = Instant::now();
    loop {
        let mut all = true;
        for (name, member) in members {
            for (other, _) in members {
                if other != name {
                    all &= member.linked_to(other).await;
                }
            }
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

/// Make one cut of a cell between alice and bob. The underlay is an endpoint of
/// its own, with its own id and ports: left alone, the direct link between the two
/// underlays is a route, and no member would forward a cell.
fn block_underlay_rung(
    rung: Rung,
    underlays: [(Option<EndpointId>, Option<EndpointId>, Vec<u16>); 2],
) {
    for (from, to, _) in underlays {
        habilis_network_iroh_webrtc_transport::block_rung_to(
            from.expect("multihop is on"),
            rung,
            to.expect("multihop is on"),
            true,
        );
    }
}

async fn apply(cut: Cut, alice: &Member, bob: &Member, carol: &Member) {
    let underlays: [(Option<iroh::PublicKey>, Option<iroh::PublicKey>, Vec<u16>); 2] =
        [(alice, bob), (bob, alice)].map(|(from, to)| {
            (
                from.membership.node.underlay_id(),
                to.membership.node.underlay_id(),
                to.membership.node.underlay_ports().to_vec(),
            )
        });
    match cut {
        Cut::IpApp => {
            alice.block_ip_to(bob.ports()).await;
            bob.block_ip_to(alice.ports()).await;
        }
        Cut::IpUnderlays => {
            for (from, _, ports) in underlays {
                let from = from.expect("multihop is on");
                habilis_network_iroh_webrtc_transport::block_ip_to(from, ports);
            }
        }
        Cut::WebRtcUnderlays => block_underlay_rung(Rung::WebRtc, underlays),
        Cut::WebRtcAlice
        | Cut::WebRtcBob
        | Cut::WebRtcCarol
        | Cut::WebRtcBobToAlice
        | Cut::WebRtcCarolToAlice
        | Cut::MultihopAlice
        | Cut::MultihopBob
        | Cut::MultihopCarol
        | Cut::GossipAlice
        | Cut::GossipBob
        | Cut::GossipCarol => {
            let (rung, from, toward) = cut
                .rung_cut()
                .expect("a cut that takes a rung from a member says so in rung_cut");
            let member = match from {
                Who::Alice => alice,
                Who::Bob => bob,
                Who::Carol => carol,
            };
            match toward {
                None => member.block_rung(rung, true).await,
                Some(remote) => member.block_rung_to(rung, remote.name()).await,
            }
        }
    }
}

/// Which endpoint id alice, the member that sends, has next to bob's. The ids are random, and
/// only the lower id offers a session, so a cell that lets iroh draw them runs half of its
/// runs one way and half the other. A cell that must hold either way names the order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SenderId {
    Any,
    Higher,
    Lower,
}

impl SenderId {
    fn holds(self, alice: EndpointId, bob: EndpointId) -> bool {
        match self {
            Self::Any => true,
            Self::Higher => alice > bob,
            Self::Lower => alice < bob,
        }
    }
}

/// Stand up alice, bob and carol, again until alice has the id order that the cell names. The
/// chance is one half for each try.
async fn members(
    relay: &RelayUrl,
    transports: &[Transport],
    sender_id: SenderId,
) -> (Member, Member, Member) {
    for _ in 0..20 {
        let alice = Member::create("alice", relay, transports.to_vec()).await;
        let bob = Member::join("bob", &alice).await;
        let carol = Member::join("carol", &alice).await;
        if sender_id.holds(alice.endpoint_id().await, bob.endpoint_id().await) {
            return (alice, bob, carol);
        }
        for member in [alice, bob, carol] {
            member.leave().await;
        }
    }
    panic!("no draw of ids gave alice the order {sender_id:?} in 20 tries");
}

/// The cell starts from the full triangle of gossip links: a pair that starts without its link
/// is in a state that the ladder does not describe, and a cut made then reads as a fault of the
/// ladder when it is a late link.
async fn expect_triangle(name: &str, alice: &Member, bob: &Member, carol: &Member) {
    assert!(
        triangle_linked(
            [("alice", alice), ("bob", bob), ("carol", carol)],
            STEP_DEADLINE
        )
        .await,
        "{name}: the three members are not all gossip-linked at both ends of every pair \
         after {STEP_DEADLINE:?}: the cell starts from that triangle, so this is a failure \
         of link formation, before any cut"
    );
}

/// Send to bob until carol has forwarded a cell, or fail at the deadline.
async fn probe_until_forwarded(name: &str, alice: &Member, carol: &Member) {
    // The rung can be selected while the route is still stale, and a cell
    // goes only when something is sent: traffic goes on, so that cells take
    // the route through carol once it is there.
    let started = Instant::now();
    let mut probes = 0_u32;
    let mut last = None;
    while carol.forwarded_cells().await == 0 {
        // One line each time the picture changes, for the run log: when the
        // route to bob appeared in alice's topology, and what she rides.
        let seen = (alice.has_route("bob").await, alice.rung_to("bob").await);
        if last != Some(seen) {
            eprintln!(
                "DIAG {name}: after {:?} and {probes} probes: has_route={} rung={:?} {}",
                started.elapsed(),
                seen.0,
                seen.1,
                alice.route_diag().await
            );
            last = Some(seen);
        }
        assert!(
            started.elapsed() < STEP_DEADLINE,
            "{name}: the multihop rung is selected, but carol forwarded no cell \
             after {probes} probes (alice has a route to bob: {}, her rung: {:?}, {})",
            alice.has_route("bob").await,
            alice.rung_to("bob").await,
            alice.route_diag().await
        );
        probes += 1;
        let _ = alice
            .send("bob", &format!("forward probe {name} {probes}"))
            .await;
        time::sleep(Duration::from_secs(1)).await;
    }
}

/// The WARN of a cell whose cut pair stays on the relay: the target and a part of its text.
const STAYS_ON_RELAY: (&str, &str) = (
    "habilis_network_iroh_multihop_transport::underlay",
    "multihop underlay stays on the relay: this hop is not advertised as a link",
);

/// The cell whose WARN depends on a cell tried on the cut hop: it is logged only if some member
/// refused a cell on the relay.
const STAYS_ON_RELAY_IF_REFUSED: &str = "udp_multihop_gossip_ip_webrtc_via_third";

/// The cells that always log the WARN for the pair that the cuts leave without a direct hop.
fn stays_on_relay(name: &str) -> bool {
    matches!(
        name,
        "udp_webrtc_multihop_ip_webrtc_via_third"
            | "udp_multihop_ip_webrtc_via_third"
            | "webrtc_multihop_ip_webrtc_via_third"
    )
}

/// Runs a cell on a runtime that drops before the guard of the test.
fn run_cell(cell: Cell, name: &str, sender_id: SenderId) {
    let guard = habilis_network_test_tracing::init();
    if stays_on_relay(name) {
        guard.expect_warn(STAYS_ON_RELAY.0, STAYS_ON_RELAY.1);
    }
    habilis_network_test_tracing::run_multi_thread(guard, 4, run(cell, name, sender_id));
}

async fn run(cell: Cell, name: &str, sender_id: SenderId) {
    if cell.has(Transport::Gossip) && !GOSSIP_INSTALLED {
        eprintln!("SKIPPED {name}: the engine does not install the gossip transport yet");
        return;
    }
    assert!(
        !cell.target_full && !cell.kinds.is_empty(),
        "{name}: a cell with a full target has no test before Phase 2"
    );
    let (relay, _server) = net::test_relay::spawn_plain().await.expect("local relay");
    let (alice, mut bob, carol) = members(&relay, cell.transports, sender_id).await;
    assert!(
        rosters_hold(&[&alice, &bob, &carol], 2, Duration::from_mins(1)).await,
        "{name}: the three members never formed a mesh"
    );
    expect_triangle(name, &alice, &bob, &carol).await;
    if cell.has(Transport::Udp) {
        alice.expect_rung("bob", "ip", name).await;
    }

    for cut in cell.cuts() {
        apply(cut, &alice, &bob, &carol).await;
    }

    let expected = cell.expected();
    if let Some(rung) = expected {
        alice
            .settle_on("bob", rung_name(rung), cell.settle(rung), name)
            .await;
        if cell.via_third && rung == Rung::Multihop {
            probe_until_forwarded(name, &alice, &carol).await;
        }
    }

    for kind in cell.kinds {
        match kind {
            Kind::Unicast => {
                if expected.is_none() {
                    // The cut takes effect when iroh re-runs the path selection, a short
                    // while after it. Until then the pooled connection is still on the path
                    // it had before the cut (IP, or WebRTC when the list has no `udp`) and
                    // carries the message: that is a payload on a rung that may carry it,
                    // and tells nothing about the rungs that may not.
                    let waiting = Instant::now();
                    while matches!(
                        alice.rung_to("bob").await,
                        Some("ip" | "webrtc" | "multihop" | "gossip")
                    ) {
                        assert!(
                            waiting.elapsed() < LEAVE_DIRECT_DEADLINE,
                            "{name}: the pair never left its path after the cut"
                        );
                        time::sleep(Duration::from_millis(250)).await;
                    }
                }
                let text = format!("matrix {name}");
                let before = alice.rung_to("bob").await;
                let sent = alice.send("bob", &text).await;
                let started = Instant::now();
                if expected.is_some() {
                    sent.unwrap_or_else(|error| panic!("{name}: the send was refused: {error}"));
                    while !bob.saw_msg(&text) {
                        assert!(
                            started.elapsed() < PAYLOAD_DEADLINE,
                            "{name}: the message never reached bob on {expected:?}"
                        );
                        time::sleep(Duration::from_millis(250)).await;
                    }
                    // The message did not move the pair: it is still where it settled.
                    let after = alice.rung_to("bob").await;
                    assert_eq!(
                        after,
                        expected.map(rung_name),
                        "{name}: the rung changed after the message arrived"
                    );
                } else {
                    // No rung may carry payload: a refusal, or silence, and never
                    // a delivery over the relay.
                    while started.elapsed() < REFUSAL_WINDOW {
                        if bob.saw_msg(&text) {
                            let now = alice.rung_to("bob").await;
                            panic!(
                                "{name}: the message arrived on a rung that may not carry payload \
                                 (alice read {before:?} before the send and {now:?} when it \
                                 arrived, {:?} after the send)",
                                started.elapsed()
                            );
                        }
                        time::sleep(Duration::from_millis(250)).await;
                    }
                }
            }
        }
    }

    let refused = if name == STAYS_ON_RELAY_IF_REFUSED {
        alice.refused_on_relay().await
            + bob.refused_on_relay().await
            + carol.refused_on_relay().await
    } else {
        0
    };
    if refused > 0 {
        // A cell was refused on the relay, so a hop was refused and the WARN is due.
        habilis_network_test_tracing::expect_warn(STAYS_ON_RELAY.0, STAYS_ON_RELAY.1);
    }
    if stays_on_relay(name) || refused > 0 {
        // The underlay logs the WARN 20 s after its first refusal of the cut pair, which can be
        // later than the checks of the cell end.
        let warned_after = Instant::now();
        while !habilis_network_test_tracing::saw_warn(STAYS_ON_RELAY.0, STAYS_ON_RELAY.1) {
            assert!(
                warned_after.elapsed() < Duration::from_mins(1),
                "{name}: the underlay never logged that it stays on the relay"
            );
            time::sleep(Duration::from_millis(250)).await;
        }
    }

    for member in [alice, bob, carol] {
        member.leave().await;
    }
}

/// A frame that is parked for the session arrives once the session is up. The sender has the
/// higher id, so nobody but its own engine can see IP go: the proof of a direct path is taken
/// back, the frames are parked (the roster reads `relay-only`), and the session carries them
/// when it attaches. Every probe that was sent while the lane read `relay-only` must reach bob,
/// and the run prints how long after the rung changed the last one arrived.
#[test]
#[ignore = "run by cargo task matrix"]
fn udp_webrtc_ip_direct_sender_has_the_higher_id_parks_a_frame() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        const NAME: &str = "udp_webrtc_ip_direct_parks_a_frame";
        const AFTER_THE_RUNG: Duration = Duration::from_secs(3);
        let (_, cell) = CELLS
            .iter()
            .find(|(cell, _)| *cell == "udp_webrtc_ip_direct")
            .expect("the cell is in the table");

        let (relay, _server) = net::test_relay::spawn_plain().await.expect("local relay");
        let (alice, mut bob, carol) = members(&relay, cell.transports, SenderId::Higher).await;
        assert!(
            rosters_hold(&[&alice, &bob, &carol], 2, Duration::from_mins(1)).await,
            "{NAME}: the three members never formed a mesh"
        );
        alice.expect_rung("bob", "ip", NAME).await;
        for cut in cell.cuts() {
            apply(cut, &alice, &bob, &carol).await;
        }

        // (text, the lane read before the send, when it went)
        let mut sent: Vec<(String, bool, Instant)> = Vec::new();
        let started = Instant::now();
        let mut on_the_rung_since: Option<Instant> = None;
        let mut next_probe = Instant::now();
        let mut last_parked_send: Option<Instant> = None;
        // The lane reads `relay-only` only between the moment the proof is taken back and the
        // attach, well under a second: so the lane is read every 20 ms, and a frame goes at once
        // while it reads so (at most one every 100 ms), besides the probe of every second.
        while started.elapsed() < STEP_DEADLINE {
            let parked = alice.lane_to("bob").await.as_deref() == Some("relay-only");
            let due = Instant::now() >= next_probe;
            let extra = parked
                && last_parked_send
                    .is_none_or(|sent_at| sent_at.elapsed() >= Duration::from_millis(100));
            if due || extra {
                let text = format!("parked {NAME} {}", sent.len());
                let _ = alice.send("bob", &text).await;
                sent.push((text, parked, Instant::now()));
                if parked {
                    last_parked_send = Some(Instant::now());
                }
            }
            if due {
                next_probe = Instant::now() + Duration::from_secs(1);
                if alice.rung_to("bob").await == Some("webrtc") {
                    let since = *on_the_rung_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= AFTER_THE_RUNG {
                        break;
                    }
                } else {
                    on_the_rung_since = None;
                }
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        let on_the_rung = on_the_rung_since.unwrap_or_else(|| {
            panic!(
                "{NAME}: the rung never became webrtc after {} probes",
                sent.len()
            )
        });

        let parked: Vec<&(String, bool, Instant)> = sent.iter().filter(|probe| probe.1).collect();
        assert!(
            !parked.is_empty(),
            "{NAME}: no probe went while the lane read relay-only, so the test proved nothing"
        );
        let waiting = Instant::now();
        let mut late = Duration::ZERO;
        for (text, _, _) in &parked {
            while !bob.saw_msg(text) {
                assert!(
                    waiting.elapsed() < PAYLOAD_DEADLINE,
                    "{NAME}: the frame {text:?} was parked and never reached bob"
                );
                time::sleep(Duration::from_millis(250)).await;
            }
            late = late.max(on_the_rung.elapsed());
        }
        let first_parked = parked.first().map(|probe| probe.2.duration_since(started));
        eprintln!(
            "DIAG {NAME}: {} probes, {} sent while the lane read relay-only (first after {:?}), \
         the last one reached bob {:?} after the rung was first read",
            sent.len(),
            parked.len(),
            first_parked,
            late,
        );
        for member in [alice, bob, carol] {
            member.leave().await;
        }
    });
}

/// `udp_webrtc_ip_direct` with the order of the ids fixed: only the lower id offers a session,
/// and a pair that loses IP while the higher id sends needs the higher id to offer by itself.
fn udp_webrtc_ip_direct_with(sender_id: SenderId, name: &str) {
    let (_, cell) = CELLS
        .iter()
        .find(|(cell, _)| *cell == "udp_webrtc_ip_direct")
        .expect("the cell is in the table");
    run_cell(*cell, name, sender_id);
}

#[test]
#[ignore = "run by cargo task matrix"]
fn udp_webrtc_ip_direct_sender_has_the_higher_id() {
    udp_webrtc_ip_direct_with(
        SenderId::Higher,
        "udp_webrtc_ip_direct_sender_has_the_higher_id",
    );
}

#[test]
#[ignore = "run by cargo task matrix"]
fn udp_webrtc_ip_direct_sender_has_the_lower_id() {
    udp_webrtc_ip_direct_with(
        SenderId::Lower,
        "udp_webrtc_ip_direct_sender_has_the_lower_id",
    );
}

/// Every cell, by name, so that a test can check the matrix against the
/// transport lists that the protocol accepts.
const CELLS: &[(&str, Cell)] = &[
    (
        "udp_none_direct",
        Cell {
            transports: &[Transport::Udp],
            blocked: Blocked::None,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_ip_direct",
        Cell {
            transports: &[Transport::Udp],
            blocked: Blocked::Ip,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "webrtc_none_direct",
        Cell {
            transports: &[Transport::WebRtc],
            blocked: Blocked::None,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "webrtc_ip_webrtc_direct",
        Cell {
            transports: &[Transport::WebRtc],
            blocked: Blocked::IpWebRtc,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_none_direct",
        Cell {
            transports: &[Transport::Udp, Transport::WebRtc],
            blocked: Blocked::None,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_ip_direct",
        Cell {
            transports: &[Transport::Udp, Transport::WebRtc],
            blocked: Blocked::Ip,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_ip_webrtc_direct",
        Cell {
            transports: &[Transport::Udp, Transport::WebRtc],
            blocked: Blocked::IpWebRtc,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_multihop_none_direct",
        Cell {
            transports: &[Transport::Udp, Transport::Multihop],
            blocked: Blocked::None,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_multihop_ip_direct",
        Cell {
            transports: &[Transport::Udp, Transport::Multihop],
            blocked: Blocked::Ip,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_multihop_ip_webrtc_multihop_direct",
        Cell {
            transports: &[Transport::Udp, Transport::Multihop],
            blocked: Blocked::IpWebRtcMultihop,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_multihop_ip_webrtc_via_third",
        Cell {
            transports: &[Transport::Udp, Transport::Multihop],
            blocked: Blocked::IpWebRtc,
            kinds: &[Kind::Unicast],
            via_third: true,
            target_full: false,
        },
    ),
    (
        "udp_relay_none_direct",
        Cell {
            transports: &[Transport::Udp, Transport::Relay],
            blocked: Blocked::None,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_relay_ip_direct",
        Cell {
            transports: &[Transport::Udp, Transport::Relay],
            blocked: Blocked::Ip,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "webrtc_relay_none_direct",
        Cell {
            transports: &[Transport::WebRtc, Transport::Relay],
            blocked: Blocked::None,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "webrtc_relay_ip_webrtc_direct",
        Cell {
            transports: &[Transport::WebRtc, Transport::Relay],
            blocked: Blocked::IpWebRtc,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_multihop_none_direct",
        Cell {
            transports: &[Transport::Udp, Transport::WebRtc, Transport::Multihop],
            blocked: Blocked::None,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_multihop_ip_direct",
        Cell {
            transports: &[Transport::Udp, Transport::WebRtc, Transport::Multihop],
            blocked: Blocked::Ip,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_multihop_ip_webrtc_direct",
        Cell {
            transports: &[Transport::Udp, Transport::WebRtc, Transport::Multihop],
            blocked: Blocked::IpWebRtc,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_multihop_ip_webrtc_multihop_direct",
        Cell {
            transports: &[Transport::Udp, Transport::WebRtc, Transport::Multihop],
            blocked: Blocked::IpWebRtcMultihop,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_multihop_ip_webrtc_via_third",
        Cell {
            transports: &[Transport::Udp, Transport::WebRtc, Transport::Multihop],
            blocked: Blocked::IpWebRtc,
            kinds: &[Kind::Unicast],
            via_third: true,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_relay_none_direct",
        Cell {
            transports: &[Transport::Udp, Transport::WebRtc, Transport::Relay],
            blocked: Blocked::None,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_relay_ip_direct",
        Cell {
            transports: &[Transport::Udp, Transport::WebRtc, Transport::Relay],
            blocked: Blocked::Ip,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_relay_ip_webrtc_direct",
        Cell {
            transports: &[Transport::Udp, Transport::WebRtc, Transport::Relay],
            blocked: Blocked::IpWebRtc,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_multihop_relay_none_direct",
        Cell {
            transports: &[Transport::Udp, Transport::Multihop, Transport::Relay],
            blocked: Blocked::None,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_multihop_relay_ip_direct",
        Cell {
            transports: &[Transport::Udp, Transport::Multihop, Transport::Relay],
            blocked: Blocked::Ip,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_multihop_relay_ip_webrtc_multihop_direct",
        Cell {
            transports: &[Transport::Udp, Transport::Multihop, Transport::Relay],
            blocked: Blocked::IpWebRtcMultihop,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_multihop_relay_none_direct",
        Cell {
            transports: &[
                Transport::Udp,
                Transport::WebRtc,
                Transport::Multihop,
                Transport::Relay,
            ],
            blocked: Blocked::None,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_multihop_relay_ip_direct",
        Cell {
            transports: &[
                Transport::Udp,
                Transport::WebRtc,
                Transport::Multihop,
                Transport::Relay,
            ],
            blocked: Blocked::Ip,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_multihop_relay_ip_webrtc_direct",
        Cell {
            transports: &[
                Transport::Udp,
                Transport::WebRtc,
                Transport::Multihop,
                Transport::Relay,
            ],
            blocked: Blocked::IpWebRtc,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_multihop_relay_ip_webrtc_multihop_direct",
        Cell {
            transports: &[
                Transport::Udp,
                Transport::WebRtc,
                Transport::Multihop,
                Transport::Relay,
            ],
            blocked: Blocked::IpWebRtcMultihop,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "webrtc_multihop_none_direct",
        Cell {
            transports: &[Transport::WebRtc, Transport::Multihop],
            blocked: Blocked::None,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "webrtc_multihop_ip_webrtc_direct",
        Cell {
            transports: &[Transport::WebRtc, Transport::Multihop],
            blocked: Blocked::IpWebRtc,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "webrtc_multihop_ip_webrtc_multihop_direct",
        Cell {
            transports: &[Transport::WebRtc, Transport::Multihop],
            blocked: Blocked::IpWebRtcMultihop,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "webrtc_multihop_ip_webrtc_via_third",
        Cell {
            transports: &[Transport::WebRtc, Transport::Multihop],
            blocked: Blocked::IpWebRtc,
            kinds: &[Kind::Unicast],
            via_third: true,
            target_full: false,
        },
    ),
    (
        "webrtc_multihop_relay_none_direct",
        Cell {
            transports: &[Transport::WebRtc, Transport::Multihop, Transport::Relay],
            blocked: Blocked::None,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "webrtc_multihop_relay_ip_webrtc_direct",
        Cell {
            transports: &[Transport::WebRtc, Transport::Multihop, Transport::Relay],
            blocked: Blocked::IpWebRtc,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "webrtc_multihop_relay_ip_webrtc_multihop_direct",
        Cell {
            transports: &[Transport::WebRtc, Transport::Multihop, Transport::Relay],
            blocked: Blocked::IpWebRtcMultihop,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_gossip_ip_direct",
        Cell {
            transports: &[Transport::Udp, Transport::Gossip],
            blocked: Blocked::Ip,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_gossip_ip_webrtc_direct",
        Cell {
            transports: &[Transport::Udp, Transport::WebRtc, Transport::Gossip],
            blocked: Blocked::IpWebRtc,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_multihop_gossip_ip_webrtc_multihop_direct",
        Cell {
            transports: &[Transport::Udp, Transport::Multihop, Transport::Gossip],
            blocked: Blocked::IpWebRtcMultihop,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_webrtc_multihop_gossip_ip_webrtc_multihop_direct",
        Cell {
            transports: &[
                Transport::Udp,
                Transport::WebRtc,
                Transport::Multihop,
                Transport::Gossip,
            ],
            blocked: Blocked::IpWebRtcMultihop,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_multihop_gossip_ip_webrtc_via_third",
        Cell {
            transports: &[Transport::Udp, Transport::Multihop, Transport::Gossip],
            blocked: Blocked::IpWebRtc,
            kinds: &[Kind::Unicast],
            via_third: true,
            target_full: false,
        },
    ),
    (
        "udp_gossip_relay_ip_direct",
        Cell {
            transports: &[Transport::Udp, Transport::Gossip, Transport::Relay],
            blocked: Blocked::Ip,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_gossip_relay_all_blocked",
        Cell {
            transports: &[Transport::Udp, Transport::Gossip, Transport::Relay],
            blocked: Blocked::IpWebRtcMultihopGossip,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
    (
        "udp_gossip_all_blocked",
        Cell {
            transports: &[Transport::Udp, Transport::Gossip],
            blocked: Blocked::IpWebRtcMultihopGossip,
            kinds: &[Kind::Unicast],
            via_third: false,
            target_full: false,
        },
    ),
];

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_none_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_none_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_none_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_ip_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_ip_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_ip_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn webrtc_none_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "webrtc_none_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "webrtc_none_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn webrtc_ip_webrtc_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "webrtc_ip_webrtc_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "webrtc_ip_webrtc_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_none_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_none_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_webrtc_none_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_ip_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_ip_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_webrtc_ip_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_ip_webrtc_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_ip_webrtc_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_webrtc_ip_webrtc_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_multihop_none_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_multihop_none_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_multihop_none_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_multihop_ip_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_multihop_ip_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_multihop_ip_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_multihop_ip_webrtc_multihop_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_multihop_ip_webrtc_multihop_direct")
        .expect("the cell is in the table");
    run_cell(
        *cell,
        "udp_multihop_ip_webrtc_multihop_direct",
        SenderId::Any,
    );
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_multihop_ip_webrtc_via_third() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_multihop_ip_webrtc_via_third")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_multihop_ip_webrtc_via_third", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_relay_none_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_relay_none_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_relay_none_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_relay_ip_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_relay_ip_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_relay_ip_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn webrtc_relay_none_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "webrtc_relay_none_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "webrtc_relay_none_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn webrtc_relay_ip_webrtc_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "webrtc_relay_ip_webrtc_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "webrtc_relay_ip_webrtc_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_multihop_none_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_multihop_none_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_webrtc_multihop_none_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_multihop_ip_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_multihop_ip_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_webrtc_multihop_ip_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_multihop_ip_webrtc_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_multihop_ip_webrtc_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_webrtc_multihop_ip_webrtc_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_multihop_ip_webrtc_multihop_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_multihop_ip_webrtc_multihop_direct")
        .expect("the cell is in the table");
    run_cell(
        *cell,
        "udp_webrtc_multihop_ip_webrtc_multihop_direct",
        SenderId::Any,
    );
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_multihop_ip_webrtc_via_third() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_multihop_ip_webrtc_via_third")
        .expect("the cell is in the table");
    run_cell(
        *cell,
        "udp_webrtc_multihop_ip_webrtc_via_third",
        SenderId::Any,
    );
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_relay_none_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_relay_none_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_webrtc_relay_none_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_relay_ip_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_relay_ip_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_webrtc_relay_ip_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_relay_ip_webrtc_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_relay_ip_webrtc_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_webrtc_relay_ip_webrtc_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_multihop_relay_none_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_multihop_relay_none_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_multihop_relay_none_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_multihop_relay_ip_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_multihop_relay_ip_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_multihop_relay_ip_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_multihop_relay_ip_webrtc_multihop_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_multihop_relay_ip_webrtc_multihop_direct")
        .expect("the cell is in the table");
    run_cell(
        *cell,
        "udp_multihop_relay_ip_webrtc_multihop_direct",
        SenderId::Any,
    );
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_multihop_relay_none_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_multihop_relay_none_direct")
        .expect("the cell is in the table");
    run_cell(
        *cell,
        "udp_webrtc_multihop_relay_none_direct",
        SenderId::Any,
    );
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_multihop_relay_ip_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_multihop_relay_ip_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_webrtc_multihop_relay_ip_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_multihop_relay_ip_webrtc_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_multihop_relay_ip_webrtc_direct")
        .expect("the cell is in the table");
    run_cell(
        *cell,
        "udp_webrtc_multihop_relay_ip_webrtc_direct",
        SenderId::Any,
    );
}

#[test]
#[ignore = "run by cargo task matrix and by the gate row"]
fn udp_webrtc_multihop_relay_ip_webrtc_multihop_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_multihop_relay_ip_webrtc_multihop_direct")
        .expect("the cell is in the table");
    run_cell(
        *cell,
        "udp_webrtc_multihop_relay_ip_webrtc_multihop_direct",
        SenderId::Any,
    );
}

// The lists without `udp` that D8 made valid: a member with `webrtc` and `multihop` reaches
// its peer on WebRTC, then on multihop (its underlay still has UDP until Phase 4c step 3).
// After step 3 the direct edge is the underlay's WebRTC session, and these cells keep their
// expectation. The relay lists have no `via_third` cell: see
// `no_cell_through_a_third_member_has_the_relay_in_its_list`.
#[test]
#[ignore = "run by cargo task matrix"]
fn webrtc_multihop_none_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "webrtc_multihop_none_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "webrtc_multihop_none_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix"]
fn webrtc_multihop_ip_webrtc_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "webrtc_multihop_ip_webrtc_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "webrtc_multihop_ip_webrtc_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix"]
fn webrtc_multihop_ip_webrtc_multihop_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "webrtc_multihop_ip_webrtc_multihop_direct")
        .expect("the cell is in the table");
    run_cell(
        *cell,
        "webrtc_multihop_ip_webrtc_multihop_direct",
        SenderId::Any,
    );
}

#[test]
#[ignore = "run by cargo task matrix"]
fn webrtc_multihop_ip_webrtc_via_third() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "webrtc_multihop_ip_webrtc_via_third")
        .expect("the cell is in the table");
    run_cell(*cell, "webrtc_multihop_ip_webrtc_via_third", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix"]
fn webrtc_multihop_relay_none_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "webrtc_multihop_relay_none_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "webrtc_multihop_relay_none_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix"]
fn webrtc_multihop_relay_ip_webrtc_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "webrtc_multihop_relay_ip_webrtc_direct")
        .expect("the cell is in the table");
    run_cell(
        *cell,
        "webrtc_multihop_relay_ip_webrtc_direct",
        SenderId::Any,
    );
}

#[test]
#[ignore = "run by cargo task matrix"]
fn webrtc_multihop_relay_ip_webrtc_multihop_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "webrtc_multihop_relay_ip_webrtc_multihop_direct")
        .expect("the cell is in the table");
    run_cell(
        *cell,
        "webrtc_multihop_relay_ip_webrtc_multihop_direct",
        SenderId::Any,
    );
}

// The gossip cells. Gossip sits between multihop and the relay: it wins over the relay,
// and loses to multihop. See `GOSSIP_INSTALLED`.
#[test]
#[ignore = "run by cargo task matrix"]
fn udp_gossip_ip_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_gossip_ip_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_gossip_ip_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix"]
fn udp_webrtc_gossip_ip_webrtc_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_gossip_ip_webrtc_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_webrtc_gossip_ip_webrtc_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix"]
fn udp_multihop_gossip_ip_webrtc_multihop_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_multihop_gossip_ip_webrtc_multihop_direct")
        .expect("the cell is in the table");
    run_cell(
        *cell,
        "udp_multihop_gossip_ip_webrtc_multihop_direct",
        SenderId::Any,
    );
}

#[test]
#[ignore = "run by cargo task matrix"]
fn udp_webrtc_multihop_gossip_ip_webrtc_multihop_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_webrtc_multihop_gossip_ip_webrtc_multihop_direct")
        .expect("the cell is in the table");
    run_cell(
        *cell,
        "udp_webrtc_multihop_gossip_ip_webrtc_multihop_direct",
        SenderId::Any,
    );
}

#[test]
#[ignore = "run by cargo task matrix"]
fn udp_multihop_gossip_ip_webrtc_via_third() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_multihop_gossip_ip_webrtc_via_third")
        .expect("the cell is in the table");
    run_cell(
        *cell,
        "udp_multihop_gossip_ip_webrtc_via_third",
        SenderId::Any,
    );
}

#[test]
#[ignore = "run by cargo task matrix"]
fn udp_gossip_relay_ip_direct() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_gossip_relay_ip_direct")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_gossip_relay_ip_direct", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix"]
fn udp_gossip_relay_all_blocked() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_gossip_relay_all_blocked")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_gossip_relay_all_blocked", SenderId::Any);
}

#[test]
#[ignore = "run by cargo task matrix"]
fn udp_gossip_all_blocked() {
    let (_, cell) = CELLS
        .iter()
        .find(|(name, _)| *name == "udp_gossip_all_blocked")
        .expect("the cell is in the table");
    run_cell(*cell, "udp_gossip_all_blocked", SenderId::Any);
}

/// The matrix covers exactly the lists that the protocol accepts: every valid
/// subset of the four transports is in a cell, and no cell names an invalid one.
/// The empty list is the default, `udp,webrtc,multihop`, and so already there.
#[test]
fn the_cells_cover_every_valid_transport_list_and_no_other() {
    use Transport::{Multihop, Relay, Udp, WebRtc};
    let all = [Udp, WebRtc, Multihop, Relay];
    let in_cells = |list: &[Transport]| {
        let same_len = |len: usize| len == list.len();
        CELLS.iter().any(|(_, cell)| {
            same_len(cell.transports.len()) && list.iter().all(|wanted| cell.has(*wanted))
        })
    };
    for mask in 1u8..16 {
        let picked = all
            .iter()
            .enumerate()
            .filter(|(bit, _)| mask >> bit & 1 == 1);
        let list: Vec<Transport> = picked.map(|(_, transport)| *transport).collect();
        let valid = MeshConfig::resolve(&[Lookup::Relay], None, &list).is_ok();
        assert_eq!(in_cells(&list), valid, "the transport list {list:?}");
    }
}

/// The part that both refusals carry. The lower-id sender gets the `HeldForDirect` text, the
/// higher-id sender gets `path::RELAY_REFUSED`, so a cell with a fixed sender id cannot match
/// one full text.
const LOOKUP_ONLY: &str = "lookup only on this mesh";

/// With `gossip` off in the list, a pair that has no direct path is refused with a clear error:
/// no silence, no delivery. The pair is alice and bob with IP between them cut, on `udp` alone.
#[test]
#[ignore = "run by cargo task matrix"]
fn a_send_with_gossip_off_and_no_direct_path_fails_with_a_clear_error() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        const NAME: &str = "udp_ip_direct_clear_error";
        let (_, cell) = CELLS
            .iter()
            .find(|(cell, _)| *cell == "udp_ip_direct")
            .expect("the cell is in the table");

        assert!(
            !cell.has(Transport::Gossip) && cell.expected().is_none(),
            "that cell has no gossip rung and expects the clear error"
        );
        let (relay, _server) = net::test_relay::spawn_plain().await.expect("local relay");
        let (alice, mut bob, carol) = members(&relay, cell.transports, SenderId::Any).await;
        assert!(
            rosters_hold(&[&alice, &bob, &carol], 2, Duration::from_mins(1)).await,
            "{NAME}: the three members never formed a mesh"
        );
        alice.expect_rung("bob", "ip", NAME).await;
        for cut in cell.cuts() {
            apply(cut, &alice, &bob, &carol).await;
        }
        let waiting = Instant::now();
        while alice.rung_to("bob").await == Some("ip") {
            assert!(
                waiting.elapsed() < LEAVE_DIRECT_DEADLINE,
                "{NAME}: the pair never left IP after the cut"
            );
            time::sleep(Duration::from_millis(250)).await;
        }

        let text = format!("matrix {NAME}");
        let refusal = alice
            .send("bob", &text)
            .await
            .expect_err("the send must fail, with either refusal");
        assert!(
            refusal.contains(LOOKUP_ONLY),
            "{NAME}: the error must give the reason, got: {refusal}"
        );
        time::sleep(REFUSAL_WINDOW).await;
        assert!(!bob.saw_msg(&text), "{NAME}: the refused message arrived");
        for member in [alice, bob, carol] {
            member.leave().await;
        }
    });
}

/// The gossip cells use lists that the protocol accepts, each with a direct path next to gossip,
/// and each expects the rung that the ladder names: gossip above the relay, below multihop.
#[test]
fn the_gossip_cells_use_valid_lists_and_the_ladder_orders_gossip_between_multihop_and_the_relay() {
    let gossip_cells: Vec<_> = CELLS
        .iter()
        .filter(|(_, cell)| cell.has(Transport::Gossip))
        .collect();
    assert_eq!(gossip_cells.len(), 8, "the eight cells of the design");
    for (name, cell) in &gossip_cells {
        assert!(
            cell.has(Transport::Udp) || cell.has(Transport::WebRtc),
            "{name}: gossip rides the links that another path carries"
        );
        assert!(
            MeshConfig::resolve(&[Lookup::Relay], None, cell.transports).is_ok(),
            "{name}: the transport list {:?}",
            cell.transports
        );
    }
    let expected = |name: &str| {
        let found = CELLS.iter().find(|(cell, _)| *cell == name);
        found.and_then(|(_, cell)| cell.expected())
    };
    assert_eq!(
        expected("udp_gossip_ip_direct"),
        Some(Rung::Gossip),
        "the udp gossip cell expects its valid list"
    );
    assert_eq!(
        expected("udp_multihop_gossip_ip_webrtc_via_third"),
        Some(Rung::Multihop),
        "gossip does not win while multihop is available"
    );
    assert_eq!(
        expected("udp_gossip_relay_ip_direct"),
        Some(Rung::Gossip),
        "gossip wins over the relay"
    );
    assert_eq!(
        expected("udp_gossip_relay_all_blocked"),
        Some(Rung::Relay),
        "the relay is what is left when gossip is blocked"
    );
    assert_eq!(
        expected("udp_gossip_all_blocked"),
        None,
        "the relay gossip cell expects gossip ordered after multihop"
    );
}

/// The cuts of a cell that goes through a third member close every rung of the
/// direct underlay edge; the cells that do not go through one leave the
/// underlays alone.
#[test]
fn a_cell_through_a_third_member_cuts_the_underlay_edge_on_every_rung() {
    for (name, cell) in CELLS {
        let cuts = cell.cuts();
        for cut in [
            Cut::IpUnderlays,
            Cut::WebRtcUnderlays,
            Cut::WebRtcBobToAlice,
        ] {
            assert_eq!(cuts.contains(&cut), cell.via_third, "{name}: {cut:?}");
        }
    }
}

/// A selector block cannot take away a path that iroh has already selected (an
/// empty selection keeps the current one), so with the relay allowed for payload
/// the direct edge between the two underlays stays alive over the relay or over
/// the path it had, and carol forwards nothing. The hop is proved by the cells
/// without the relay; a via-third cell with the relay would only repeat the direct
/// cell with a longer wait.
#[test]
fn no_cell_through_a_third_member_has_the_relay_in_its_list() {
    for (name, cell) in CELLS {
        assert!(
            !(cell.via_third && cell.has(Transport::Relay)),
            "{name}: a hop cannot be forced when the relay may carry payload"
        );
    }
}

/// A selection block at one end exists only in our test hooks: no production fault takes a rung
/// from one side of a pair and leaves it to the other. So a cell that takes `WebRTC` or multihop
/// from alice takes it from bob too (user decision, 2026-10-08: "All one-ended cells"). A cell
/// through a third member already cuts bob toward alice (`WebRtcBobToAlice`).
#[test]
fn no_cell_cuts_the_webrtc_or_multihop_rung_at_one_end_only() {
    let mut one_ended = Vec::new();
    for (name, cell) in CELLS {
        let cuts = cell.cuts();
        if cuts.contains(&Cut::WebRtcAlice) && !cell.via_third && !cuts.contains(&Cut::WebRtcBob) {
            one_ended.push(format!("{name}: WebRTC at alice only"));
        }
        if cuts.contains(&Cut::MultihopAlice) && !cuts.contains(&Cut::MultihopBob) {
            one_ended.push(format!("{name}: multihop at alice only"));
        }
    }
    assert!(
        one_ended.is_empty(),
        "{} cells cut one end only:\n{}",
        one_ended.len(),
        one_ended.join("\n")
    );
}

/// The block table is per node and rung: a cut that takes a rung from alice takes it toward every
/// remote, carol included. A pair that keeps the rung at one end only has two ends that select
/// different paths, and the path that gets no return traffic times out after 15 s. So for every
/// pair of the three members, a cell that takes a rung in one direction takes it in the other too.
/// In a cell through a third member, carol is cut toward alice only and keeps the rung toward
/// bob, and bob is cut toward alice only: the pair bob and carol keeps the rung at both ends.
#[test]
fn no_member_keeps_a_rung_that_another_member_has_cut() {
    let mut one_ended = Vec::new();
    for (name, cell) in CELLS {
        let mut taken = Vec::new();
        let rung_cuts: Vec<(Rung, Who, Option<Who>)> =
            cell.cuts().into_iter().filter_map(Cut::rung_cut).collect();
        for (rung, from, toward) in rung_cuts {
            for to in Who::ALL {
                if to != from && toward.is_none_or(|only| only == to) {
                    taken.push((rung, from, to));
                }
            }
        }
        for &(rung, from, to) in &taken {
            if !taken.contains(&(rung, to, from)) {
                one_ended.push(format!(
                    "{name}: {rung:?} cut from {from:?} toward {to:?} only"
                ));
            }
        }
    }
    assert!(
        one_ended.is_empty(),
        "{} one-ended cuts:\n{}",
        one_ended.len(),
        one_ended.join("\n")
    );
}

#[test]
fn a_cell_name_is_in_the_table_once() {
    let indexed: Vec<(usize, &(&str, Cell))> = CELLS.iter().enumerate().collect();
    for (index, (name, _)) in indexed {
        assert!(
            CELLS.iter().skip(index + 1).all(|(other, _)| other != name),
            "{name} is twice in the table"
        );
    }
}
