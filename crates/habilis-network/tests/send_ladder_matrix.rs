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
//! Two cells run in the gate (`cargo task ci`): the default list with IP blocked
//! and the cell that goes through carol. The others are `#[ignore]`, for
//! `cargo task matrix`, which runs them all with `--include-ignored
//! --test-threads=1` (the nightly workflow does the same).
//!
//! The lists are the valid ones of the 16 subsets of `udp,webrtc,multihop,relay`
//! (`MeshConfig::resolve`); a test below keeps the two in step, so an invalid
//! list is never built. A cell is left out where blocking a rung that the list
//! does not have changes nothing, and `via_third` is set only where it changes
//! the path: with `IpWebRtc` blocked and `multihop` in the list. `target_full`
//! (a receiver at the cap of `WebRTC` sessions) has no cells until Phase 2.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inbound, Membership, Request, Rung};
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
/// cell blocked. The pair leaves the relay for such a rung only on the next alive
/// tick (15 s) and after a JSEP round (about 5 s), so a lower rung that is read
/// for less than that proves nothing: the engine may still be about to climb.
const SETTLE_BELOW_A_BLOCK: Duration = Duration::from_secs(30);
/// How long a message that must not arrive is given to arrive.
const REFUSAL_WINDOW: Duration = Duration::from_secs(8);

/// Which rungs a cell takes away from alice, from the top of the ladder down.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Blocked {
    None,
    Ip,
    IpWebRtc,
    IpWebRtcMultihop,
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

impl Cell {
    fn has(self, transport: Transport) -> bool {
        self.transports.contains(&transport)
    }

    /// How long the expected rung must be read before the cell counts as settled.
    fn settle(self, expected: Rung) -> Duration {
        let allowed_above = [Rung::Ip, Rung::WebRtc, Rung::Multihop]
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
        match rung {
            Rung::Ip => self.has(Transport::Udp),
            Rung::WebRtc => self.has(Transport::WebRtc),
            Rung::Multihop => self.has(Transport::Multihop),
            Rung::Relay => self.has(Transport::Relay),
            // Gossip has no transport yet: its cells come with Phase 6.
            Rung::Gossip | Rung::Other => false,
        }
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
                Rung::Gossip | Rung::Other => false,
                Rung::Relay => true,
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
    }
}

struct Member {
    membership: Membership,
    _events: UnboundedReceiver<String>,
    seen_msgs: Vec<Inbound>,
}

impl Member {
    async fn open(opts: &membership::Opts) -> Self {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(opts, sink).await.expect("open a member");
        Self {
            membership,
            _events: events,
            seen_msgs: Vec::new(),
        }
    }

    async fn create(nick: &str, relay: &RelayUrl, transport: Vec<Transport>) -> Self {
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

    async fn forwarded_cells(&self) -> u64 {
        self.membership
            .request(|reply| Request::ForwardedCells { reply })
            .await
            .expect("the loop answers")
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
            tokio::time::sleep(Duration::from_millis(500)).await;
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
        while started.elapsed() < STEP_DEADLINE {
            probes += 1;
            let _ = self.send(peer, &format!("probe {cell} {probes}")).await;
            seen = self.rung_to(peer).await;
            if seen == Some(expected) {
                if held_since.get_or_insert_with(Instant::now).elapsed() >= hold {
                    return;
                }
            } else {
                held_since = None;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
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
            .request(|reply| Request::Send { to, body, reply })
            .await
            .expect("the loop answers")
    }

    fn saw_msg(&mut self, text: &str) -> bool {
        while let Ok(msg) = self.membership.inbound.try_recv() {
            self.seen_msgs.push(msg);
        }
        self.seen_msgs
            .iter()
            .any(|msg| msg.directed && msg.text == text)
    }

    async fn leave(self) {
        let _ = self.membership.node.leave().await;
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

/// Take every IP path between `first` and `second` away from both on the
/// application endpoint, and, when `underlay` is set, on the multihop underlay
/// too. The underlay is an endpoint of its own: left alone, the direct link
/// between the two underlays is a route, and no member would forward a cell.
async fn cut_ip_between(first: &Member, second: &Member, underlay: bool) {
    first.block_ip_to(second.ports()).await;
    second.block_ip_to(first.ports()).await;
    if !underlay {
        return;
    }
    for (from, to) in [(first, second), (second, first)] {
        let id = from.membership.node.underlay_id().expect("multihop is on");
        habilis_network_iroh_webrtc_transport::block_ip_to(
            id,
            to.membership.node.underlay_ports().iter().copied(),
        );
    }
}

async fn run(cell: Cell, name: &str) {
    init_logging();
    assert!(
        !cell.target_full && !cell.kinds.is_empty(),
        "{name}: a cell with a full target has no test before Phase 2"
    );
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let alice = Member::create("alice", &relay, cell.transports.to_vec()).await;
    let mut bob = Member::join("bob", &alice).await;
    let carol = Member::join("carol", &alice).await;
    assert!(
        rosters_hold(&[&alice, &bob, &carol], 2, Duration::from_mins(1)).await,
        "{name}: the three members never formed a mesh"
    );
    if cell.has(Transport::Udp) {
        alice.expect_rung("bob", "ip", name).await;
    }

    if cell.blocked >= Blocked::Ip {
        cut_ip_between(&alice, &bob, cell.via_third).await;
    }
    if cell.blocked >= Blocked::IpWebRtc {
        alice.block_rung(Rung::WebRtc, true).await;
    }
    if cell.blocked >= Blocked::IpWebRtcMultihop {
        alice.block_rung(Rung::Multihop, true).await;
    }

    let expected = cell.expected();
    if let Some(rung) = expected {
        alice
            .settle_on("bob", rung_name(rung), cell.settle(rung), name)
            .await;
        if cell.via_third && rung == Rung::Multihop {
            let started = Instant::now();
            while carol.forwarded_cells().await == 0 {
                assert!(
                    started.elapsed() < STEP_DEADLINE,
                    "{name}: the multihop rung is selected, but carol forwarded no cell"
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }

    for kind in cell.kinds {
        match kind {
            Kind::Unicast => {
                let text = format!("matrix {name}");
                let sent = alice.send("bob", &text).await;
                let started = Instant::now();
                if expected.is_some() {
                    sent.unwrap_or_else(|error| panic!("{name}: the send was refused: {error}"));
                    while !bob.saw_msg(&text) {
                        assert!(
                            started.elapsed() < PAYLOAD_DEADLINE,
                            "{name}: the message never reached bob on {expected:?}"
                        );
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                } else {
                    // No rung may carry payload: a refusal, or silence, and never
                    // a delivery over the relay.
                    while started.elapsed() < REFUSAL_WINDOW {
                        assert!(
                            !bob.saw_msg(&text),
                            "{name}: the message arrived on a rung that may not carry payload"
                        );
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }
            }
        }
    }

    for member in [alice, bob, carol] {
        member.leave().await;
    }
}

macro_rules! cells {
    ($($(#[$meta:meta])* $name:ident { $($transport:ident),+ } $blocked:ident $via_third:literal;)*) => {
        /// Every cell, by name, so that a test can check the matrix against the
        /// transport lists that the protocol accepts.
        const CELLS: &[(&str, Cell)] = &[$((
            stringify!($name),
            Cell {
                transports: &[$(Transport::$transport),+],
                blocked: Blocked::$blocked,
                kinds: &[Kind::Unicast],
                via_third: $via_third,
                target_full: false,
            },
        )),*];

        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            $(#[$meta])*
            async fn $name() {
                let (_, cell) = CELLS
                    .iter()
                    .find(|(name, _)| *name == stringify!($name))
                    .expect("the cell is in the table");
                run(*cell, stringify!($name)).await;
            }
        )*
    };
}

cells! {
    #[ignore = "nightly: cargo task matrix"]
    udp_none_direct { Udp } None false;
    #[ignore = "nightly: cargo task matrix"]
    udp_ip_direct { Udp } Ip false;
    #[ignore = "nightly: cargo task matrix"]
    webrtc_none_direct { WebRtc } None false;
    #[ignore = "nightly: cargo task matrix"]
    webrtc_ip_webrtc_direct { WebRtc } IpWebRtc false;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_none_direct { Udp, WebRtc } None false;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_ip_direct { Udp, WebRtc } Ip false;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_ip_webrtc_direct { Udp, WebRtc } IpWebRtc false;
    #[ignore = "nightly: cargo task matrix"]
    udp_multihop_none_direct { Udp, Multihop } None false;
    #[ignore = "nightly: cargo task matrix"]
    udp_multihop_ip_direct { Udp, Multihop } Ip false;
    #[ignore = "nightly: cargo task matrix"]
    udp_multihop_ip_webrtc_multihop_direct { Udp, Multihop } IpWebRtcMultihop false;
    #[ignore = "nightly: cargo task matrix"]
    udp_multihop_ip_webrtc_via_third { Udp, Multihop } IpWebRtc true;
    #[ignore = "nightly: cargo task matrix"]
    udp_relay_none_direct { Udp, Relay } None false;
    #[ignore = "nightly: cargo task matrix"]
    udp_relay_ip_direct { Udp, Relay } Ip false;
    #[ignore = "nightly: cargo task matrix"]
    webrtc_relay_none_direct { WebRtc, Relay } None false;
    #[ignore = "nightly: cargo task matrix"]
    webrtc_relay_ip_webrtc_direct { WebRtc, Relay } IpWebRtc false;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_multihop_none_direct { Udp, WebRtc, Multihop } None false;
    udp_webrtc_multihop_ip_direct { Udp, WebRtc, Multihop } Ip false;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_multihop_ip_webrtc_direct { Udp, WebRtc, Multihop } IpWebRtc false;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_multihop_ip_webrtc_multihop_direct { Udp, WebRtc, Multihop } IpWebRtcMultihop false;
    udp_webrtc_multihop_ip_webrtc_via_third { Udp, WebRtc, Multihop } IpWebRtc true;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_relay_none_direct { Udp, WebRtc, Relay } None false;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_relay_ip_direct { Udp, WebRtc, Relay } Ip false;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_relay_ip_webrtc_direct { Udp, WebRtc, Relay } IpWebRtc false;
    #[ignore = "nightly: cargo task matrix"]
    udp_multihop_relay_none_direct { Udp, Multihop, Relay } None false;
    #[ignore = "nightly: cargo task matrix"]
    udp_multihop_relay_ip_direct { Udp, Multihop, Relay } Ip false;
    #[ignore = "nightly: cargo task matrix"]
    udp_multihop_relay_ip_webrtc_multihop_direct { Udp, Multihop, Relay } IpWebRtcMultihop false;
    #[ignore = "nightly: cargo task matrix"]
    udp_multihop_relay_ip_webrtc_via_third { Udp, Multihop, Relay } IpWebRtc true;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_multihop_relay_none_direct { Udp, WebRtc, Multihop, Relay } None false;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_multihop_relay_ip_direct { Udp, WebRtc, Multihop, Relay } Ip false;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_multihop_relay_ip_webrtc_direct { Udp, WebRtc, Multihop, Relay } IpWebRtc false;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_multihop_relay_ip_webrtc_multihop_direct { Udp, WebRtc, Multihop, Relay } IpWebRtcMultihop false;
    #[ignore = "nightly: cargo task matrix"]
    udp_webrtc_multihop_relay_ip_webrtc_via_third { Udp, WebRtc, Multihop, Relay } IpWebRtc true;
}

/// The matrix covers exactly the lists that the protocol accepts: every valid
/// subset of the four transports is in a cell, and no cell names an invalid one.
/// The empty list is the default, `udp,webrtc,multihop`, and so already there.
#[test]
fn the_cells_cover_every_valid_transport_list_and_no_other() {
    use Transport::{Multihop, Relay, Udp, WebRtc};
    let all = [Udp, WebRtc, Multihop, Relay];
    let in_cells = |list: &[Transport]| {
        CELLS.iter().any(|(_, cell)| {
            cell.transports.len() == list.len() && list.iter().all(|wanted| cell.has(*wanted))
        })
    };
    for mask in 1u8..16 {
        let list: Vec<Transport> = all
            .iter()
            .enumerate()
            .filter(|(bit, _)| mask >> bit & 1 == 1)
            .map(|(_, transport)| *transport)
            .collect();
        let valid = MeshConfig::resolve(&[Lookup::Relay], None, &list).is_ok();
        assert_eq!(in_cells(&list), valid, "the transport list {list:?}");
    }
}

#[test]
fn a_cell_name_is_in_the_table_once() {
    for (index, (name, _)) in CELLS.iter().enumerate() {
        assert!(
            CELLS.iter().skip(index + 1).all(|(other, _)| other != name),
            "{name} is twice in the table"
        );
    }
}
