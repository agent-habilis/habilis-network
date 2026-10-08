//! Requirement 9: gossip carries the payload of a pair that has no other path, and the features
//! run over it (Phase 6, design section 7).
//!
//! Four members on a local relay, A (alice), B (bob), C (carol) and D (dave), on the transport
//! list `udp,gossip`. IP between alice and carol is cut in both directions, so they are not
//! neighbors: alice-bob and bob-carol keep their paths and carry the gossip links, and dave is a
//! bystander that must carry the flood. A message from alice to carol can then ride the gossip
//! rung only.
//!
//! Every test is `#[ignore]`: each stands up four real members, and they run one at a time, under
//! a host grant, with `--include-ignored --test-threads=1` (`cargo task matrix`). While the engine
//! does not install the gossip transport (`common::GOSSIP_INSTALLED`), a test prints SKIPPED and
//! returns. The helpers are a slim copy of those of `send_ladder_matrix.rs`: the two files are
//! separate test crates.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

mod common;

use std::time::{Duration, Instant};

use common::GOSSIP_INSTALLED;
use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inbound, Membership, Request};
use habilis_network::protocol::{Lookup, Transport};
use tokio::sync::mpsc::UnboundedReceiver;

/// Long enough for the gossip path to be tried and chosen: a probe goes every second.
const STEP_DEADLINE: Duration = Duration::from_mins(2);
const PAYLOAD_DEADLINE: Duration = Duration::from_secs(20);
/// How long the gossip rung must be read, in a row, for the pair to count as settled.
const SETTLE: Duration = Duration::from_secs(10);

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

    async fn create(nick: &str, relay: &RelayUrl) -> Self {
        Self::open(&membership::Opts {
            nick: Some(nick.to_owned()),
            lookup: vec![Lookup::Relay],
            transport: vec![Transport::Udp, Transport::Gossip],
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

    /// A directed message. A refusal is an answer, not a failure of the harness.
    async fn send(&self, to: &str, text: &str) -> Result<(), String> {
        let to = membership::parse_to(Some(to)).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Send { to, body, reply })
            .await
            .expect("the loop answers")
    }

    /// The nicknames that answered one ping round.
    async fn ping(&self) -> Vec<String> {
        self.membership
            .request(|reply| Request::Ping { reply })
            .await
            .expect("the loop answers")
            .into_iter()
            .map(|(nick, _)| nick.as_str().to_owned())
            .collect()
    }

    /// How many gossip connections the recursion rule has closed in this process so far.
    async fn recursion_closes(&self) -> u64 {
        self.membership
            .request(|reply| Request::GossipRecursionCloses { reply })
            .await
            .expect("the loop answers")
    }

    async fn state_merge(&self, merge: serde_json::Value) -> Result<(), String> {
        self.membership
            .request(|reply| Request::StateMerge { merge, reply })
            .await
            .expect("the loop answers")
    }

    async fn state_json(&self) -> String {
        self.membership
            .request(|reply| Request::StateJson { reply })
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

    /// Settle the pair on `expected`, driving it as production does: the engine tries a better
    /// path only for a pair that is sent to, so a probe goes every second.
    async fn settle_on(&self, peer: &str, expected: &str, name: &str) {
        let started = Instant::now();
        let mut held_since: Option<Instant> = None;
        let mut seen = None;
        let mut probes = 0u32;
        while started.elapsed() < STEP_DEADLINE {
            probes += 1;
            let _ = self.send(peer, &format!("probe {name} {probes}")).await;
            seen = self.rung_to(peer).await;
            if seen == Some(expected) {
                if held_since.get_or_insert_with(Instant::now).elapsed() >= SETTLE {
                    return;
                }
            } else {
                held_since = None;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        panic!(
            "{name}: expected the rung {expected}, the last rung read was {seen:?} after {probes} probes"
        );
    }

    async fn leave(self) {
        let _ = self.membership.node.leave().await;
    }
}

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

/// The four members, cut between alice and carol, with the rungs asserted: alice reaches bob on
/// IP and carol on gossip.
struct Fixture {
    alice: Member,
    bob: Member,
    carol: Member,
    dave: Member,
    _relay: Box<dyn std::any::Any + Send>,
}

impl Fixture {
    async fn stand_up(name: &str) -> Self {
        init_logging();
        let (relay_url, relay) = habilis_network::net::test_relay::spawn_plain()
            .await
            .expect("local relay");
        let alice = Member::create("alice", &relay_url).await;
        let bob = Member::join("bob", &alice).await;
        let carol = Member::join("carol", &alice).await;
        let dave = Member::join("dave", &alice).await;
        assert!(
            rosters_hold(&[&alice, &bob, &carol, &dave], 3, Duration::from_mins(1)).await,
            "{name}: the four members never formed a mesh"
        );
        // The pair that keeps its path stands on IP.
        alice.settle_on("bob", "ip", name).await;

        alice.block_ip_to(carol.ports()).await;
        carol.block_ip_to(alice.ports()).await;
        alice.settle_on("carol", "gossip", name).await;
        assert_eq!(
            alice.rung_to("bob").await,
            Some("ip"),
            "{name}: alice-bob keeps its IP path while alice-carol rides gossip"
        );
        Self {
            alice,
            bob,
            carol,
            dave,
            _relay: Box::new(relay),
        }
    }

    async fn leave(self) {
        for member in [self.alice, self.bob, self.carol, self.dave] {
            member.leave().await;
        }
    }
}

/// The gate: the test needs the gossip transport that the engine does not install yet.
fn skipped(name: &str) -> bool {
    if GOSSIP_INSTALLED {
        return false;
    }
    eprintln!("SKIPPED {name}: the engine does not install the gossip transport yet");
    true
}

/// A directed message from alice reaches carol, who has no other path to her, and the reply
/// from carol reaches alice: the rung is gossip both ways. The design lists "unicast" and
/// "directed" as two features; here they are one API, a payload on the pooled unicast connection
/// to the peer, so this one test covers both. A request and its response are two such frames:
/// the engine routes a directed frame with a correlation id as it routes a message
/// (`transport/send.rs`, `directed_rpc_and_pong_also_take_unicast`), and the waiter is the
/// application's. A broadcast does not use the transports, so it is not in this list.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn a_directed_message_crosses_a_pair_with_no_other_path_on_the_gossip_rung() {
    const NAME: &str = "gossip_only_directed";
    if skipped(NAME) {
        return;
    }
    let mut fixture = Fixture::stand_up(NAME).await;

    let text = format!("{NAME} alice to carol");
    fixture
        .alice
        .send("carol", &text)
        .await
        .unwrap_or_else(|error| panic!("{NAME}: the send was refused: {error}"));
    let started = Instant::now();
    while !fixture.carol.saw_msg(&text) {
        assert!(
            started.elapsed() < PAYLOAD_DEADLINE,
            "{NAME}: the message never reached carol on the gossip rung"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let reply = format!("{NAME} carol to alice");
    fixture
        .carol
        .send("alice", &reply)
        .await
        .unwrap_or_else(|error| panic!("{NAME}: the reply was refused: {error}"));
    let reply_started = Instant::now();
    while !fixture.alice.saw_msg(&reply) {
        assert!(
            reply_started.elapsed() < PAYLOAD_DEADLINE,
            "{NAME}: the reply never reached alice on the gossip rung"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    assert_eq!(
        fixture.alice.rung_to("carol").await,
        Some("gossip"),
        "{NAME}: the pair is still on the gossip rung after the exchange"
    );
    fixture.leave().await;
}

/// Every member answers a ping, and carol answers alice, whose only path to her is the gossip
/// rung. The pong goes out over a warm unicast connection or not at all, so the answer shows
/// that this connection runs on the gossip rung. The pair stays on that rung after the round.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn a_ping_is_answered_across_a_pair_with_no_other_path_on_the_gossip_rung() {
    const NAME: &str = "gossip_only_auto_pong";
    if skipped(NAME) {
        return;
    }
    let fixture = Fixture::stand_up(NAME).await;
    // The pong goes out over a warm unicast connection or not at all, and only alice has sent
    // to carol so far: carol warms her side the way production does, by sending.
    fixture.carol.settle_on("alice", "gossip", NAME).await;

    let answered = fixture.alice.ping().await;
    for peer in ["bob", "carol", "dave"] {
        assert!(
            answered.iter().any(|nick| nick == peer),
            "{NAME}: {peer} never answered alice's ping: {answered:?}"
        );
    }
    let answered_by_alice = fixture.carol.ping().await;
    assert!(
        answered_by_alice.iter().any(|nick| nick == "alice"),
        "{NAME}: alice never answered carol's ping on the gossip rung: {answered_by_alice:?}"
    );

    assert_eq!(
        fixture.alice.rung_to("carol").await,
        Some("gossip"),
        "{NAME}: the pair is still on the gossip rung after the round"
    );
    fixture.leave().await;
}

/// The most gossip connections that the recursion rule may close in `CHURN_WINDOW` for a pair
/// that has only the gossip rung. The rule closes a gossip link whose path is the gossip rung, so
/// the engine must not graft such a pair: `request_graft` refuses it. With the bound at 0 the
/// engine grafted the pair again about every 10 s (3, 2 and 3 closes in 30 s). A guard in
/// `graft_proven` alone left the `PeerInfo` graft: 2, 0, 0, 2, 0, 2, 1 and 1 closes. With the
/// guard in `request_graft`, six runs gave 0.
const CHURN_BOUND: u64 = 0;
const CHURN_WINDOW: Duration = Duration::from_secs(30);

/// A pair with only the gossip rung does not churn: while the pair is read for `CHURN_WINDOW`
/// (a probe goes every second, as production sends), the count of closes of the recursion rule
/// stays within `CHURN_BOUND`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn a_pair_with_only_the_gossip_rung_does_not_churn_its_gossip_link() {
    const NAME: &str = "gossip_only_churn";
    if skipped(NAME) {
        return;
    }
    let fixture = Fixture::stand_up(NAME).await;
    let before = fixture.alice.recursion_closes().await;
    let started = Instant::now();
    let mut probes = 0_u32;
    while started.elapsed() < CHURN_WINDOW {
        probes += 1;
        let _ = fixture
            .alice
            .send("carol", &format!("churn probe {NAME} {probes}"))
            .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let closes = fixture.alice.recursion_closes().await - before;
    eprintln!("DIAG {NAME}: {closes} closes of the recursion rule in {CHURN_WINDOW:?}");
    assert!(
        closes <= CHURN_BOUND,
        "{NAME}: the recursion rule closed {closes} gossip links in {CHURN_WINDOW:?}, \
         more than the bound {CHURN_BOUND}: the pair loops"
    );
    assert_eq!(
        fixture.alice.rung_to("carol").await,
        Some("gossip"),
        "{NAME}: the pair is on the gossip rung at the end"
    );
    fixture.leave().await;
}

/// State is a topic broadcast: a change that alice writes reaches carol through the mesh, and
/// the gossip rung carries none of it. This is the row for state in the gossip-only list. It
/// shows that state still converges while the pair has only the rung, and it does not claim
/// that the rung carried the change. Backfill (the unicast answer to a digest) goes only to a
/// linked neighbor, and a gossip-only pair cannot keep a link, so the unit tests in
/// `transport/send.rs` own it: a proven asker that is not linked is answered on the topic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn state_written_by_alice_reaches_carol_while_the_pair_has_only_the_gossip_rung() {
    const NAME: &str = "gossip_only_state";
    if skipped(NAME) {
        return;
    }
    let fixture = Fixture::stand_up(NAME).await;

    fixture
        .alice
        .state_merge(serde_json::json!({ NAME: "held" }))
        .await
        .unwrap_or_else(|error| panic!("{NAME}: the merge was refused: {error}"));
    let started = Instant::now();
    let pair = format!("\"{NAME}\":\"held\"");
    while !fixture
        .carol
        .state_json()
        .await
        .replace(' ', "")
        .contains(&pair)
    {
        assert!(
            started.elapsed() < PAYLOAD_DEADLINE,
            "{NAME}: carol never held alice's change"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    fixture.leave().await;
}
