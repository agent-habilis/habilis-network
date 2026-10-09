//! A pair that cannot use IP or `WebRTC` to each other reaches each other through a
//! third member, on the multihop rung, and a message arrives.
//!
//! Three native members on a local relay, with the list `udp,webrtc,multihop`: no relay
//! carries payload. `bob` and `carol` deny each other (`Request::DenyPeer`, on the
//! application endpoint and on the underlay, as a tab that has no direct session would
//! look to a native) and lose IP to each other, so every packet of the pair takes the
//! route bob -> alice -> carol. The test shows whether a message crosses that route and
//! whether `alice` forwards cells for it. It is the native counterpart of the browser
//! cell of the multihop e2e: a green run here puts the fault on the browser side, a red
//! run on the multihop data path after a deny.
//!
//! What the run does and does not show:
//! - Bob and carol are IP pairs to the engine. The climb to multihop comes from the
//!   `Multihop` branch of `on_path_change`, and not from the sweep rule, so a green run says
//!   nothing about the sweep, and a red run is below the engine.
//! - The IP cuts only take IP away from selection: the IP paths exist and cannot be
//!   selected. A browser pair has no IP path at all.
//! - `before`, the count of the cells that alice forwarded, is read right before the payload
//!   is sent, because the probes that were flushed add cells.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inbound, Membership, Request};
use habilis_network::protocol::{Lookup, Transport};
use habilis_network_iroh_multihop_transport::MultihopCounters;
use tokio::sync::mpsc::UnboundedReceiver;

/// Long enough for the climb to multihop and for the topology to hold the route.
const STEP_DEADLINE: Duration = Duration::from_mins(3);

/// How long a message may take over a route that is already up.
const PAYLOAD_DEADLINE: Duration = Duration::from_secs(30);

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

    fn underlay_id(&self) -> iroh::EndpointId {
        self.membership.node.underlay_id().expect("multihop is on")
    }

    fn underlay_ports(&self) -> Vec<u16> {
        self.membership.node.underlay_ports().to_vec()
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

    /// Refuse every `WebRTC` session with `peer`, on the application endpoint and on the
    /// underlay.
    async fn deny_peer(&self, peer: &str) {
        self.membership
            .request(|reply| Request::DenyPeer {
                peer: peer.to_owned(),
                denied: true,
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

    async fn forwarded_cells(&self) -> u64 {
        self.membership
            .request(|reply| Request::ForwardedCells { reply })
            .await
            .expect("the loop answers")
    }

    async fn counters(&self) -> MultihopCounters {
        self.membership
            .request(|reply| Request::MultihopCounters { reply })
            .await
            .expect("the loop answers")
    }

    /// Send a directed message. A refusal is an answer, not a failure.
    async fn send(&self, to: &str, text: &str) -> Result<(), String> {
        let to = membership::parse_to(Some(to)).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Send { to, body, reply })
            .await
            .expect("the loop answers")
    }

    /// Whether a directed message with this text has arrived at this member.
    fn saw_msg(&mut self, text: &str) -> bool {
        while let Ok(msg) = self.membership.inbound.try_recv() {
            self.seen_msgs.push(msg);
        }
        self.seen_msgs
            .iter()
            .any(|msg| msg.directed && msg.text == text)
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

/// What the three members counted, for the message of a failure.
async fn counters_of(alice: &Member, bob: &Member, carol: &Member) -> String {
    format!(
        "alice {:?}, bob {:?}, carol {:?}",
        alice.counters().await,
        bob.counters().await,
        carol.counters().await
    )
}

/// IP between the two, on the application endpoints and on the underlays, both ways.
async fn cut_ip_between(first: &Member, second: &Member) {
    first.block_ip_to(second.ports()).await;
    second.block_ip_to(first.ports()).await;
    for (from, to) in [(first, second), (second, first)] {
        habilis_network_iroh_webrtc_transport::block_ip_to(from.underlay_id(), to.underlay_ports());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pair_that_denied_each_other_still_gets_a_message_through_a_third_member() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let list = vec![Transport::Udp, Transport::WebRtc, Transport::Multihop];
    let alice = Member::create("alice", &relay, list).await;
    let bob = Member::join("bob", &alice).await;
    let mut carol = Member::join("carol", &alice).await;
    assert!(
        rosters_hold(&[&alice, &bob, &carol], 2, Duration::from_mins(1)).await,
        "the three members never formed a mesh"
    );

    // Bob and carol deny each other at both ends, then lose IP to each other: the only way
    // between them is alice.
    bob.deny_peer("carol").await;
    carol.deny_peer("bob").await;
    cut_ip_between(&bob, &carol).await;

    // The rung is read on bob's pooled connection to carol. A probe goes out each second,
    // because it is traffic that makes the engine try a better path.
    let started = Instant::now();
    let mut probes = 0_u32;
    let mut rung = None;
    while started.elapsed() < STEP_DEADLINE {
        probes += 1;
        let _ = bob.send("carol", &format!("probe {probes}")).await;
        rung = bob.rung_to("carol").await;
        if rung == Some("multihop") {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert_eq!(
        rung,
        Some("multihop"),
        "bob never reached carol on the multihop rung after {probes} probes: {}",
        counters_of(&alice, &bob, &carol).await
    );

    // The rung can be selected while the route is still stale: traffic goes on, until
    // alice has forwarded a cell.
    let forward_started = Instant::now();
    while alice.forwarded_cells().await == 0 {
        assert!(
            forward_started.elapsed() < STEP_DEADLINE,
            "bob reached carol on the multihop rung, but alice forwarded no cell: {}",
            counters_of(&alice, &bob, &carol).await
        );
        probes += 1;
        let _ = bob.send("carol", &format!("forward probe {probes}")).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // A payload goes from bob to carol over the hop: the message arrives, and alice has
    // forwarded more cells than before it was sent.
    let before = alice.forwarded_cells().await;
    let text = "payload over the hop";
    bob.send("carol", text)
        .await
        .unwrap_or_else(|error| panic!("the send over the hop was refused: {error}"));
    let sent_at = Instant::now();
    while !carol.saw_msg(text) {
        assert!(
            sent_at.elapsed() < PAYLOAD_DEADLINE,
            "the message never reached carol over the hop: {}",
            counters_of(&alice, &bob, &carol).await
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        alice.forwarded_cells().await > before,
        "the message reached carol, but alice forwarded no cell for it: {}",
        counters_of(&alice, &bob, &carol).await
    );

    eprintln!(
        "COUNTERS after the payload: {}",
        counters_of(&alice, &bob, &carol).await
    );
    for member in [alice, bob, carol] {
        let _ = member.membership.node.leave().await;
    }
}
