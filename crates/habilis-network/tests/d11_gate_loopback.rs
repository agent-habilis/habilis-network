//! End-to-end checks of decision D11 (the ceiling C of direct connections) on a local relay, with
//! real members. Each test is `#[ignore]`: it stands up several real members, so it runs alone, in
//! the host slot of the gate (`cargo test --test d11_gate_loopback -- --include-ignored
//! --test-threads=1`).
//!
//! - `a_node_at_a_ceiling_of_two_delivers_every_frame_while_it_evicts`: alice holds at most two
//!   direct connections and sends in rotation to three peers. Every frame must arrive, and the
//!   ledger must never count more than two units once the sends have ended. Eviction closes an idle
//!   connection, a send dials at once, and a busy connection is not a victim.
//! - `a_lane_pair_delivers_a_frame_sent_as_soon_as_the_roster_forms`: a mesh whose only transport
//!   is `webrtc` (the relay is lookup only), so every pair needs the lane. A frame in each direction,
//!   sent when the roster holds, must arrive: the node that holds the frame is the higher id in one of
//!   the two directions.
//!
//! What these do not show: a slow reader. The acceptor of a real member reads at once, so the busy
//! mark with a slow reader is covered by the unit test in `transport/pool.rs`.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inbound, Membership, Request};
use habilis_network::protocol::{Lookup, Transport};
use tokio::sync::mpsc::UnboundedReceiver;

const ROSTER_DEADLINE: Duration = Duration::from_mins(2);
const FRAME_DEADLINE: Duration = Duration::from_mins(2);

struct Member {
    membership: Membership,
    _events: UnboundedReceiver<String>,
    seen: Vec<Inbound>,
}

impl Member {
    async fn open(opts: &membership::Opts) -> Self {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(opts, sink).await.expect("open a member");
        Self {
            membership,
            _events: events,
            seen: Vec::new(),
        }
    }

    async fn create(
        nick: &str,
        relay: &RelayUrl,
        transport: Vec<Transport>,
        max_direct: usize,
    ) -> Self {
        Self::open(&membership::Opts {
            nick: Some(nick.to_owned()),
            lookup: vec![Lookup::Relay],
            transport,
            relay_urls: vec![relay.to_string()],
            max_direct,
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

    async fn direct_units(&self) -> (usize, usize) {
        self.membership
            .request(|reply| Request::DirectUnits { reply })
            .await
            .expect("the loop answers")
    }

    async fn send(&self, to: &str, text: &str) -> Result<(), String> {
        let to = membership::parse_to(Some(to)).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Send { to, body, reply })
            .await
            .expect("the loop answers")
    }

    fn saw(&mut self, text: &str) -> bool {
        while let Ok(msg) = self.membership.inbound.try_recv() {
            self.seen.push(msg);
        }
        self.seen.iter().any(|msg| msg.directed && msg.text == text)
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

/// Send `text` from `from` to `to` until it is read at `to`, or the deadline ends. A refusal while
/// no path may carry the frame is an answer, so the send goes again.
async fn delivered(from: &Member, to: &mut Member, to_nick: &str, text: &str) -> bool {
    let started = Instant::now();
    loop {
        let _ = from.send(to_nick, text).await;
        if to.saw(text) {
            return true;
        }
        if started.elapsed() >= FRAME_DEADLINE {
            return false;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs real members; run alone in the host slot"]
async fn a_node_at_a_ceiling_of_two_delivers_every_frame_while_it_evicts() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let alice = Member::create("alice", &relay, vec![Transport::Udp], 2).await;
    let mut bob = Member::join("bob", &alice).await;
    let mut carol = Member::join("carol", &alice).await;
    let mut dave = Member::join("dave", &alice).await;
    assert!(
        rosters_hold(&[&alice, &bob, &carol, &dave], 3, ROSTER_DEADLINE).await,
        "the four members never formed a mesh"
    );

    for round in 0..3 {
        for (nick, member) in [
            ("bob", &mut bob),
            ("carol", &mut carol),
            ("dave", &mut dave),
        ] {
            let text = format!("rotation {round} to {nick}");
            assert!(
                delivered(&alice, member, nick, &text).await,
                "{text:?} never arrived"
            );
            let (units, _) = alice.direct_units().await;
            eprintln!("DIAG after {text:?}: alice counts {units} direct units");
        }
    }

    // Busy units can put the count over the ceiling for a moment; once the sends end, it settles.
    let started = Instant::now();
    loop {
        let (units, over) = alice.direct_units().await;
        if units <= 2 && over == 0 {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "alice still counts {units} units ({over} over) 30 s after the last send"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    for member in [alice, bob, carol, dave] {
        member.leave().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs real members; run alone in the host slot"]
async fn a_lane_pair_delivers_a_frame_sent_as_soon_as_the_roster_forms() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let mut alice = Member::create("alice", &relay, vec![Transport::WebRtc], 0).await;
    let mut bob = Member::join("bob", &alice).await;
    assert!(
        rosters_hold(&[&alice, &bob], 1, ROSTER_DEADLINE).await,
        "the two members never formed a mesh"
    );

    // One of the two ids is the higher: the frame is held on it in one direction, and on the lower
    // id in the other.
    assert!(
        delivered(&alice, &mut bob, "bob", "lane frame alice to bob").await,
        "alice to bob never arrived"
    );
    assert!(
        delivered(&bob, &mut alice, "alice", "lane frame bob to alice").await,
        "bob to alice never arrived"
    );

    alice.leave().await;
    bob.leave().await;
}
