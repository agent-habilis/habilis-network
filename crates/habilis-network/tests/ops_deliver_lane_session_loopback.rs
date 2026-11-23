//! A directed send by `ops::deliver` to a peer with no IP path asks for the lane session of the peer.
//!
//! Two members on a local relay, with the transport list `udp,webrtc`: the relay carries no payload.
//! Bob has no UDP socket and so no IP address: the pair has only `WebRTC`, and a session must open
//! for a frame to go. The test sends only by `ops::deliver`, the way a consumer app does: no
//! `send_app`, and no `Membership` send anywhere, so nothing but the engine can ask for the session.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{
    self, Blocking, Inbound, Inspect, InspectTest, Membership, MessagingTest, Request,
};
use habilis_network::net;
use habilis_network::protocol::{Lookup, Transport};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time;

/// How long the mesh may take to form.
const MESH_DEADLINE: Duration = Duration::from_mins(1);

/// How long the session of the pair may take to open after the first send.
const SESSION_DEADLINE: Duration = Duration::from_mins(2);

/// How long a send may take once the session is open.
const PAYLOAD_DEADLINE: Duration = Duration::from_secs(30);

struct Member {
    membership: Membership,
    _events: UnboundedReceiver<String>,
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
        }
    }

    async fn create(nick: &str, relay: &RelayUrl) -> Self {
        let options = membership::JoinOptions::default()
            .nick(Some(nick.to_owned()))
            .lookup(vec![Lookup::Relay])
            .transport(vec![Transport::Udp, Transport::WebRtc])
            .relay_urls(vec![relay.to_string()]);
        Self::open(&options).await
    }

    /// A member of the mesh of `creator` with the same transport list.
    async fn join_with_webrtc(nick: &str, creator: &Self, relay: &RelayUrl) -> Self {
        let mesh = creator.membership.node.mesh_id().to_string();
        Self::open(
            &membership::JoinOptions::default()
                .nick(Some(nick.to_owned()))
                .mesh(Some(mesh))
                .lookup(vec![Lookup::Relay])
                .transport(vec![Transport::Udp, Transport::WebRtc])
                .relay_urls(vec![relay.to_string()]),
        )
        .await
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

    /// The rung of the selected path on the pooled connection to `peer`, if the member holds one.
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

    /// A directed send through `ops::deliver`, as a consumer app calls it. An error is an answer.
    async fn ops_send(&self, to: &str, text: &str) -> Result<(), String> {
        let to = membership::parse_to(Some(to)).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::MessagingTest(MessagingTest::OpsSend { to, body, reply }))
            .await
            .expect("the loop answers")
    }

    /// How many messages of directed sends the loop of this member has handled.
    async fn sends_started_handled(&self) -> u64 {
        self.membership
            .request(|reply| Request::InspectTest(InspectTest::SendsStartedHandled { reply }))
            .await
            .expect("the loop answers")
    }

    fn arrived(&mut self, text: &str) -> bool {
        let mut seen = false;
        while let Ok(Inbound {
            directed,
            text: got,
            ..
        }) = self.membership.inbound.try_recv()
        {
            seen |= directed && got == text;
        }
        seen
    }
}

/// Two members that formed a mesh on IP, then lose IP to each other, with no send in between.
async fn pair_with_ip_cut() -> (Member, Member, Instant, impl Sized) {
    let (relay, server) = net::test_relay::spawn_plain().await.expect("local relay");
    let alice = Member::create("alice", &relay).await;
    let bob = Member::join_with_webrtc("bob", &alice, &relay).await;
    let started = Instant::now();
    while alice.roster_len().await < 1 || bob.roster_len().await < 1 {
        assert!(started.elapsed() < MESH_DEADLINE, "the mesh never formed");
        time::sleep(Duration::from_millis(500)).await;
    }
    alice
        .block_ip_to(bob.membership.node.bound_ports().to_vec())
        .await;
    bob.block_ip_to(alice.membership.node.bound_ports().to_vec())
        .await;
    (alice, bob, Instant::now(), server)
}

/// Waits for the rung `webrtc` to `bob`, and says how long it took from `since`.
async fn wait_for_webrtc(alice: &Member, since: Instant) -> Option<Duration> {
    while since.elapsed() < SESSION_DEADLINE {
        if alice.rung_to("bob").await == Some("webrtc") {
            return Some(since.elapsed());
        }
        time::sleep(Duration::from_millis(250)).await;
    }
    None
}

/// With no send at all after the cut, does the session open, and when, counted from the cut?
#[test]
fn the_session_of_a_pair_that_lost_ip_opens_with_no_send() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (alice, bob, cut_at, _server) = pair_with_ip_cut().await;
        let opened = wait_for_webrtc(&alice, cut_at).await;
        eprintln!("TIMING no send: the rung is webrtc after {opened:?} from the cut");
        for member in [alice, bob] {
            let _ = member.membership.node.leave().await;
        }
    });
}

/// A send by `ops::deliver` right after the cut, and the one property that it must keep: a frame
/// that bob reads was not written on a relay path, and a send that is refused names the relay and
/// delivers nothing. The cut of the harness is not instant, so the first send can ride the IP path
/// that iroh still has selected, ride a `WebRTC` path that a dial finds, or meet the relay and be
/// refused. Each case is checked in full, and the test does not count which one a run takes. The
/// read of the rung before the send opens a connection if the member holds none (`rung None` then
/// means that no connection was there), and the property holds with or without it. A second send
/// after the session is open is delivered and read.
#[test]
fn a_send_by_ops_deliver_after_the_ip_cut_ends_with_a_verdict_and_the_next_one_is_delivered() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (alice, mut bob, cut_at, _server) = pair_with_ip_cut().await;

        // The cut of the harness is not instant: iroh keeps the IP path selected until its path
        // statistics move. A send before that carries the frame on IP, and tests nothing.
        while alice.rung_to("bob").await == Some("ip") && cut_at.elapsed() < SESSION_DEADLINE {
            time::sleep(Duration::from_millis(250)).await;
        }
        let before = alice.rung_to("bob").await;
        eprintln!(
            "TIMING rung just before the first send: {before:?} after {:?} from the cut",
            cut_at.elapsed()
        );
        let first = alice.ops_send("bob", "first").await;
        eprintln!(
            "TIMING first ops send: {first:?} after {:?} from the cut",
            cut_at.elapsed()
        );
        let after = alice.rung_to("bob").await;
        eprintln!("TIMING rung just after the first send: {after:?}");
        time::sleep(Duration::from_secs(3)).await;
        let read = bob.arrived("first");
        eprintln!("TIMING bob read the first send: {read}");
        // Either the frame went on a path that is not the relay and bob read it, or the send was
        // refused with the relay text and bob read nothing. Both are safe. A frame that bob reads
        // after a refusal, or a send that is delivered while the rung reads relay, is a payload
        // on the relay.
        match &first {
            Ok(()) => {
                assert!(read, "the send was delivered and bob did not read it");
                assert_ne!(
                    after,
                    Some("relay"),
                    "a delivered send with the rung on the relay"
                );
            }
            Err(text) => {
                assert!(
                    text.contains("the relay is lookup only on this mesh"),
                    "the refusal does not name the relay: {text}"
                );
                assert!(!read, "bob read a frame whose send was refused");
            }
        }

        let opened = wait_for_webrtc(&alice, cut_at).await;
        eprintln!("TIMING the rung is webrtc after {opened:?} from the cut");
        assert!(
            opened.is_some(),
            "no session within {SESSION_DEADLINE:?} of the cut"
        );

        let second_at = Instant::now();
        let mut second = alice.ops_send("bob", "second").await;
        while second.is_err() && second_at.elapsed() < PAYLOAD_DEADLINE {
            time::sleep(Duration::from_secs(1)).await;
            second = alice.ops_send("bob", "second").await;
        }
        assert_eq!(second, Ok(()), "the send after the session is open must go");
        assert!(
            time::timeout(PAYLOAD_DEADLINE, async {
                while !bob.arrived("second") {
                    time::sleep(Duration::from_millis(200)).await;
                }
            })
            .await
            .is_ok(),
            "bob never read the second message"
        );
        for member in [alice, bob] {
            let _ = member.membership.node.leave().await;
        }
    });
}

/// The wiring, in a real node: a send by `ops::deliver` makes the select arm of the loop run the
/// function for it. The unit tests call that function themselves, so only a real loop shows that the
/// sender is installed and that the arm is there.
#[test]
fn a_send_by_ops_deliver_reaches_the_arm_of_a_real_loop() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = net::test_relay::spawn_plain().await.expect("local relay");
        let alice = Member::create("alice", &relay).await;
        let bob = Member::join_with_webrtc("bob", &alice, &relay).await;
        let started = Instant::now();
        while alice.roster_len().await < 1 || bob.roster_len().await < 1 {
            assert!(started.elapsed() < MESH_DEADLINE, "the mesh never formed");
            time::sleep(Duration::from_millis(500)).await;
        }
        let before = alice.sends_started_handled().await;
        let _ = alice.ops_send("bob", "wired").await;
        let mut after = alice.sends_started_handled().await;
        let waited = Instant::now();
        while after <= before && waited.elapsed() < Duration::from_secs(5) {
            time::sleep(Duration::from_millis(100)).await;
            after = alice.sends_started_handled().await;
        }
        assert!(
            after > before,
            "the loop handled no message for the send: {before} before, {after} after"
        );
        for member in [alice, bob] {
            let _ = member.membership.node.leave().await;
        }
    });
}
