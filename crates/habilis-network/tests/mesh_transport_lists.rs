//! Two native members on one transport list each. The mesh id decides which
//! direct paths exist: a `webrtc` mesh must carry every lane over data
//! channels, and a `udp` mesh must never open one.
//!
//! The cells share one process-wide log buffer, so they run one at a time.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inbound, Membership, Request};
use habilis_network::protocol::{Lookup, Transport};
use tokio::sync::mpsc::UnboundedReceiver;

/// A JSEP round and a graft, with room to spare: a healthy pair is direct in
/// about 4 s. Below the 15 s heal tick on purpose, so a pair that only links
/// once a heal re-grafts it fails here instead of passing slowly.
const LINK_DEADLINE: Duration = Duration::from_secs(12);
const PAYLOAD_DEADLINE: Duration = Duration::from_secs(20);

fn serial() -> &'static tokio::sync::Mutex<()> {
    static SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn log_buffer() -> &'static Mutex<String> {
    static BUFFER: OnceLock<Mutex<String>> = OnceLock::new();
    BUFFER.get_or_init(|| Mutex::new(String::new()))
}

struct BufferWriter;

impl std::io::Write for BufferWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        log_buffer()
            .lock()
            .expect("no poison")
            .push_str(&String::from_utf8_lossy(bytes));
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Debug on the transport target (the session lines are debug) and on
/// iroh-gossip's dialer, which says which side dialed and what it closed.
fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(
            "habilis_network=info,habilis_network::transport=debug,iroh_gossip::net=debug",
        )
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(|| BufferWriter)
        .with_ansi(false)
        .try_init();
    log_buffer().lock().expect("no poison").clear();
}

fn logs() -> String {
    log_buffer().lock().expect("no poison").clone()
}

/// The engine lines that say how a link formed or why it did not.
fn link_trace() -> String {
    logs()
        .lines()
        .filter(|line| {
            [
                "session attached",
                "refused",
                "neighbor",
                "webrtc offer",
                "webrtc answer",
                "graft",
                "beacon role",
                "start to dial",
                "connection established",
                "connection closed",
                "Neighbor(",
                "watching the selected path",
                "watcher started",
                "selected path changed",
                "racing again",
                "udp",
                "not negotiating",
            ]
            .iter()
            .any(|needle| line.contains(needle))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

async fn eventually(deadline: Duration, mut done: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < deadline {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    done()
}

struct Member {
    membership: Membership,
    events: UnboundedReceiver<String>,
    seen_events: Vec<serde_json::Value>,
    seen_msgs: Vec<Inbound>,
}

impl Member {
    async fn open(opts: &membership::Opts) -> Self {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(opts, sink).await.expect("open a member");
        Self {
            membership,
            events,
            seen_events: Vec::new(),
            seen_msgs: Vec::new(),
        }
    }

    /// Mint a mesh over the local relay alone, with `transport` as its list.
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

    fn pump(&mut self) {
        while let Ok(json) = self.events.try_recv() {
            if let Ok(event) = serde_json::from_str(&json) {
                self.seen_events.push(event);
            }
        }
        while let Ok(msg) = self.membership.inbound.try_recv() {
            self.seen_msgs.push(msg);
        }
    }

    fn saw_joined(&mut self, nick: &str) -> bool {
        self.pump();
        self.seen_events.iter().any(|event| {
            event.get("kind").and_then(serde_json::Value::as_str) == Some("joined")
                && event.get("nick").and_then(serde_json::Value::as_str) == Some(nick)
        })
    }

    fn saw_msg(&mut self, text: &str, directed: bool) -> bool {
        self.pump();
        self.seen_msgs
            .iter()
            .any(|msg| msg.directed == directed && msg.text == text)
    }

    async fn roster(&self) -> String {
        self.membership
            .request(|reply| Request::Peers { reply })
            .await
            .unwrap_or_default()
    }

    async fn send(&self, to: Option<&str>, text: &str) {
        let to = membership::parse_to(to).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Send { to, body, reply })
            .await
            .expect("the loop answers")
            .expect("sent");
    }

    async fn state_merge(&self, merge: serde_json::Value) {
        self.membership
            .request(|reply| Request::StateMerge { merge, reply })
            .await
            .expect("the loop answers")
            .expect("merged");
    }

    async fn endpoint_id(&self) -> iroh::EndpointId {
        self.membership
            .request(|reply| Request::EndpointId { reply })
            .await
            .expect("the loop answers")
    }

    async fn block_udp(&self, blocked: bool) {
        self.membership
            .request(|reply| Request::BlockUdp { blocked, reply })
            .await
            .expect("the loop answers");
    }

    async fn state_json(&self) -> String {
        self.membership
            .request(|reply| Request::StateJson { reply })
            .await
            .unwrap_or_default()
    }
}

/// Stand up `alice` on `transport`, let her claim the beacon, join `bob`, and
/// wait until each has the other on a direct `unicast` lane.
async fn linked_pair(relay: &RelayUrl, transport: Vec<Transport>) -> (Member, Member) {
    let mut alice = Member::create("alice", relay, transport).await;
    assert!(
        eventually(Duration::from_mins(1), || logs()
            .contains("beacon role active"))
        .await,
        "alice never claimed the beacon"
    );
    let mut bob = Member::join("bob", &alice).await;
    let linked = eventually(LINK_DEADLINE, || {
        alice.saw_joined("bob") && bob.saw_joined("alice")
    })
    .await;
    assert!(linked, "the pair never linked\n{}", link_trace());
    let started = Instant::now();
    loop {
        let (alice_roster, bob_roster) = (alice.roster().await, bob.roster().await);
        if alice_roster.contains("\"transport\":\"unicast\"")
            && bob_roster.contains("\"transport\":\"unicast\"")
        {
            break;
        }
        assert!(
            started.elapsed() < LINK_DEADLINE,
            "the pair never went direct: {alice_roster} / {bob_roster}\n{}",
            link_trace()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    (alice, bob)
}

/// [`linked_pair`] again, until bob's endpoint id has the order given: the ids are random, and
/// only the lower id has a path watcher, so a test of the race names the order it is about.
async fn linked_pair_ordered(
    relay: &RelayUrl,
    transport: Vec<Transport>,
    bob_is_higher: bool,
) -> (Member, Member) {
    for _ in 0..20 {
        let (alice, bob) = linked_pair(relay, transport.clone()).await;
        if (alice.endpoint_id().await < bob.endpoint_id().await) == bob_is_higher {
            return (alice, bob);
        }
        let _ = alice.membership.node.leave().await;
        let _ = bob.membership.node.leave().await;
        log_buffer().lock().expect("no poison").clear();
    }
    panic!("no draw of ids gave bob the order (higher: {bob_is_higher}) in 20 tries");
}

/// Broadcast, a directed message and a state merge, each checked on the far
/// side.
async fn every_lane_carries(alice: &mut Member, bob: &mut Member) {
    alice.send(None, "hello, everyone").await;
    assert!(
        eventually(PAYLOAD_DEADLINE, || bob.saw_msg("hello, everyone", false)).await,
        "bob never got the broadcast"
    );
    bob.send(Some("alice"), "just for you").await;
    assert!(
        eventually(PAYLOAD_DEADLINE, || alice.saw_msg("just for you", true)).await,
        "alice never got the directed message"
    );
    alice
        .state_merge(serde_json::json!({ "lane": "state" }))
        .await;
    let started = Instant::now();
    while !bob.state_json().await.contains("\"lane\":\"state\"") {
        assert!(
            started.elapsed() < PAYLOAD_DEADLINE,
            "bob never got the state merge"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_webrtc_only_mesh_carries_every_lane_between_natives() {
    let _serial = serial().lock().await;
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");

    let (mut alice, mut bob) = linked_pair(&relay, vec![Transport::WebRtc]).await;
    every_lane_carries(&mut alice, &mut bob).await;

    let logs = logs();
    let _ = alice.membership.node.leave().await;
    let _ = bob.membership.node.leave().await;
    assert_eq!(
        logs.matches("IP transports cleared").count(),
        2,
        "the creator and the joiner must both leave UDP out"
    );
    // No check for "relay-only path refused": the accept gate also refuses
    // the short-lived probe endpoints of the beacon arbitration, which is
    // not a lane. The relay may not carry payload on this mesh, so the lanes
    // above arriving at all is what proves they rode the data channel.
    assert!(logs.contains("webrtc session attached"), "no data channel");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_udp_only_mesh_never_opens_a_webrtc_session() {
    let _serial = serial().lock().await;
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");

    let (mut alice, mut bob) = linked_pair(&relay, vec![Transport::Udp]).await;
    every_lane_carries(&mut alice, &mut bob).await;

    let logs = logs();
    let _ = alice.membership.node.leave().await;
    let _ = bob.membership.node.leave().await;
    assert!(
        !logs.contains("webrtc session attached"),
        "a udp mesh opened a data channel"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_udp_and_webrtc_mesh_races_and_keeps_no_session_once_udp_wins() {
    let _serial = serial().lock().await;
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");

    let (mut alice, mut bob) = linked_pair(&relay, vec![Transport::Udp, Transport::WebRtc]).await;
    every_lane_carries(&mut alice, &mut bob).await;
    // The race is judged by the lower id alone, which offers. Wait for its
    // round to end one way or the other.
    let raced = eventually(Duration::from_secs(30), || {
        let logs = logs();
        logs.contains("udp already selected")
            || logs.matches("webrtc session attached (offerer)").count()
                == logs
                    .matches("udp won the race; webrtc session detached")
                    .count()
                && logs.contains("webrtc session attached (offerer)")
    })
    .await;

    let logs = logs();
    let _ = alice.membership.node.leave().await;
    let _ = bob.membership.node.leave().await;
    assert!(
        raced,
        "no race ran, or a session outlived udp:\n{}",
        link_trace()
    );
    assert!(
        !logs.contains("both ends advertise IP"),
        "the pair skipped the race"
    );
}

/// Requirements 3 and 4 in one cycle: UDP wins, UDP is taken away and the pair
/// races again onto a data channel, UDP comes back and the session is dropped.
/// Payload flows in every stage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pair_races_again_when_udp_drops_and_detaches_when_it_returns() {
    pair_races_again_when_udp_drops(None).await;
}

/// The same cycle with the order of the ids fixed: bob sends the one directed message, so only
/// bob holds a pooled connection, and the lower id has the only path watcher. With bob as the
/// higher id nobody watches, and the engine must see the loss from the admission table.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pair_races_again_when_udp_drops_and_bob_has_the_higher_id() {
    pair_races_again_when_udp_drops(Some(true)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pair_races_again_when_udp_drops_and_bob_has_the_lower_id() {
    pair_races_again_when_udp_drops(Some(false)).await;
}

async fn pair_races_again_when_udp_drops(bob_is_higher: Option<bool>) {
    let _serial = serial().lock().await;
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");

    let transport = vec![Transport::Udp, Transport::WebRtc];
    let (mut alice, mut bob) = match bob_is_higher {
        Some(higher) => linked_pair_ordered(&relay, transport, higher).await,
        None => linked_pair(&relay, transport).await,
    };
    every_lane_carries(&mut alice, &mut bob).await;
    let attached = || logs().matches("webrtc session attached (offerer)").count();
    let before = attached();

    alice.block_udp(true).await;
    let raced = eventually(Duration::from_mins(1), || {
        logs().contains("direct path lost; racing again") && attached() > before
    })
    .await;
    // The race's own check for UDP after the attach takes at most 8 s (a
    // 3 s dial, then 5 s for UDP to be selected). Waiting 9 s past the attach
    // lets it end first, so the session is kept and the watcher, not the
    // race, has to drop it once UDP is back.
    tokio::time::sleep(Duration::from_secs(9)).await;
    let carried_on_webrtc = if raced {
        alice.send(None, "over the data channel").await;
        eventually(PAYLOAD_DEADLINE, || {
            bob.saw_msg("over the data channel", false)
        })
        .await
    } else {
        false
    };

    alice.block_udp(false).await;
    let detached = eventually(Duration::from_secs(30), || {
        logs().contains("udp selected again; webrtc session detached")
    })
    .await;
    alice.send(None, "back on udp").await;
    let carried_on_udp = eventually(PAYLOAD_DEADLINE, || bob.saw_msg("back on udp", false)).await;

    let _ = alice.membership.node.leave().await;
    let _ = bob.membership.node.leave().await;
    assert!(raced, "no race after udp dropped:\n{}", link_trace());
    assert!(carried_on_webrtc, "no payload while udp was gone");
    assert!(
        detached,
        "the session outlived udp's return:\n{}",
        link_trace()
    );
    assert!(carried_on_udp, "no payload once udp was back");
}
