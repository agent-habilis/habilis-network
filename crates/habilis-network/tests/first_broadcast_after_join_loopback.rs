//! A broadcast sent right after join, before the sender has a first real-peer link, reaches the
//! creator (the report of a lost chat broadcast on 2b468bb).
//!
//! Three members on a local relay: the creator C and two joiners J1 and J2. Each joiner sends a
//! broadcast as soon as `join` returns. A frame sent before the node is meshed is parked and
//! flushed on its first non-rendezvous link (`gossip::recv::flush_pending`), and the creator asks
//! for what it missed with a digest on its first real link (`gossip::antientropy`). The lost
//! message is the one that neither path brings.
//!
//! The tests record WHEN each broadcast reaches two observers, the creator and the other
//! joiner, up to `OBSERVE`, and fail if the creator gets one later than the bound of the race (`EXPECTED`, or 5 s for the control). The failure
//! message carries the arrival times and classifies each message:
//! - nobody got it: the send or the flush dropped it;
//! - only the creator: the flood stopped at the first hop;
//! - the creator missed it and the other joiner got it: the creator's inbound path;
//! - both, late: a resend. An arrival near 90 s is the sender's own gossip actor dropping the
//!   resend as a duplicate until iroh-gossip forgets the message id (`message_id_retention`).
//!
//! They also read the length of each member's message log before the send and at the end, which
//! is where anti-entropy finds what it serves: a sender whose log did not grow while the
//! creator's did cannot serve its own message again.
//!
//! `transport: Vec::new()` is the default list of the mesh (udp, webrtc, multihop, gossip).
//!
//! Two apps run the race. The membership app never retains chat, so anti-entropy cannot resend
//! it there. The logging app retains every chat frame it receives, as agent-gossip's app does,
//! and so exercises the resend. Each report names its app.
//!
//! Debug greps for a run: `RUST_LOG=habilis_network::messages=info,habilis_network::gossip=debug`.
//! Every test is `#[ignore]`: each stands up three real members and runs under a host grant, with
//! `--include-ignored --test-threads=1` (`cargo task matrix`). Each race runs with the send at
//! once (the frame is parked and flushed at the meshed edge) and one second after join (a direct
//! delivery on a link that is seconds old).

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use habilis_network::protocol::message::Authored;
use std::time::{Duration, Instant};

use std::sync::{Arc, Mutex};

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inbound, Membership, Request};
use habilis_network::ops::{app_frame, send_app};
use habilis_network::protocol::{
    AppFrameParams, AppTag, Lookup, LookupOpts, MessageBody, Nickname, Transport,
};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::oneshot;

use habilis_network::net::test_relay;
/// How long a broadcast may take to reach the creator before the test calls it lost.
const EXPECTED: Duration = Duration::from_mins(1);
/// How long the test keeps looking, to tell a late message from one that never comes: past the
/// 90 s that iroh-gossip keeps a message id.
const OBSERVE: Duration = Duration::from_mins(2);
const MESH_DEADLINE: Duration = Duration::from_mins(1);

struct Member {
    membership: Membership,
    _events: UnboundedReceiver<String>,
    seen: Vec<Inbound>,
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
            seen: Vec::new(),
        }
    }

    async fn create(nick: &str, relay: &RelayUrl, transport: Vec<Transport>) -> Self {
        let options = membership::JoinOptions::default()
            .with_nick(Some(nick.to_owned()))
            .with_lookup(vec![Lookup::Relay]);
        let options = options
            .with_transport(transport)
            .with_relay_urls(vec![relay.to_string()]);
        Self::open(&options).await
    }

    async fn join(nick: &str, creator: &Self) -> Self {
        let mesh = creator.membership.node.mesh_id().to_string();
        let options = membership::JoinOptions::default()
            .with_nick(Some(nick.to_owned()))
            .with_mesh(Some(mesh));
        Self::open(&options).await
    }

    /// A broadcast, which is a `msg` with no addressee.
    async fn broadcast(&self, text: &str) -> Result<(), String> {
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Send {
                to: None,
                body,
                reply,
            })
            .await
            .expect("the loop answers")
    }

    /// Whether a broadcast with this text has reached this member.
    fn saw_broadcast(&mut self, text: &str) -> bool {
        while let Ok(message) = self.membership.inbound.try_recv() {
            self.seen.push(message);
        }
        self.seen
            .iter()
            .any(|message| !message.directed && message.text == text)
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
}

/// One broadcast, and when each observer got it, counted from its send.
struct Probe {
    text: String,
    sent_at: Instant,
    creator: Option<Duration>,
    other_joiner: Option<Duration>,
}

impl Probe {
    fn sent(text: String) -> Self {
        Self {
            text,
            sent_at: Instant::now(),
            creator: None,
            other_joiner: None,
        }
    }

    fn observed(&self) -> bool {
        self.creator.is_some() && self.other_joiner.is_some()
    }

    fn reached_creator_in_time(&self, bound: Duration) -> bool {
        self.creator.is_some_and(|elapsed| elapsed <= bound)
    }

    fn describe(&self) -> String {
        let seconds = |arrival: Option<Duration>| {
            arrival.map_or_else(
                || format!("never in {OBSERVE:?}"),
                |elapsed| format!("{:.1} s", elapsed.as_secs_f32()),
            )
        };
        let verdict = match (self.creator.is_some(), self.other_joiner.is_some()) {
            (false, false) => "nobody got it: the send or the flush dropped it",
            (true, false) => "only the creator got it: the flood stopped at the first hop",
            (false, true) => "the creator missed it and the other joiner got it: its inbound path",
            (true, true) => "both got it",
        };
        format!(
            "creator {}, other joiner {} ({verdict})",
            seconds(self.creator),
            seconds(self.other_joiner)
        )
    }
}

/// A member of a race, whatever app it runs.
trait Peer: Sized {
    /// Names the app in the report: a verdict means little without it.
    const APP: &'static str;

    async fn broadcast(&self, text: &str) -> Result<(), String>;
    /// Whether a broadcast with this text has reached this member.
    fn saw_broadcast(&mut self, text: &str) -> bool;
    /// How many messages the member holds in the log that anti-entropy serves from.
    async fn log_len(&self) -> usize;
    /// How many other members this one lists; a member does not list itself.
    async fn peer_count(&self) -> usize;
    async fn leave(self);
}

impl Peer for Member {
    const APP: &'static str = "membership (chat is not retained)";

    async fn broadcast(&self, text: &str) -> Result<(), String> {
        Member::broadcast(self, text).await
    }

    fn saw_broadcast(&mut self, text: &str) -> bool {
        Member::saw_broadcast(self, text)
    }

    async fn log_len(&self) -> usize {
        self.membership
            .request(|reply| Request::MessageLogLen { reply })
            .await
            .expect("the loop answers")
    }

    async fn peer_count(&self) -> usize {
        self.membership
            .request(|reply| Request::PeerCount { reply })
            .await
            .expect("the loop answers")
    }

    async fn leave(self) {
        let _ = self.membership.node.leave().await;
    }
}

/// Records the chat frames it gets, and logs them as agent-gossip's app does.
#[derive(Clone, Default)]
struct Chat {
    // Shared with the sink the membership owns: the test reads what arrived after the join.
    received: Arc<Mutex<Vec<String>>>,
}

enum ChatSession {
    Send(String, oneshot::Sender<Result<(), String>>),
    LogLen(oneshot::Sender<usize>),
    PeerCount(oneshot::Sender<usize>),
}

#[habilis_network::async_trait]
impl NodeApp for Chat {
    fn classify(&self, _message: &Authored) -> AppClass {
        AppClass::NONE
            .union(AppClass::LOGGABLE)
            .union(AppClass::VALID)
    }

    async fn on_app_frame(
        &mut self,
        frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        _ctx: &HandlerCtx<'_>,
    ) -> bool {
        if frame.surfaceable {
            let text = frame.message.body.as_str().to_owned();
            self.received.lock().expect("no poison").push(text);
        }
        true
    }
}

#[habilis_network::async_trait]
impl NodeDriver for Chat {
    type Session = ChatSession;
    type Http = ();
    type Ipc = serde_json::Value;

    async fn handle_session(
        &mut self,
        session: Self::Session,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match session {
            ChatSession::Send(text, reply) => {
                let frame = app_frame(
                    context,
                    AppFrameParams::new(
                        AppTag::try_new("chat").expect("a valid app tag"),
                        None,
                        None,
                        MessageBody::try_new(&text).expect("a short body"),
                    ),
                );
                let class = self.classify(&frame.authored());
                let sent = send_app(state, context, frame, class).await.map(|_| ());
                let _ = reply.send(sent.map_err(|error| error.to_string()));
                true
            }
            ChatSession::LogLen(reply) => {
                let _ = reply.send(state.message_log_len());
                false
            }
            ChatSession::PeerCount(reply) => {
                let _ = reply.send(state.roster_snapshot().peers.len());
                false
            }
        }
    }
}

struct Quiet;

impl NodeSink for Quiet {
    fn emit(&self, _event: NodeEvent) {}
}

/// A member of a topic mesh on loopback, running [`Chat`].
struct LoggingMember {
    node: Node<Chat>,
    chat: Chat,
}

impl LoggingMember {
    async fn start(topic: &str, name: &str) -> Self {
        let mesh =
            derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
        let topic_string = topic.to_owned();
        let config = setup_mesh(
            SetupKind::Topic { mesh, topic_string },
            SetupParams::new(
                Nickname::try_new(name).expect("valid nickname"),
                // The membership keeps its sink as a trait object for its whole life.
                Arc::new(Quiet),
            )
            .with_max_peers(16),
        )
        .await
        .expect("setup_mesh on a loopback mesh");
        let chat = Chat::default();
        Self {
            node: Node::spawn(config, chat.clone(), None, SignalHandling::Leave),
            chat,
        }
    }
}

impl Peer for LoggingMember {
    const APP: &'static str = "logging chat (loggable: true)";

    async fn broadcast(&self, text: &str) -> Result<(), String> {
        let (reply, answer) = oneshot::channel();
        self.node
            .send(ChatSession::Send(text.to_owned(), reply))
            .await
            .map_err(|error| error.to_string())?;
        answer.await.map_err(|error| error.to_string())?
    }

    fn saw_broadcast(&mut self, text: &str) -> bool {
        self.chat
            .received
            .lock()
            .expect("no poison")
            .iter()
            .any(|received| received == text)
    }

    async fn log_len(&self) -> usize {
        let (reply, answer) = oneshot::channel();
        self.node
            .send(ChatSession::LogLen(reply))
            .await
            .expect("the loop takes the request");
        answer.await.expect("the loop answers")
    }

    async fn peer_count(&self) -> usize {
        let (reply, answer) = oneshot::channel();
        self.node
            .send(ChatSession::PeerCount(reply))
            .await
            .expect("the loop takes the request");
        answer.await.expect("the loop answers")
    }

    async fn leave(self) {
        let _ = self.node.leave().await;
    }
}

/// Poll until both broadcasts reached both observers, or `OBSERVE` has passed. The observers of
/// the first broadcast are the creator and joiner two, and of the second the creator and joiner
/// one.
async fn watch<P: Peer>(
    creator: &mut P,
    joiner_one: &mut P,
    joiner_two: &mut P,
    probes: &mut [Probe; 2],
) {
    let started = Instant::now();
    while started.elapsed() < OBSERVE {
        let now = Instant::now();
        for (probe, other) in probes.iter_mut().zip([&mut *joiner_two, &mut *joiner_one]) {
            if probe.creator.is_none() && creator.saw_broadcast(&probe.text) {
                probe.creator = Some(now - probe.sent_at);
            }
            if probe.other_joiner.is_none() && other.saw_broadcast(&probe.text) {
                probe.other_joiner = Some(now - probe.sent_at);
            }
        }
        if probes.iter().all(Probe::observed) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The lengths of the three message logs: the creator, joiner one and joiner two.
async fn log_lens<P: Peer>(members: [&P; 3]) -> [usize; 3] {
    [
        members[0].log_len().await,
        members[1].log_len().await,
        members[2].log_len().await,
    ]
}

/// The report line of a run, for the failure message and the log.
fn report(
    name: &str,
    app: &str,
    probes: &[Probe; 2],
    before: [usize; 3],
    after: [usize; 3],
) -> String {
    let growth = |index: usize| {
        i64::try_from(after[index]).unwrap_or(i64::MAX)
            - i64::try_from(before[index]).unwrap_or(i64::MAX)
    };
    format!(
        "DIAG {name} [app: {app}]: joiner one's broadcast: {}; joiner two's broadcast: {}; message \
         log growth (end minus before the sends): creator {:+}, joiner one {:+}, joiner two {:+}",
        probes[0].describe(),
        probes[1].describe(),
        growth(0),
        growth(1),
        growth(2),
    )
}

/// Wait until every member lists the other two; the roster does not list its owner.
async fn wait_until_meshed<P: Peer>(members: [&P; 3]) {
    let deadline = Instant::now() + MESH_DEADLINE;
    for member in members {
        while member.peer_count().await < members.len() - 1 {
            assert!(Instant::now() < deadline, "the mesh did not settle");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

/// Both joiners are in the mesh, then each broadcasts `delay` after its `join` returned. Each
/// broadcast is observed by the creator and by the other joiner, and must reach the creator
/// within `expected`. With `settle`, the race waits first until every member lists the others.
async fn run_race<P: Peer>(
    name: &str,
    delay: Duration,
    expected: Duration,
    settle: bool,
    members: [P; 3],
) {
    if let Err(line) = measure_race(name, delay, expected, settle, members).await {
        panic!(
            "{name}: a broadcast sent after join did not reach the creator within {expected:?}: {line}"
        );
    }
}

/// [`run_race`] that returns the report line of a failed race instead of panicking.
async fn measure_race<P: Peer>(
    name: &str,
    delay: Duration,
    expected: Duration,
    settle: bool,
    [mut creator, mut j1, mut j2]: [P; 3],
) -> Result<(), String> {
    if settle {
        wait_until_meshed([&creator, &j1, &j2]).await;
    }
    let before = log_lens([&creator, &j1, &j2]).await;
    tokio::time::sleep(delay).await;
    let first = Probe::sent(format!("{name} one"));
    j1.broadcast(&first.text)
        .await
        .unwrap_or_else(|error| panic!("{name}: joiner one could not send: {error}"));
    let second = Probe::sent(format!("{name} two"));
    j2.broadcast(&second.text)
        .await
        .unwrap_or_else(|error| panic!("{name}: joiner two could not send: {error}"));

    let mut probes = [first, second];
    watch(&mut creator, &mut j1, &mut j2, &mut probes).await;
    let line = report(
        name,
        P::APP,
        &probes,
        before,
        log_lens([&creator, &j1, &j2]).await,
    );
    eprintln!("{line}");
    let in_time = probes
        .iter()
        .all(|probe| probe.reached_creator_in_time(expected));
    for member in [creator, j1, j2] {
        member.leave().await;
    }
    if in_time { Ok(()) } else { Err(line) }
}

/// Three members of the membership app on a local relay. `cut` takes IP away between the two
/// joiners, so that neither is a neighbor of the other and each has the creator as its only real
/// peer. `transport: Vec::new()` is the default list.
fn membership_race(
    name: &str,
    transport: Vec<Transport>,
    cut: bool,
    delay: Duration,
    expected: Duration,
    settle: bool,
) {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay_url, _relay) = test_relay::spawn_plain().await.expect("local relay");
        let creator = Member::create("creator", &relay_url, transport).await;
        let j1 = Member::join("joiner-one", &creator).await;
        let j2 = Member::join("joiner-two", &creator).await;
        if cut {
            j1.block_ip_to(j2.ports()).await;
            j2.block_ip_to(j1.ports()).await;
        }
        run_race(name, delay, expected, settle, [creator, j1, j2]).await;
    });
}

/// Three members of the logging chat app on a loopback topic mesh.
fn logging_race(name: &str, delay: Duration, expected: Duration, settle: bool) {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let topic = format!("first-broadcast-{}", rand::random::<u64>());

        let creator = LoggingMember::start(&topic, "creator").await;
        let j1 = LoggingMember::start(&topic, "joiner-one").await;
        let j2 = LoggingMember::start(&topic, "joiner-two").await;
        run_race(name, delay, expected, settle, [creator, j1, j2]).await;
    });
}

#[test]
#[ignore = "run by cargo task matrix"]
fn a_broadcast_sent_right_after_join_reaches_the_creator() {
    membership_race(
        "default list, at once",
        Vec::new(),
        false,
        Duration::ZERO,
        EXPECTED,
        false,
    );
}

#[test]
#[ignore = "run by cargo task matrix"]
fn a_broadcast_sent_a_second_after_join_reaches_the_creator() {
    membership_race(
        "default list, after 1 s",
        Vec::new(),
        false,
        Duration::from_secs(1),
        EXPECTED,
        false,
    );
}

/// UDP only, with the joiners cut from each other: each joiner has the creator as its only
/// real peer, so the flood has one hop to make.
#[test]
#[ignore = "run by cargo task matrix"]
fn a_broadcast_right_after_join_reaches_the_creator_when_the_joiners_are_not_neighbors() {
    membership_race(
        "udp, joiners cut, at once",
        vec![Transport::Udp],
        true,
        Duration::ZERO,
        EXPECTED,
        false,
    );
}

/// Control: 20 s pass before the send, so the path is proven, and the broadcast must arrive at
/// once.
#[test]
#[ignore = "run by cargo task matrix"]
fn a_broadcast_sent_after_the_mesh_settled_reaches_the_creator() {
    membership_race(
        "default list, 20 s after join",
        Vec::new(),
        false,
        Duration::from_secs(20),
        Duration::from_secs(5),
        true,
    );
}

/// The reporter's case: an app that logs chat, so that anti-entropy can resend it.
#[test]
#[ignore = "run by cargo task matrix"]
fn a_logged_broadcast_sent_right_after_join_reaches_the_creator() {
    logging_race("logging app, at once", Duration::ZERO, EXPECTED, false);
}

#[test]
#[ignore = "run by cargo task matrix"]
fn a_logged_broadcast_sent_a_second_after_join_reaches_the_creator() {
    logging_race(
        "logging app, after 1 s",
        Duration::from_secs(1),
        EXPECTED,
        false,
    );
}

/// Control for the logging app.
#[test]
#[ignore = "run by cargo task matrix"]
fn a_logged_broadcast_sent_after_the_mesh_settled_reaches_the_creator() {
    logging_race(
        "logging app, 20 s after join",
        Duration::from_secs(20),
        Duration::from_secs(5),
        true,
    );
}

/// How many races run at once in the load test: the monitor contract of agent-gossip runs 30
/// tests in parallel, each with three in-process members.
const PARALLEL_RACES: usize = 24;

/// The reporter's shape: many meshes of the logging app at once, so that the host is loaded and
/// the joiners mesh with each other before the creator has its first link. Each joiner sends at
/// once. The test reports how many races lost a broadcast.
#[test]
#[ignore = "run by cargo task matrix"]
fn broadcasts_sent_right_after_join_reach_the_creator_under_load() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let races: Vec<_> = (0..PARALLEL_RACES)
            .map(|index| {
                tokio::spawn(async move {
                    let topic = format!("first-broadcast-load-{index}-{}", rand::random::<u64>());
                    let creator = LoggingMember::start(&topic, "creator").await;
                    let j1 = LoggingMember::start(&topic, "joiner-one").await;
                    let j2 = LoggingMember::start(&topic, "joiner-two").await;
                    measure_race(
                        &format!("logging app, load race {index}"),
                        Duration::ZERO,
                        EXPECTED,
                        false,
                        [creator, j1, j2],
                    )
                    .await
                })
            })
            .collect();
        let mut lost = Vec::new();
        for race in races {
            if let Err(line) = race.await.expect("the race task ends") {
                lost.push(line);
            }
        }
        for line in &lost {
            eprintln!("{line}");
        }
        assert!(
            lost.is_empty(),
            "{} of {PARALLEL_RACES} races lost a broadcast to the creator",
            lost.len()
        );
    });
}
