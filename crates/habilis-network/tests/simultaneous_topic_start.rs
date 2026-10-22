//! Members of one topic room that start at the same moment must become one mesh.
//!
//! Every member probes the rendezvous of the room before it holds a beacon, and
//! every probe finds nothing. So every member claims a beacon of the same id, and
//! each joiner dials the beacon it holds itself. The room splits into islands, and
//! only the periodic rival re-check can merge them. A member that starts after the
//! first beacon is live finds it and yields, so a staggered start is the control
//! for the lane: if it fails, mDNS does not work on this host and the other tests
//! prove nothing.
//!
//! The mesh has the reach of a public topic room cut down to the LAN (mDNS only, no
//! DHT, no relay), the same lane as `agent-gossip` `tests/topic_split.rs`. That is
//! the public beacon path: `bind_ports` is empty, so the rival re-check applies. A
//! pure loopback mesh takes the port ladder and is not what this test covers.
//!
//! Own integration binary: `Tuning` is a process-wide `OnceLock`, and this file
//! shortens the cadences of the heal and of the rival re-check to seconds.
//!
//! Every test is `#[ignore]`: each runs real mDNS responders for many rounds, so they
//! run one at a time, under `cargo task matrix`.

#![cfg(feature = "host")]

use habilis_network::protocol::message::Authored;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::net::TransportOpts;
use habilis_network::protocol::{LookupOpts, MessageKind, Nickname, PresenceSubtype, RelayChoice};
use habilis_network::runtime::tuning::{Tuning, init};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use tokio::sync::Notify;

/// The time that a mesh of members has to converge. A quiet run converges in 15 to 25
/// seconds. The merge is a race over several rounds of the re-check, so the bound is
/// the one of `agent-gossip` `topic_split.rs`.
const MERGE_BUDGET: Duration = Duration::from_secs(75);

/// Rounds of a simultaneous start. One round proves little about a race. On the unfixed
/// code (`8e3874c`) two members split in 2 of 40 rounds (5 percent), so 20 rounds catch
/// the bug in 64 percent of the runs and 40 rounds in 87 percent. Three members split in
/// 0 of 40 rounds, but 6 of those 40 converged after 30 seconds. On fixed code every run
/// must pass all rounds: that is the property that counts.
const TWO_MEMBER_ROUNDS: usize = 20;

/// Rounds of three members started together.
const THREE_MEMBER_ROUNDS: usize = 20;

/// A round that converges later than this keeps its log, like a round that splits: the slow
/// tail is the same fault healing late.
const KEEP_LOG_OVER: Duration = Duration::from_secs(20);

/// The first rounds of a test keep their log whatever their time, so a run always holds a few
/// fast rounds to set beside the slow ones.
const KEEP_FIRST_ROUNDS: usize = 6;

/// The rounds of the staggered control. It must be green every time, so a few
/// rounds show that the lane works.
const CONTROL_ROUNDS: usize = 5;

/// Tests of this file take turns: each one runs real mDNS responders, and two of
/// them on one host starve each other past their deadlines.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The file that the log of the running round goes to. Rounds run one after the other.
static ROUND_LOG: Mutex<Option<std::fs::File>> = Mutex::new(None);

struct RoundLogWriter;

impl std::io::Write for RoundLogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(file) = ROUND_LOG.lock().expect("no poison").as_mut() {
            file.write_all(bytes)?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The whole log of a round: `HABILIS_TEST_LOG_DUMP` names the prefix of the file (the
/// temp directory if it is not set), and the topic of the round ends the name. A round
/// that converges within `KEEP_LOG_OVER` erases its file, unless it is one of the first
/// `KEEP_FIRST_ROUNDS`. A round that splits, or converges later, keeps it, unfiltered: set
/// `RUST_LOG=habilis_network=debug,iroh_gossip=debug` to fill it. The log of one process
/// has no tag per member, so a line names its member only when it has a `local=` or
/// `node=` field.
fn round_log_path(topic: &str) -> std::path::PathBuf {
    let prefix = std::env::var("HABILIS_TEST_LOG_DUMP").unwrap_or_else(|_| {
        std::env::temp_dir()
            .join("simultaneous-start")
            .display()
            .to_string()
    });
    format!("{prefix}.{topic}").into()
}

fn init_process() -> habilis_network_test_tracing::Guard {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        init(Tuning {
            heal_interval: Duration::from_secs(5),
            rival_recheck_first: Duration::from_secs(3),
            rival_recheck: Duration::from_secs(8),
            rival_recheck_meshed: Duration::from_secs(12),
            rival_recheck_alone: Duration::from_secs(12),
            ..Tuning::DEFAULTS
        });
    });
    habilis_network_test_tracing::init_with_writer(
        "habilis_network=info,habilis_network::beacon=info",
        || RoundLogWriter,
    )
}

/// A member that only forms the mesh. Presence does the work.
struct Member;

#[habilis_network::async_trait]
impl NodeApp for Member {
    fn classify(&self, _message: &Authored) -> AppClass {
        AppClass {
            loggable: false,
            beat: true,
            valid: true,
            chained: false,
            sealed: false,
        }
    }

    async fn on_app_frame(
        &mut self,
        _frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        _ctx: &HandlerCtx<'_>,
    ) -> bool {
        false
    }
}

#[habilis_network::async_trait]
impl NodeDriver for Member {
    type Session = ();
    type Http = ();
    type Ipc = serde_json::Value;

    async fn handle_session(
        &mut self,
        _resp: Self::Session,
        _state: &mut EventLoopState,
        _ctx: &HandlerCtx<'_>,
    ) -> bool {
        false
    }
}

/// Records when each `joined` presence reaches the member, by nickname.
#[derive(Default)]
struct Joined {
    seen: Mutex<Vec<Nickname>>,
    changed: Notify,
}

impl NodeSink for Joined {
    fn emit(&self, event: NodeEvent) {
        if let NodeEvent::Presence { msg, .. } = event
            && let MessageKind::Presence {
                subtype: PresenceSubtype::Joined,
            } = msg.kind
        {
            let mut seen = self.seen.lock().expect("no poison");
            if !seen.contains(&msg.author) {
                seen.push(msg.author.clone());
            }
            drop(seen);
            self.changed.notify_waiters();
        }
    }
}

impl Joined {
    fn has_seen(&self, nick: &Nickname) -> bool {
        self.seen.lock().expect("no poison").contains(nick)
    }

    /// When the member has seen every nickname of `others`, or `None` at the deadline.
    async fn wait_for_all(&self, others: &[Nickname], until: Instant) -> Option<Instant> {
        let wait = async {
            loop {
                let changed = self.changed.notified();
                if others.iter().all(|nick| self.has_seen(nick)) {
                    return;
                }
                changed.await;
            }
        };
        let left = until.saturating_duration_since(Instant::now());
        let done = tokio::time::timeout(left, wait).await.is_ok() || {
            others.iter().all(|nick| self.has_seen(nick))
        };
        done.then(Instant::now)
    }

    /// The nicknames this member has seen join, for the text of a failure.
    fn seen_names(&self) -> Vec<Nickname> {
        self.seen.lock().expect("no poison").clone()
    }
}

/// The reach of a public topic room cut down to the LAN. See the doc of the file.
fn mdns_only() -> LookupOpts {
    LookupOpts {
        mdns: true,
        dht: false,
        relay_lookup: RelayChoice::Disabled,
    }
}

async fn spawn(topic: &str, nick: &str, sink: Arc<Joined>) -> Node<Member> {
    let mesh = derive_topic_mesh_with(topic, mdns_only()).expect("derive an mDNS-only mesh");
    let author = Nickname::new(nick).expect("valid nickname");
    let config = setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic.to_owned(),
        },
        SetupParams {
            author,
            max_peers: 16,
            max_direct: 0,
            endpoint: None,
            protocols: Vec::new(),
            transports: TransportOpts::default(),
            runtime_base: None,
            state_file: None,
            sink,
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await
    .expect("setup_mesh on an mDNS-only mesh");
    Node::spawn(config, Member, None, SignalHandling::Leave)
}

/// How the members of a round start.
#[derive(Clone, Copy)]
enum Start {
    /// All at once: every startup probe runs before any beacon exists.
    Together,
    /// The second one after the first one holds a beacon: the case without a race.
    Staggered,
}

/// The result of one round: the time to converge, or the text of the split.
async fn round(members: usize, start: Start, index: usize) -> Result<Duration, String> {
    let topic = format!(
        "simultaneous-start-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    );
    let log_path = round_log_path(&topic);
    *ROUND_LOG.lock().expect("no poison") =
        Some(std::fs::File::create(&log_path).expect("create the log file of the round"));
    let names: Vec<String> = (0..members).map(|number| format!("peer{number}")).collect();
    let nicks: Vec<Nickname> = names
        .iter()
        .map(|name| Nickname::new(name.as_str()).expect("valid nickname"))
        .collect();
    let sinks: Vec<Arc<Joined>> = nicks.iter().map(|_| Arc::default()).collect();

    let began = Instant::now();
    let nodes = match start {
        Start::Together => {
            futures_util::future::join_all(
                names
                    .iter()
                    .zip(&sinks)
                    .map(|(name, sink)| spawn(&topic, name, Arc::clone(sink))),
            )
            .await
        }
        Start::Staggered => {
            let mut nodes = Vec::new();
            for (name, sink) in names.iter().zip(&sinks) {
                nodes.push(spawn(&topic, name, Arc::clone(sink)).await);
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            nodes
        }
    };

    let until = began + MERGE_BUDGET;
    let mut slowest = Duration::ZERO;
    let mut stuck = Vec::new();
    for (member, sink) in sinks.iter().enumerate() {
        let others: Vec<Nickname> = nicks
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != member)
            .map(|(_, nick)| nick.clone())
            .collect();
        match sink.wait_for_all(&others, until).await {
            Some(when) => slowest = slowest.max(when.duration_since(began)),
            None => stuck.push(format!("{} saw {:?}", names[member], sink.seen_names())),
        }
    }
    let verdict = if stuck.is_empty() {
        Ok(slowest)
    } else {
        Err(format!(
            "the mesh did not converge inside {MERGE_BUDGET:?}: {}; the log of the round is in {}",
            stuck.join("; "),
            log_path.display()
        ))
    };
    for node in nodes {
        node.leave().await.expect("a member leaves");
    }
    *ROUND_LOG.lock().expect("no poison") = None;
    if index >= KEEP_FIRST_ROUNDS && matches!(verdict, Ok(time) if time <= KEEP_LOG_OVER) {
        let _ = std::fs::remove_file(&log_path);
    }
    verdict
}

/// The time to converge, as numbers a run can set beside another run. A split is
/// the failure, but a round that converges late is the same fault healing late.
fn distribution(times: &[Duration]) -> String {
    let mut sorted = times.to_vec();
    sorted.sort();
    let over = |limit: u64| {
        times
            .iter()
            .filter(|time| **time > Duration::from_secs(limit))
            .count()
    };
    format!(
        "median {:?}, over 20 s {}, over 30 s {}, max {:?}",
        sorted.get(sorted.len() / 2).copied().unwrap_or_default(),
        over(20),
        over(30),
        sorted.last().copied().unwrap_or_default()
    )
}

/// Run `rounds` rounds one after the other and fail if any round split.
fn converge(members: usize, start: Start, rounds: usize) {
    let guard = init_process();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let _serial = SERIAL.lock().await;
        let mut times = Vec::new();
        let mut splits = Vec::new();

        for index in 0..rounds {
            match round(members, start, index).await {
                Ok(time) => times.push(time),
                Err(text) => splits.push((index, text)),
            }
        }
        eprintln!(
            "{members} members, {rounds} rounds: {}, split {} times, converged {times:?}",
            distribution(&times),
            splits.len()
        );
        assert!(
            splits.is_empty(),
            "{} of {rounds} rounds split with {members} members; converged times {times:?}\nfirst split, round {}: {}",
            splits.len(),
            splits[0].0,
            splits[0].1
        );
    });
}

#[test]
#[ignore = "run by cargo task matrix"]
fn two_members_started_together_become_one_mesh() {
    converge(2, Start::Together, TWO_MEMBER_ROUNDS);
}

#[test]
#[ignore = "run by cargo task matrix"]
fn three_members_started_together_become_one_mesh() {
    converge(3, Start::Together, THREE_MEMBER_ROUNDS);
}

/// The control of the lane: a second member that starts after the first one holds a
/// beacon must always converge.
#[test]
#[ignore = "run by cargo task matrix"]
fn two_members_started_one_after_the_other_become_one_mesh() {
    converge(2, Start::Staggered, CONTROL_ROUNDS);
}
