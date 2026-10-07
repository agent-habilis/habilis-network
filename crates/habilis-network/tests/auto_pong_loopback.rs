//! Two real habilis-network nodes linked only by gossip must each answer the other's
//! ping.
//!
//! The auto-pong goes out over a warm unicast connection or not at all, so a
//! receive arm never dials inline. Only the side that grafted through the
//! direct-path probe holds such a connection; the side that accepted the link
//! never dialed, and its pongs were skipped until something else warmed the
//! pool. Pinging in both directions covers whichever side accepted.

#![cfg(feature = "host")]

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
    PingRound,
};
use habilis_network::net::TransportOpts;
use habilis_network::protocol::{LookupOpts, Message, MessageKind, Nickname, PresenceSubtype};
use habilis_network::runtime::{Node, SetupKind, SetupParams, derive_topic_mesh_with, setup_mesh};
use tokio::sync::{Notify, oneshot};

type Rtts = Vec<(Nickname, u64)>;

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

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("habilis_network=info,habilis_network::transport=debug")
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(|| BufferWriter)
        .with_ansi(false)
        .try_init();
}

/// The last lines of the log, for the message of a failed assertion. The log is
/// also written to the file that `HABILIS_TEST_LOG_DUMP` names, if set.
fn trace() -> String {
    let log = log_buffer().lock().expect("no poison").clone();
    if let Ok(path) = std::env::var("HABILIS_TEST_LOG_DUMP") {
        let _ = std::fs::write(path, &log);
    }
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(200)..].join("\n")
}

/// Presence alone forms the mesh; a session request runs one ping round.
struct Pinger;

#[habilis_network::async_trait]
impl NodeApp for Pinger {
    fn classify(&self, _message: &Message) -> AppClass {
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
impl NodeDriver for Pinger {
    type Session = oneshot::Sender<Rtts>;
    type Http = ();
    type Ipc = serde_json::Value;

    async fn handle_session(
        &mut self,
        resp: Self::Session,
        state: &mut EventLoopState,
        ctx: &HandlerCtx<'_>,
    ) -> bool {
        let now = tokio::time::Instant::now();
        state.arm_ping_round(PingRound {
            t1: now,
            deadline: now
                + Duration::from_secs(habilis_network::runtime::tuning::ping_window_secs()),
            pongs: std::collections::HashMap::new(),
            resp: Some(resp),
        });
        habilis_network::ops::broadcast_msg(
            ctx.sender,
            &Message::new_ping(ctx.mesh, ctx.author).signed(ctx.identity),
        )
        .await;
        true
    }
}

/// Records every `joined` presence the engine surfaces.
#[derive(Default)]
struct Joined {
    peers: Mutex<Vec<Nickname>>,
    changed: Notify,
}

impl NodeSink for Joined {
    fn emit(&self, event: NodeEvent) {
        if let NodeEvent::Presence { msg } = event
            && let MessageKind::Presence {
                subtype: PresenceSubtype::Joined,
            } = msg.kind
        {
            self.peers
                .lock()
                .expect("no poison")
                .push(msg.author.clone());
            self.changed.notify_waiters();
        }
    }
}

impl Joined {
    async fn wait_for(&self, nick: &Nickname, deadline: Duration) -> bool {
        let seen = || self.peers.lock().expect("no poison").contains(nick);
        let wait = async {
            loop {
                let changed = self.changed.notified();
                if seen() {
                    return;
                }
                changed.await;
            }
        };
        tokio::time::timeout(deadline, wait).await.is_ok() || seen()
    }
}

async fn spawn(topic: &str, nick: &str, sink: Arc<Joined>) -> Node<Pinger> {
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
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
    .expect("setup_mesh on a loopback mesh must not touch the network");
    Node::spawn(config, Pinger, None, false)
}

async fn ping(node: &Node<Pinger>) -> Rtts {
    let (tx, rx) = oneshot::channel();
    node.send(tx)
        .await
        .expect("the ping request reaches the loop");
    rx.await.expect("the round is finalized")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_peer_linked_only_by_gossip_answers_the_others_ping() {
    init_logging();
    let topic = format!("auto-pong-{}", rand::random::<u64>());
    let alice_saw = Arc::new(Joined::default());
    let bob_saw = Arc::new(Joined::default());
    let alice = spawn(&topic, "alice", Arc::clone(&alice_saw)).await;
    let bob = spawn(&topic, "bob", Arc::clone(&bob_saw)).await;

    let deadline = Duration::from_secs(45);
    let alice_nick = Nickname::new("alice").expect("valid");
    let bob_nick = Nickname::new("bob").expect("valid");
    assert!(
        alice_saw.wait_for(&bob_nick, deadline).await,
        "alice never saw bob join\n{}",
        trace()
    );
    assert!(
        bob_saw.wait_for(&alice_nick, deadline).await,
        "bob never saw alice join\n{}",
        trace()
    );

    let (alice_rtts, bob_rtts) = tokio::join!(ping(&alice), ping(&bob));
    let answered = |rtts: &Rtts, nick: &Nickname| rtts.iter().any(|(peer, _)| peer == nick);
    assert!(
        answered(&alice_rtts, &bob_nick),
        "bob never answered alice's ping: {alice_rtts:?}\n{}",
        trace()
    );
    assert!(
        answered(&bob_rtts, &alice_nick),
        "alice never answered bob's ping: {bob_rtts:?}\n{}",
        trace()
    );

    alice.leave().await.expect("alice leaves");
    bob.leave().await.expect("bob leaves");
}
