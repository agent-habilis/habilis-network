//! A message that the gossip layer delivered but the app never read still reaches the app.
//!
//! The gossip layer drops a message id it has already seen for 90 s, so an anti-entropy resend
//! of the same bytes cannot repair what the app missed. The case here: the topic is swapped
//! while the old subscription holds queued messages (the heal tick resubscribes, and the old
//! queue must reach the app before it is dropped). `resend_dedup_loopback.rs` holds the other.
//!
//! Two members on a local relay, the default transport list.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inbound, Membership, Request};
use habilis_network::protocol::Lookup;
use tokio::sync::mpsc::UnboundedReceiver;

/// One heal tick (15 s) to resubscribe, the re-graft, and an anti-entropy cycle, with margin.
/// Less than the 90 s dedup of the gossip layer: a message that waits for the dedup is a failure.
const RECOVERY: Duration = Duration::from_secs(75);
const FORMATION: Duration = Duration::from_mins(1);
const LIVE: Duration = Duration::from_secs(20);

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
        tracing_subscriber::EnvFilter::new("habilis_network=info,habilis_network::gossip=debug")
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(|| BufferWriter)
        .with_ansi(false)
        .try_init();
}

/// The lines that say how the swap and the repair went.
fn trace() -> String {
    log_buffer()
        .lock()
        .expect("no poison")
        .lines()
        .filter(|line| {
            [
                "restored",
                "drained",
                "anti-entropy",
                "dropped",
                "failed to parse",
            ]
            .iter()
            .any(|needle| line.contains(needle))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

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

    async fn create(nick: &str, relay: &RelayUrl) -> Self {
        Self::open(&membership::Opts {
            nick: Some(nick.to_owned()),
            lookup: vec![Lookup::Relay],
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

    async fn send(&self, text: &str) {
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Send {
                to: None,
                body,
                reply,
            })
            .await
            .expect("the loop answers")
            .expect("sent");
    }

    async fn sever_gossip(&self) {
        self.membership
            .request(|reply| Request::SeverGossip { reply })
            .await
            .expect("the loop answers");
    }

    fn saw(&mut self, text: &str) -> bool {
        while let Ok(msg) = self.membership.inbound.try_recv() {
            self.seen.push(msg);
        }
        self.seen
            .iter()
            .any(|msg| !msg.directed && msg.text == text)
    }

    /// Wait until `text` has reached the app, or the deadline passes. The wait of the test is
    /// the time of the repair, in seconds, so the numbers are in the output of a green run too.
    async fn waits_for(&mut self, text: &str, deadline: Duration) -> Option<Duration> {
        let started = Instant::now();
        while started.elapsed() < deadline {
            if self.saw(text) {
                return Some(started.elapsed());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        self.saw(text).then(|| started.elapsed())
    }
}

async fn meshed_pair(relay: &RelayUrl) -> (Member, Member) {
    let alice = Member::create("alice", relay).await;
    let bob = Member::join("bob", &alice).await;
    let started = Instant::now();
    while alice.roster_len().await != 1 || bob.roster_len().await != 1 {
        assert!(
            started.elapsed() < FORMATION,
            "the pair never met\n{}",
            trace()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    (alice, bob)
}

/// A message sent while the topic of the receiver is severed waits in the queue of the old
/// subscription. The swap must hand it to the app before the queue is dropped: the gossip layer
/// counted it as delivered, so neither the overlay nor an anti-entropy resend of the same bytes
/// brings it again inside the 90 s dedup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_that_waited_in_the_old_subscription_reaches_the_app_after_the_swap() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let (alice, mut bob) = meshed_pair(&relay).await;

    bob.sever_gossip().await;
    alice.send("during-outage").await;

    let after = bob.waits_for("during-outage", RECOVERY).await;
    eprintln!("the message reached the app after: {after:?}");
    assert!(
        after.is_some(),
        "a message sent during the outage never reached the app inside {RECOVERY:?}\n{}",
        trace()
    );
    alice.send("after-recovery").await;
    assert!(
        bob.waits_for("after-recovery", LIVE).await.is_some(),
        "live traffic does not flow after the swap\n{}",
        trace()
    );
}
