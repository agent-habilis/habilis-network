//! The link to the rendezvous loses its IP path while it is up, and the link stays.
//!
//! The relay policy closes a gossip link that stays on the relay for the probe
//! deadline (15 s). The rendezvous link is such a link. The `WebRTC` session to
//! the rendezvous used to be offered only after that close, so each holder of
//! the link paid one `NeighborDown` and a re-graft. The offer now comes when
//! the link leaves its direct path, and a session that attaches inside the
//! deadline gives the link a path again.
//!
//! Two members on a local relay, the default transport list. The joiner holds
//! the rendezvous link: it has one link, below the release count of three.
//! UDP is taken away from every connection of the process, so both ends of the
//! rendezvous link lose IP. The block is a selection block only: it removes no
//! socket, so the IP path stays in iroh's list and is merely not selected.
//!
//! The test reads no path kind for the rendezvous link, because no reader
//! exists for it. It does not need one: the relay watcher closes a link that
//! stays on the relay after 15 s, and the window is 25 s. A link that is still
//! up at the end of the window, with no `NeighborDown`, has a direct path.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Membership, Request};
use habilis_network::protocol::Lookup;
use tokio::sync::mpsc::UnboundedReceiver;

/// The probe deadline of 15 s and 10 s more: a link that stayed on the relay
/// would be closed inside it, and a session round takes a few seconds.
const WINDOW: Duration = Duration::from_secs(25);

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
        tracing_subscriber::EnvFilter::new(
            "habilis_network=info,habilis_network::transport=debug,habilis_network::gossip=info",
        )
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(|| BufferWriter)
        .with_ansi(false)
        .try_init();
}

fn logs() -> String {
    log_buffer().lock().expect("no poison").clone()
}

/// How many times a member reported its link to the rendezvous up, or down. The
/// line does not name the member. The creator hosts the rendezvous and has no
/// such link, so the joiner is the only member that counts.
fn rendezvous_lines(state: &str) -> usize {
    let needle = format!("gossip neighbor {state}");
    logs()
        .lines()
        .filter(|line| line.contains(&needle) && line.contains("is_rendezvous=true"))
        .count()
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
    _events: UnboundedReceiver<String>,
}

impl Member {
    async fn open(opts: &membership::Opts) -> Self {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(opts, sink).await.expect("open a member");
        Self {
            membership,
            _events: events,
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

    async fn block_udp(&self, blocked: bool) {
        self.membership
            .request(|reply| Request::BlockUdp { blocked, reply })
            .await
            .expect("the loop answers");
    }
}

/// The rendezvous trace: the lines that say how the link went and what was offered.
fn trace() -> String {
    logs()
        .lines()
        .filter(|line| {
            [
                "gossip neighbor",
                "closing it",
                "rendezvous",
                "webrtc session attached",
            ]
            .iter()
            .any(|needle| line.contains(needle))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_rendezvous_link_stays_up_when_ip_is_lost() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let alice = Member::create("alice", &relay).await;
    let bob = Member::join("bob", &alice).await;

    assert!(
        eventually(Duration::from_mins(1), || rendezvous_lines("up") >= 1).await,
        "the joiner never linked to the rendezvous\n{}",
        trace()
    );
    let linking = Instant::now();
    while alice.roster_len().await != 1 || bob.roster_len().await != 1 {
        assert!(
            linking.elapsed() < Duration::from_mins(1),
            "the pair never linked\n{}",
            trace()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let downs_before = rendezvous_lines("down");

    alice.block_udp(true).await;
    let went_down = eventually(WINDOW, || rendezvous_lines("down") > downs_before).await;
    alice.block_udp(false).await;

    assert!(
        !went_down,
        "the rendezvous link went down inside {WINDOW:?} of the IP loss: the \
         WebRTC session is offered only after the close\n{}",
        trace()
    );
    assert!(
        logs().contains("webrtc session attached to the linked rendezvous"),
        "no session attached to the linked rendezvous\n{}",
        trace()
    );
}
