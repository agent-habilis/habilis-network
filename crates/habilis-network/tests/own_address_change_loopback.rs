//! A member's own address changes after its first `PeerInfo` flood, and the
//! others are told.
//!
//! The arrival flood goes out on the first `NeighborUp`, in the same
//! milliseconds in which the endpoint gets its home relay, so it can carry no
//! relay. A flood later in the window does not repair that, and a receiver keeps
//! the first address it saw. A member must therefore flood again when its own
//! address changes.
//!
//! Two members on a local relay. After they are linked, one member adds an
//! external address (the same change as a late home relay or an interface
//! change: the address that its endpoint reports changes). The test counts the
//! `peerinfo flooded` and `peerinfo received` debug lines that name the new
//! address. It is the address of a documentation range, so no other line names it.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Membership, Request};
use habilis_network::protocol::Lookup;
use tokio::sync::mpsc::UnboundedReceiver;

/// The address that the member adds: a documentation range (RFC 5737), so no
/// real interface carries it and no other log line names it.
const NEW_ADDR: &str = "192.0.2.77:4000";

/// How long the flood and its receipt may take after the address changed.
const WINDOW: Duration = Duration::from_secs(10);

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

fn logs() -> String {
    log_buffer().lock().expect("no poison").clone()
}

/// How many log lines of `message` name `NEW_ADDR`.
fn lines_naming_new_addr(message: &str) -> usize {
    logs()
        .lines()
        .filter(|line| line.contains(message) && line.contains(NEW_ADDR))
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

    async fn add_external_addr(&self, addr: std::net::SocketAddr) {
        self.membership
            .request(|reply| Request::AddExternalAddr { addr, reply })
            .await
            .expect("the loop answers");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_that_changes_its_own_address_floods_it_again() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let alice = Member::create("alice", &relay).await;
    let bob = Member::join("bob", &alice).await;

    let linking = Instant::now();
    while alice.roster_len().await != 1 || bob.roster_len().await != 1 {
        assert!(
            linking.elapsed() < Duration::from_mins(1),
            "the pair never linked\n{}",
            trace()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(
        lines_naming_new_addr("peerinfo flooded"),
        0,
        "the new address is named before it was added"
    );

    alice
        .add_external_addr(NEW_ADDR.parse().expect("an address"))
        .await;

    assert!(
        eventually(WINDOW, || lines_naming_new_addr("peerinfo flooded") >= 1).await,
        "no PeerInfo flood carried the new address within {WINDOW:?}\n{}",
        trace()
    );
    assert!(
        eventually(WINDOW, || lines_naming_new_addr("peerinfo received") >= 1).await,
        "no member received a PeerInfo that carries the new address\n{}",
        trace()
    );
}

/// The lines about `PeerInfo` floods and receipts, to read a failure by.
fn trace() -> String {
    logs()
        .lines()
        .filter(|line| line.contains("peerinfo flooded") || line.contains("peerinfo received"))
        .collect::<Vec<_>>()
        .join("\n")
}
