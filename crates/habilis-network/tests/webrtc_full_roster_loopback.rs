//! A `WebRTC`-only mesh larger than the direct-peer ceiling must still give
//! every member the full roster.
//!
//! Each node holds at most `MAX_DIRECT_PEERS` (16) sessions. The rendezvous
//! session used to count as one of them, and the rendezvous pseudo-node
//! accepted only 16 sessions itself and never let one go. The first 16 joiners
//! therefore filled the rendezvous, and every later joiner stayed alone with
//! an empty roster.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Membership, Request};
use habilis_network::protocol::{Lookup, Transport};

/// One more than `MAX_DIRECT_PEERS + 1`, so that a node cannot hold a session
/// to every other member and still keep one for the rendezvous.
const MEMBERS: usize = 18;
const FORMATION_DEADLINE: Duration = Duration::from_mins(2);

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
    log_buffer().lock().expect("no poison").clear();
}

fn logs() -> String {
    log_buffer().lock().expect("no poison").clone()
}

async fn open(nick: &str, opts: membership::Opts) -> Membership {
    let (sink, _events) = membership::json_sink();
    let opts = membership::Opts {
        nick: Some(nick.to_owned()),
        ..opts
    };
    membership::join(&opts, sink).await.expect("open a member")
}

async fn roster_len(member: &Membership) -> usize {
    let json = member
        .request(|reply| Request::Peers { reply })
        .await
        .unwrap_or_default();
    serde_json::from_str::<serde_json::Value>(&json)
        .ok()
        .and_then(|roster| {
            // A swept peer stays in the roster as quiet, so count the live ones.
            roster["peers"].as_array().map(|peers| {
                peers
                    .iter()
                    .filter(|peer| peer["quiet"] != serde_json::Value::Bool(true))
                    .count()
            })
        })
        .unwrap_or(0)
}

/// A creator that hosts the rendezvous and `MEMBERS - 1` joiners on one
/// `WebRTC`-only mesh over a local relay, as live members.
async fn start_group(relay: &RelayUrl) -> Vec<Membership> {
    let creator = open(
        "member-00",
        membership::Opts {
            lookup: vec![Lookup::Relay],
            transport: vec![Transport::WebRtc],
            relay_urls: vec![relay.to_string()],
            ..membership::Opts::default()
        },
    )
    .await;
    let beacon_wait = Instant::now();
    while !logs().contains("beacon role active") {
        assert!(
            beacon_wait.elapsed() < Duration::from_mins(1),
            "the creator never claimed the beacon"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let mesh = creator.node.mesh_id().to_string();
    let mut members = vec![creator];
    for index in 1..MEMBERS {
        members.push(
            open(
                &format!("member-{index:02}"),
                membership::Opts {
                    mesh: Some(mesh.clone()),
                    ..membership::Opts::default()
                },
            )
            .await,
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    members
}

/// The roster size of every member, once all hold `peers` or the deadline ends.
async fn rosters_until(members: &[Membership], peers: usize, deadline: Duration) -> Vec<usize> {
    let started = Instant::now();
    let mut rosters = Vec::new();
    while started.elapsed() < deadline {
        rosters.clear();
        for member in members {
            rosters.push(roster_len(member).await);
        }
        if rosters.iter().all(|len| *len == peers) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    rosters
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn every_member_of_a_webrtc_only_mesh_past_the_ceiling_gets_the_full_roster() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let members = start_group(&relay).await;

    let rosters = rosters_until(&members, MEMBERS - 1, FORMATION_DEADLINE).await;

    for member in members {
        let _ = member.node.leave().await;
    }
    let trace = logs()
        .lines()
        .filter(|line| {
            ["direct-peer cap", "refused a signal offer", "evicted"]
                .iter()
                .any(|needle| line.contains(needle))
        })
        .take(60)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        rosters.iter().all(|len| *len == MEMBERS - 1),
        "every roster must hold {} peers; roster sizes by member: {rosters:?}\n{trace}",
        MEMBERS - 1
    );
}

/// A crash is the case that puts every member back on the rendezvous: the
/// sweep removes the silent member, and each member that had let go of the
/// rendezvous owes it one return. The rendezvous has 16 slots, so the return
/// must end: the members that came back must let go again, or a joiner that
/// arrives after the crash finds the rendezvous full and the mesh is closed to
/// it, as it was before members let go at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_joiner_after_a_crash_still_gets_the_full_roster() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let mut members = start_group(&relay).await;
    let rosters = rosters_until(&members, MEMBERS - 1, FORMATION_DEADLINE).await;
    assert!(
        rosters.iter().all(|len| *len == MEMBERS - 1),
        "the mesh never formed: {rosters:?}"
    );
    let released_before = logs().matches("released the rendezvous").count();
    let visits_before = rendezvous_visits();

    // A crash: the member vanishes with no `Left`, so only the sweep removes it.
    drop(members.pop().expect("a member to crash"));
    let swept = rosters_until(&members, MEMBERS - 2, Duration::from_mins(4)).await;
    assert!(
        swept.iter().all(|len| *len == MEMBERS - 2),
        "the sweep never removed the crashed member: {swept:?}"
    );

    // The sweep sends the members that let go of the rendezvous back to it. A
    // member at its own 16 sessions has no slot for the visit, so some come
    // back and some do not. Every one that came back must let go again.
    let started = Instant::now();
    loop {
        let visits = rendezvous_visits() - visits_before;
        let releases = logs().matches("released the rendezvous").count() - released_before;
        if visits >= 1 && releases >= visits {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_mins(3),
            "{visits} members came back to the rendezvous after the crash and {releases} let go \
             again\n{}",
            come_back_trace()
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let mesh = members[0].node.mesh_id().to_string();
    members.push(
        open(
            "late-joiner",
            membership::Opts {
                mesh: Some(mesh),
                ..membership::Opts::default()
            },
        )
        .await,
    );
    let joined = rosters_until(&members, MEMBERS - 1, Duration::from_mins(2)).await;

    let trace = come_back_trace();
    if let Ok(path) = std::env::var("HABILIS_TEST_LOG_DUMP") {
        let _ = std::fs::write(path, logs());
    }
    for member in members {
        let _ = member.node.leave().await;
    }
    assert!(
        joined.iter().all(|len| *len == MEMBERS - 1),
        "a joiner after the crash must see everyone; roster sizes: {joined:?}\n{trace}"
    );
}

/// How many times a member has linked to the rendezvous, in this run.
fn rendezvous_visits() -> usize {
    logs()
        .lines()
        .filter(|line| line.contains("gossip neighbor up") && line.contains("is_rendezvous=true"))
        .count()
}

/// The lines that say how the rendezvous was released and visited again.
fn come_back_trace() -> String {
    logs()
        .lines()
        .filter(|line| {
            [
                "released the rendezvous",
                "refused a signal offer",
                "nothing to close",
            ]
            .iter()
            .any(|needle| line.contains(needle))
        })
        .take(60)
        .collect::<Vec<_>>()
        .join("\n")
}
