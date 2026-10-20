//! A joiner that arrives after every old member released the rendezvous.
//!
//! A rendezvous that all members released has no gossip neighbor, so a join
//! to it starts no walk. The joiner must still learn the members, and the
//! members must still learn the joiner, before the 90 s plumtree dedup window
//! ends. A delivery that waits for that window is a failure.
//!
//! Six members on a local relay, the default transport list. The test waits
//! until each of the five joiners logged the release of the rendezvous with
//! three links or more. Then a seventh member joins.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use habilis_network::membership::{self, Membership, Request};
use habilis_network::protocol::Lookup;

const OLD_MEMBERS: usize = 6;
const RELEASE_LINKS: usize = 3;
const PRECONDITION_DEADLINE: Duration = Duration::from_mins(1);
const FORMATION_DEADLINE: Duration = Duration::from_mins(2);
/// Less than the 90 s dedup window: a delivery that waited for it is a failure.
const LATE_JOINER_DEADLINE: Duration = Duration::from_mins(1);

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

/// The nicknames of the live peers in the roster of a member.
async fn roster(member: &Membership) -> Vec<String> {
    let json = member
        .request(|reply| Request::Peers { reply })
        .await
        .unwrap_or_default();
    serde_json::from_str::<serde_json::Value>(&json)
        .ok()
        .and_then(|roster| {
            roster["peers"].as_array().map(|peers| {
                peers
                    .iter()
                    .filter(|peer| peer["quiet"] != serde_json::Value::Bool(true))
                    .filter_map(|peer| peer["nickname"].as_str().map(str::to_owned))
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// How many different members logged a release with `RELEASE_LINKS` links or
/// more. A member that releases twice counts once.
fn members_released_with_enough_links() -> usize {
    let logs = logs();
    logs.lines()
        .filter(|line| line.contains("released the rendezvous"))
        .filter(|line| {
            line.split("links=")
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|count| count.parse::<usize>().ok())
                .is_some_and(|count| count >= RELEASE_LINKS)
        })
        .filter_map(|line| line.split("local=").nth(1)?.split_whitespace().next())
        .collect::<BTreeSet<_>>()
        .len()
}

fn release_lines() -> String {
    logs()
        .lines()
        .filter(|line| line.contains("rendezvous"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joiner_after_every_member_released_the_rendezvous_meets_all_members() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");

    let creator = open(
        "member-00",
        membership::Opts {
            lookup: vec![Lookup::Relay],
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
    for index in 1..OLD_MEMBERS {
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

    let formation = Instant::now();
    loop {
        let mut full = true;
        for member in &members {
            full &= roster(member).await.len() == OLD_MEMBERS - 1;
        }
        if full {
            break;
        }
        assert!(
            formation.elapsed() < FORMATION_DEADLINE,
            "the old mesh never formed\n{}",
            release_lines()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let precondition = Instant::now();
    while members_released_with_enough_links() < OLD_MEMBERS - 1 {
        assert!(
            precondition.elapsed() < PRECONDITION_DEADLINE,
            "not every joiner released the rendezvous with {RELEASE_LINKS} links or more \
             inside {PRECONDITION_DEADLINE:?}\n{}",
            release_lines()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let late = open(
        "member-late",
        membership::Opts {
            mesh: Some(mesh),
            ..membership::Opts::default()
        },
    )
    .await;
    let started = Instant::now();
    let mut old_learned: BTreeMap<usize, Duration> = BTreeMap::new();
    let mut late_learned_all = None;
    while started.elapsed() < LATE_JOINER_DEADLINE
        && (old_learned.len() < OLD_MEMBERS || late_learned_all.is_none())
    {
        for (index, member) in members.iter().enumerate() {
            if !old_learned.contains_key(&index)
                && roster(member)
                    .await
                    .iter()
                    .any(|nick| nick == "member-late")
            {
                old_learned.insert(index, started.elapsed());
            }
        }
        if late_learned_all.is_none() && roster(&late).await.len() >= OLD_MEMBERS {
            late_learned_all = Some(started.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    eprintln!("old members that learned the joiner, after the join: {old_learned:?}");
    eprintln!("the joiner learned all {OLD_MEMBERS} members after: {late_learned_all:?}");
    assert!(
        old_learned.len() == OLD_MEMBERS,
        "only {} of {OLD_MEMBERS} old members learned the joiner inside \
         {LATE_JOINER_DEADLINE:?}: {old_learned:?}\n{}",
        old_learned.len(),
        release_lines()
    );
    assert!(
        late_learned_all.is_some(),
        "the joiner did not learn all {OLD_MEMBERS} members inside {LATE_JOINER_DEADLINE:?}\n{}",
        release_lines()
    );
}
