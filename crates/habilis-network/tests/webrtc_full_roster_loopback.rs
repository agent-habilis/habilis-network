//! A `WebRTC`-only mesh larger than the direct-peer ceiling must still give
//! every member the full roster.
//!
//! Each node holds at most `MAX_DIRECT_PEERS` (16) sessions. The rendezvous
//! session used to count as one of them, and the rendezvous pseudo-node
//! accepted only 16 sessions itself and never let one go. The first 16 joiners
//! therefore filled the rendezvous, and every later joiner stayed alone with
//! an empty roster.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inspect, Membership, Request};
use habilis_network::protocol::{Lookup, Transport};

use habilis_network::net::test_relay;
use std::{env, fs};
use tokio::{sync, time};
/// One more than `MAX_DIRECT_PEERS + 1`, so that a node cannot hold a session
/// to every other member and still keep one for the rendezvous.
const MEMBERS: usize = 18;
const FORMATION_DEADLINE: Duration = Duration::from_mins(2);

/// The tests share one log buffer, and a test counts lines in it, so a second test that runs at
/// the same time adds its own lines to the count.
fn serial() -> &'static sync::Mutex<()> {
    static SERIAL: OnceLock<sync::Mutex<()>> = OnceLock::new();
    SERIAL.get_or_init(|| sync::Mutex::new(()))
}

fn logs() -> String {
    habilis_network_test_tracing::captured_logs()
}

async fn open(nick: &str, options: membership::JoinOptions) -> Membership {
    let (sink, _events) = membership::json_sink();
    let options = options.nick(Some(nick.to_owned()));
    membership::join(&options, sink)
        .await
        .expect("open a member")
}

async fn roster_len(member: &Membership) -> usize {
    let json = member
        .request(|reply| Request::Inspect(Inspect::Peers { reply }))
        .await
        .unwrap_or_default();
    let decoded: Option<serde_json::Value> = serde_json::from_str(&json).ok();
    decoded
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
    let relay_urls = vec![relay.to_string()];
    let creator = open(
        "member-00",
        membership::JoinOptions::default()
            .lookup(vec![Lookup::Relay])
            .transport(vec![Transport::WebRtc])
            .relay_urls(relay_urls),
    )
    .await;
    let beacon_wait = Instant::now();
    while !logs().contains("beacon role active") {
        assert!(
            beacon_wait.elapsed() < Duration::from_mins(1),
            "the creator never claimed the beacon"
        );
        time::sleep(Duration::from_millis(250)).await;
    }

    let mesh = creator.node.mesh_id().to_string();
    let mut members = vec![creator];
    for index in 1..MEMBERS {
        members.push(
            open(
                &format!("member-{index:02}"),
                membership::JoinOptions::default().mesh(Some(mesh.clone())),
            )
            .await,
        );
        time::sleep(Duration::from_millis(500)).await;
    }
    members
}

/// Every member leaves, the first one last. The first member holds the rendezvous. If it left
/// first, the members that remain would all claim the rendezvous at once: two of them can claim
/// it a few milliseconds apart, and the relay then logs a WARN for the connection that it
/// replaced. That overlap is the contest the beacon resolves by design, and no test here is
/// about it.
async fn leave_all(members: Vec<Membership>) {
    for member in members.into_iter().rev() {
        let _ = member.node.leave().await;
    }
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
        time::sleep(Duration::from_secs(1)).await;
    }
    rosters
}

#[test]
fn every_member_of_a_webrtc_only_mesh_past_the_ceiling_gets_the_full_roster() {
    let guard = habilis_network_test_tracing::init_capturing(
        "habilis_network=info,habilis_network::transport=debug",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 8, async {
        let _serial = serial().lock().await;
        habilis_network_test_tracing::clear_captured_logs();

        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let members = start_group(&relay).await;

        let rosters = rosters_until(&members, MEMBERS - 1, FORMATION_DEADLINE).await;

        leave_all(members).await;
        let text = logs();
        let lines: Vec<_> = text
            .lines()
            .filter(|line| {
                ["direct-peer cap", "refused a signal offer", "evicted"]
                    .iter()
                    .any(|needle| line.contains(needle))
            })
            .take(60)
            .collect();
        let trace = lines.join("\n");
        assert!(
            rosters.iter().all(|len| *len == MEMBERS - 1),
            "every roster must hold {} peers; roster sizes by member: {rosters:?}\n{trace}",
            MEMBERS - 1
        );
    });
}

/// A crash is the case that puts every member back on the rendezvous: the
/// sweep removes the silent member, and each member that had let go of the
/// rendezvous owes it one return. The rendezvous has 16 slots, so the return
/// must end: the members that came back must let go again, or a joiner that
/// arrives after the crash finds the rendezvous full and the mesh is closed to
/// it, as it was before members let go at all.
#[test]
fn a_joiner_after_a_crash_still_gets_the_full_roster() {
    let guard = habilis_network_test_tracing::init_capturing(
        "habilis_network=info,habilis_network::transport=debug",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 8, async {
        let _serial = serial().lock().await;
        habilis_network_test_tracing::clear_captured_logs();

        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let mut members = start_group(&relay).await;
        let rosters = rosters_until(&members, MEMBERS - 1, FORMATION_DEADLINE).await;
        assert!(
            rosters.iter().all(|len| *len == MEMBERS - 1),
            "the mesh never formed: {rosters:?}"
        );
        let visits_before = rendezvous_visits();

        // A crash, as a dead process leaves things: no `Left`, and its sessions
        // abort with no close, so the survivors drop them when ICE consent times
        // out. Dropping the member instead leaves its sessions answering consent,
        // and each survivor keeps one of its direct-peer slots for it.
        tracing::info!(target: "habilis_network::test", "member crashed");
        members.pop().expect("a member to crash").node.crash().await;
        let swept = rosters_until(&members, MEMBERS - 2, Duration::from_mins(4)).await;
        assert!(
            swept.iter().all(|len| *len == MEMBERS - 2),
            "the sweep never removed the crashed member: {swept:?}"
        );

        // The sweep sends the members that let go of the rendezvous back to it. A
        // member at its own 16 sessions has no slot for the visit, so some come
        // back and some do not. Every one that came back must let go again, by its
        // own release or because the beacon dropped it from a full view.
        let started = Instant::now();
        loop {
            let visits = rendezvous_visits() - visits_before;
            let holders = rendezvous_holders(&logs());
            if visits >= 1 && holders == 0 {
                break;
            }
            if started.elapsed() >= Duration::from_mins(3) {
                dump_logs();
            }
            assert!(
                started.elapsed() < Duration::from_mins(3),
                "{visits} members came back to the rendezvous after the crash and {holders} still \
             hold it\n{}",
                come_back_trace()
            );
            time::sleep(Duration::from_secs(1)).await;
        }

        let mesh = members[0].node.mesh_id().to_string();
        members.push(
            open(
                "late-joiner",
                membership::JoinOptions::default().mesh(Some(mesh)),
            )
            .await,
        );
        let joined = rosters_until(&members, MEMBERS - 1, Duration::from_mins(2)).await;

        let trace = come_back_trace();
        dump_logs();
        leave_all(members).await;
        assert!(
            joined.iter().all(|len| *len == MEMBERS - 1),
            "a joiner after the crash must see everyone; roster sizes: {joined:?}\n{trace}"
        );
    });
}

/// The whole log, written to the file that `HABILIS_TEST_LOG_DUMP` names, if set.
fn dump_logs() {
    if let Ok(path) = env::var("HABILIS_TEST_LOG_DUMP") {
        let _ = fs::write(path, logs());
    }
}

/// How many times a member has linked to the rendezvous, in this run.
fn rendezvous_visits() -> usize {
    let text = logs();
    let visits = text.lines().filter(|line| {
        let up = line.contains("gossip neighbor up");
        up && line.contains("is_rendezvous=true")
    });
    visits.count()
}

/// How many members hold a link to the rendezvous that they made after the crash: those whose
/// last rendezvous event after the crash is a `neighbor up`. A member lets go of the link by its
/// own release, or because the beacon drops it from a full view. Both end in a `neighbor down`,
/// and only the first logs a release. A member that held the link before the crash and logs no
/// event after it is none of these: it did not come back.
fn rendezvous_holders(log: &str) -> usize {
    let after_the_crash = log.split("member crashed").nth(1).unwrap_or_default();
    let mut last_is_up = HashMap::new();
    for line in after_the_crash
        .lines()
        .filter(|line| line.contains("is_rendezvous=true"))
    {
        let up = line.contains("gossip neighbor up");
        if !up && !line.contains("gossip neighbor down") {
            continue;
        }
        let rest = line.split("local=").nth(1);
        let Some(local) = rest.and_then(|rest| rest.split_whitespace().next()) else {
            continue;
        };
        last_is_up.insert(local, up);
    }
    last_is_up.values().filter(|up| **up).count()
}

/// A member that the beacon dropped is gone from the rendezvous, though it logged no release: it
/// is no holder, and a member that came back after its drop is one. A member that held the link
/// since before the crash and stayed is none.
#[test]
fn a_member_that_the_beacon_dropped_holds_no_link() {
    let rendezvous = "endpoint_id=aa is_rendezvous=true";
    let log: String = [
        format!("gossip neighbor up local=stayed {rendezvous}"),
        format!("gossip neighbor up local=crashed {rendezvous}"),
        "member crashed".to_owned(),
        format!("gossip neighbor up local=one {rendezvous}"),
        format!("gossip neighbor up local=two {rendezvous}"),
        format!("gossip neighbor down local=two {rendezvous}"),
        format!("gossip neighbor up local=three {rendezvous}"),
        "enough links to members: released the rendezvous local=three links=3".to_owned(),
        format!("gossip neighbor down local=three {rendezvous}"),
        format!("gossip neighbor up local=three {rendezvous}"),
        "gossip neighbor up local=four endpoint_id=bb is_rendezvous=false".to_owned(),
    ]
    .join("\n");
    assert_eq!(
        rendezvous_holders(&log),
        2,
        "one and the returned three, not the member that stayed"
    );
}

/// The lines that say how the rendezvous was released and visited again.
fn come_back_trace() -> String {
    let text = logs();
    let lines: Vec<_> = text
        .lines()
        .filter(|line| {
            [
                "released the rendezvous",
                "refused a signal offer",
                "nothing to close",
                "is_rendezvous=true",
            ]
            .iter()
            .any(|needle| line.contains(needle))
        })
        .collect();
    let newest = lines.into_iter().rev().take(60);
    let recent: Vec<_> = newest.rev().collect();
    recent.join("\n")
}
