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
use std::time::{Duration, Instant};

use habilis_network::membership::{self, Membership, Request};
use habilis_network::protocol::Lookup;

use habilis_network::net::test_relay;
use tokio::time;
const OLD_MEMBERS: usize = 6;
const RELEASE_LINKS: usize = 3;
const PRECONDITION_DEADLINE: Duration = Duration::from_mins(1);
const FORMATION_DEADLINE: Duration = Duration::from_mins(2);
/// Less than the 90 s dedup window: a delivery that waited for it is a failure.
const LATE_JOINER_DEADLINE: Duration = Duration::from_mins(1);

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

/// The nicknames of the live peers in the roster of a member.
async fn roster(member: &Membership) -> Vec<String> {
    let json = member
        .request(|reply| Request::Peers { reply })
        .await
        .unwrap_or_default();
    let roster = serde_json::from_str::<serde_json::Value>(&json).ok();
    roster
        .and_then(|roster| {
            roster["peers"].as_array().map(|peers| {
                let live = peers
                    .iter()
                    .filter(|peer| peer["quiet"] != serde_json::Value::Bool(true));
                live.filter_map(|peer| peer["nickname"].as_str().map(str::to_owned))
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// How many different members logged a release with `RELEASE_LINKS` links or
/// more. A member that releases twice counts once.
fn members_released_with_enough_links() -> usize {
    let logs = logs();
    let local_member = |line: &str| -> Option<String> {
        let field = line.split("local=").nth(1)?;
        field.split_whitespace().next().map(str::to_owned)
    };
    let members: BTreeSet<String> = logs
        .lines()
        .filter(|line| line.contains("released the rendezvous"))
        .filter(|line| {
            let field = line.split("links=").nth(1);
            let word = field.and_then(|rest| rest.split_whitespace().next());
            word.and_then(|count| -> Option<usize> { count.parse().ok() })
                .is_some_and(|count| count >= RELEASE_LINKS)
        })
        .filter_map(local_member)
        .collect();
    members.len()
}

fn release_lines() -> String {
    let text = logs();
    let lines: Vec<_> = text
        .lines()
        .filter(|line| line.contains("rendezvous"))
        .collect();
    lines.join("\n")
}

#[test]
fn a_joiner_after_every_member_released_the_rendezvous_meets_all_members() {
    let guard = habilis_network_test_tracing::init_capturing(
        "habilis_network=info,habilis_network::transport=debug",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");

        let creator = open(
            "member-00",
            membership::JoinOptions::default()
                .lookup(vec![Lookup::Relay])
                .relay_urls(vec![relay.to_string()]),
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
        for index in 1..OLD_MEMBERS {
            members.push(
                open(
                    &format!("member-{index:02}"),
                    membership::JoinOptions::default().mesh(Some(mesh.clone())),
                )
                .await,
            );
            time::sleep(Duration::from_millis(500)).await;
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
            time::sleep(Duration::from_millis(250)).await;
        }

        let precondition = Instant::now();
        while members_released_with_enough_links() < OLD_MEMBERS - 1 {
            assert!(
                precondition.elapsed() < PRECONDITION_DEADLINE,
                "not every joiner released the rendezvous with {RELEASE_LINKS} links or more \
             inside {PRECONDITION_DEADLINE:?}\n{}",
                release_lines()
            );
            time::sleep(Duration::from_millis(250)).await;
        }

        let late = open(
            "member-late",
            membership::JoinOptions::default().mesh(Some(mesh)),
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
            time::sleep(Duration::from_millis(250)).await;
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
        for member in members.into_iter().chain([late]) {
            let _ = member.node.leave().await;
        }
    });
}
