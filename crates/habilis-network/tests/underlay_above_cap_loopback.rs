//! The sessions of the multihop underlay do not churn when a node knows more members than its cap.
//!
//! Four members without `udp`, and `max_peers` 2, so the cap of every underlay is 2 and every
//! member knows three others. The underlay of a node without `udp` wants a session to each known
//! member. A session of the underlay is a route edge, so its table refuses a newcomer at the cap and
//! evicts nobody; when it evicted, the evicted member was dialed again and the sessions swung (measured
//! on c4e507c: 1, 2 and 2 evictions in the three windows). The test counts the evictions in three
//! windows of a minute, after the mesh has settled, and expects none in the last one, and the same
//! number of sessions in the last two windows.
//!
//! It does not assert that every member holds a session: a cap of 2 on 4 members can leave a node
//! whose partners are all full with none, and above the cap a pair routes through others. The rule
//! promises no eviction and a stable count, and the test asserts that.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::membership::{self, Membership, Request};
use habilis_network::protocol::{Lookup, Transport};

use habilis_network::net::test_relay;
const MEMBERS: usize = 4;
const CAP: usize = 2;
const MESH_DEADLINE: Duration = Duration::from_mins(3);
const SETTLE: Duration = Duration::from_secs(30);
const WINDOW: Duration = Duration::from_mins(1);
const WINDOWS: usize = 3;
const EVICTION: &str = "evicting a session at the ceiling";

fn evictions() -> usize {
    habilis_network_test_tracing::captured_logs()
        .matches(EVICTION)
        .count()
}

async fn roster_len(member: &Membership) -> usize {
    let json = member
        .request(|reply| Request::Peers { reply })
        .await
        .unwrap_or_default();
    let roster = serde_json::from_str::<serde_json::Value>(&json).ok();
    roster
        .and_then(|roster| roster["peers"].as_array().map(Vec::len))
        .unwrap_or(0)
}

async fn underlay_sessions(member: &Membership) -> usize {
    member
        .request(|reply| Request::UnderlaySessions { reply })
        .await
        .expect("the loop answers")
}

async fn sessions_of_all(members: &[Membership]) -> Vec<usize> {
    let mut counts = Vec::new();
    for member in members {
        counts.push(underlay_sessions(member).await);
    }
    counts
}

#[test]
fn the_underlay_does_not_evict_in_steady_state_above_its_cap() {
    let guard = habilis_network_test_tracing::init_capturing(
        "habilis_network=info,habilis_network::transport=debug",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let (first_sink, _first_events) = membership::json_sink();
        let options = membership::JoinOptions::default()
            .with_nick(Some("m0".to_owned()))
            .with_lookup(vec![Lookup::Relay]);
        let options = options
            .with_transport(vec![
                Transport::WebRtc,
                Transport::Multihop,
                Transport::Relay,
            ])
            .with_relay_urls(vec![relay.to_string()])
            .with_max_peers(CAP);
        let creator: Membership = membership::join(&options, first_sink)
            .await
            .expect("open the first member");
        let mesh = creator.node.mesh_id().to_string();
        let mut members = vec![creator];
        let mut sinks = Vec::new();
        for index in 1..MEMBERS {
            let (sink, events) = membership::json_sink();
            sinks.push(events);
            let member_options = membership::JoinOptions::default()
                .with_nick(Some(format!("m{index}")))
                .with_mesh(Some(mesh.clone()))
                .with_max_peers(CAP);
            members.push(
                membership::join(&member_options, sink)
                    .await
                    .expect("open a member"),
            );
        }

        let meshing = Instant::now();
        'mesh: loop {
            for member in &members {
                if roster_len(member).await != MEMBERS - 1 {
                    assert!(
                        meshing.elapsed() < MESH_DEADLINE,
                        "the members never saw each other"
                    );
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue 'mesh;
                }
            }
            break;
        }
        tokio::time::sleep(SETTLE).await;

        let mut per_window = Vec::new();
        let mut totals = Vec::new();
        for window in 0..WINDOWS {
            let before = evictions();
            tokio::time::sleep(WINDOW).await;
            let sessions = sessions_of_all(&members).await;
            let count = evictions() - before;
            eprintln!(
                "WINDOW {window}: {count} evictions, underlay sessions per member {sessions:?}"
            );
            per_window.push(count);
            totals.push(sessions.iter().sum::<usize>());
        }
        for member in members {
            let _ = member.node.leave().await;
        }
        assert_eq!(
            totals[WINDOWS - 1],
            totals[WINDOWS - 2],
            "the sessions still swung between the last two windows (sums per window: {totals:?})"
        );
        assert_eq!(
            per_window.last().copied(),
            Some(0),
            "the underlay still evicted sessions in the last minute (evictions per minute: {per_window:?})"
        );
    });
}
