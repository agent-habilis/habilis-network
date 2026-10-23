//! An underlay tick inside a link gap keeps the live session of the pair.
//!
//! Two members without `udp`: the only path between their underlays is a `WebRTC` session. The
//! relay watcher closes a gossip link that stays on the relay on purpose, and the link vector of
//! the member stays. The session carries a route that other members use, so it must outlive
//! the gossip link. The test closes the gossip connection of the pair, waits for the engine's own
//! neighbor down on both ends, and reads the session count and the log.
//!
//! `Request::UnderlayTick` exists because a test cannot steer the alive tick, and the pair grafts
//! again within seconds: the hook runs the same function the alive tick runs, inside the gap.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

mod until_known;

use std::time::{Duration, Instant};

use habilis_network::iroh::EndpointId;
use habilis_network::membership::{self, Membership, Request};
use habilis_network::protocol::{Lookup, Transport};
use until_known::until_peer_known;

const STEP_DEADLINE: Duration = Duration::from_mins(3);

/// How long both ends tick after the close.
const SETTLE: Duration = Duration::from_secs(5);

fn log_len() -> usize {
    habilis_network_test_tracing::captured_logs()
        .lines()
        .count()
}

fn logs_since(since: usize) -> String {
    habilis_network_test_tracing::captured_logs()
        .lines()
        .skip(since)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether, since `since`, `local` logged the gossip neighbor `remote` going down.
fn neighbor_down(since: usize, local: &EndpointId, remote: &EndpointId) -> bool {
    logs_since(since).lines().any(|line| {
        line.contains("gossip neighbor down")
            && line.contains(&format!("local={} ", local.fmt_short()))
            && line.contains(&format!("endpoint_id={remote} "))
    })
}

async fn underlay_sessions(member: &Membership) -> usize {
    member
        .request(|reply| Request::UnderlaySessions { reply })
        .await
        .expect("the loop answers")
}

async fn roster_len(member: &Membership) -> usize {
    let json = member
        .request(|reply| Request::Peers { reply })
        .await
        .unwrap_or_default();
    serde_json::from_str::<serde_json::Value>(&json)
        .ok()
        .and_then(|roster| roster["peers"].as_array().map(Vec::len))
        .unwrap_or(0)
}

#[test]
fn an_underlay_tick_inside_a_link_gap_keeps_the_session() {
    let guard = habilis_network_test_tracing::init_capturing(
        "habilis_network=info,habilis_network::transport=debug",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
            .await
            .expect("local relay");
        let (sink_a, _events_a) = membership::json_sink();
        let alice = membership::join(
            &membership::Opts::default()
                .with_nick(Some("alice".to_owned()))
                .with_lookup(vec![Lookup::Relay])
                .with_transport(vec![
                    Transport::WebRtc,
                    Transport::Multihop,
                    Transport::Relay,
                ])
                .with_relay_urls(vec![relay.to_string()]),
            sink_a,
        )
        .await
        .expect("open alice");
        let (sink_b, _events_b) = membership::json_sink();
        let bob = membership::join(
            &membership::Opts::default()
                .with_nick(Some("bob".to_owned()))
                .with_mesh(Some(alice.node.mesh_id().to_string())),
            sink_b,
        )
        .await
        .expect("open bob");

        let meshing = Instant::now();
        while roster_len(&alice).await != 1 || roster_len(&bob).await != 1 {
            assert!(
                meshing.elapsed() < STEP_DEADLINE,
                "the two never formed a mesh"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let started = Instant::now();
        while underlay_sessions(&alice).await == 0 || underlay_sessions(&bob).await == 0 {
            assert!(
                started.elapsed() < STEP_DEADLINE,
                "the underlay never opened a session"
            );
            let to = membership::parse_to(Some("bob")).expect("a nickname");
            let body = membership::msg_body("probe").expect("fits one frame");
            let _ = alice
                .request(|reply| Request::Send { to, body, reply })
                .await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        let alice_id = alice
            .request(|reply| Request::EndpointId { reply })
            .await
            .expect("the loop answers");
        let bob_id = bob
            .request(|reply| Request::EndpointId { reply })
            .await
            .expect("the loop answers");

        // One close of the connection; the engine runs its own `NeighborDown` on both ends.
        let since = log_len();
        until_peer_known(&alice, "bob", |reply| Request::CloseLink {
            peer: "bob".to_owned(),
            reply,
        })
        .await;
        // A tick has to run while the link is down, or the test proves nothing: the pair grafts again
        // within tens of milliseconds (28 ms in a run that failed). So both ends tick every 5 ms
        // through the window.
        let window = Instant::now();
        while window.elapsed() < SETTLE {
            for member in [&alice, &bob] {
                member
                    .request(|reply| Request::UnderlayTick { reply })
                    .await
                    .expect("the loop answers");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            neighbor_down(since, &alice_id, &bob_id) && neighbor_down(since, &bob_id, &alice_id),
            "the close never reached the engine of both ends as a neighbor down"
        );
        assert!(
            logs_since(since)
                .lines()
                .any(|line| line.contains("underlay tick") && line.contains("linked=0 ")),
            "no underlay tick ran while a member had no gossip link"
        );

        let detached = logs_since(since)
            .lines()
            .filter(|line| line.contains("underlay session detached"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            detached.is_empty(),
            "a session was detached after the gossip link closed:\n{detached}"
        );
        assert_eq!(underlay_sessions(&alice).await, 1, "alice kept the session");
        assert_eq!(underlay_sessions(&bob).await, 1, "bob kept the session");

        for member in [alice, bob] {
            let _ = member.node.leave().await;
        }
    });
}
