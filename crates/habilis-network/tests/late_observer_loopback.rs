//! Two members of a loopback mesh use one nickname, and a third member joins after both. The observer
//! must hold ONE holder of the nickname within seconds: the first proof that it processes binds the name
//! and ends the other session. A window of two holders that lasts a minute is a window in which a node
//! lists an impostor under a bound nickname.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, process};

use habilis_network::membership::{self, Inspect, Membership, Request};
use habilis_network::protocol::{Mesh, MeshConfig, MeshName, Seed};
use tokio::time;

/// A seed that no other test of this process and no other run has: the clock, the pid and a counter.
fn fresh_seed() -> Seed {
    static CALLS: AtomicU64 = AtomicU64::new(0);
    let nanos: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_nanos();
    let call = u128::from(CALLS.fetch_add(1, Ordering::Relaxed));
    let mut bytes = [0u8; 32];
    for (index, chunk) in bytes.chunks_mut(16).enumerate() {
        let value = nanos.rotate_left(u32::try_from(index * 17).expect("small"))
            ^ u128::from(process::id())
            ^ call.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    Seed::new(bytes)
}

/// The rows of the roster of `member` that use `nickname`.
async fn rows_named(member: &Membership, nickname: &str) -> usize {
    let json: String = member
        .request(|reply| Request::Inspect(Inspect::Peers { reply }))
        .await
        .unwrap_or_default();
    let roster: Option<serde_json::Value> = serde_json::from_str(&json).ok();
    if env::var("LATE_OBSERVER_DEBUG").is_ok() {
        eprintln!("ROSTER {json}");
    }
    roster
        .and_then(|roster| {
            roster["peers"].as_array().map(|rows| {
                rows.iter()
                    .filter(|row| row["nickname"].as_str() == Some(nickname))
                    .count()
            })
        })
        .unwrap_or(0)
}

/// A member of `mesh` under `nick`.
async fn join_as(mesh: &Mesh, nick: &str) -> Membership {
    let options: membership::JoinOptions = membership::JoinOptions::default()
        .mesh(Some(mesh.to_string()))
        .nick(Some(nick.to_owned()));
    let (sink, _events) = membership::json_sink();
    membership::join(&options, sink)
        .await
        .expect("open a member")
}

#[test]
fn a_late_observer_holds_one_holder_of_a_shared_nickname_within_seconds() {
    let guard = habilis_network_test_tracing::init();
    guard.allow_warn(
        "habilis_network::lifecycle",
        "our nickname is held by another member",
    );
    guard.allow_warn(
        "habilis_network::gossip",
        "no peer answered the digest of the state channel within the time limit",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
        let mesh: Mesh = Mesh::try_new(
            fresh_seed(),
            MeshName::try_new("late-observer").expect("a name"),
            config,
        )
        .expect("a mesh");
        let first = join_as(&mesh, "alice").await;
        let second = join_as(&mesh, "alice").await;
        // Both members run before the observer joins.
        time::sleep(Duration::from_secs(8)).await;
        let observer = join_as(&mesh, "carol").await;

        let started = Instant::now();
        let mut held_one_at: Option<Duration> = None;
        let mut max_rows = 0;
        while started.elapsed() < Duration::from_secs(90) {
            let rows = rows_named(&observer, "alice").await;
            max_rows = max_rows.max(rows);
            if rows == 1 && held_one_at.is_none() {
                held_one_at = Some(started.elapsed());
                eprintln!(
                    "LATE_OBSERVER one holder after {:?} (max rows {max_rows})",
                    started.elapsed()
                );
                break;
            }
            time::sleep(Duration::from_millis(250)).await;
        }
        let _ = observer.node.leave().await;
        let _ = second.node.leave().await;
        let _ = first.node.leave().await;
        let at = held_one_at.expect("the observer never held one holder of the nickname");
        assert!(
            at < Duration::from_secs(10),
            "the observer held two holders of one nickname for {at:?}"
        );
    });
}

#[test]
fn an_observer_that_joins_with_the_two_members_holds_one_holder_ten_seconds_later() {
    let guard = habilis_network_test_tracing::init();
    guard.allow_warn(
        "habilis_network::lifecycle",
        "our nickname is held by another member",
    );
    guard.allow_warn(
        "habilis_network::gossip",
        "no peer answered the digest of the state channel within the time limit",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
        let mesh: Mesh = Mesh::try_new(
            fresh_seed(),
            MeshName::try_new("together").expect("a name"),
            config,
        )
        .expect("a mesh");
        // The creator, the two members under one nickname and the observer start one after the other
        // with no pause, as the real daemons of the churn tests do.
        let creator = join_as(&mesh, "boss").await;
        let first = join_as(&mesh, "alice").await;
        let second = join_as(&mesh, "alice").await;
        let observer = join_as(&mesh, "carol").await;
        time::sleep(Duration::from_secs(10)).await;

        let rows = rows_named(&observer, "alice").await;
        eprintln!("TOGETHER rows after ten seconds: {rows}");
        for member in [observer, second, first, creator] {
            let _ = member.node.leave().await;
        }
        assert_eq!(
            rows, 1,
            "the observer holds {rows} rows under one nickname ten seconds after it joined, and it must hold one"
        );
    });
}
