//! Two members of a loopback mesh meet although a foreign endpoint holds a rung of the port ladder
//! below the rung of the beacon.
//!
//! The ladder is derived from the seed of the mesh: eight ports that every member tries in order.
//! On a host with many endpoints, another process can hold one of them. The claim walk reads such a
//! rung as foreign and takes a higher one. A joiner must not dial the rung of the foreign endpoint
//! all the same: a listener there answers the dial with its own identity, or with a TLS alert for
//! an ALPN that it does not serve, and the dial of the joiner fails as a whole, again and again.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::Endpoint;
use habilis_network::iroh::endpoint::presets;
use habilis_network::membership::{self, Membership, Request};
use habilis_network::protocol::{Mesh, MeshConfig, MeshName, Seed};

const MEET_DEADLINE: Duration = Duration::from_secs(90);

/// A seed that differs from run to run, so that the ladder of one run is not the ladder of another
/// run on the same host.
fn fresh_seed() -> Seed {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_nanos();
    let mut bytes = [0u8; 32];
    for (index, chunk) in bytes.chunks_mut(16).enumerate() {
        let value = nanos.rotate_left(u32::try_from(index * 17).expect("small"))
            ^ u128::from(std::process::id());
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    Seed::new(bytes)
}

/// A listener on `port` that serves one ALPN, so it answers a gossip dial with a TLS alert. It is a
/// plain accept loop: an iroh `Router` would log every failed accept as a warning of its own.
async fn foreign_on(port: u16) -> (Endpoint, tokio::task::JoinHandle<()>) {
    let builder = Endpoint::builder(presets::Minimal)
        .alpns(vec![b"foreign".to_vec()])
        .clear_ip_transports();
    let address = format!("127.0.0.1:{port}");
    let bound = builder
        .bind_addr(address.as_str())
        .expect("a valid address");
    let endpoint: Endpoint = bound
        .bind()
        .await
        .expect("bind the foreign endpoint on the rung");
    let accepting = endpoint.clone();
    let task = tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            if let Ok(connecting) = incoming.accept() {
                let _ = connecting.await;
            }
        }
    });
    (endpoint, task)
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

/// Two members of a fresh loopback mesh, with a foreign endpoint on the rungs of `foreign_rungs`
/// (indexes into the ladder), and whether they met.
async fn meet(foreign_rungs: &[usize]) -> (bool, [u16; 8]) {
    let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
    // iroh tries the addresses of an id in the order of their ports. A ladder whose first two
    // rungs are in that order puts the foreign listener of rung 0 before the rung that the
    // beacon takes (rung 1, the first one that binds), which is the order that fails every dial.
    let (mesh, ladder) = loop {
        let mesh = Mesh::try_new(
            fresh_seed(),
            MeshName::try_new("foreign-rung").expect("a name"),
            config.clone(),
        )
        .expect("a mesh");
        let ladder = mesh.rendezvous_ports();
        if ladder[0] < ladder[1] {
            break (mesh, ladder);
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let mut foreign = Vec::new();
    for &rung in foreign_rungs {
        foreign.push(foreign_on(ladder[rung]).await);
    }

    let open = |nick: &'static str| {
        let options = membership::JoinOptions::default()
            .with_mesh(Some(mesh.to_string()))
            .with_nick(Some(nick.to_owned()));
        async move {
            let (sink, _events) = membership::json_sink();
            membership::join(&options, sink)
                .await
                .expect("open a member")
        }
    };
    let alice = open("alice").await;
    let bob = open("bob").await;

    let started = Instant::now();
    let mut met = false;
    while started.elapsed() < MEET_DEADLINE {
        if roster_len(&alice).await >= 1 && roster_len(&bob).await >= 1 {
            met = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let _ = alice.node.leave().await;
    let _ = bob.node.leave().await;
    for (endpoint, task) in foreign {
        task.abort();
        endpoint.close().await;
    }
    (met, ladder)
}

/// The control: nobody holds a rung.
#[test]
fn two_members_meet_on_a_free_ladder() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (met, ladder) = meet(&[]).await;
        assert!(
            met,
            "the two members never met on the free ladder {ladder:?}"
        );
    });
}

#[test]
fn two_members_meet_when_a_foreign_endpoint_holds_the_first_rung() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (met, ladder) = meet(&[0]).await;
        assert!(
            met,
            "the two members never met with a foreign endpoint on rung 0 of the ladder {ladder:?}"
        );
    });
}
