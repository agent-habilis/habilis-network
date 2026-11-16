//! The topology snapshot of a real member on a local relay: three members form a full mesh, and
//! the snapshot of one of them names its peers, counts its units against `max_connections`, and
//! carries the multihop graph. The test is `#[ignore]`: it stands up real members, so it runs
//! alone (`cargo test --features iroh-test-utils --test topology_snapshot_loopback --
//! --include-ignored --test-threads=1`).

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::embed::{PathLabel, PeerLink, TopologySnapshot};
use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inspect, Membership, Request};
use habilis_network::net::test_relay;
use habilis_network::protocol::{Lookup, Transport};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time;

const MAX_CONNECTIONS: usize = 16;
const DEADLINE: Duration = Duration::from_mins(2);

struct Member {
    membership: Membership,
    _events: UnboundedReceiver<String>,
}

impl Member {
    async fn open(options: &membership::JoinOptions) -> Self {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(options, sink)
            .await
            .expect("open a member");
        Self {
            membership,
            _events: events,
        }
    }

    async fn create(nick: &str, relay: &RelayUrl) -> Self {
        let base: membership::JoinOptions = membership::JoinOptions::default()
            .nick(Some(nick.to_owned()))
            .lookup(vec![Lookup::Relay]);
        let paths: membership::JoinOptions = base
            .transport(vec![Transport::Udp, Transport::Multihop])
            .relay_urls(vec![relay.to_string()]);
        let options: membership::JoinOptions = paths.max_connections(MAX_CONNECTIONS);
        Self::open(&options).await
    }

    async fn join(nick: &str, creator: &Self) -> Self {
        let mesh = creator.membership.node.mesh_id().to_string();
        let options = membership::JoinOptions::default()
            .nick(Some(nick.to_owned()))
            .mesh(Some(mesh));
        Self::open(&options).await
    }

    async fn roster_len(&self) -> usize {
        let request = self
            .membership
            .request(|reply| Request::Inspect(Inspect::Peers { reply }));
        let json: String = request.await.unwrap_or_default();
        let roster: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
        roster["peers"].as_array().map_or(0, Vec::len)
    }

    async fn snapshot(&self) -> TopologySnapshot {
        let request = self
            .membership
            .request(|reply| Request::Inspect(Inspect::Topology { reply }));
        request.await.expect("the loop answers")
    }
}

async fn rosters_hold(members: &[&Member], peers: usize) -> bool {
    let started = Instant::now();
    loop {
        let mut all = true;
        for member in members {
            all &= member.roster_len().await == peers;
        }
        if all {
            return true;
        }
        if started.elapsed() >= DEADLINE {
            return false;
        }
        time::sleep(Duration::from_millis(500)).await;
    }
}

#[test]
#[ignore = "runs real members; run alone in the host slot"]
fn the_snapshot_of_a_member_names_its_peers_units_cap_and_graph() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let alice = Member::create("alice", &relay).await;
        let bob = Member::join("bob", &alice).await;
        let carol = Member::join("carol", &alice).await;
        assert!(
            rosters_hold(&[&alice, &bob, &carol], 2).await,
            "the three members never formed a mesh"
        );

        // The two links of a full mesh of three come up a moment after the roster.
        let started = Instant::now();
        let snapshot: TopologySnapshot = loop {
            let snapshot: TopologySnapshot = alice.snapshot().await;
            let neighbors: usize = snapshot.peers.iter().filter(|peer| peer.neighbor).count();
            if neighbors == 2 {
                break snapshot;
            }
            assert!(
                started.elapsed() < DEADLINE,
                "alice never linked both peers: {snapshot:?}"
            );
            time::sleep(Duration::from_millis(500)).await;
        };

        assert!(
            !snapshot.self_id.is_empty(),
            "the snapshot names the endpoint of alice"
        );
        assert_eq!(
            snapshot.max_connections, MAX_CONNECTIONS,
            "the snapshot reports the cap that alice was made with"
        );
        assert_eq!(
            snapshot.quic_cap,
            2 * MAX_CONNECTIONS,
            "the total cap of QUIC connections is twice the cap"
        );
        assert_eq!(
            snapshot.peers.len(),
            2,
            "alice holds a link to bob and one to carol: {snapshot:?}"
        );
        assert_eq!(
            snapshot.direct_units, 2,
            "a gossip neighbor is one unit each: {snapshot:?}"
        );
        assert_eq!(snapshot.over_ceiling, 0, "no unit is over the ceiling");
        for nick in ["bob", "carol"] {
            let peer: &PeerLink = snapshot
                .peers
                .iter()
                .find(|peer| peer.nickname.as_deref() == Some(nick))
                .unwrap_or_else(|| panic!("{nick} is not a peer of the snapshot: {snapshot:?}"));
            assert!(peer.neighbor, "{nick} is a gossip neighbor");
            assert!(
                !peer.pinned,
                "{nick} is not pinned: the ceiling is not full"
            );
            assert!(!peer.endpoint.is_empty(), "{nick} has an endpoint id");
            assert_ne!(
                peer.path,
                PathLabel::Multihop,
                "{nick} is reached directly on a full mesh"
            );
            assert!(peer.via.is_none(), "a direct path has no first hop");
        }
        assert!(
            snapshot.graph.is_some(),
            "multihop is on, so the snapshot carries its graph"
        );

        for member in [alice, bob, carol] {
            let _ = member.membership.node.leave().await;
        }
    });
}
