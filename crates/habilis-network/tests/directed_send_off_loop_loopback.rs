//! A directed send that waits on a dial does not stop the node.
//!
//! The daemon runs one `select!`. A directed send to a member with no pooled connection dials it,
//! then waits for a direct path, and while the loop awaits that, no other request of the node is
//! served. The test cuts IP from alice to bob, so that the cold dial has no direct path to wait
//! for, sends a directed message, and asks alice a local question while the send is still waiting.
//! The ordering is the assertion: alice answers the local question before the send gives up.
//! A clock ceiling alone would pass on a fast host, so the send must take longer than the local
//! answer by a wide margin, and the test says so when it did not.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Membership, Request};
use habilis_network::protocol::{Lookup, Transport};
use tokio::sync::mpsc::UnboundedReceiver;

use habilis_network::net::test_relay;
const FORMATION: Duration = Duration::from_mins(1);
/// The local request goes out this long after the send, so that the send is already in the loop.
const ASK_AFTER: Duration = Duration::from_millis(200);
/// A local answer later than this, after the ask, is a stall whatever the send does.
const LOCAL_CEILING: Duration = Duration::from_secs(2);
/// The send must wait at least this long, or the test did not make the loop wait and proves nothing.
const PREMISE: Duration = Duration::from_secs(1);
/// How many times alice is asked to forget the connection of bob before the send. A probe of the
/// direct path can pool one again, so one forget is not enough; the answer `false` says there is none.
const FORGET_TRIES: usize = 20;
/// How long iroh may take to re-run path selection after the block. It reads the path list on its
/// path-stat updates, which come within a few seconds.
const BLOCK_TAKES_EFFECT: Duration = Duration::from_secs(30);

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
        Self::open(
            &membership::Opts::default()
                .with_nick(Some(nick.to_owned()))
                .with_lookup(vec![Lookup::Relay])
                .with_transport(vec![Transport::Udp])
                .with_relay_urls(vec![relay.to_string()]),
        )
        .await
    }

    async fn join(nick: &str, creator: &Self) -> Self {
        Self::open(
            &membership::Opts::default()
                .with_nick(Some(nick.to_owned()))
                .with_mesh(Some(creator.membership.node.mesh_id().to_string())),
        )
        .await
    }

    async fn knows(&self, nick: &str) -> bool {
        let json = self
            .membership
            .request(|reply| Request::Peers { reply })
            .await
            .unwrap_or_default();
        json.contains(&format!("\"{nick}\""))
    }

    async fn block_ip_to(&self, ports: Vec<u16>) {
        self.membership
            .request(|reply| Request::BlockIpTo {
                remote_ports: ports,
                reply,
            })
            .await
            .expect("the loop answers");
    }

    /// A directed send that never takes the warm fast path: see [`Request::SendCold`].
    async fn send_cold(&self, to: &str, text: &str) -> Result<(), String> {
        let to = membership::parse_to(Some(to)).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::SendCold { to, body, reply })
            .await
            .expect("the loop answers")
    }

    /// The rung of the selected path on the connection of alice to `peer`: `ip`, `relay`, and so
    /// on. `None` while no path is selected.
    async fn selected_rung(&self, peer: &str) -> Option<&'static str> {
        self.membership
            .request(|reply| Request::SelectedRung {
                peer: peer.to_owned(),
                reply,
            })
            .await
            .expect("the loop answers")
    }

    /// Whether a unicast connection to `peer` was pooled, and is forgotten now.
    async fn forget_unicast(&self, peer: &str) -> bool {
        self.membership
            .request(|reply| Request::ForgetUnicast {
                peer: peer.to_owned(),
                reply,
            })
            .await
            .expect("the loop answers")
            .expect("alice knows bob")
    }

    async fn message_log_len(&self) -> usize {
        self.membership
            .request(|reply| Request::MessageLogLen { reply })
            .await
            .expect("the loop answers")
    }
}

#[test]
fn a_directed_send_that_waits_on_a_dial_does_not_stop_the_node() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let alice = Member::create("alice", &relay).await;
        let bob = Member::join("bob", &alice).await;

        let formation_ends = Instant::now() + FORMATION;
        while !alice.knows("bob").await {
            assert!(
                Instant::now() < formation_ends,
                "alice did not learn bob within {FORMATION:?}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        alice
            .block_ip_to(bob.membership.node.bound_ports().to_vec())
            .await;
        // `BlockIpTo` returns before iroh has re-run path selection, and a connection that is opened
        // before it does rides the IP path that iroh still holds. Wait until the path to bob has left
        // UDP, so that a new connection to bob finds no direct path.
        let block_ends = Instant::now() + BLOCK_TAKES_EFFECT;
        while alice.selected_rung("bob").await != Some("relay") {
            assert!(
                Instant::now() < block_ends,
                "the path of alice to bob did not leave UDP within {BLOCK_TAKES_EFFECT:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Forget the connection to bob, so that the send dials in the common case. A probe of the direct
        // path can still pool one again before the send, so the send is `SendCold`: it never takes the
        // warm fast path, and its wait does not depend on this race.
        for _ in 0..FORGET_TRIES {
            if !alice.forget_unicast("bob").await {
                break;
            }
        }

        let started = Instant::now();
        let send = async {
            let verdict = alice.send_cold("bob", "hello").await;
            (verdict, started.elapsed())
        };
        let local = async {
            tokio::time::sleep(ASK_AFTER).await;
            let _ = alice.message_log_len().await;
            started.elapsed()
        };
        let ((verdict, send_done), local_done) = tokio::join!(send, local);

        let _ = bob.membership.node.leave().await;
        let _ = alice.membership.node.leave().await;

        assert!(
            send_done >= PREMISE,
            "the send took {send_done:?} and returned {verdict:?}: it did not wait on a dial, so this run proves nothing"
        );
        assert!(
            verdict.is_err(),
            "a directed send with no direct path must still tell the sender it was refused"
        );
        assert!(
            local_done < send_done,
            "alice answered the local request at {local_done:?}, after the send gave up at \
         {send_done:?}: the loop served nothing while it waited on the dial"
        );
        assert!(
            local_done < ASK_AFTER + LOCAL_CEILING,
            "alice answered the local request at {local_done:?}, more than {LOCAL_CEILING:?} after it was asked"
        );
    });
}
