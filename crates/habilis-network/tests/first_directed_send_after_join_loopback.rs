//! A directed send right after a join is not refused for want of a probe.
//!
//! Alice creates a mesh where the relay is lookup only, and bob joins it. As soon as alice knows
//! bob, she sends him a directed message once. Nothing waits for a probe tick of the alive loop,
//! and the test never retries: the first send is the one that counts. A send that the node held
//! for a direct path that was not yet proven fails the test with its error text.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inspect, Membership, Messaging, Request};
use habilis_network::protocol::{Lookup, Transport};
use tokio::sync::mpsc::UnboundedReceiver;

use habilis_network::net::test_relay;
use tokio::time;

const FORMATION: Duration = Duration::from_mins(1);
/// How long bob may take to receive the message that alice's send accepted.
const ARRIVAL: Duration = Duration::from_secs(10);

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
        let options = membership::JoinOptions::default()
            .nick(Some(nick.to_owned()))
            .lookup(vec![Lookup::Relay]);
        let options = options
            .transport(vec![Transport::Udp])
            .relay_urls(vec![relay.to_string()]);
        Self::open(&options).await
    }

    async fn join(nick: &str, creator: &Self) -> Self {
        let mesh_id = creator.membership.node.mesh_id();
        let mesh = mesh_id.to_string();
        let options = membership::JoinOptions::default()
            .nick(Some(nick.to_owned()))
            .mesh(Some(mesh));
        Self::open(&options).await
    }

    async fn knows(&self, nick: &str) -> bool {
        let json = self
            .membership
            .request(|reply| Request::Inspect(Inspect::Peers { reply }))
            .await
            .unwrap_or_default();
        json.contains(&format!("\"{nick}\""))
    }

    async fn until_knows(&self, nick: &str) {
        let formation_ends = Instant::now() + FORMATION;
        while !self.knows(nick).await {
            assert!(
                Instant::now() < formation_ends,
                "the member did not learn {nick} within {FORMATION:?}"
            );
            time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn send(&self, to: &str, text: &str) -> Result<(), String> {
        let to = membership::parse_to(Some(to)).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Messaging(Messaging::Send { to, body, reply }))
            .await
            .expect("the loop answers")
    }

    /// Whether a directed message with `text` arrives within `ARRIVAL`.
    async fn receives(&mut self, text: &str) -> bool {
        let ends = Instant::now() + ARRIVAL;
        while Instant::now() < ends {
            while let Ok(message) = self.membership.inbound.try_recv() {
                if message.directed && message.text == text {
                    return true;
                }
            }
            time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
}

/// Only the lower id of a pair has a path watcher, so the two directions of one pair differ: the
/// test sends both ways, and one of them is the unwatched direction whatever the ids are.
#[test]
fn the_first_directed_send_of_each_member_after_the_join_is_accepted_and_arrives() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let mut alice = Member::create("alice", &relay).await;
        let mut bob = Member::join("bob", &alice).await;

        alice.until_knows("bob").await;
        bob.until_knows("alice").await;
        // Both sends start before either ends, so neither is sent on a pair that the other
        // send has already warmed: each is a first send on a cold pair.
        let (to_bob, to_alice) =
            tokio::join!(alice.send("bob", "to bob"), bob.send("alice", "to alice"));
        let bob_got = to_bob.is_ok() && bob.receives("to bob").await;
        let alice_got = to_alice.is_ok() && alice.receives("to alice").await;

        let _ = bob.membership.node.leave().await;
        let _ = alice.membership.node.leave().await;

        assert_eq!(
            to_bob,
            Ok(()),
            "the first directed send of alice after the join was refused"
        );
        assert_eq!(
            to_alice,
            Ok(()),
            "the first directed send of bob after the join was refused"
        );
        assert!(
            bob_got,
            "bob did not receive the message that the send accepted"
        );
        assert!(
            alice_got,
            "alice did not receive the message that the send accepted"
        );
    });
}
