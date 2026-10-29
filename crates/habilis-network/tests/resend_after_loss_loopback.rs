//! A message that the gossip layer delivered but the app never read still reaches the app.
//!
//! The gossip layer drops a message id it has already seen for 90 s, so an anti-entropy resend
//! of the same bytes cannot repair what the app missed. The case here: the topic is swapped
//! while the old subscription holds queued messages (the heal tick resubscribes, and the old
//! queue must reach the app before it is dropped). `resend_dedup_loopback.rs` holds the other.
//!
//! Two members on a local relay, the default transport list.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inbound, Membership, Request};
use habilis_network::protocol::Lookup;
use tokio::sync::mpsc::UnboundedReceiver;

use habilis_network::net::test_relay;
/// One heal tick (15 s) to resubscribe, the re-graft, and an anti-entropy cycle, with margin.
/// Less than the 90 s dedup of the gossip layer: a message that waits for the dedup is a failure.
const RECOVERY: Duration = Duration::from_secs(75);
const FORMATION: Duration = Duration::from_mins(1);
const LIVE: Duration = Duration::from_secs(20);

/// The lines that say how the swap and the repair went.
fn trace() -> String {
    let text = habilis_network_test_tracing::captured_logs();
    let lines: Vec<_> = text
        .lines()
        .filter(|line| {
            [
                "restored",
                "drained",
                "anti-entropy",
                "dropped",
                "failed to parse",
            ]
            .iter()
            .any(|needle| line.contains(needle))
        })
        .collect();
    lines.join("\n")
}

struct Member {
    membership: Membership,
    _events: UnboundedReceiver<String>,
    seen: Vec<Inbound>,
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
            seen: Vec::new(),
        }
    }

    async fn create(nick: &str, relay: &RelayUrl) -> Self {
        let options = membership::JoinOptions::default()
            .nick(Some(nick.to_owned()))
            .lookup(vec![Lookup::Relay]);
        let options = options.relay_urls(vec![relay.to_string()]);
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
        let json = self
            .membership
            .request(|reply| Request::Peers { reply })
            .await
            .unwrap_or_default();
        let roster = serde_json::from_str::<serde_json::Value>(&json).ok();
        roster
            .and_then(|roster| roster["peers"].as_array().map(Vec::len))
            .unwrap_or(0)
    }

    async fn send(&self, text: &str) {
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Send {
                to: None,
                body,
                reply,
            })
            .await
            .expect("the loop answers")
            .expect("sent");
    }

    async fn sever_gossip(&self) {
        self.membership
            .request(|reply| Request::SeverGossip { reply })
            .await
            .expect("the loop answers");
    }

    fn saw(&mut self, text: &str) -> bool {
        while let Ok(message) = self.membership.inbound.try_recv() {
            self.seen.push(message);
        }
        self.seen
            .iter()
            .any(|message| !message.directed && message.text == text)
    }

    /// Wait until `text` has reached the app, or the deadline passes. The wait of the test is
    /// the time of the repair, in seconds, so the numbers are in the output of a green run too.
    async fn waits_for(&mut self, text: &str, deadline: Duration) -> Option<Duration> {
        let started = Instant::now();
        while started.elapsed() < deadline {
            if self.saw(text) {
                return Some(started.elapsed());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        self.saw(text).then(|| started.elapsed())
    }
}

async fn meshed_pair(relay: &RelayUrl) -> (Member, Member) {
    let alice = Member::create("alice", relay).await;
    let bob = Member::join("bob", &alice).await;
    let started = Instant::now();
    while alice.roster_len().await != 1 || bob.roster_len().await != 1 {
        assert!(
            started.elapsed() < FORMATION,
            "the pair never met\n{}",
            trace()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    (alice, bob)
}

/// A message sent while the topic of the receiver is severed waits in the queue of the old
/// subscription. The swap must hand it to the app before the queue is dropped: the gossip layer
/// counted it as delivered, so neither the overlay nor an anti-entropy resend of the same bytes
/// brings it again inside the 90 s dedup.
#[test]
fn a_message_that_waited_in_the_old_subscription_reaches_the_app_after_the_swap() {
    let guard = habilis_network_test_tracing::init_capturing(
        "habilis_network=info,habilis_network::gossip=debug",
    );
    guard.expect_warn(
        "habilis_network::gossip",
        "gossip stream restored (resubscribed)",
    );
    guard.expect_warn(
        "habilis_network::gossip",
        "mesh starvation: no inbound traffic",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let (alice, mut bob) = meshed_pair(&relay).await;

        bob.sever_gossip().await;
        alice.send("during-outage").await;

        let after = bob.waits_for("during-outage", RECOVERY).await;
        eprintln!("the message reached the app after: {after:?}");
        assert!(
            after.is_some(),
            "a message sent during the outage never reached the app inside {RECOVERY:?}\n{}",
            trace()
        );
        alice.send("after-recovery").await;
        assert!(
            bob.waits_for("after-recovery", LIVE).await.is_some(),
            "live traffic does not flow after the swap\n{}",
            trace()
        );
        for member in [alice, bob] {
            let _ = member.membership.node.leave().await;
        }
    });
}
