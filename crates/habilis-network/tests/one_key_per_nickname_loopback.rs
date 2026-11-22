//! A nickname is bound to one key on a mesh. A second key under the nickname is not admitted: the two
//! holders do not see the messages of each other, and the node that sees the claim raises one error event.
//!
//! Three members on a local relay and the real transport: alpha creates the mesh as `dup`, beta joins the
//! same mesh as `dup` too (a second key under the nickname), and an observer joins as `samenick-obs`. Neither
//! of the two `dup` members has a runtime base, so no host lock refuses the second one: the gate that
//! this test pins is the one of the engine, between two members of one mesh.
//!
//! A gossip holds no log, and a message that is sent before the links exist is lost. So the observer
//! sends again, up to `ROUNDS` times, until one message reaches both holders: the proof that the mesh is up and that
//! each holder hears the observer. The messages of the two holders must reach nobody under the other
//! one's name.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Membership, Messaging, Request};
use habilis_network::net::test_relay;
use habilis_network::protocol::Lookup;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time;

/// How many times the observer sends, until one message reaches both holders.
const ROUNDS: usize = 6;
/// How long the test waits for a message to come, or for a message that must not come.
const WAIT: Duration = Duration::from_secs(5);

struct Member {
    membership: Membership,
    events: UnboundedReceiver<String>,
    texts: Vec<String>,
    event_lines: Vec<String>,
}

impl Member {
    async fn open(options: &membership::JoinOptions) -> Self {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(options, sink)
            .await
            .expect("open a member");
        Self {
            membership,
            events,
            texts: Vec::new(),
            event_lines: Vec::new(),
        }
    }

    async fn create(nick: &str, relay: &RelayUrl) -> Self {
        let named = membership::JoinOptions::default().nick(Some(nick.to_owned()));
        let options = named
            .lookup(vec![Lookup::Relay])
            .relay_urls(vec![relay.to_string()]);
        Self::open(&options).await
    }

    async fn join(nick: &str, creator: &Self) -> Self {
        let mesh = creator.membership.node.mesh_id().to_string();
        let options = membership::JoinOptions::default()
            .nick(Some(nick.to_owned()))
            .mesh(Some(mesh));
        Self::open(&options).await
    }

    /// A broadcast, which is a `msg` with no addressee.
    async fn broadcast(&self, text: &str) {
        let body = membership::msg_body(text).expect("fits one frame");
        let sent = self
            .membership
            .request(|reply| {
                Request::Messaging(Messaging::Send {
                    to: None,
                    body,
                    reply,
                })
            })
            .await
            .expect("the loop answers");
        sent.expect("the broadcast is sent");
    }

    /// Whether a broadcast with this text has reached this member, and the events that it raised.
    fn saw(&mut self, text: &str) -> bool {
        while let Ok(message) = self.membership.inbound.try_recv() {
            if !message.directed {
                self.texts.push(message.text);
            }
        }
        while let Ok(line) = self.events.try_recv() {
            self.event_lines.push(line);
        }
        self.texts.iter().any(|seen| seen == text)
    }

    async fn leave(self) {
        let _ = self.membership.node.leave().await;
    }
}

/// Whether `text` reaches the member inside `WAIT`.
async fn arrives(member: &mut Member, text: &str) -> bool {
    let started = Instant::now();
    while started.elapsed() < WAIT {
        if member.saw(text) {
            return true;
        }
        time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[test]
fn a_second_key_under_a_nickname_is_not_admitted_and_the_two_holders_do_not_see_each_other() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        habilis_network_test_tracing::allow_warn(
            "habilis_network::lifecycle",
            "our nickname is held by another member",
        );
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let mut alpha = Member::create("dup", &relay).await;
        let mut beta = Member::join("dup", &alpha).await;
        let observer = Member::join("samenick-obs", &alpha).await;

        alpha.broadcast("from-alpha").await;
        beta.broadcast("from-beta").await;
        let mut meshed = false;
        for round in 0..ROUNDS {
            let text = format!("from-observer-{round}");
            observer.broadcast(&text).await;
            let at_alpha = arrives(&mut alpha, &text).await;
            let at_beta = arrives(&mut beta, &text).await;
            if at_alpha && at_beta {
                meshed = true;
                break;
            }
        }
        let beta_saw_alpha = arrives(&mut beta, "from-alpha").await;
        let alpha_saw_beta = arrives(&mut alpha, "from-beta").await;
        // The error event comes from the node that sees the claim of the other key.
        alpha.saw("");
        beta.saw("");
        let lines: Vec<&String> = alpha.event_lines.iter().chain(&beta.event_lines).collect();
        let held_events: usize = lines
            .iter()
            .filter(|line| line.contains("is held by another member"))
            .count();

        alpha.leave().await;
        beta.leave().await;
        observer.leave().await;

        assert!(
            meshed,
            "the observer never reached both holders in {ROUNDS} rounds: the mesh does not work at all"
        );
        assert!(
            !beta_saw_alpha,
            "the gate admitted a second key under the nickname: beta got from-alpha"
        );
        assert!(
            !alpha_saw_beta,
            "the gate admitted a second key under the nickname: alpha got from-beta"
        );
        assert!(
            held_events >= 1,
            "no member raised the nickname held event: {held_events}"
        );
    });
}
