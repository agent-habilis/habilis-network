//! With the list `udp` alone and the minimum cap of 8, a directed message that a send reported as
//! sent arrives.
//!
//! Fifteen native members on a local relay (the relay is a lookup only). Each has a cap of 8, so
//! each holds 8 of the 14 others as gossip neighbors, and a directed send to any of the 6 others
//! needs a dial at the ceiling. With ten members only one member is outside the view of each node,
//! and a node whose ceiling is full of gossip neighbors has no connection to evict for it.
//! There is no multihop route, so the dial is direct and evicts a connection. Each ordered pair
//! sends one message, with no retry. A send that answers `Ok` and a message that never arrives is
//! a silent loss, and the test names each one.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use futures_util::future;
use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inbound, Inspect, Membership, Messaging, Request};
use habilis_network::net;
use habilis_network::net::Bind;
use habilis_network::protocol::{Lookup, Transport};
use habilis_network::util::tuning::MIN_MAX_CONNECTIONS;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time;

const CAP: usize = MIN_MAX_CONNECTIONS;
const NICKS: [&str; 15] = [
    "ann", "ben", "cat", "dan", "eve", "fay", "gus", "hal", "ivy", "jon", "kim", "lee", "max",
    "ned", "oli",
];
const MESH_DEADLINE: Duration = Duration::from_mins(1);
/// How long the receivers get, after the last send, to read the messages.
const ARRIVAL_WINDOW: Duration = Duration::from_secs(20);
const EVICTION_LINE: &str = "evicting a direct connection at the ceiling";

struct Member {
    nick: &'static str,
    membership: Membership,
    _events: UnboundedReceiver<String>,
    seen: Vec<Inbound>,
}

impl Member {
    async fn open(nick: &'static str, options: &membership::JoinOptions) -> Self {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(options, sink)
            .await
            .expect("open a member");
        Self {
            nick,
            membership,
            _events: events,
            seen: Vec::new(),
        }
    }

    async fn create(nick: &'static str, relay: &RelayUrl) -> Self {
        let named = membership::JoinOptions::default()
            .bind(Bind::Loopback)
            .nick(Some(nick.to_owned()));
        let found = named.lookup(vec![Lookup::Relay]);
        let options: membership::JoinOptions = found
            .transport(vec![Transport::Udp])
            .relay_urls(vec![relay.to_string()])
            .max_connections(CAP);
        Self::open(nick, &options).await
    }

    async fn join(nick: &'static str, creator: &Self, relay: &RelayUrl) -> Self {
        let mesh = creator.membership.node.mesh_id().to_string();
        let named = membership::JoinOptions::default()
            .bind(Bind::Loopback)
            .nick(Some(nick.to_owned()));
        let joined = named.mesh(Some(mesh));
        let options: membership::JoinOptions = joined
            .transport(vec![Transport::Udp])
            .relay_urls(vec![relay.to_string()])
            .max_connections(CAP);
        Self::open(nick, &options).await
    }

    async fn roster_len(&self) -> usize {
        let json = self
            .membership
            .request(|reply| Request::Inspect(Inspect::Peers { reply }))
            .await
            .unwrap_or_default();
        let roster: Option<serde_json::Value> = serde_json::from_str(&json).ok();
        roster
            .and_then(|roster| roster["peers"].as_array().map(Vec::len))
            .unwrap_or(0)
    }

    async fn send(&self, to: &str, text: &str) -> Result<(), String> {
        let to = membership::parse_to(Some(to)).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Messaging(Messaging::Send { to, body, reply }))
            .await
            .expect("the loop answers")
    }

    fn drain(&mut self) {
        while let Ok(message) = self.membership.inbound.try_recv() {
            self.seen.push(message);
        }
    }

    fn saw(&self, text: &str) -> bool {
        self.seen
            .iter()
            .any(|message| message.directed && message.text == text)
    }
}

fn text_of(from: &str, to: &str) -> String {
    format!("{from} to {to}")
}

#[test]
fn a_directed_send_at_the_cap_on_udp_alone_that_answers_ok_arrives() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network::transport=info");
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        // Open fault, not this test's subject: the relay reports that another endpoint connected
        // with the same endpoint id. Measured once, with 10 members on one relay at a cap of 2:
        // about 3 of 4 runs, with and without the acknowledgement of a unicast frame. It is not
        // measured again with 15 members at a cap of 8: this allow hides it from the 5 runs of the
        // move, so they cannot count it.
        habilis_network_test_tracing::allow_warn(
            "iroh::socket::transports::relay::actor",
            "Another endpoint connected with the same endpoint id",
        );
        let (relay, _server) = net::test_relay::spawn_plain().await.expect("local relay");
        let mut members: Vec<Member> = vec![Member::create(NICKS[0], &relay).await];
        for nick in &NICKS[1..] {
            let member = Member::join(nick, &members[0], &relay).await;
            members.push(member);
        }
        let started = Instant::now();
        loop {
            let mut all = true;
            for member in &members {
                all &= member.roster_len().await == NICKS.len() - 1;
            }
            if all {
                break;
            }
            assert!(
                started.elapsed() < MESH_DEADLINE,
                "the fifteen members never formed a mesh"
            );
            time::sleep(Duration::from_millis(500)).await;
        }

        // One send for each ordered pair, no retry. The answer of each send is kept.
        // All the sends of one sender go at once: a send to a member outside the view needs a
        // dial at the ceiling.
        let mut answers: Vec<(&str, &str, Result<(), String>)> = Vec::new();
        for from in &members {
            let sends = members
                .iter()
                .filter(|to| to.nick != from.nick)
                .map(|to| async move {
                    let text = text_of(from.nick, to.nick);
                    (from.nick, to.nick, from.send(to.nick, &text).await)
                });
            answers.extend(future::join_all(sends).await);
        }
        time::sleep(ARRIVAL_WINDOW).await;
        for member in &mut members {
            member.drain();
        }

        let mut silent: Vec<String> = Vec::new();
        let mut refused: Vec<String> = Vec::new();
        for (from, to, answer) in &answers {
            let receiver = members
                .iter()
                .find(|member| member.nick == *to)
                .expect("a member");
            let arrived = receiver.saw(&text_of(from, to));
            match answer {
                Ok(()) if !arrived => silent.push(format!("{from} -> {to}")),
                Err(error) => refused.push(format!("{from} -> {to}: {error}")),
                Ok(()) => {}
            }
        }
        let logs = habilis_network_test_tracing::captured_logs();
        let eviction_lines = logs.lines().filter(|line| line.contains(EVICTION_LINE));
        let evictions: usize = eviction_lines.count();
        assert!(
            evictions > 0,
            "the premise: the dials at the ceiling evicted nothing"
        );
        let (never_arrived, answered, errored) = (silent.len(), answers.len(), refused.len());
        let silent_list = silent.join(", ");
        let errors = refused.join(" | ");
        assert!(
            silent.is_empty(),
            "{never_arrived} of {answered} sends answered ok and never arrived ({errored} answered an error, \
             {evictions} evictions at the ceiling): {silent_list}\nerrors: {errors}"
        );

        for member in members {
            let _ = member.membership.node.leave().await;
        }
    });
}
