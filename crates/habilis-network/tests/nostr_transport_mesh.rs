//! Two members of a mesh that lists the Nostr transport, with no other path between them, exchange
//! a message over Nostr. The same mesh without the transport never forms a Nostr path.
//!
//! Three real members on a local iroh relay and a local Nostr relay, with the transport list
//! `udp,relay,nostr`. Carol keeps both of the others linked, so that the mesh stands while alice
//! and bob lose IP and the relay to each other. The cut comes first and the pooled connection is
//! dialed again after it, so that the first dial of the pair rides Nostr: a connection that stood
//! on a path before a cut keeps it selected.
//!
//! Run with `cargo test -p habilis-network --test nostr_transport_mesh`.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

mod until_known;

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{
    self, Blocking, Inbound, Inspect, InspectTest, Linking, Membership, Messaging, Request, Rung,
};
use habilis_network::net;
use habilis_network::protocol::{Lookup, Transport};
use habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time;

const STEP_DEADLINE: Duration = Duration::from_mins(2);
const PAYLOAD_DEADLINE: Duration = Duration::from_secs(30);

struct Member {
    membership: Membership,
    _events: UnboundedReceiver<String>,
    seen_msgs: Vec<Inbound>,
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
            seen_msgs: Vec::new(),
        }
    }

    async fn create(
        nick: &str,
        relay: &RelayUrl,
        nostr: &TestRelay,
        transport: Vec<Transport>,
    ) -> Self {
        let options = membership::JoinOptions::default()
            .nick(Some(nick.to_owned()))
            .lookup(vec![Lookup::Relay, Lookup::Nostr]);
        let relay_url = relay.to_string();
        let nostr_url = nostr.url().to_string();
        let options = options.transport(transport);
        let options = options.relay_urls(vec![relay_url]);
        let options = options.nostr_urls(vec![nostr_url]);
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
            .request(|reply| Request::Inspect(Inspect::Peers { reply }))
            .await
            .unwrap_or_default();
        let roster: Option<serde_json::Value> = serde_json::from_str(&json).ok();
        roster
            .and_then(|roster| roster["peers"].as_array().map(Vec::len))
            .unwrap_or(0)
    }

    fn ports(&self) -> Vec<u16> {
        self.membership.node.bound_ports().to_vec()
    }

    async fn block_ip_to(&self, ports: Vec<u16>) {
        self.membership
            .request(|reply| {
                Request::Blocking(Blocking::BlockIpTo {
                    remote_ports: ports,
                    reply,
                })
            })
            .await
            .expect("the loop answers");
    }

    async fn block_rung(&self, rung: Rung) {
        self.membership
            .request(|reply| {
                Request::Blocking(Blocking::BlockRung {
                    rung,
                    blocked: true,
                    reply,
                })
            })
            .await
            .expect("the loop answers");
    }

    async fn block_rung_to(&self, rung: Rung, peer: &str) {
        until_known::until_peer_known(&self.membership, peer, |reply| {
            Request::Blocking(Blocking::BlockRungTo {
                rung,
                peer: peer.to_owned(),
                blocked: true,
                reply,
            })
        })
        .await;
    }

    /// Lift every block of IP and of the relay rung to `peer`, as a repaired network does.
    async fn lift_cut(&self, peer: &str) {
        self.block_ip_to(Vec::new()).await;
        until_known::until_peer_known(&self.membership, peer, |reply| {
            Request::Blocking(Blocking::BlockRungTo {
                rung: Rung::Relay,
                peer: peer.to_owned(),
                blocked: false,
                reply,
            })
        })
        .await;
    }

    /// Close the gossip link to `peer`, as the loss of its path does: the pair is unlinked, and the
    /// alive tick probes it again for a direct path.
    async fn close_link(&self, peer: &str) {
        self.membership
            .request(|reply| {
                Request::Linking(Linking::CloseLink {
                    peer: peer.to_owned(),
                    reply,
                })
            })
            .await
            .expect("the loop answers")
            .expect("the peer is known");
    }

    /// Drop the pooled connection to `peer`: the next read or send dials a new one, under the
    /// blocks that stand now.
    async fn forget_connection(&self, peer: &str) {
        let answer = self
            .membership
            .request(|reply| {
                Request::Linking(Linking::ForgetUnicast {
                    peer: peer.to_owned(),
                    reply,
                })
            })
            .await
            .expect("the loop answers");
        answer.expect("the peer is known");
    }

    async fn rung_to(&self, peer: &str) -> Option<&'static str> {
        self.membership
            .request(|reply| {
                Request::InspectTest(InspectTest::SelectedRung {
                    peer: peer.to_owned(),
                    reply,
                })
            })
            .await
            .ok()
            .flatten()
    }

    async fn expect_rung(&self, peer: &str, expected: &str, step: &str) {
        let started = Instant::now();
        let mut seen = None;
        while started.elapsed() < STEP_DEADLINE {
            seen = self.rung_to(peer).await;
            if seen == Some(expected) {
                return;
            }
            time::sleep(Duration::from_millis(500)).await;
        }
        panic!("{step}: expected the rung {expected}, the last rung read was {seen:?}");
    }

    /// Wait for the rung, and dial the pair again every 10 s while it reads otherwise: a new
    /// connection races its paths again, and the Nostr address of a dial opens a path only if IP
    /// has not been selected yet. A real outage leaves no IP path to win that race.
    async fn expect_rung_redialing(&self, peer: &str, expected: &str, step: &str) {
        let started = Instant::now();
        let mut redialed = Instant::now();
        let mut seen = None;
        while started.elapsed() < STEP_DEADLINE {
            seen = self.rung_to(peer).await;
            if seen == Some(expected) {
                return;
            }
            if redialed.elapsed() >= Duration::from_secs(10) {
                self.forget_connection(peer).await;
                redialed = Instant::now();
            }
            time::sleep(Duration::from_millis(500)).await;
        }
        panic!("{step}: expected the rung {expected}, the last rung read was {seen:?}");
    }

    async fn send(&self, to: &str, text: &str) -> Result<(), String> {
        let to = membership::parse_to(Some(to)).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Messaging(Messaging::Send { to, body, reply }))
            .await
            .expect("the loop answers")
    }

    /// Send until the engine takes the message. A directed frame to a pair whose probe has not
    /// found a direct path yet is held, and the refusal says to retry: the alive tick probes the
    /// pair again and records the verdict, so the wait is on that verdict and not on a clock.
    async fn send_when_proven(&self, to: &str, text: &str) {
        let started = Instant::now();
        loop {
            match self.send(to, text).await {
                Ok(()) => return,
                Err(error) if error.contains("retry the send later") => {
                    assert!(
                        started.elapsed() < STEP_DEADLINE,
                        "the pair was never proven for payload: {error}"
                    );
                    time::sleep(Duration::from_secs(2)).await;
                }
                Err(error) => panic!("the send over Nostr was refused: {error}"),
            }
        }
    }

    fn saw_msg(&mut self, text: &str) -> bool {
        while let Ok(message) = self.membership.inbound.try_recv() {
            self.seen_msgs.push(message);
        }
        self.seen_msgs
            .iter()
            .any(|message| message.directed && message.text == text)
    }
}

async fn all_know_each_other(members: &[&Member], deadline: Duration) -> bool {
    let started = Instant::now();
    loop {
        let mut all = true;
        for member in members {
            all &= member.roster_len().await == members.len() - 1;
        }
        if all {
            return true;
        }
        if started.elapsed() >= deadline {
            return false;
        }
        time::sleep(Duration::from_millis(500)).await;
    }
}

/// Cut alice and bob from each other on IP and on the relay, and drop their pooled connections.
async fn cut(alice: &Member, bob: &Member) {
    alice.block_ip_to(bob.ports()).await;
    bob.block_ip_to(alice.ports()).await;
    alice.block_rung_to(Rung::Relay, "bob").await;
    bob.block_rung_to(Rung::Relay, "alice").await;
    alice.close_link("bob").await;
    bob.close_link("alice").await;
    alice.forget_connection("bob").await;
    bob.forget_connection("alice").await;
}

/// The cut of a mesh on the default list: no direct path between alice and bob on any rung but
/// Nostr. The relay is lookup only there, so the relay path that iroh keeps carries no payload.
async fn cut_every_rung(alice: &Member, bob: &Member) {
    for rung in [Rung::WebRtc, Rung::Multihop, Rung::Gossip] {
        alice.block_rung(rung).await;
        bob.block_rung(rung).await;
    }
    cut(alice, bob).await;
}

/// The same cut with the relay left alone: only IP, the data channel, multihop and gossip are
/// cut between alice and bob. The iroh relay stays reachable and iroh keeps its path.
async fn cut_every_direct_rung(alice: &Member, bob: &Member) {
    for rung in [Rung::WebRtc, Rung::Multihop, Rung::Gossip] {
        alice.block_rung(rung).await;
        bob.block_rung(rung).await;
    }
    alice.block_ip_to(bob.ports()).await;
    bob.block_ip_to(alice.ports()).await;
    alice.close_link("bob").await;
    bob.close_link("alice").await;
    alice.forget_connection("bob").await;
    bob.forget_connection("alice").await;
}

/// The usual production case: the relay is for lookup alone and it stays reachable. A pair with no
/// direct path would select the relay path, which carries no payload on such a mesh, and the send
/// would be held. The selector ranks Nostr above the relay there, so the pair selects Nostr.
#[test]
fn a_pair_selects_nostr_over_a_reachable_lookup_only_relay() {
    let guard = habilis_network_test_tracing::init();
    guard.allow_warn(
        "iroh::socket::transports::relay::actor",
        "Lost connection to relay server",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = net::test_relay::spawn_plain().await.expect("local relay");
        let nostr = TestRelay::spawn().await.expect("local Nostr relay");
        let list = vec![
            Transport::Udp,
            Transport::WebRtc,
            Transport::Multihop,
            Transport::Gossip,
            Transport::Nostr,
        ];
        let alice = Member::create("alice", &relay, &nostr, list).await;
        let mut bob = Member::join("bob", &alice).await;
        let carol = Member::join("carol", &alice).await;
        assert!(
            all_know_each_other(&[&alice, &bob, &carol], Duration::from_mins(1)).await,
            "the three members never formed a mesh"
        );

        cut_every_direct_rung(&alice, &bob).await;
        alice
            .expect_rung_redialing(
                "bob",
                "nostr",
                "only the direct rungs cut between alice and bob",
            )
            .await;
        let before = nostr.data_events();

        let text = "over nostr, relay reachable";
        alice.send_when_proven("bob", text).await;
        let started = Instant::now();
        while !bob.saw_msg(text) {
            assert!(
                started.elapsed() < PAYLOAD_DEADLINE,
                "the message never reached bob over Nostr"
            );
            time::sleep(Duration::from_millis(250)).await;
        }
        assert!(
            nostr.data_events() > before,
            "the datagrams of the message went through the Nostr relay as data events"
        );

        for member in [alice, bob, carol] {
            let _ = member.membership.node.leave().await;
        }
    });
}

/// The default option-A mesh: the default list plus Nostr, no relay transport, the relay for
/// lookup alone. A pair that has only Nostr must still carry a directed message, which the
/// direct-path gates of a lookup-only relay refuse unless they count a Nostr path.
#[test]
fn a_pair_on_the_default_list_plus_nostr_exchanges_a_message_over_nostr() {
    let guard = habilis_network_test_tracing::init();
    // The relay is blocked for this pair, and the wait below is long: iroh reports the lost relay
    // connection of the endpoint.
    guard.allow_warn(
        "iroh::socket::transports::relay::actor",
        "Lost connection to relay server",
    );
    // Every address of the pair is taken from iroh for a moment, until the Nostr address opens a
    // path.
    guard.allow_warn(
        "iroh::socket::remote_map::remote_state",
        "No paths to remote endpoint known",
    );
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = net::test_relay::spawn_plain().await.expect("local relay");
        let nostr = TestRelay::spawn().await.expect("local Nostr relay");
        let list = vec![
            Transport::Udp,
            Transport::WebRtc,
            Transport::Multihop,
            Transport::Gossip,
            Transport::Nostr,
        ];
        let alice = Member::create("alice", &relay, &nostr, list).await;
        let mut bob = Member::join("bob", &alice).await;
        let carol = Member::join("carol", &alice).await;
        assert!(
            all_know_each_other(&[&alice, &bob, &carol], Duration::from_mins(1)).await,
            "the three members never formed a mesh"
        );

        cut_every_rung(&alice, &bob).await;
        alice
            .expect_rung(
                "bob",
                "nostr",
                "every rung but Nostr cut between alice and bob",
            )
            .await;
        let before = nostr.data_events();

        let text = "default list over nostr";
        alice.send_when_proven("bob", text).await;
        let started = Instant::now();
        while !bob.saw_msg(text) {
            assert!(
                started.elapsed() < PAYLOAD_DEADLINE,
                "the message never reached bob over Nostr"
            );
            time::sleep(Duration::from_millis(250)).await;
        }
        assert!(
            nostr.data_events() > before,
            "the datagrams of the message went through the Nostr relay as data events"
        );

        for member in [alice, bob, carol] {
            let _ = member.membership.node.leave().await;
        }
    });
}

#[test]
fn two_members_with_no_other_path_exchange_a_message_over_nostr() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = net::test_relay::spawn_plain().await.expect("local relay");
        let nostr = TestRelay::spawn().await.expect("local Nostr relay");
        let list = vec![Transport::Udp, Transport::Relay, Transport::Nostr];
        let alice = Member::create("alice", &relay, &nostr, list).await;
        let mut bob = Member::join("bob", &alice).await;
        let carol = Member::join("carol", &alice).await;
        assert!(
            all_know_each_other(&[&alice, &bob, &carol], Duration::from_mins(1)).await,
            "the three members never formed a mesh"
        );

        cut(&alice, &bob).await;
        alice
            .expect_rung_redialing("bob", "nostr", "IP and the relay cut between alice and bob")
            .await;
        let before = nostr.data_events();

        let text = "over nostr";
        alice.send_when_proven("bob", text).await;
        let started = Instant::now();
        while !bob.saw_msg(text) {
            assert!(
                started.elapsed() < PAYLOAD_DEADLINE,
                "the message never reached bob over Nostr"
            );
            time::sleep(Duration::from_millis(250)).await;
        }
        assert!(
            nostr.data_events() > before,
            "the datagrams of the message went through the Nostr relay as data events"
        );

        // The network is repaired: IP and the relay return. The test shows that a new dial selects IP; a
        // connection that stands on Nostr does not move back by itself before it ends.
        alice.lift_cut("bob").await;
        bob.lift_cut("alice").await;
        alice.forget_connection("bob").await;
        alice
            .expect_rung_redialing("bob", "ip", "a new dial after IP and the relay returned")
            .await;

        for member in [alice, bob, carol] {
            let _ = member.membership.node.leave().await;
        }
    });
}

#[test]
fn a_mesh_that_does_not_list_nostr_never_forms_a_nostr_path() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = net::test_relay::spawn_plain().await.expect("local relay");
        // The Nostr relays are the lookup, and the list names no Nostr transport.
        let nostr = TestRelay::spawn().await.expect("local Nostr relay");
        let list = vec![Transport::Udp, Transport::Relay];
        let alice = Member::create("alice", &relay, &nostr, list).await;
        let bob = Member::join("bob", &alice).await;
        let carol = Member::join("carol", &alice).await;
        assert!(
            all_know_each_other(&[&alice, &bob, &carol], Duration::from_mins(1)).await,
            "the three members never formed a mesh"
        );

        cut(&alice, &bob).await;
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(10) {
            assert_ne!(
                alice.rung_to("bob").await,
                Some("nostr"),
                "a mesh that does not list Nostr never selects it"
            );
            time::sleep(Duration::from_millis(500)).await;
        }

        for member in [alice, bob, carol] {
            let _ = member.membership.node.leave().await;
        }
    });
}
