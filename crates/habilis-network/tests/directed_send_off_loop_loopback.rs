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
use habilis_network::membership::{
    self, Blocking, Inspect, InspectTest, Linking, Membership, Messaging, MessagingTest, Request,
};
use habilis_network::protocol::{Lookup, Transport};
use tokio::sync::mpsc::UnboundedReceiver;

use habilis_network::net::test_relay;
use tokio::time;
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
/// The send of the warm test must still wait this long after it started, or it was refused before the wait.
const WAIT_PREMISE: Duration = Duration::from_millis(500);
/// The path-select budget of a send (5 s) and a margin.
const PATH_BUDGET: Duration = Duration::from_secs(8);
/// A send that must fail on the relay refusal ends within this: the path budget (5 s) and a margin.
const SAFETY_BUDGET: Duration = Duration::from_secs(6);
/// The end of the refusal of a held send, which the caller can retry.
const HELD_TEXT: &str = "retry the send later";
/// The cooldown text of the pool (`COOLDOWN_REFUSED`), which is not public.
const COOLDOWN_TEXT: &str = "unicast dial on cooldown after a recent failure";
/// The relay refusal of the pool (`RELAY_REFUSED`), which is not public.
const RELAY_TEXT: &str = "the relay is lookup only on this mesh";

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
        let mesh = creator.membership.node.mesh_id().to_string();
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
            time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Cut IP from this member to `peer`, and wait until the selected path to it is the relay.
    async fn cut_ip_to(&self, nick: &str, peer: &Self) {
        self.block_ip_to(peer.membership.node.bound_ports().to_vec())
            .await;
        // `BlockIpTo` returns before iroh has re-run path selection, and a connection that is opened
        // before it does rides the IP path that iroh still holds. Wait until the path to the peer has
        // left UDP, so that a connection to it reads relay.
        let block_ends = Instant::now() + BLOCK_TAKES_EFFECT;
        while self.selected_rung(nick).await != Some("relay") {
            assert!(
                Instant::now() < block_ends,
                "the path to {nick} did not leave UDP within {BLOCK_TAKES_EFFECT:?}"
            );
            time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// A directed send over the normal path, the warm fast path included.
    async fn send(&self, to: &str, text: &str) -> Result<(), String> {
        let to = membership::parse_to(Some(to)).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Messaging(Messaging::Send { to, body, reply }))
            .await
            .expect("the loop answers")
    }

    /// The texts of the directed messages that arrived since the last call.
    fn arrived(&mut self) -> Vec<String> {
        let mut texts = Vec::new();
        while let Ok(message) = self.membership.inbound.try_recv() {
            if message.directed {
                texts.push(message.text);
            }
        }
        texts
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

    /// A directed send that never takes the warm fast path: see [`MessagingTest::SendCold`].
    async fn send_cold(&self, to: &str, text: &str) -> Result<(), String> {
        let to = membership::parse_to(Some(to)).expect("a nickname");
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::MessagingTest(MessagingTest::SendCold { to, body, reply }))
            .await
            .expect("the loop answers")
    }

    /// The rung of the selected path on the connection of alice to `peer`: `ip`, `relay`, and so
    /// on. `None` while no path is selected.
    async fn selected_rung(&self, peer: &str) -> Option<&'static str> {
        self.membership
            .request(|reply| {
                Request::InspectTest(InspectTest::SelectedRung {
                    peer: peer.to_owned(),
                    reply,
                })
            })
            .await
            .expect("the loop answers")
    }

    /// Forget the pooled connection to `peer` and put it on the dial-failure cooldown.
    async fn note_dial_failure(&self, peer: &str) {
        self.membership
            .request(|reply| {
                Request::Linking(Linking::NoteDialFailure {
                    peer: peer.to_owned(),
                    reply,
                })
            })
            .await
            .expect("the loop answers")
            .expect("alice knows bob");
    }

    /// Forget that `peer` is proven direct, so that the node reads no path for the pair, as it
    /// does before the first probe.
    async fn forget_direct(&self, peer: &str) {
        self.membership
            .request(|reply| {
                Request::Linking(Linking::ForgetDirect {
                    peer: peer.to_owned(),
                    reply,
                })
            })
            .await
            .expect("the loop answers")
            .expect("alice knows bob");
    }

    /// Whether a unicast connection to `peer` was pooled, and is forgotten now.
    async fn forget_unicast(&self, peer: &str) -> bool {
        self.membership
            .request(|reply| {
                Request::Linking(Linking::ForgetUnicast {
                    peer: peer.to_owned(),
                    reply,
                })
            })
            .await
            .expect("the loop answers")
            .expect("alice knows bob")
    }
}

#[test]
fn a_directed_send_that_waits_on_a_dial_does_not_stop_the_node() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let alice = Member::create("alice", &relay).await;
        let bob = Member::join("bob", &alice).await;

        alice.until_knows("bob").await;
        alice.cut_ip_to("bob", &bob).await;

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
            time::sleep(ASK_AFTER).await;
            let _ = alice.knows("bob").await;
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

/// **A directed send on a warm connection that reads relay waits for the path that comes.**
///
/// A pooled connection whose selected path is the relay is not a refusal: its direct path can
/// still be forming. The send waits on a task of its own, so the node serves other requests, and
/// when IP is back before the budget ends, the frame goes out once. The test cuts IP after a
/// first message pooled the connection, sends while the path reads relay, and gives IP back.
///
/// The send is never `Held` here, because this mesh has no `WebRTC`: the admission demote does
/// nothing, so the pair stays `Direct` after the cut. On a mesh with `WebRTC`, the same cut makes
/// the pair `RelayOnly`, and the send is `Held` by design.
#[test]
fn a_directed_send_on_a_warm_connection_that_reads_relay_waits_and_arrives_once_ip_is_back() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let alice = Member::create("alice", &relay).await;
        let mut bob = Member::join("bob", &alice).await;
        alice.until_knows("bob").await;

        // The first message pools the connection that the next send finds warm. It tries until the
        // pair is direct, as a caller does.
        let warm_ends = Instant::now() + FORMATION;
        while let Err(refusal) = alice.send("bob", "warm").await {
            assert!(
                Instant::now() < warm_ends,
                "the first message did not go out within {FORMATION:?}: {refusal}"
            );
            time::sleep(Duration::from_millis(250)).await;
        }
        alice.cut_ip_to("bob", &bob).await;

        let verdict = {
            let send = alice.send("bob", "hello");
            tokio::pin!(send);
            // The premise: the send is still waiting. An answer here is a refusal before the wait, and
            // the run proves nothing about the wait.
            let early = time::timeout(WAIT_PREMISE, &mut send).await;
            assert!(
                early.is_err(),
                "the send answered {early:?} within {WAIT_PREMISE:?}: it did not wait for a path"
            );
            alice.block_ip_to(Vec::new()).await;
            time::timeout(PATH_BUDGET, send)
                .await
                .expect("the send ends within the path budget")
        };
        assert_eq!(
            verdict,
            Ok(()),
            "IP came back during the wait, so the send must go out"
        );

        let arrival_ends = Instant::now() + PATH_BUDGET;
        let mut texts = Vec::new();
        while !texts.iter().any(|text| text == "hello") {
            assert!(
                Instant::now() < arrival_ends,
                "bob did not read the message; it read {texts:?}"
            );
            time::sleep(Duration::from_millis(100)).await;
            texts.extend(bob.arrived());
        }
        time::sleep(Duration::from_secs(1)).await;
        texts.extend(bob.arrived());
        let hellos = texts.iter().filter(|text| *text == "hello").count();
        let _ = bob.membership.node.leave().await;
        let _ = alice.membership.node.leave().await;
        assert_eq!(hellos, 1, "bob read the message {hellos} times: {texts:?}");
    });
}

/// **The reply of a send to a peer on the dial-failure cooldown names the cooldown.**
///
/// The pool refuses the send with a context and the cooldown text below it. The `Messaging::Send`
/// reply is the text that a user reads, so it must print the whole chain and not the outer message.
#[test]
fn the_reply_of_a_send_to_a_peer_on_the_dial_failure_cooldown_names_the_cooldown() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let alice = Member::create("alice", &relay).await;
        let bob = Member::join("bob", &alice).await;
        alice.until_knows("bob").await;

        // A send before the node is meshed is refused for another reason, so the first message tries
        // until it goes out. The cooldown then replaces the connection that it pooled.
        let warm_ends = Instant::now() + FORMATION;
        while let Err(refusal) = alice.send("bob", "warm").await {
            assert!(
                Instant::now() < warm_ends,
                "the first message did not go out within {FORMATION:?}: {refusal}"
            );
            time::sleep(Duration::from_millis(250)).await;
        }
        alice.note_dial_failure("bob").await;
        let verdict = alice.send("bob", "hello").await;

        let _ = bob.membership.node.leave().await;
        let _ = alice.membership.node.leave().await;
        let refusal = verdict.expect_err("the cooldown refuses the send");
        assert!(
            refusal.contains(COOLDOWN_TEXT),
            "the reply names the cooldown, and it reads: {refusal}"
        );
    });
}

/// **The reply of a send that fails on its dial task names the cause.**
///
/// A pooled connection that reads relay is waited on by a task, so the failure after the path
/// budget does not come back from the send itself. That reply is built on another arm of the
/// reply code than the cooldown refusal, and it must print the whole chain too.
#[test]
fn the_reply_of_a_send_that_fails_on_its_dial_task_names_the_relay_refusal() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let alice = Member::create("alice", &relay).await;
        let bob = Member::join("bob", &alice).await;
        alice.until_knows("bob").await;

        let warm_ends = Instant::now() + FORMATION;
        while let Err(refusal) = alice.send("bob", "warm").await {
            assert!(
                Instant::now() < warm_ends,
                "the first message did not go out within {FORMATION:?}: {refusal}"
            );
            time::sleep(Duration::from_millis(250)).await;
        }
        alice.cut_ip_to("bob", &bob).await;

        let verdict = time::timeout(PATH_BUDGET, alice.send("bob", "late"))
            .await
            .expect("the send ends within the path budget");

        let _ = bob.membership.node.leave().await;
        let _ = alice.membership.node.leave().await;
        let refusal = verdict.expect_err("no direct path comes back, so the send fails");
        assert!(
            refusal.contains(RELAY_TEXT),
            "the reply names the relay refusal, and it reads: {refusal}"
        );
    });
}

/// **A send to an unprobed pair whose only path is the relay is refused and delivers nothing.**
///
/// A directed send is no longer held for want of a probe: the node reads no path for the pair, so
/// it dials and waits for a direct path. The safety of a lookup-only mesh is the live path of the
/// connection, so the frame must not go out while the path reads relay. The test cuts IP, erases
/// the proof of the pair, and sends. The send fails inside the path budget, with the relay refusal
/// after a wait or with a hold if the path watcher read the pair first, and bob reads nothing. The
/// accept side holds a connection on a relay path unread, so the test proves that bob reads
/// nothing, and not that the relay carried no byte.
#[test]
fn a_directed_send_to_an_unprobed_pair_on_the_relay_is_refused_and_bob_reads_nothing() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let (relay, _server) = test_relay::spawn_plain().await.expect("local relay");
        let alice = Member::create("alice", &relay).await;
        let mut bob = Member::join("bob", &alice).await;
        alice.until_knows("bob").await;

        let warm_ends = Instant::now() + FORMATION;
        while let Err(refusal) = alice.send("bob", "warm").await {
            assert!(
                Instant::now() < warm_ends,
                "the first message did not go out within {FORMATION:?}: {refusal}"
            );
            time::sleep(Duration::from_millis(250)).await;
        }
        let arrival_ends = Instant::now() + PATH_BUDGET;
        let mut earlier = Vec::new();
        while !earlier.iter().any(|text| text == "warm") {
            assert!(
                Instant::now() < arrival_ends,
                "bob did not read the first message; it read {earlier:?}"
            );
            time::sleep(Duration::from_millis(100)).await;
            earlier.extend(bob.arrived());
        }
        alice.cut_ip_to("bob", &bob).await;
        alice.forget_direct("bob").await;

        let started = Instant::now();
        let verdict = time::timeout(SAFETY_BUDGET, alice.send("bob", "late"))
            .await
            .expect("the send ends within the safety budget");
        let waited = started.elapsed();
        time::sleep(Duration::from_secs(1)).await;
        let read = bob.arrived();

        let _ = bob.membership.node.leave().await;
        let _ = alice.membership.node.leave().await;
        let refusal = verdict.expect_err("the only path is the relay, so the send fails");
        assert!(
            refusal.contains(RELAY_TEXT),
            "the reply names the relay refusal, and it reads: {refusal}"
        );
        // The path watcher of the lower id can read the pair as relay-only between the erase and the
        // send, and then the send is held at once. Both refusals are safe, so only the one that is
        // not held must have waited.
        let held = refusal.contains(HELD_TEXT);
        assert!(
            held || waited >= WAIT_PREMISE,
            "the send was refused after {waited:?} with no wait and no hold: {refusal}"
        );
        assert!(
            read.is_empty(),
            "bob read {read:?} over a path that is the relay on a lookup-only mesh"
        );
    });
}
