//! A `PeerInfo` that a member missed comes again by the periodic refresh.
//!
//! No frame repairs a lost `PeerInfo`; only the flood of its sender does. Its sender floods it again
//! on a few events (a new neighbor, a changed address, a new `joined`), and in a quiet mesh none
//! of them comes. Without the endpoint proof that the `PeerInfo` carries, the node answers no ping
//! of its sender and drops its link-state vectors.
//!
//! Two nodes on a loopback mesh. One of them forgets the proof of the other, as if the `PeerInfo`
//! had not reached it. The refresh period is set to 2 s, and the sweep to 1 s.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::process;
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, SilentSink,
};
use habilis_network::protocol::messages::Authored;
use habilis_network::protocol::{LookupOpts, Nickname};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use habilis_network::util::tuning::{self, Tuning};
use tokio::sync::oneshot;
use tokio::time::{self, Instant};

/// Up to the time of the alive tick (30 s), whose deferred `PeerInfo` can also give the proof back.
const REFRESH_WINDOW: Duration = Duration::from_secs(15);
const MEETING: Duration = Duration::from_mins(1);

enum Request {
    ForgetProof(Nickname, oneshot::Sender<()>),
    IsProven(Nickname, oneshot::Sender<bool>),
}

/// An app that reads nothing and answers the two requests of this test.
struct Probe;

#[habilis_network::async_trait]
impl NodeApp for Probe {
    fn classify(&self, _message: &Authored) -> AppClass {
        AppClass::NONE
    }

    async fn on_app_frame(
        &mut self,
        _frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        _ctx: &HandlerCtx<'_>,
    ) -> bool {
        false
    }
}

#[habilis_network::async_trait]
impl NodeDriver for Probe {
    type Session = Request;
    type Http = ();
    type Ipc = serde_json::Value;

    async fn handle_session(
        &mut self,
        request: Self::Session,
        state: &mut EventLoopState,
        _context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            Request::ForgetProof(peer, done) => {
                state.forget_endpoint_proof(&peer);
                let _ = done.send(());
            }
            Request::IsProven(peer, answer) => {
                let _ = answer.send(state.endpoint_is_proven(&peer));
            }
        }
        false
    }
}

fn nick(name: &str) -> Nickname {
    Nickname::try_new(name).expect("valid nickname")
}

async fn spawn(topic: &str, name: &str) -> Node<Probe> {
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
    let config = setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic.to_owned(),
        },
        SetupParams::new(nick(name), SilentSink::default()).max_peers(16),
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network");
    Node::spawn(config, Probe, None, SignalHandling::Leave)
}

async fn is_proven(node: &Node<Probe>, peer: &str) -> bool {
    let (answer, proven) = oneshot::channel();
    node.send(Request::IsProven(nick(peer), answer))
        .await
        .expect("the request reaches the loop");
    proven.await.expect("the loop answers")
}

async fn forget_proof(node: &Node<Probe>, peer: &str) {
    let (done, forgotten) = oneshot::channel();
    node.send(Request::ForgetProof(nick(peer), done))
        .await
        .expect("the request reaches the loop");
    forgotten.await.expect("the loop answers");
}

/// A node that lost the `PeerInfo` of a quiet member gets the proof back by the refresh of its
/// sender, with no event of the mesh to cause a flood.
#[test]
fn a_lost_peerinfo_is_resent_by_the_periodic_refresh() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run(guard, async {
        tuning::init(
            Tuning::default()
                .sweep_interval(Duration::from_secs(1))
                .peerinfo_refresh_min(Duration::from_secs(2))
                .peerinfo_refresh_per_peer(Duration::ZERO),
        );
        let topic = format!("habilis-network-peerinfo-refresh-{}", process::id());
        let alice = spawn(&topic, "alice").await;
        let bob = spawn(&topic, "bob").await;

        let meeting = Instant::now();
        while !is_proven(&bob, "alice").await {
            assert!(
                meeting.elapsed() < MEETING,
                "bob never took the PeerInfo of alice"
            );
            time::sleep(Duration::from_millis(250)).await;
        }

        forget_proof(&bob, "alice").await;
        assert!(
            !is_proven(&bob, "alice").await,
            "the forget left the proof of alice"
        );

        let waiting = Instant::now();
        while !is_proven(&bob, "alice").await {
            assert!(
                waiting.elapsed() < REFRESH_WINDOW,
                "alice sent no PeerInfo again inside {REFRESH_WINDOW:?}, so bob holds no proof of her"
            );
            time::sleep(Duration::from_millis(250)).await;
        }

        alice.leave().await.expect("alice leaves");
        bob.leave().await.expect("bob leaves");
    });
}
