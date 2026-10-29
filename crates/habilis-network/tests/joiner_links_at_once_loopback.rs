//! A joiner meets a beacon that already runs on its host without waiting for the co-host grace.
//!
//! Since the loopback ladder stopped being registered up front, a joiner's book leaves the busy
//! rungs out and its walk admits the one that reads as ours. A `Deferred` joiner walks only once
//! it is meshed or after the co-host grace, and on one host the busy rung is the beacon it came
//! for: without a read of the busy rungs at startup, its first link waited the whole grace.

#![cfg(feature = "host")]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::protocol::message::Authored;
use habilis_network::protocol::{
    Mesh, MeshConfig, MeshName, MessageKind, Nickname, PresenceSubtype, Seed,
};
use habilis_network::runtime::{
    CoHostPolicy, Node, SetupKind, SetupParams, SignalHandling, setup_mesh,
};
use tokio::sync::Notify;

/// Half of the reclaim ticker, which is when a joiner's first dial could be replaced at the
/// earliest: with the busy rung read before that dial, the link is one loopback handshake.
const FIRST_LINK: Duration = Duration::from_millis(500);

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

/// Presence alone forms the mesh.
struct Inert;

#[habilis_network::async_trait]
impl NodeApp for Inert {
    fn classify(&self, _message: &Authored) -> AppClass {
        AppClass::BEAT.union(AppClass::VALID)
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
impl NodeDriver for Inert {
    type Session = ();
    type Http = ();
    type Ipc = serde_json::Value;

    async fn handle_session(
        &mut self,
        (): Self::Session,
        _state: &mut EventLoopState,
        _ctx: &HandlerCtx<'_>,
    ) -> bool {
        false
    }
}

/// Records every `joined` presence the engine surfaces.
#[derive(Default)]
struct Joined {
    peers: Mutex<Vec<Nickname>>,
    changed: Notify,
}

impl NodeSink for Joined {
    fn emit(&self, event: NodeEvent) {
        if let NodeEvent::Presence { message, .. } = event
            && let MessageKind::Presence {
                subtype: PresenceSubtype::Joined,
            } = message.kind
        {
            self.peers
                .lock()
                .expect("no poison")
                .push(message.author.clone());
            self.changed.notify_waiters();
        }
    }
}

impl Joined {
    async fn wait_for(&self, nick: &Nickname, deadline: Duration) -> bool {
        let seen = || self.peers.lock().expect("no poison").contains(nick);
        let wait = async {
            loop {
                let changed = self.changed.notified();
                if seen() {
                    return;
                }
                changed.await;
            }
        };
        tokio::time::timeout(deadline, wait).await.is_ok() || seen()
    }
}

fn nick(name: &str) -> Nickname {
    Nickname::try_new(name).expect("valid nickname")
}

async fn spawn(mesh: &Mesh, name: &str, cohost: CoHostPolicy) -> (Node<Inert>, Arc<Joined>) {
    let sink = Arc::new(Joined::default());
    let params = SetupParams::new(nick(name), Arc::clone(&sink))
        .with_max_peers(16)
        .with_max_direct(0)
        .with_cohost(cohost);
    let config = setup_mesh(
        SetupKind::Join {
            mesh: mesh.clone(),
            password: None,
        },
        params,
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network");
    (
        Node::spawn(config, Inert, None, SignalHandling::Leave),
        sink,
    )
}

/// The origin co-hosts from t=0 (`Eager`, as `create` does) and so holds a rung of the ladder; the
/// joiner is a plain `Deferred` member, as `join` is. It must meet the origin long before the
/// co-host grace, which is when its own walk would first read the busy rung.
#[test]
fn a_joiner_meets_a_running_beacon_before_the_grace() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
        let mesh = Mesh::try_new(
            fresh_seed(),
            MeshName::try_new("fast-join").expect("a name"),
            config,
        )
        .expect("a mesh");
        let (origin, _origin_saw) = spawn(&mesh, "origin", CoHostPolicy::Eager).await;
        // The origin binds its rung at once; a moment, so that the rung is busy when the joiner
        // looks.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let started = Instant::now();
        let (joiner, joiner_saw) = spawn(&mesh, "joiner", CoHostPolicy::Deferred).await;
        let met = joiner_saw.wait_for(&nick("origin"), FIRST_LINK).await;
        let took = started.elapsed();
        eprintln!("first link took {took:?}");
        let _ = joiner.leave().await;
        let _ = origin.leave().await;
        assert!(
            met,
            "the joiner did not meet the running beacon within {FIRST_LINK:?} (waited {took:?}): \
             it waited for a tick to read the busy rung"
        );
    });
}
