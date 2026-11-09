//! Two live daemons cannot be one member: while a node runs on a state path, a second start of that
//! path fails, and the lock goes with the node. The lock must live as long as the event loop, not
//! only as long as the setup, so the node is a real one, spawned through `Node::spawn`.

#![cfg(all(unix, feature = "host"))]

use std::path::Path;
use std::{env, fs, process};

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, SilentSink,
};
use habilis_network::protocol::messages::Authored;
use habilis_network::protocol::{MeshConfig, MeshName, Nickname};
use tokio::sync::oneshot;

use habilis_network::runtime::{
    EventLoopConfig, Node, SetupError, SetupKind, SetupParams, SignalHandling, setup_mesh,
};

struct Idle;

#[habilis_network::async_trait]
impl NodeApp for Idle {
    fn classify(&self, _message: &Authored) -> AppClass {
        AppClass::NONE
    }

    async fn on_app_frame(
        &mut self,
        _frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        _ctx: &HandlerCtx<'_>,
    ) -> bool {
        true
    }
}

#[habilis_network::async_trait]
impl NodeDriver for Idle {
    // A request is answered by the event loop itself, so an answer proves that the loop is running.
    type Session = oneshot::Sender<()>;
    type Http = ();
    type Ipc = ();

    async fn handle_session(
        &mut self,
        request: Self::Session,
        _state: &mut EventLoopState,
        _context: &HandlerCtx<'_>,
    ) -> bool {
        let _ = request.send(());
        true
    }
}

/// A start of a new mesh whose member key lives under `state`.
async fn start(name: &str, state: &Path) -> Result<EventLoopConfig, SetupError> {
    let kind = SetupKind::Create {
        name: MeshName::try_new(name).expect("a name"),
        config: MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh"),
        advertise: None,
        password: None,
        invite_only: false,
    };
    let params = SetupParams::new(
        Nickname::try_new("member").expect("a nickname"),
        SilentSink::default(),
    )
    .state_file(state.to_path_buf());
    setup_mesh(kind, params).await
}

#[test]
fn a_second_start_of_the_state_path_of_a_running_node_fails_and_works_after_it_left() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let dir = env::temp_dir().join(format!("habilis-state-lock-loop-{}", process::id()));
        fs::create_dir_all(&dir).expect("a temp dir");
        let state = dir.join("member.json");

        let config = start("lock-first", &state).await.expect("the first start");
        let node = Node::spawn(config, Idle, None, SignalHandling::Leave);
        // Wait until the loop of the first node answers: the second start then meets a node that runs,
        // and not a setup that is still on its way, so the result does not depend on timing.
        let (running, answered) = oneshot::channel();
        node.send(running)
            .await
            .expect("the request reaches the loop");
        answered.await.expect("the loop of the first node runs");

        let second = start("lock-second", &state).await;
        let refused = second.err().map(|error| error.to_string());
        assert!(
            refused
                .as_deref()
                .is_some_and(|text| text.contains("member.key")),
            "a second start of the state path of a running node fails and names the key file: {refused:?}"
        );

        let _ = node.leave().await;
        let after = start("lock-third", &state).await;
        assert!(
            after.is_ok(),
            "the lock goes with the node: a start after it left works: {:?}",
            after.as_ref().err()
        );
        if let Ok(third) = after {
            let _ = Node::spawn(third, Idle, None, SignalHandling::Leave)
                .leave()
                .await;
        }
        fs::remove_dir_all(&dir).ok();
    });
}
