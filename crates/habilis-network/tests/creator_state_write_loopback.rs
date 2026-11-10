//! The creator of a mesh has no peer to sync with, so its first state write goes through at once.
//! A plain create, with no invite, must not wait for the first sync.

#![cfg(feature = "host")]

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, SilentSink,
};
use habilis_network::ops::{StateMergeParams, broadcast_state_merge};
use habilis_network::protocol::messages::Authored;
use habilis_network::protocol::{Channel, MeshConfig, MeshName, Nickname};
use habilis_network::runtime::{Node, SetupKind, SetupParams, SignalHandling, setup_mesh};
use serde_json::{Value, json};
use tokio::sync::oneshot;

enum Request {
    Merge(Value, oneshot::Sender<Result<(), String>>),
}

struct Writer;

#[habilis_network::async_trait]
impl NodeApp for Writer {
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
impl NodeDriver for Writer {
    type Session = Request;
    type Http = ();
    type Ipc = Value;

    async fn handle_session(
        &mut self,
        request: Self::Session,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        let Request::Merge(merge, done) = request;
        let params = StateMergeParams::new(context.into(), Channel::State, merge).surface(false);
        let sent = broadcast_state_merge(state, params).await;
        let written: Result<(), String> = sent.map(|_sent| ()).map_err(|error| error.to_string());
        let _ = done.send(written);
        true
    }
}

#[test]
fn the_creator_of_a_plain_mesh_writes_state_at_once() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
        let kind = SetupKind::Create {
            name: MeshName::try_new("creator-write").expect("a name"),
            config,
            advertise: None,
            password: None,
            invite_only: false,
        };
        let params = SetupParams::new(
            Nickname::try_new("creator").expect("a nickname"),
            SilentSink::default(),
        );
        let loop_config = setup_mesh(kind, params).await.expect("a created mesh");
        let node = Node::spawn(loop_config, Writer, None, SignalHandling::Leave);
        let (done, written) = oneshot::channel();
        node.send(Request::Merge(json!({ "a": 1 }), done))
            .await
            .expect("the request reaches the loop");
        let result = written.await.expect("the loop answers");
        let _ = node.leave().await;
        assert_eq!(
            result,
            Ok(()),
            "the creator has no peer to sync with: no wait"
        );
    });
}
