//! A joiner of a mesh whose state is empty everywhere ends its wait for the first sync in one round
//! trip: a peer answers its first request, and the answer says that the peer had nothing to send.
//! The default wait of 30 s stays the outer bound, so it must not be what ends this one.

#![cfg(feature = "host")]

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, SilentSink,
};
use habilis_network::ops::{StateMergeParams, broadcast_state_merge};
use habilis_network::protocol::messages::Authored;
use habilis_network::protocol::{Channel, LookupOpts, Nickname};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio::time;

const WITHIN: Duration = Duration::from_secs(3);

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

async fn spawn(topic: &str, name: &str) -> Node<Writer> {
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
    let kind = SetupKind::Topic {
        mesh,
        topic_string: topic.to_owned(),
    };
    let params = SetupParams::new(
        Nickname::try_new(name).expect("a nickname"),
        SilentSink::default(),
    )
    .max_peers(16);
    let loop_config = setup_mesh(kind, params).await.expect("a joined mesh");
    Node::spawn(loop_config, Writer, None, SignalHandling::Leave)
}

async fn merge(node: &Node<Writer>) -> Result<(), String> {
    let (done, written) = oneshot::channel();
    node.send(Request::Merge(json!({ "a": 1 }), done))
        .await
        .expect("the request reaches the loop");
    written.await.expect("the loop answers")
}

/// Merge on `node` until it goes through or `WITHIN` has passed, and give the last result.
async fn merge_within(node: &Node<Writer>, started: Instant) -> Result<(), String> {
    let mut last = merge(node).await;
    while last.is_err() && started.elapsed() < WITHIN {
        time::sleep(Duration::from_millis(100)).await;
        last = merge(node).await;
    }
    last
}

#[test]
fn two_joiners_of_a_mesh_with_empty_state_both_write_state_within_a_few_seconds() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        let first = spawn("empty-state-join", "first").await;
        let second = spawn("empty-state-join", "second").await;
        let started = Instant::now();
        let second_result = merge_within(&second, started).await;
        let first_result = merge_within(&first, started).await;
        let took = started.elapsed();
        let _ = second.leave().await;
        let _ = first.leave().await;
        assert_eq!(
            second_result,
            Ok(()),
            "the second joiner has asked a peer that holds nothing: the write goes through within {WITHIN:?} (waited {took:?})"
        );
        assert_eq!(
            first_result,
            Ok(()),
            "the first joiner is answered by the second, which also holds nothing (waited {took:?})"
        );
    });
}
