//! A write that finds the clock of the shared state ahead of the machine waits a short time for the
//! wall clock to move, then gives the app a typed refusal and sends nothing. The clock of the
//! machine is set by the test, so no real clock has to be wrong.

#![cfg(feature = "host")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, SilentSink, TimeSource,
};
use habilis_network::ops::{StateMergeParams, broadcast_state_merge};
use habilis_network::protocol::messages::Authored;
use habilis_network::protocol::{Channel, MeshConfig, MeshName, Nickname};
use habilis_network::runtime::{
    Node, SendError, SetupKind, SetupParams, SignalHandling, StateRefusal, setup_mesh,
};
use serde_json::{Value, json};
use tokio::sync::oneshot;

const NOW_MS: u64 = 1_700_000_000_000;
const TWO_HOURS_MS: u64 = 7_200_000;

enum Request {
    /// Move the wall clock that the state document reads.
    // Shared: the test moves the clock after the node took a handle to it.
    Clock(Arc<AtomicU64>, oneshot::Sender<()>),
    Merge(Value, oneshot::Sender<Result<(), SendError>>),
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
        match request {
            Request::Clock(cell, done) => {
                let source = TimeSource::new(move || cell.load(Ordering::Relaxed));
                state.doc_mut(Channel::State).set_time_source(source);
                let _ = done.send(());
            }
            Request::Merge(merge, done) => {
                let params =
                    StateMergeParams::new(context.into(), Channel::State, merge).surface(false);
                let _ = done.send(broadcast_state_merge(state, params).await);
            }
        }
        true
    }
}

#[test]
fn a_write_while_the_clock_is_ahead_waits_and_then_gets_a_typed_refusal() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
        let kind = SetupKind::Create {
            name: MeshName::try_new("clock-ahead").expect("a name"),
            config,
            advertise: None,
            password: None,
            invite_only: false,
        };
        let params = SetupParams::new(
            Nickname::try_new("writer").expect("a nickname"),
            SilentSink::default(),
        );
        let loop_config = setup_mesh(kind, params).await.expect("a created mesh");
        let node = Node::spawn(loop_config, Writer, None, SignalHandling::Leave);
        // Shared with the node, which reads it.
        let wall_clock = Arc::new(AtomicU64::new(NOW_MS + TWO_HOURS_MS));
        let (clock_set, set) = oneshot::channel();
        node.send(Request::Clock(Arc::clone(&wall_clock), clock_set))
            .await
            .expect("the request reaches the loop");
        set.await.expect("the loop answers");
        let (first_done, first) = oneshot::channel();
        node.send(Request::Merge(json!({ "a": 1 }), first_done))
            .await
            .expect("the request reaches the loop");
        let first = first.await.expect("the loop answers");

        // The wall clock is set right: the time that the node already sent is 2 hours ahead.
        wall_clock.store(NOW_MS, Ordering::Relaxed);
        let started = Instant::now();
        let (second_done, second) = oneshot::channel();
        node.send(Request::Merge(json!({ "a": 2 }), second_done))
            .await
            .expect("the request reaches the loop");
        let second = second.await.expect("the loop answers");
        let waited = started.elapsed();
        let _ = node.leave().await;

        assert!(first.is_ok(), "the first write is made: {first:?}");
        assert!(
            matches!(second, Err(SendError::State(StateRefusal::ClockAhead))),
            "the second write gets the typed refusal: {second:?}"
        );
        assert!(
            waited >= Duration::from_millis(45),
            "the write waited for the wall clock to move, 1 ms for each of 50 tries: {waited:?}"
        );
        assert!(
            waited < Duration::from_secs(2),
            "and the wait is bounded: {waited:?}"
        );
    });
}
