//! A value of one member that does not fit one frame travels as chunks, and the other member shows it whole.
//!
//! The first member writes a value of the cap, `1 MiB`. Its slice is a pointer, and the second member fetches
//! the 17 chunks over the chunk plane. The second member shows the value when it is whole, so both views
//! agree. A shrink to a small value replaces it, and a write past the cap is refused with the text that says
//! what to do.

#![cfg(feature = "host")]

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, SilentSink,
};
use habilis_network::ops::{StateMergeParams, broadcast_state_merge};
use habilis_network::protocol::messages::Authored;
use habilis_network::protocol::{AuthorKey, Channel, LookupOpts, Nickname};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use serde_json::{Map, Value, json};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio::time;

/// The cap of one value: the encoded value takes `1 MiB` at most.
const CAP: usize = 1024 * 1024;

/// Wide enough for the mesh link, the fetch of 17 chunks and a loaded machine.
const WITHIN: Duration = Duration::from_secs(30);

enum Request {
    Merge(Value, oneshot::Sender<Result<(), String>>),
    View(oneshot::Sender<Value>),
    Key(oneshot::Sender<AuthorKey>),
}

struct Member;

#[habilis_network::async_trait]
impl NodeApp for Member {
    fn classify(&self, _message: &Authored) -> AppClass {
        AppClass::NONE
    }

    async fn on_app_frame(
        &mut self,
        _frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        _context: &HandlerCtx<'_>,
    ) -> bool {
        true
    }
}

#[habilis_network::async_trait]
impl NodeDriver for Member {
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
            Request::Merge(merge, done) => {
                let params =
                    StateMergeParams::new(context.into(), Channel::State, merge).surface(false);
                let sent = broadcast_state_merge(state, params).await;
                let written: Result<(), String> =
                    sent.map(|_sent| ()).map_err(|error| error.to_string());
                let _ = done.send(written);
                true
            }
            Request::View(response) => {
                let _ = response.send(state.view(Channel::State));
                false
            }
            Request::Key(response) => {
                let _ = response.send(state.identity().author_key());
                false
            }
        }
    }
}

async fn spawn(topic: &str, name: &str) -> Node<Member> {
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
    Node::spawn(loop_config, Member, None, SignalHandling::Leave)
}

async fn merge(node: &Node<Member>, value: Value) -> Result<(), String> {
    let (done, written) = oneshot::channel();
    node.send(Request::Merge(value, done))
        .await
        .expect("the request reaches the loop");
    written.await.expect("the loop answers")
}

/// Merge on `node` until it goes through or `WITHIN` has passed: the mesh may not be linked yet.
async fn merge_within(node: &Node<Member>, value: &Value) -> Result<(), String> {
    let started = Instant::now();
    let mut last = merge(node, value.clone()).await;
    while last.is_err() && started.elapsed() < WITHIN {
        time::sleep(Duration::from_millis(100)).await;
        last = merge(node, value.clone()).await;
    }
    last
}

async fn view(node: &Node<Member>) -> Value {
    let (response, read) = oneshot::channel();
    node.send(Request::View(response))
        .await
        .expect("the request reaches the loop");
    read.await.expect("the loop answers")
}

async fn hex_key(node: &Node<Member>) -> String {
    let (response, read) = oneshot::channel();
    node.send(Request::Key(response))
        .await
        .expect("the request reaches the loop");
    let key = read.await.expect("the loop answers");
    String::from_utf8_lossy(&key.hex()).into_owned()
}

/// The slice of `author` in the view of `node`, once it is `expected`, or whatever is there after `WITHIN`.
async fn slice_within(node: &Node<Member>, author: &str, expected: &Value) -> Option<Value> {
    let started = Instant::now();
    loop {
        let held = view(node).await.get(author).cloned();
        if held.as_ref() == Some(expected) || started.elapsed() >= WITHIN {
            return held;
        }
        time::sleep(Duration::from_millis(100)).await;
    }
}

/// An object of one key whose text varies, so that no two chunks of its encoding are equal. Its encoding takes
/// exactly `encoded` bytes.
fn value_of(encoded: usize) -> Value {
    let mut seed = 17_u32;
    let text: String = (0..encoded - 8)
        .map(|_| {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let index = u8::try_from((seed >> 16) % 26).expect("a letter index");
            char::from(b'a' + index)
        })
        .collect();
    let mut object = Map::new();
    object.insert("k".to_owned(), Value::String(text));
    Value::Object(object)
}

#[test]
fn a_value_at_the_cap_reaches_the_other_member_whole_and_both_views_agree() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        // A topic of its own, so two runs on one host do not join one loopback mesh.
        let nonce: u64 = rand::random();
        let topic = format!("chunked-state-{nonce}");
        let first = spawn(&topic, "first").await;
        let second = spawn(&topic, "second").await;
        let author = hex_key(&first).await;

        // A small value first: it goes through once the mesh is linked, and the second member shows it.
        let small = json!({ "small": 1 });
        let warmed = merge_within(&first, &small).await;
        assert_eq!(warmed, Ok(()), "the first small write goes through");
        let seen = slice_within(&second, &author, &small).await;
        assert_eq!(
            seen,
            Some(small.clone()),
            "the second member shows the small value"
        );

        // The value at the cap: a pointer on the wire, 17 chunks on the chunk plane.
        let big = value_of(CAP);
        let merged = merge_within(&first, &json!({ "small": null, "k": big["k"].clone() })).await;
        assert_eq!(merged, Ok(()), "a value at the cap is accepted");
        let shown = slice_within(&second, &author, &big).await;
        assert_eq!(
            shown.as_ref(),
            Some(&big),
            "the second member must show the whole value of the first"
        );
        assert_eq!(
            view(&first).await,
            view(&second).await,
            "both members must show the same document"
        );

        // A shrink replaces the chunked value with an inline one.
        merge(&first, json!({ "k": null, "after": "shrink" }))
            .await
            .expect("a shrink is accepted");
        let after = json!({ "after": "shrink" });
        let shrunk = slice_within(&second, &author, &after).await;
        assert_eq!(
            shrunk,
            Some(after),
            "the shrink must reach the second member"
        );

        // A write past the cap is refused, says what to do, and changes nothing.
        let refused = merge(&first, value_of(CAP + 1024)).await;
        let message = refused.expect_err("a value past the cap must be refused");
        assert!(
            message.contains("blob") && message.contains("ticket"),
            "the refusal must say to use a blob and put the ticket in the value, got: {message}"
        );
        assert_eq!(
            view(&first).await.get(&author).cloned(),
            Some(json!({ "after": "shrink" })),
            "a refused write must keep the last complete value"
        );

        let _ = second.leave().await;
        let _ = first.leave().await;
    });
}
