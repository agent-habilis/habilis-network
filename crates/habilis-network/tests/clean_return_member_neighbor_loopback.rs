//! A member that leaves cleanly and returns on its state file is the same member, has a member
//! neighbor, and is live again for the others.
//!
//! Alice, bob and carol meet on a topic mesh. Carol runs on a state file. She leaves cleanly: she says
//! goodbye, and the others keep a tombstone for her run. She starts again on the same state file and the
//! same topic. The params are built as the product does (`agent-gossip` `run_session.rs`): the state file
//! is set and `keys_in_default_state` is `true`. Three things must hold:
//! - her member key is the same as before, so no member refuses her nickname (the tracing guard stays
//!   strict: a "nickname is held" warning fails the test);
//! - she holds a gossip neighbor that is alice or bob, by nickname;
//! - alice and bob list her as a live member again, and not as quiet.
//!
//! The mesh has free slots, so no member refuses a `Neighbor` request: the test covers the return to a
//! mesh that has room, and not the return to members that are at their cap (`multihop_at_cap_loopback`
//! fills the members). It runs on a strict loopback topic mesh with no relay, and the product returns on a
//! mesh with a relay lookup. It is not shown here that the contact walk and the graft rule do not depend on
//! the lookup kind.

#![cfg(all(unix, feature = "host", feature = "iroh-test-utils"))]

use std::path::Path;
use std::time::{Duration, Instant};
use std::{env, fs, process};

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, SilentSink,
};
use habilis_network::protocol::messages::Authored;
use habilis_network::protocol::{AuthorKey, LookupOpts, Nickname};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use tokio::sync::oneshot;
use tokio::time;

/// The upper limit for the mesh and the return to settle, not a tuned window. The property is that the
/// return does not wait for the `STARVED` clock (5 minutes), so a bound below it has a meaning. The
/// measured time of the return is printed.
const SETTLE_DEADLINE: Duration = Duration::from_secs(90);

/// What a member says about itself and the others, read inside its loop.
struct View {
    /// The member key of this node, from its roster snapshot.
    own_member: Option<AuthorKey>,
    /// The nickname and the quiet flag of each roster row.
    roster: Vec<(String, bool)>,
    /// The nicknames of the gossip neighbors of this node.
    neighbors: Vec<String>,
}

struct Watcher;

#[habilis_network::async_trait]
impl NodeApp for Watcher {
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
impl NodeDriver for Watcher {
    type Session = oneshot::Sender<View>;
    type Http = ();
    type Ipc = ();

    async fn handle_session(
        &mut self,
        request: Self::Session,
        state: &mut EventLoopState,
        _context: &HandlerCtx<'_>,
    ) -> bool {
        let roster = state.roster_snapshot();
        let topology = state.topology_snapshot();
        let rows: Vec<(String, bool)> = roster
            .peers
            .iter()
            .map(|row| (row.nickname.to_string(), row.quiet))
            .collect();
        let neighbors: Vec<String> = topology
            .peers
            .into_iter()
            .filter(|peer| peer.neighbor)
            .filter_map(|peer| peer.nickname)
            .collect();
        let _ = request.send(View {
            own_member: roster.own_member,
            roster: rows,
            neighbors,
        });
        true
    }
}

fn nick(name: &str) -> Nickname {
    Nickname::try_new(name).expect("a nickname")
}

/// A node on the topic mesh. `state` is the state file of the node, when it keeps its identity.
async fn start(topic: &str, name: &str, state: Option<&Path>) -> Node<Watcher> {
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
    let mut params = SetupParams::new(nick(name), SilentSink::default())
        .max_connections(16)
        .keys_in_default_state(true);
    if let Some(state) = state {
        params = params.state_file(state.to_path_buf());
    }
    let config = setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic.to_owned(),
        },
        params,
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network");
    Node::spawn(config, Watcher, None, SignalHandling::Leave)
}

async fn view(node: &Node<Watcher>) -> View {
    let (reply, answer) = oneshot::channel();
    node.send(reply)
        .await
        .expect("the request reaches the loop");
    answer.await.expect("the loop answers")
}

async fn wait_for(deadline: Duration, mut done: impl AsyncFnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < deadline {
        if done().await {
            return true;
        }
        time::sleep(Duration::from_millis(250)).await;
    }
    false
}

fn has_neighbor_among(view: &View, names: &[&str]) -> bool {
    view.neighbors
        .iter()
        .any(|name| names.contains(&name.as_str()))
}

fn lists_live(view: &View, name: &str) -> bool {
    view.roster
        .iter()
        .any(|(nickname, quiet)| nickname == name && !quiet)
}

/// Whether `carol` holds a neighbor among alice and bob, and both of them list her as live.
async fn carol_is_back(alice: &Node<Watcher>, bob: &Node<Watcher>, carol: &Node<Watcher>) -> bool {
    let (from_alice, from_bob, from_carol) =
        (view(alice).await, view(bob).await, view(carol).await);
    has_neighbor_among(&from_carol, &["alice", "bob"])
        && lists_live(&from_alice, "carol")
        && lists_live(&from_bob, "carol")
}

#[test]
fn a_member_that_leaves_cleanly_and_returns_on_its_state_file_is_the_same_live_member() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        use std::os::unix::fs::PermissionsExt as _;

        let nonce: u64 = rand::random();
        let topic = format!("clean-return-{nonce}");
        let dir = env::temp_dir().join(format!("habilis-clean-return-{}-{nonce}", process::id()));
        fs::create_dir_all(&dir).expect("a temp dir");
        // A setup refuses a state folder that the group or the others can write.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("a private temp dir");
        let state = dir.join("carol.json");

        let alice = start(&topic, "alice", None).await;
        let bob = start(&topic, "bob", None).await;
        let carol = start(&topic, "carol", Some(&state)).await;
        assert!(
            wait_for(SETTLE_DEADLINE, async || {
                carol_is_back(&alice, &bob, &carol).await
            })
            .await,
            "the three members never formed a mesh"
        );
        let before = view(&carol).await.own_member;
        assert!(before.is_some(), "premise: carol holds a member key");

        let _ = carol.leave().await;
        let returned = start(&topic, "carol", Some(&state)).await;

        let returned_at = Instant::now();
        let settled = wait_for(SETTLE_DEADLINE, async || {
            carol_is_back(&alice, &bob, &returned).await
        })
        .await;
        eprintln!(
            "TIMING carol is back (neighbor, live for alice and bob): {settled} after {:?}",
            returned_at.elapsed()
        );
        let after = view(&returned).await;
        assert_eq!(
            after.own_member, before,
            "carol returned on her state file with another member key"
        );
        assert!(
            has_neighbor_among(&after, &["alice", "bob"]),
            "carol holds no neighbor among alice and bob after {SETTLE_DEADLINE:?}"
        );
        assert!(
            lists_live(&view(&alice).await, "carol") && lists_live(&view(&bob).await, "carol"),
            "alice and bob do not list carol as a live member after {SETTLE_DEADLINE:?}"
        );

        for node in [alice, bob, returned] {
            let _ = node.leave().await;
        }
        fs::remove_dir_all(&dir).ok();
    });
}
