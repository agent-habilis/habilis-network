//! The cut of the state channel on the node: which node cuts, on which thread the seed is built,
//! and how the chain is signed. A state document with epochs asks for a cut when its size crosses
//! the ceiling of its lines (`MeshDoc::cut_due`). The node reads the document into a plan on the
//! event loop, builds the chain from the plan on a blocking thread so that the loop keeps ticking
//! (a seed of 20 000 paths takes seconds), and gets the chain back through the handle of the job.

use std::collections::HashSet;
use std::fmt::Display;
use std::future::pending;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(not(target_family = "wasm"))]
use tokio::task::spawn_blocking;
use tokio::task::{JoinError, JoinHandle};

use crate::doc::{DocError, MeshDoc, SeedChain, SeedPlan, Stamp, wire};
use crate::protocol::identity::Identity;
use crate::protocol::messages::{Verified, WireFrame};
use crate::protocol::{Channel, MeshId, Message, Nickname, SymmetricKey};
use crate::transport::MeshSender;
use crate::util::bounded_fifo_set::BoundedFifoSet;
use crate::util::clock::Instant as ClockInstant;
use crate::util::consts::{DOC_EPOCH_FRAME_MARGIN, DOC_STATE_SYNC_WAIT, MAX_MESSAGE_SIZE};

use super::state::EventLoopState;

/// The time that the stamps of the paths of a merge get in the `fits` of a seed: the largest
/// Lamport time (`2^53 - 1`), so a frame that fits with it fits with any stamp.
const LARGEST_TIME: u64 = (1 << 53) - 1;

/// What a node needs to build the chain of a seed and to measure its frames, copied out of the
/// event-loop state so that the build runs on another thread.
#[derive(Debug)]
pub(crate) struct SeedJob {
    pub(crate) epoch: u64,
    /// The actor of the chain: the signing key of the cutter.
    pub(crate) actor: [u8; 32],
    /// The key that seals the bodies of the state channel, if the mesh has a password.
    pub(crate) seal: Option<Arc<SymmetricKey>>,
    // The same signing key as the loop's: the job signs the frames that it measures.
    pub(crate) identity: Arc<Identity>,
    pub(crate) mesh: MeshId,
    pub(crate) author: Nickname,
}

/// What a finished build gives back to the event loop.
#[derive(Debug)]
pub(crate) struct SeedOutcome {
    pub(crate) epoch: u64,
    pub(crate) chain: Result<SeedChain, DocError>,
    /// How long the build took, for the log.
    pub(crate) took: Duration,
}

/// The position of this node among the nodes that it sees alive, in the order that the epoch gives:
/// the nicknames of the live peers and our own are mixed with the epoch and sorted, so the nodes
/// that hold the same roster agree on who is first, and the first one cuts at once (see
/// `MeshDoc::cut_due`). A node that is quiet does not count. The view is soft: a node that
/// misses a peer delays or doubles a cut and never blocks it.
pub(crate) fn rank_of(
    me: &Nickname,
    peers: &HashSet<Nickname>,
    quiet: &BoundedFifoSet<Nickname>,
    epoch: u64,
) -> usize {
    let mine = (mix(me, epoch), me.as_str());
    let mut ahead = 0;
    for peer in peers {
        if peer == me || quiet.contains(peer) {
            continue;
        }
        if (mix(peer, epoch), peer.as_str()) < mine {
            ahead += 1;
        }
    }
    ahead
}

/// A hash of the nickname and the epoch that every node computes alike (FNV-1a over the bytes of
/// the nickname, then the epoch spread over the 64 bits).
fn mix(nickname: &Nickname, epoch: u64) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in nickname.as_str().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash ^ epoch.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

/// Whether the frame of `merge`, as a seed would carry it (with the largest stamp of each path,
/// sealed if the mesh has a key, signed and serialized), leaves the margin of the envelope under a
/// message. It is the check of the daemon for a seed: a frame that fits here fits at the send.
fn seed_frame_fits(job: &SeedJob, merge: &serde_json::Value) -> bool {
    let timeless = MeshDoc::new_ungated();
    let Ok(Some(change)) = timeless.build_change(merge, &job.actor) else {
        return true;
    };
    let mut stamps: Vec<Stamp> = Vec::new();
    for _ in 0..count_leaves(merge) {
        stamps.push(Stamp::new(LARGEST_TIME, "ffffffffffffffff".to_owned()));
    }
    let time = Some(LARGEST_TIME);
    let plain = wire::change_body_tombstoned(&change, None, job.epoch, None, time, &stamps, &[]);
    let Ok(plain) = plain else {
        return false;
    };
    let body = match job.seal.as_deref() {
        Some(key) => match wire::encrypt_body(&plain, key) {
            Ok(sealed) => sealed,
            Err(_) => return false,
        },
        None => plain,
    };
    let message = Message::new_channel_event(&job.mesh, &job.author, body, Channel::State);
    let frame = message.sign(&job.identity);
    frame
        .serialize()
        .is_ok_and(|wire| wire.as_bytes().len() + DOC_EPOCH_FRAME_MARGIN <= MAX_MESSAGE_SIZE)
}

/// The leaves of a merge: a value that is not an object, or an empty object.
fn count_leaves(merge: &serde_json::Value) -> usize {
    match merge {
        serde_json::Value::Object(fields) if !fields.is_empty() => {
            let mut leaves = 0;
            for field in fields.values() {
                leaves += count_leaves(field);
            }
            leaves
        }
        serde_json::Value::Object(_)
        | serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_)
        | serde_json::Value::Array(_) => 1,
    }
}

/// Build the chain from `plan` on a blocking thread, and give back a handle. The event loop keeps
/// its timers and its sockets while the thread works. A browser has no thread to spare, so there
/// the build runs as a task of the loop (a state document of a browser is small).
pub(crate) fn spawn_build(plan: SeedPlan, job: SeedJob) -> JoinHandle<SeedOutcome> {
    let build = move || {
        let started = Instant::now();
        let chain = plan.build(job.epoch, &job.actor, |merge| seed_frame_fits(&job, merge));
        SeedOutcome {
            epoch: job.epoch,
            chain,
            took: started.elapsed(),
        }
    };
    #[cfg(not(target_family = "wasm"))]
    {
        spawn_blocking(build)
    }
    #[cfg(target_family = "wasm")]
    {
        tokio::spawn(async move { build() })
    }
}

/// The signed frames of `chain`, root first, with their wire bytes: each change in a body with its
/// stamps and tombstones, the root with the mark of the seed, sealed if the mesh has a key.
///
/// # Errors
/// When a body does not encode, does not seal, or does not serialize.
pub(crate) fn signed_frames(
    chain: &SeedChain,
    job: &SeedJob,
) -> anyhow::Result<Vec<(Verified, WireFrame)>> {
    let mut frames: Vec<(Verified, WireFrame)> = Vec::with_capacity(chain.changes.len());
    let numbered = chain.changes.iter().enumerate();
    for (position, bytes) in numbered {
        let mark = (position == 0).then_some(&chain.mark);
        let plain = wire::change_body_tombstoned(
            bytes,
            None,
            job.epoch,
            mark,
            Some(chain.time),
            &chain.origins[position],
            &chain.tombstones[position],
        )?;
        let body = match job.seal.as_deref() {
            Some(key) => wire::encrypt_body(&plain, key)?,
            None => plain,
        };
        let message = Message::new_channel_event(&job.mesh, &job.author, body, Channel::State);
        let signed = message.sign(&job.identity);
        let wire_frame = signed.serialize()?;
        frames.push((signed, wire_frame));
    }
    Ok(frames)
}

/// Send the frames of a seed, root first: each one is taken as a candidate by this node (it adopts
/// its own seed after the wait, like every node) and then goes to the overlay, or waits in the
/// buffer of a node that does not reach it yet. A send that fails stops the chain and holds the
/// next cut back. Returns how many frames went out.
pub(crate) async fn send_frames(
    state: &mut EventLoopState,
    sender: &MeshSender,
    frames: Vec<(Verified, WireFrame)>,
) -> usize {
    let mut sent = 0;
    for (signed, bytes) in frames {
        let _ = state.doc_mut(Channel::State).ingest(&signed);
        if state.overlay_reachable() {
            if let Err(error) = sender.broadcast(bytes).await {
                cut_failed(state, &error);
                return sent;
            }
        } else {
            state.pending_outbound.push((signed, bytes));
        }
        sent += 1;
    }
    sent
}

/// Cut the state channel now, on the calling thread, and send the seed: the plan, the build, the
/// signing and the send of a cut, in one call. The loop does the same in pieces, with the build on
/// another thread; this is for a test that measures the send, and for a tool.
///
/// # Errors
/// When the document holds a candidate, or the seed does not build.
pub(crate) async fn cut_now(
    state: &mut EventLoopState,
    me: &Nickname,
    mesh: &MeshId,
    sender: &MeshSender,
) -> anyhow::Result<usize> {
    let plan = state.doc(Channel::State).seed_plan()?;
    let job = job_for(
        state,
        me,
        mesh,
        state.doc(Channel::State).epoch().saturating_add(1),
    );
    let started = Instant::now();
    let chain = plan.build(job.epoch, &job.actor, |merge| seed_frame_fits(&job, merge))?;
    let outcome = SeedOutcome {
        epoch: job.epoch,
        chain: Ok(chain),
        took: started.elapsed(),
    };
    let frames = finish(state, Ok(outcome), me, mesh);
    Ok(send_frames(state, sender, frames).await)
}

/// One tick of the state channel, on the minute timer: the document counts its epoch and the size
/// of its frames, and when a cut is due for this node and none is running, the node reads the
/// document into a plan and starts the build on another thread. Nothing happens for a document
/// with no state epochs.
pub(crate) fn tick(state: &mut EventLoopState, me: &Nickname, mesh: &MeshId) {
    if !state.doc(Channel::State).has_state_epochs() {
        return;
    }
    let doc = state.doc_mut(Channel::State);
    let epoch = doc.epoch();
    let _ = doc.tick_epoch(me);
    for key in doc.take_dropped() {
        state.seen.remove(&key);
    }
    if state.seed_job.is_some() {
        return;
    }
    let rank = rank_of(me, &state.peers, &state.quiet, epoch);
    if !state.doc(Channel::State).cut_due(rank) {
        return;
    }
    let plan = match state.doc(Channel::State).seed_plan() {
        Ok(plan) => plan,
        // A candidate that the node holds is adopted, not cut over.
        Err(DocError::CandidateHeld) => return,
        Err(error) => {
            cut_failed(state, &error);
            return;
        }
    };
    let job = job_for(state, me, mesh, epoch.saturating_add(1));
    state.seed_job = Some(spawn_build(plan, job));
}

/// What a node needs to build and sign the chain of a seed of `epoch`.
fn job_for(state: &EventLoopState, me: &Nickname, mesh: &MeshId, epoch: u64) -> SeedJob {
    let actor = *state.identity.public().as_bytes();
    SeedJob {
        epoch,
        actor,
        seal: state.state_seal.clone(),
        // Shared with the loop: the job signs with the same key.
        identity: Arc::clone(&state.identity),
        mesh: mesh.clone(),
        author: me.clone(),
    }
}

/// A peer showed its heads for `channel` and this node holds all of them: it is not behind that
/// peer, so every time that the peer has seen is in the history of this node and its clock is above
/// them. That ends the wait of the state document for its first sync (the first full answer to the
/// digest, or an answer that has nothing to give: a peer with no heads is held too).
pub(crate) fn peer_heads_seen(state: &mut EventLoopState, channel: Channel, heads: &[String]) {
    if channel != Channel::State {
        return;
    }
    let doc = state.doc_mut(channel);
    if doc.is_awaiting_first_sync() && doc.holds_heads(heads) {
        doc.finish_sync();
        tracing::debug!(target: "habilis_network::gossip", "the state channel synced with a peer, and its writes go on");
    }
}

/// The end of the wait for the first sync at its deadline, on the sweep tick: the node writes with
/// the clock that it has, and warns. Without it a node with no peer, or a mesh whose peers are all
/// down, would hold every write for ever.
pub(crate) fn sync_deadline(state: &mut EventLoopState) {
    let doc = state.doc(Channel::State);
    if !doc.is_awaiting_first_sync() || ClockInstant::now() < state.state_sync_deadline {
        return;
    }
    state.doc_mut(Channel::State).finish_sync();
    let limit_secs = DOC_STATE_SYNC_WAIT.as_secs();
    tracing::warn!(target: "habilis_network::gossip", limit_secs, "no peer answered the digest of the state channel within the time limit, so the node writes with the clock that it has; a write that it made before a restart can win against its new ones");
}

/// A cut that failed: the document holds the next one back, and the node warns once.
pub(crate) fn cut_failed(state: &mut EventLoopState, error: &impl Display) {
    state.doc_mut(Channel::State).note_cut_failed();
    tracing::warn!(target: "habilis_network::gossip", %error, "the cut of the state channel failed, and the next one waits");
}

/// Wait for the build of the seed that runs on a blocking thread, and take the handle. It waits
/// for ever when no build runs, so the `select!` of the event loop can hold it as an arm.
pub(crate) async fn seed_job_done(
    job: &mut Option<JoinHandle<SeedOutcome>>,
) -> Result<SeedOutcome, JoinError> {
    match job.as_mut() {
        Some(handle) => {
            let outcome = handle.await;
            *job = None;
            outcome
        }
        None => pending().await,
    }
}

/// The frames to send for the outcome of a build, root first: the chain is counted (the paths that
/// had no stamp), signed and sealed. A build that failed, or a chain that does not sign, holds the
/// next cut back and gives no frame.
pub(crate) fn finish(
    state: &mut EventLoopState,
    outcome: Result<SeedOutcome, JoinError>,
    me: &Nickname,
    mesh: &MeshId,
) -> Vec<(Verified, WireFrame)> {
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            cut_failed(state, &error);
            return Vec::new();
        }
    };
    let chain = match outcome.chain {
        Ok(chain) => chain,
        Err(error) => {
            cut_failed(state, &error);
            return Vec::new();
        }
    };
    state.doc(Channel::State).note_seed_built(&chain);
    let job = job_for(state, me, mesh, outcome.epoch);
    match signed_frames(&chain, &job) {
        Ok(frames) => {
            tracing::info!(target: "habilis_network::gossip", epoch = outcome.epoch, frames = frames.len(), built_ms = u64::try_from(outcome.took.as_millis()).unwrap_or(u64::MAX), "the seed of the state channel is built");
            frames
        }
        Err(error) => {
            cut_failed(state, &error);
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::{Map, Value, json};

    use super::{
        ClockInstant, SeedJob, SeedOutcome, finish, peer_heads_seen, rank_of, spawn_build,
        sync_deadline, tick,
    };
    use tokio::time::interval;

    use crate::daemon::state::EventLoopState;
    use crate::doc::{DocError, Ingested, Limits, MeshDoc};
    use crate::protocol::identity::Identity;
    use crate::protocol::{Channel, MeshId, Message, Nickname};
    use crate::testing;
    use crate::util::bounded_fifo_set::BoundedFifoSet;

    fn roster(names: &[&str]) -> HashSet<Nickname> {
        names.iter().map(|name| testing::nick(name)).collect()
    }

    fn no_quiet() -> BoundedFifoSet<Nickname> {
        BoundedFifoSet::new(16)
    }

    /// The nodes that hold one roster agree on the order: each node's rank is a different number.
    #[test]
    fn the_ranks_of_the_nodes_of_one_roster_are_the_numbers_from_0_to_the_count_less_1() {
        let names = ["alice", "bob", "carol", "dave", "erin"];
        let mut ranks: Vec<usize> = Vec::new();
        for name in names {
            let me = testing::nick(name);
            let others: Vec<&str> = names
                .iter()
                .copied()
                .filter(|other| *other != name)
                .collect();
            ranks.push(rank_of(&me, &roster(&others), &no_quiet(), 3));
        }
        ranks.sort_unstable();
        assert_eq!(
            ranks,
            [0, 1, 2, 3, 4],
            "one node is first, one is second, and so on"
        );
    }

    #[test]
    fn a_quiet_peer_does_not_count_and_the_epoch_changes_the_order() {
        let me = testing::nick("alice");
        let peers = roster(&["bob", "carol", "dave"]);
        let mut quiet = no_quiet();
        for peer in &peers {
            quiet.insert(peer.clone());
        }
        assert_eq!(
            rank_of(&me, &peers, &quiet, 3),
            0,
            "a node whose peers are all quiet is first"
        );
        let mut firsts: HashSet<usize> = HashSet::new();
        for epoch in 0..20 {
            firsts.insert(rank_of(&me, &peers, &no_quiet(), epoch));
        }
        assert!(
            firsts.len() > 1,
            "the rank of a node is not the same in every epoch: {firsts:?}"
        );
    }

    /// Write `count` leaves into `doc`, as `who`, one frame of 100.
    fn write_leaves(doc: &mut MeshDoc, identity: &Identity, who: &Nickname, count: usize) {
        let mesh = MeshId::from("test");
        let mut done = 0;
        while done < count {
            let take = 100.min(count - done);
            let mut leaves = Map::new();
            for leaf in 0..take {
                leaves.insert(format!("l{:05}", done + leaf), json!(leaf % 10));
            }
            let merge = json!({ "live": Value::Object(leaves) });
            let built = doc.build_change(&merge, identity.public().as_bytes());
            let change = built.expect("the merge applies").expect("a change");
            let (body, _plain) = doc.compose_wire_body(&change, None).expect("a body");
            let signed =
                Message::new_channel_event(&mesh, who, body, Channel::State).sign(identity);
            let outcome = doc.ingest(&signed);
            assert!(
                matches!(outcome, Ingested::Applied { .. }),
                "the frame applies"
            );
            done += take;
        }
    }

    // The test keeps the key that the job signs with.
    fn job_of(identity: &Arc<Identity>, epoch: u64) -> SeedJob {
        SeedJob {
            epoch,
            actor: *identity.public().as_bytes(),
            seal: None,
            // Shared with the test, which also signs with it.
            identity: Arc::clone(identity),
            mesh: MeshId::from("test"),
            author: testing::nick("me"),
        }
    }

    /// The timers of the loop go on while the seed is built: a ticker of 10 ms counts the ticks that
    /// pass on a loop of one thread while the build of a document of 3 000 leaves runs.
    #[tokio::test(flavor = "current_thread")]
    async fn the_loop_keeps_ticking_while_the_seed_of_a_large_document_is_built() {
        // Shared with the job that builds on another thread.
        let identity = Arc::new(Identity::generate());
        let me = testing::nick("me");
        let mut doc = MeshDoc::new_state(None);
        doc.finish_sync();
        write_leaves(&mut doc, &identity, &me, 3_000);
        let plan = doc.seed_plan().expect("a plan");
        let mut handle = spawn_build(plan, job_of(&identity, 1));
        let mut ticker = interval(Duration::from_millis(10));
        let mut ticks: u32 = 0;
        let outcome = loop {
            tokio::select! {
                _ = ticker.tick() => ticks += 1,
                outcome = &mut handle => break outcome,
            }
        };
        let outcome = outcome.expect("the build task ends");
        assert!(outcome.chain.is_ok(), "the seed is built");
        assert!(
            ticks >= 10,
            "the loop ticked {ticks} times while the seed of 3 000 leaves was built in {:?}",
            outcome.took
        );
    }

    /// The chain that a build gives is signed by `finish`, and a second node that takes the frames
    /// holds the same document after the wait.
    #[tokio::test(flavor = "current_thread")]
    async fn the_frames_that_finish_gives_are_adopted_by_another_node() {
        // Shared with the job that builds on another thread.
        let identity = Arc::new(Identity::generate());
        let me = testing::nick("me");
        let mut state = testing::fresh_state();
        state.state_doc = MeshDoc::new_state(None);
        state.doc_mut(Channel::State).finish_sync();
        let mut cutter = MeshDoc::new_state(None);
        cutter.finish_sync();
        write_leaves(&mut cutter, &identity, &me, 600);
        let plan = cutter.seed_plan().expect("a plan");
        let outcome = spawn_build(plan, job_of(&state.identity, 4)).await;
        let frames = finish(&mut state, outcome, &me, &MeshId::from("test"));
        assert!(
            frames.len() > 1,
            "the chain has several frames: {}",
            frames.len()
        );
        let mut joiner = MeshDoc::new_state(None);
        joiner.finish_sync();
        for (signed, _bytes) in &frames {
            joiner.ingest(signed);
        }
        let waiting = testing::nick("joiner");
        for _ in 0..5 {
            joiner.tick_epoch(&waiting);
        }
        assert_eq!(
            joiner.epoch(),
            4,
            "the joiner adopted the epoch of the seed"
        );
        assert_eq!(
            joiner.to_json(),
            cutter.to_json(),
            "the joiner holds the document of the cutter"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_build_gives_no_frame_and_holds_the_next_cut_back() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "the cut of the state channel failed, and the next one waits",
        );
        // Shared with the job that builds on another thread.
        let identity = Arc::new(Identity::generate());
        let me = testing::nick("me");
        let mesh = MeshId::from("test");
        let mut state = testing::fresh_state();
        let mut doc = MeshDoc::new_state(None);
        doc.finish_sync();
        write_leaves(&mut doc, &identity, &me, 1_700);
        state.state_doc = doc.limits(Limits::with_seed_frames(40));
        state.doc_mut(Channel::State).tick_epoch(&me);
        assert!(
            state.doc(Channel::State).cut_due(0),
            "the document is over the ceiling, so a cut is due"
        );
        let failed = SeedOutcome {
            epoch: 1,
            chain: Err(DocError::SeedTooLong { frames: 9_999 }),
            took: Duration::ZERO,
        };
        let frames = finish(&mut state, Ok(failed), &me, &mesh);
        assert!(frames.is_empty(), "a failed build gives no frame to send");
        assert!(
            !state.doc(Channel::State).cut_due(0),
            "the failed cut holds the next one back"
        );
    }

    /// The tick starts a build when a cut is due and none runs, and not before.
    #[tokio::test(flavor = "current_thread")]
    async fn the_tick_starts_one_build_when_the_cut_is_due() {
        // Shared with the job that builds on another thread.
        let identity = Arc::new(Identity::generate());
        let me = testing::nick("me");
        let mesh = MeshId::from("test");
        let mut state = testing::fresh_state();
        let mut doc = MeshDoc::new_state(None);
        doc.finish_sync();
        write_leaves(&mut doc, &identity, &me, 1_700);
        state.state_doc = doc.limits(Limits::with_seed_frames(40));

        tick(&mut state, &me, &mesh);
        assert!(
            state.seed_job.is_some(),
            "a document over the cut ceiling starts a build at the first tick (rank 0)"
        );
        let first = state.seed_job.take().expect("the job").await;
        assert!(
            first.is_ok_and(|outcome| outcome.chain.is_ok()),
            "the build ends"
        );

        let mut small = testing::fresh_state();
        let mut few = MeshDoc::new_state(None).limits(Limits::with_seed_frames(40));
        few.finish_sync();
        write_leaves(&mut few, &identity, &me, 300);
        small.state_doc = few;
        tick(&mut small, &me, &mesh);
        assert!(small.seed_job.is_none(), "a small document starts no build");

        let mut plain = testing::fresh_state();
        tick(&mut plain, &me, &mesh);
        assert!(
            plain.seed_job.is_none(),
            "a state document with no state epochs (the daemon today) starts no build"
        );
    }

    /// A state document that waits for its first sync, inside a state.
    fn state_that_waits_for_the_first_sync() -> EventLoopState {
        let mut state = testing::fresh_state();
        state.state_doc = MeshDoc::new_state(None);
        state
    }

    #[test]
    fn the_heads_of_a_peer_that_this_node_holds_end_the_wait_for_the_first_sync() {
        let mut state = state_that_waits_for_the_first_sync();
        assert!(
            state.doc(Channel::State).is_awaiting_first_sync(),
            "the node waits"
        );
        let ours: Vec<String> = state.doc(Channel::State).heads().collect();
        let unknown = vec!["3yMApqCuCjXDWPrbjfR5mjCPTHqFG8Pux1TxQrEM35jj".to_owned()];
        peer_heads_seen(&mut state, Channel::State, &unknown);
        assert!(
            state.doc(Channel::State).is_awaiting_first_sync(),
            "a peer that is ahead of this node (heads that it does not hold) does not end the wait"
        );
        peer_heads_seen(&mut state, Channel::Meta, &ours);
        assert!(
            state.doc(Channel::State).is_awaiting_first_sync(),
            "the heads of the meta channel say nothing of the clock of the state channel"
        );
        peer_heads_seen(&mut state, Channel::State, &ours);
        assert!(
            !state.doc(Channel::State).is_awaiting_first_sync(),
            "heads that this node holds end the wait"
        );
    }

    #[test]
    fn a_peer_with_no_heads_is_an_empty_answer_and_ends_the_wait() {
        let mut state = state_that_waits_for_the_first_sync();
        peer_heads_seen(&mut state, Channel::State, &[]);
        assert!(
            !state.doc(Channel::State).is_awaiting_first_sync(),
            "a peer that holds nothing has nothing that this node lacks"
        );
    }

    #[test]
    fn the_wait_for_the_first_sync_ends_at_its_deadline_with_a_warning_that_names_the_limit() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "no peer answered the digest of the state channel within the time limit",
        );
        let mut state = state_that_waits_for_the_first_sync();
        sync_deadline(&mut state);
        assert!(
            state.doc(Channel::State).is_awaiting_first_sync(),
            "the deadline is 30 s from the start: a node that just started still waits"
        );
        state.state_sync_deadline = ClockInstant::now();
        sync_deadline(&mut state);
        assert!(
            !state.doc(Channel::State).is_awaiting_first_sync(),
            "at the deadline the node writes with the clock that it has"
        );
    }

    #[test]
    fn a_node_with_no_state_epochs_has_nothing_to_wait_for_at_the_deadline() {
        let mut state = testing::fresh_state();
        state.state_sync_deadline = ClockInstant::now();
        sync_deadline(&mut state);
        assert!(
            !state.doc(Channel::State).is_awaiting_first_sync(),
            "the daemon today: no wait, no warning"
        );
    }
}
