//! The cut of the state channel on the node: which node cuts, on which thread the seed is built,
//! and how the chain is signed. A state document with epochs asks for a cut when its size crosses
//! the ceiling of its lines (`MeshDoc::cut_due`). The node reads the document into a plan on the
//! event loop, builds the chain from the plan on a blocking thread so that the loop keeps ticking
//! (a seed of 20 000 paths takes seconds), and gets the chain back through the handle of the job.

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::future::pending;
use std::sync::Arc;
use std::time::Duration;

use n0_future::task::{JoinError, JoinHandle};
#[cfg(not(target_family = "wasm"))]
use tokio::task::spawn_blocking;

use crate::doc::{DocError, MeshDoc, SeedChain, SeedPlan, Stamp, StampedPaths, wire};
use crate::protocol::identity::Identity;
use crate::protocol::messages::{Verified, WireFrame};
use crate::protocol::{Channel, MeshId, Message, Nickname, SymmetricKey};
use crate::transport::MeshSender;
use crate::util::bounded_fifo_set::BoundedFifoSet;
use crate::util::clock::Instant;
use crate::util::consts::{DOC_EPOCH_FRAME_MARGIN, MAX_MESSAGE_SIZE};
use crate::util::tuning;

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

/// Whether the frame of `merge`, as a seed would carry it (with the stamps of the plan for its
/// paths, sealed if the mesh has a key, signed and serialized), leaves the margin of the envelope
/// under a message. It is the check of the daemon for a seed: a frame that fits here fits at the
/// send, and it is as full as the real stamps let it be.
fn seed_frame_fits(job: &SeedJob, plan: &SeedPlan, merge: &serde_json::Value) -> bool {
    let stamps: Vec<Stamp> = plan.stamps_for(merge).collect();
    frame_fits_with(job, merge, &stamps)
}

/// [`seed_frame_fits`] with the stamps given.
fn frame_fits_with(job: &SeedJob, merge: &serde_json::Value, stamps: &[Stamp]) -> bool {
    let timeless = MeshDoc::new_ungated();
    let Ok(Some(change)) = timeless.build_change(merge, &job.actor) else {
        return true;
    };
    let time = Some(LARGEST_TIME);
    let plain = wire::change_body_tombstoned(&change, None, job.epoch, None, time, stamps, &[]);
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

/// Build the chain from `plan` on a blocking thread, and give back a handle. The event loop keeps
/// its timers and its sockets while the thread works. A browser has no thread to spare and a build
/// takes seconds, so a browser never cuts (see [`start_cut`]).
#[cfg(not(target_family = "wasm"))]
pub(crate) fn spawn_build(plan: SeedPlan, job: SeedJob) -> JoinHandle<SeedOutcome> {
    let build = move || {
        let started = Instant::now();
        let chain = plan.build(job.epoch, &job.actor, |merge| {
            seed_frame_fits(&job, &plan, merge)
        });
        SeedOutcome {
            epoch: job.epoch,
            chain,
            took: started.elapsed(),
        }
    };
    spawn_blocking(build)
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

/// Send frames in order: with `take_first` (a seed) each one is taken by this node as a candidate
/// first (it adopts its own seed after the wait, like every node), and then it goes to the overlay,
/// or waits in the buffer of a node that does not reach it yet. A send that fails stops the chain
/// and holds the next cut back. Returns how many frames went out.
pub(crate) async fn send_frames(
    state: &mut EventLoopState,
    sender: &MeshSender,
    frames: Vec<(Verified, WireFrame)>,
    take_first: bool,
) -> usize {
    let mut sent = 0;
    for (signed, bytes) in frames {
        if take_first {
            let _ = state.doc_mut(Channel::State).ingest(&signed);
        }
        if state.overlay_reachable() {
            if let Err(error) = sender.broadcast(bytes).await {
                cut_failed(state, &error);
                return sent;
            }
        } else if !buffer_frame(state, (signed, bytes)) {
            return sent;
        }
        sent += 1;
    }
    sent
}

/// Hold a frame for a node that the overlay does not reach yet. The buffer is bounded and shared
/// with the chat, and a full one refuses the new frame: for a seed that is a hole in the chain, so
/// the cut fails and the node does not go on with the rest.
fn buffer_frame(state: &mut EventLoopState, frame: (Verified, WireFrame)) -> bool {
    if state.pending_outbound.push(frame) {
        return true;
    }
    cut_failed(state, &"the buffer of outbound frames is full");
    false
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
    let chain = plan.build(job.epoch, &job.actor, |merge| {
        seed_frame_fits(&job, &plan, merge)
    })?;
    let outcome = SeedOutcome {
        epoch: job.epoch,
        chain: Ok(chain),
        took: started.elapsed(),
    };
    let frames = finish(state, Ok(outcome), me, mesh);
    Ok(send_frames(state, sender, frames, true).await)
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
    let switch = doc.tick_epoch(me);
    for key in doc.take_dropped() {
        state.seen.remove(&key);
    }
    // The writes that a seed lacks, and the restores that are due, wait for the loop to send them.
    let restores = state.doc_mut(Channel::State).take_restores();
    let replay = switch.and_then(|switch| {
        let stamps = switch.replay_stamps;
        switch.replay.map(|patch| (patch, stamps))
    });
    if let Some(item) = replay {
        queue_replay(state, item);
    }
    if let Some(item) = restores {
        queue_replay(state, item);
    }
    // A node that no peer reaches ranks 0 on an empty roster and would cut at once: its chain would
    // wait in the buffer, and the node would adopt a seed that no peer holds.
    if state.seed_job.is_some() || !state.overlay_reachable() {
        return;
    }
    let rank = rank_of(me, &state.peers, &state.quiet, epoch);
    if !state.doc(Channel::State).cut_due(rank) {
        return;
    }
    start_cut(state, me, mesh, epoch);
}

/// A browser never cuts: the build is one synchronous call of seconds, and the loop of a browser
/// has no other thread. The nodes of the host cut after their own slots, so a browser ranked ahead
/// of them costs the mesh a delay of one slot (2 ticks).
#[cfg(target_family = "wasm")]
fn start_cut(_state: &mut EventLoopState, _me: &Nickname, _mesh: &MeshId, _epoch: u64) {}

/// Read the document into a plan and start the build on another thread.
#[cfg(not(target_family = "wasm"))]
fn start_cut(state: &mut EventLoopState, me: &Nickname, mesh: &MeshId, epoch: u64) {
    let planned = state.doc(Channel::State).seed_plan();
    // A candidate that the node holds is adopted, not cut over.
    if matches!(planned, Err(DocError::CandidateHeld)) {
        return;
    }
    let plan = match planned {
        Ok(plan) => plan,
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

/// A closing digest of a peer for `channel` came in. It ends the wait of the state document for
/// its first sync when it came point-to-point and this node holds all of its heads: the peer
/// answered the request of this node (frames, then the closing heads, or the closing heads alone
/// when it had nothing to send), so every time that the peer has seen is in the history of this
/// node and its clock is above them. A plain request or a digest on gossip never ends the wait: a
/// node that only announces its heads has answered nobody. The deadline stays the outer bound.
pub(crate) fn closing_digest_seen(
    state: &mut EventLoopState,
    channel: Channel,
    heads: &[String],
    on_unicast: bool,
) {
    if channel != Channel::State || !on_unicast {
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
    if !doc.is_awaiting_first_sync() || Instant::now() < state.state_sync_deadline {
        return;
    }
    state.doc_mut(Channel::State).finish_sync();
    let limit_secs = tuning::state_sync_wait().as_secs();
    // A node with no peer (the first member of a topic, or a mesh that has not met yet) had nobody
    // to answer: that is no fault, so only a node with peers warns.
    if state.peers.is_empty() {
        tracing::info!(target: "habilis_network::gossip", limit_secs, "the node has no peer to sync the state channel with, so it writes with the clock that it has");
        return;
    }
    tracing::warn!(target: "habilis_network::gossip", limit_secs, "no peer answered the digest of the state channel within the time limit, so the node writes with the clock that it has; a write that it made before a restart can win against its new ones");
}

/// Put a replay or a restore in the queue that the loop drains after the tick. The queue is bounded:
/// when it is full the new item is refused, and the node warns. The document does not keep a
/// refused item (`take_restores` empties it), so a replay or a restore that is refused is a write
/// that the seed lacks and that no node sends: the warning is the signal. The loop drains the queue
/// on the arm of the tick, so a full queue is not expected.
fn queue_replay(state: &mut EventLoopState, item: (serde_json::Value, StampedPaths)) {
    if !state.replay_queue.push(item) {
        tracing::warn!(target: "habilis_network::gossip", "the replay of the state channel was dropped: its queue is full");
    }
}

/// The paths that a merge writes: its leaves and the objects that it makes.
fn merge_paths(merge: &serde_json::Value, prefix: &mut Vec<String>, paths: &mut Vec<Vec<String>>) {
    if let serde_json::Value::Object(fields) = merge
        && !fields.is_empty()
    {
        if !prefix.is_empty() {
            paths.push(prefix.clone());
        }
        for (key, inner) in fields {
            prefix.push(key.clone());
            merge_paths(inner, prefix, paths);
            prefix.pop();
        }
    } else if !prefix.is_empty() {
        paths.push(prefix.clone());
    }
}

/// Whether the frame of a replay `merge` fits a message: the stamp of each path is the one that
/// the replay names for it (the largest stamp for a path that it names none for).
fn replay_frame_fits(
    job: &SeedJob,
    merge: &serde_json::Value,
    known: &HashMap<&Vec<String>, &Stamp>,
) -> bool {
    let mut paths: Vec<Vec<String>> = Vec::new();
    merge_paths(merge, &mut Vec::new(), &mut paths);
    let mut stamps: Vec<Stamp> = Vec::with_capacity(paths.len());
    let worst = Stamp::new(LARGEST_TIME, "ffffffffffffffff".to_owned());
    for path in &paths {
        let named: Option<&&Stamp> = known.get(path);
        stamps.push(named.map_or_else(|| worst.clone(), |stamp| (*stamp).clone()));
    }
    frame_fits_with(job, merge, &stamps)
}

/// The signed frames that write `patch` again, with the stamps of the old epoch: the replay of the
/// writes that a seed lacks after a switch, or a restore. The patch is split into merges that each
/// fit a frame (all or none: a leaf that does not fit sends nothing and warns), and each merge is
/// built on the document as the last one left it and taken by it at once, so the frames follow
/// one another. A write that puts a value back is not refused at the lines of the state, only over
/// the memory line (`MeshDoc::build_restore`).
pub(crate) fn replay_frames(
    state: &mut EventLoopState,
    patch: &serde_json::Value,
    stamps: &StampedPaths,
    me: &Nickname,
    mesh: &MeshId,
) -> Vec<(Verified, WireFrame)> {
    let job = job_for(state, me, mesh, state.doc(Channel::State).epoch());
    let mut known: HashMap<&Vec<String>, &Stamp> = HashMap::with_capacity(stamps.len());
    for (path, stamp) in stamps {
        known.insert(path, stamp);
    }
    let split = state
        .doc(Channel::State)
        .split_replay(patch, |merge| replay_frame_fits(&job, merge, &known));
    let merges = match split {
        Ok(merges) => merges,
        Err(error) => {
            tracing::warn!(target: "habilis_network::gossip", %error, "a value of the replay of the state channel is too large for a frame, so the replay is not sent");
            return Vec::new();
        }
    };
    let mut frames: Vec<(Verified, WireFrame)> = Vec::new();
    for merge in merges {
        let doc = state.doc(Channel::State);
        let change = match doc.build_restore(&merge, &job.actor) {
            Ok(Some(change)) => change,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(target: "habilis_network::gossip", %error, "the replay of the state channel stopped: the document refused a frame of it");
                break;
            }
        };
        let body = match doc.compose_replay_body(&change, stamps) {
            Ok(body) => body,
            Err(error) => {
                tracing::warn!(target: "habilis_network::gossip", %error, "the replay of the state channel stopped: a frame of it does not compose");
                break;
            }
        };
        let signed =
            Message::new_channel_event(mesh, me, body, Channel::State).sign(&state.identity);
        let Ok(bytes) = signed.serialize() else {
            break;
        };
        let _ = state.doc_mut(Channel::State).ingest(&signed);
        frames.push((signed, bytes));
    }
    frames
}

/// Build and send what waits in the queue of the replays and the restores of the state channel.
pub(crate) async fn send_replays(
    state: &mut EventLoopState,
    sender: &MeshSender,
    me: &Nickname,
    mesh: &MeshId,
) {
    let waiting = state.replay_queue.take();
    for (patch, stamps) in waiting {
        let frames = replay_frames(state, &patch, &stamps, me, mesh);
        send_frames(state, sender, frames, false).await;
    }
}

/// The creator of a mesh has nothing to sync with: the mesh is new, so the node wrote nothing
/// before and its clock cannot be below an earlier write of its own. Its state document ends the
/// wait for the first sync at once. A node that joins keeps the wait (a restart is a join: only the
/// creating session holds the issuer key).
pub(crate) fn creator_has_nothing_to_sync(state: &mut EventLoopState, is_creator: bool) {
    // A wait of zero (a test that writes at once) ends at the start too.
    if is_creator || tuning::state_sync_wait().is_zero() {
        state.doc_mut(Channel::State).finish_sync();
    }
}

/// A cut that failed: the document holds the next one back, and the node warns once.
pub(crate) fn cut_failed(state: &mut EventLoopState, error: &impl Display) {
    state.state_cuts_failed = state.state_cuts_failed.saturating_add(1);
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
    // A seed came in while the build ran (or the epoch moved on): the rival rule can drop ours.
    let doc = state.doc(Channel::State);
    if doc.has_candidate() || doc.epoch() >= outcome.epoch {
        tracing::info!(target: "habilis_network::gossip", epoch = outcome.epoch, "the seed of the state channel is dropped: another seed came in during the build");
        return Vec::new();
    }
    state.doc(Channel::State).note_seed_built(&chain);
    let job = job_for(state, me, mesh, outcome.epoch);
    match signed_frames(&chain, &job) {
        Ok(frames) => {
            state.state_cuts = state.state_cuts.saturating_add(1);
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
        Instant, LARGEST_TIME, SeedJob, SeedOutcome, buffer_frame, closing_digest_seen,
        creator_has_nothing_to_sync, finish, frame_fits_with, queue_replay, rank_of, replay_frames,
        spawn_build, sync_deadline, tick,
    };
    use tokio::time::interval;

    use crate::daemon::state::{EventLoopState, Standing};
    use crate::doc::{DocError, Ingested, Limits, MeshDoc, Stamp};
    use crate::protocol::identity::Identity;
    use crate::protocol::messages::Verified;
    use crate::protocol::{Channel, MeshId, Message, Nickname};
    use crate::testing;
    use crate::util::bounded_fifo_set::BoundedFifoSet;
    use crate::util::tuning::PENDING_OUTBOUND_CAP;

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

    /// Write `merge` into `doc`, as `who`, and give the signed frame.
    fn write_merge(
        doc: &mut MeshDoc,
        identity: &Identity,
        who: &Nickname,
        merge: &Value,
    ) -> Verified {
        let mesh = MeshId::from("test");
        let built = doc.build_change(merge, identity.public().as_bytes());
        let change = built.expect("the merge applies").expect("a change");
        let (body, _plain) = doc.compose_wire_body(&change, None).expect("a body");
        let signed = Message::new_channel_event(&mesh, who, body, Channel::State).sign(identity);
        let outcome = doc.ingest(&signed);
        assert!(
            matches!(outcome, Ingested::Applied { .. }),
            "the frame applies"
        );
        signed
    }

    /// Write `count` leaves into `doc`, as `who`, one frame of 100, and give the frames.
    fn write_leaves(
        doc: &mut MeshDoc,
        identity: &Identity,
        who: &Nickname,
        count: usize,
    ) -> Vec<Verified> {
        let mut frames: Vec<Verified> = Vec::new();
        let mut done = 0;
        while done < count {
            let take = 100.min(count - done);
            let mut leaves = Map::new();
            for leaf in 0..take {
                leaves.insert(format!("l{:05}", done + leaf), json!(leaf % 10));
            }
            let merge = json!({ "live": Value::Object(leaves) });
            frames.push(write_merge(doc, identity, who, &merge));
            done += take;
        }
        frames
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
        // The build runs on a thread: the loop ticks for at least half of the time that it took,
        // however fast the machine builds. A build on the loop would give 1 tick.
        let expected = outcome.took.as_millis() / 10;
        assert!(
            u128::from(ticks) * 2 >= expected,
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
        assert_eq!(state.state_cuts, 1, "the cut is counted");
        assert_eq!(state.state_cuts_failed, 0, "and no cut failed");
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

    /// A rival root that came in while the build ran: the node holds a candidate, so its own seed
    /// of the same epoch would be dropped by the rival rule. It sends nothing and fails no cut.
    #[tokio::test(flavor = "current_thread")]
    async fn a_build_that_ends_after_a_rival_seed_came_in_gives_no_frame() {
        // Shared with the jobs that build on another thread.
        let identity = Arc::new(Identity::generate());
        // The rival signs with its own key, shared with the job that builds on another thread.
        let rival_identity = Arc::new(Identity::generate());
        let me = testing::nick("me");
        let mesh = MeshId::from("test");
        let mut cutter = MeshDoc::new_state(None);
        cutter.finish_sync();
        write_leaves(&mut cutter, &identity, &me, 300);
        let mut rival = testing::fresh_state();
        rival.identity = Arc::clone(&rival_identity);
        let rival_outcome = spawn_build(
            cutter.seed_plan().expect("a plan"),
            job_of(&rival_identity, 4),
        )
        .await;
        let rival_frames = finish(&mut rival, rival_outcome, &testing::nick("rival"), &mesh);
        let mut state = testing::fresh_state();
        state.state_doc = MeshDoc::new_state(None);
        state.doc_mut(Channel::State).finish_sync();
        let own = spawn_build(
            cutter.seed_plan().expect("a plan"),
            job_of(&state.identity, 4),
        );
        for (signed, _bytes) in &rival_frames {
            state.doc_mut(Channel::State).ingest(signed);
        }
        assert!(
            state.doc(Channel::State).has_candidate(),
            "the rival seed is a candidate"
        );
        let frames = finish(&mut state, own.await, &me, &mesh);
        assert!(
            frames.is_empty(),
            "the node does not send a seed that the rival rule can drop"
        );
        assert_eq!(state.state_cuts, 0, "it is no cut");
        assert_eq!(state.state_cuts_failed, 0, "and no failure");
    }

    /// A frame that the buffer of a cut-off node refuses is a seed with a hole: the cut fails, so
    /// the node does not adopt a chain that no peer holds whole.
    #[test]
    fn a_full_buffer_fails_the_cut_and_the_chain_stops() {
        let identity = Identity::generate();
        let me = testing::nick("me");
        let mut doc = MeshDoc::new_state(None);
        doc.finish_sync();
        let frame = write_merge(&mut doc, &identity, &me, &json!({ "a": 1 }));
        let bytes = frame.serialize().expect("a wire frame");
        let mut state = testing::fresh_state();
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "the cut of the state channel failed, and the next one waits",
        );
        let cap = PENDING_OUTBOUND_CAP;
        for _ in 0..cap {
            assert!(
                buffer_frame(&mut state, (frame.clone(), bytes.clone())),
                "room"
            );
        }
        assert_eq!(
            state.state_cuts_failed, 0,
            "a buffer with room fails no cut"
        );
        assert!(
            !buffer_frame(&mut state, (frame, bytes)),
            "a full buffer refuses the frame"
        );
        assert_eq!(state.state_cuts_failed, 1, "and the cut fails");
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
        assert_eq!(state.state_cuts_failed, 1, "the failed cut is counted");
        assert_eq!(state.state_cuts, 0, "and it is no cut");
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

        // A node that no peer reaches is rank 0 at once: it must not cut, or it holds the chain.
        tick(&mut state, &me, &mesh);
        assert!(
            state.seed_job.is_none(),
            "a node that the overlay does not reach starts no build"
        );
        state.standing.insert(Standing::Meshed);
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
        small.standing.insert(Standing::Meshed);
        let mut few = MeshDoc::new_state(None).limits(Limits::with_seed_frames(40));
        few.finish_sync();
        write_leaves(&mut few, &identity, &me, 300);
        small.state_doc = few;
        tick(&mut small, &me, &mesh);
        assert!(small.seed_job.is_none(), "a small document starts no build");

        let mut plain = testing::fresh_state();
        plain.state_doc = MeshDoc::new_ungated();
        tick(&mut plain, &me, &mesh);
        assert!(
            plain.seed_job.is_none(),
            "a state document with no state epochs starts no build"
        );
    }

    /// A state document that waits for its first sync, inside a state.
    fn state_that_waits_for_the_first_sync() -> EventLoopState {
        testing::fresh_state_that_waits()
    }

    #[test]
    fn a_closing_digest_on_unicast_with_heads_that_this_node_holds_ends_the_wait() {
        let mut state = state_that_waits_for_the_first_sync();
        assert!(
            state.doc(Channel::State).is_awaiting_first_sync(),
            "the node waits"
        );
        let mut peer = MeshDoc::new_state(None);
        peer.finish_sync();
        let written = write_merge(
            &mut peer,
            &state.identity,
            &testing::nick("peer"),
            &json!({ "a": 1 }),
        );
        state.doc_mut(Channel::State).ingest(&written);
        let ours: Vec<String> = state.doc(Channel::State).heads().collect();
        assert!(!ours.is_empty(), "the node holds a change");
        let unknown = vec!["3yMApqCuCjXDWPrbjfR5mjCPTHqFG8Pux1TxQrEM35jj".to_owned()];
        closing_digest_seen(&mut state, Channel::State, &unknown, true);
        assert!(
            state.doc(Channel::State).is_awaiting_first_sync(),
            "a peer that is ahead of this node (heads that it does not hold) does not end the wait"
        );
        closing_digest_seen(&mut state, Channel::Meta, &ours, true);
        assert!(
            state.doc(Channel::State).is_awaiting_first_sync(),
            "the heads of the meta channel say nothing of the clock of the state channel"
        );
        closing_digest_seen(&mut state, Channel::State, &ours, false);
        assert!(
            state.doc(Channel::State).is_awaiting_first_sync(),
            "a closing digest on gossip is not the answer to the request of this node"
        );
        closing_digest_seen(&mut state, Channel::State, &ours, true);
        assert!(
            !state.doc(Channel::State).is_awaiting_first_sync(),
            "a closing digest on unicast with heads that this node holds ends the wait"
        );
    }

    #[test]
    fn the_empty_answer_of_a_peer_that_had_nothing_to_send_ends_the_wait_only_on_unicast() {
        let mut state = state_that_waits_for_the_first_sync();
        closing_digest_seen(&mut state, Channel::State, &[], false);
        assert!(
            state.doc(Channel::State).is_awaiting_first_sync(),
            "empty heads on gossip are a node that announces itself: no answer"
        );
        closing_digest_seen(&mut state, Channel::State, &[], true);
        assert!(
            !state.doc(Channel::State).is_awaiting_first_sync(),
            "a peer that answered the request with nothing to send had its chance"
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
        state.peers.insert(testing::nick("peer"));
        sync_deadline(&mut state);
        assert!(
            state.doc(Channel::State).is_awaiting_first_sync(),
            "the deadline is 30 s from the start: a node that just started still waits"
        );
        state.state_sync_deadline = Instant::now();
        sync_deadline(&mut state);
        assert!(
            !state.doc(Channel::State).is_awaiting_first_sync(),
            "at the deadline the node writes with the clock that it has"
        );
    }

    /// A node with no peer at its deadline has nobody that did not answer: no warning (the guard of
    /// the test tracing fails a test on a WARN that it did not expect).
    #[test]
    fn a_node_with_no_peer_ends_the_wait_at_its_deadline_without_a_warning() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = state_that_waits_for_the_first_sync();
        state.state_sync_deadline = Instant::now();
        sync_deadline(&mut state);
        assert!(
            !state.doc(Channel::State).is_awaiting_first_sync(),
            "the node writes with the clock that it has"
        );
    }

    #[test]
    fn the_creator_of_a_mesh_writes_at_once_and_a_joiner_waits() {
        let mut creator = state_that_waits_for_the_first_sync();
        creator_has_nothing_to_sync(&mut creator, true);
        assert!(
            !creator.doc(Channel::State).is_awaiting_first_sync(),
            "the creator of a new mesh has nothing to sync with"
        );
        let mut joiner = state_that_waits_for_the_first_sync();
        creator_has_nothing_to_sync(&mut joiner, false);
        assert!(
            joiner.doc(Channel::State).is_awaiting_first_sync(),
            "a node that joins waits for its first sync"
        );
    }

    #[test]
    fn a_node_whose_wait_has_ended_has_nothing_to_wait_for_at_the_deadline() {
        let mut state = testing::fresh_state();
        state.state_sync_deadline = Instant::now();
        sync_deadline(&mut state);
        assert!(
            !state.doc(Channel::State).is_awaiting_first_sync(),
            "a node that already synced: no wait, no warning"
        );
    }

    /// The daemon builds its state document in one place, `EventLoopState::new`, and a node starts
    /// with state epochs on and the wait for the first sync (gate item 7: no node of this version
    /// has epochs off, so none writes a body with no time that another node would refuse).
    #[test]
    fn the_state_document_of_the_daemon_starts_with_epochs_and_the_wait_for_the_first_sync() {
        let state = testing::fresh_state_that_waits();
        let doc = state.doc(Channel::State);
        assert!(doc.has_state_epochs(), "the state channel has epochs");
        assert!(
            doc.is_awaiting_first_sync(),
            "and it waits for the first sync"
        );
        assert!(
            !state.doc(Channel::Meta).has_state_epochs(),
            "the meta channel is not a state channel: it keeps its own epochs"
        );
    }

    /// The leaves of a merge: a value that is not an object, or an empty object.
    fn count_leaves(merge: &Value) -> usize {
        match merge {
            Value::Object(fields) if !fields.is_empty() => {
                let mut leaves = 0;
                for field in fields.values() {
                    leaves += count_leaves(field);
                }
                leaves
            }
            Value::Object(_)
            | Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_)
            | Value::Array(_) => 1,
        }
    }

    /// The largest stamp for each leaf of a merge: the measure that the daemon used before it read
    /// the stamps of the plan.
    fn worst_stamps(merge: &Value) -> Vec<Stamp> {
        let mut stamps: Vec<Stamp> = Vec::new();
        for _ in 0..count_leaves(merge) {
            stamps.push(Stamp::new(LARGEST_TIME, "ffffffffffffffff".to_owned()));
        }
        stamps
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_frames_of_a_seed_measured_with_the_real_stamps_are_fewer_than_with_the_worst_stamp()
     {
        // Shared with the job that builds on another thread.
        let identity = Arc::new(Identity::generate());
        let me = testing::nick("me");
        let mut doc = MeshDoc::new_state(None);
        doc.finish_sync();
        write_leaves(&mut doc, &identity, &me, 3_000);
        let plan = doc.seed_plan().expect("a plan");
        let job = job_of(&identity, 1);
        let worst = plan
            .build(1, &job.actor, |merge| {
                frame_fits_with(&job, merge, &worst_stamps(merge))
            })
            .expect("the worst case builds");
        let real = spawn_build(plan, job_of(&identity, 1))
            .await
            .expect("the build ends");
        let real = real.chain.expect("the real build works");
        assert!(
            real.changes.len() < worst.changes.len(),
            "the real stamps give {} frames, the worst stamp gives {}",
            real.changes.len(),
            worst.changes.len()
        );
    }

    /// The frames of the seed that the document `peer` cuts in the epoch 4, signed by a cutter.
    async fn seed_frames_of(peer: &MeshDoc) -> Vec<Verified> {
        // Shared with the job that builds on another thread.
        let cutter = Arc::new(Identity::generate());
        let plan = peer.seed_plan().expect("a plan");
        let outcome = spawn_build(plan, job_of(&cutter, 4))
            .await
            .expect("the build ends");
        let chain = outcome.chain.expect("the seed is built");
        let frames = super::signed_frames(&chain, &job_of(&cutter, 4)).expect("the frames sign");
        let mut verified: Vec<Verified> = Vec::new();
        for (frame, _bytes) in frames {
            verified.push(frame);
        }
        verified
    }

    /// Tick the state channel of `state` 5 times, the wait of an adopter.
    fn tick_to_adoption(state: &mut EventLoopState, me: &Nickname, mesh: &MeshId) {
        for _ in 0..5 {
            tick(state, me, mesh);
        }
    }

    /// A node that wrote a value after the seed was cut writes it again after the switch, and a
    /// third node that took the seed and then the frames of the replay holds the same document.
    #[tokio::test(flavor = "current_thread")]
    async fn a_write_that_the_seed_lacks_is_sent_again_after_the_switch_and_another_node_takes_it()
    {
        let me = testing::nick("me");
        let mesh = MeshId::from("test");
        let mut state = testing::fresh_state();
        let identity = Arc::clone(&state.identity);
        let mut doc = MeshDoc::new_state(None);
        doc.finish_sync();
        let base = write_leaves(&mut doc, &identity, &me, 300);
        let mut peer = MeshDoc::new_state(None);
        peer.finish_sync();
        for frame in &base {
            peer.ingest(frame);
        }
        write_merge(&mut doc, &identity, &me, &json!({ "x": 7 }));
        state.state_doc = doc;
        let seed = seed_frames_of(&peer).await;
        for frame in &seed {
            state.doc_mut(Channel::State).ingest(frame);
        }
        tick_to_adoption(&mut state, &me, &mesh);
        assert_eq!(
            state.doc(Channel::State).epoch(),
            4,
            "the node adopted the seed"
        );
        let waiting = state.replay_queue.take();
        assert_eq!(
            waiting.len(),
            1,
            "the write that the seed lacks waits to be sent"
        );
        let (patch, stamps) = waiting.into_iter().next().expect("the replay");
        let frames = replay_frames(&mut state, &patch, &stamps, &me, &mesh);
        assert!(!frames.is_empty(), "the replay has a frame");
        let mut third = MeshDoc::new_state(None);
        third.finish_sync();
        for frame in &seed {
            third.ingest(frame);
        }
        let waiter = testing::nick("third");
        for _ in 0..5 {
            third.tick_epoch(&waiter);
        }
        for (frame, _bytes) in &frames {
            third.ingest(frame);
        }
        assert_eq!(
            third.to_json().get("x"),
            Some(&json!(7)),
            "the third node holds the write"
        );
        assert_eq!(
            third.to_json(),
            state.doc(Channel::State).to_json(),
            "the third node and the writer hold the same document"
        );
    }

    /// A node that holds the write of another node that the seed lacks writes it again as a
    /// restore, a few ticks after the author had its turn.
    #[tokio::test(flavor = "current_thread")]
    async fn a_holder_writes_again_what_the_seed_lacks_when_the_author_does_not() {
        let me = testing::nick("me");
        let mesh = MeshId::from("test");
        let mut state = testing::fresh_state();
        let own = Arc::clone(&state.identity);
        // Shared with the author that writes the value.
        let author_key = Arc::new(Identity::generate());
        let mut doc = MeshDoc::new_state(None);
        doc.finish_sync();
        let base = write_leaves(&mut doc, &own, &me, 300);
        let mut peer = MeshDoc::new_state(None);
        peer.finish_sync();
        for frame in &base {
            peer.ingest(frame);
        }
        let author = testing::nick("author");
        let from_author = frame_after(&doc, &author_key, &author, &json!({ "x": 7 }));
        doc.ingest(&from_author);
        state.state_doc = doc;
        let seed = seed_frames_of(&peer).await;
        for frame in &seed {
            state.doc_mut(Channel::State).ingest(frame);
        }
        tick_to_adoption(&mut state, &me, &mesh);
        let mut restored = None;
        for _ in 0..3 {
            tick(&mut state, &me, &mesh);
            restored = state.replay_queue.take().into_iter().next();
            if restored.is_some() {
                break;
            }
        }
        let (patch, stamps) = restored.expect("the holder restores the write within 3 ticks");
        let frames = replay_frames(&mut state, &patch, &stamps, &me, &mesh);
        let mut third = MeshDoc::new_state(None);
        third.finish_sync();
        for frame in &seed {
            third.ingest(frame);
        }
        for _ in 0..5 {
            third.tick_epoch(&testing::nick("third"));
        }
        for (frame, _bytes) in &frames {
            third.ingest(frame);
        }
        assert_eq!(
            third.to_json().get("x"),
            Some(&json!(7)),
            "the third node holds the value"
        );
    }

    /// The frame of `who` that writes `merge` on top of `doc`, with `identity`, not applied.
    fn frame_after(doc: &MeshDoc, identity: &Identity, who: &Nickname, merge: &Value) -> Verified {
        let mesh = MeshId::from("test");
        let built = doc.build_change(merge, identity.public().as_bytes());
        let change = built.expect("the merge applies").expect("a change");
        let (body, _plain) = doc.compose_wire_body(&change, None).expect("a body");
        Message::new_channel_event(&mesh, who, body, Channel::State).sign(identity)
    }

    #[test]
    fn the_queue_of_replays_holds_at_most_its_cap_when_it_is_fed_10_times_the_cap() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::gossip",
            "the replay of the state channel was dropped: its queue is full",
        );
        let mut state = testing::fresh_state();
        let cap = state.replay_queue.remaining();
        for index in 0..(10 * cap) {
            queue_replay(&mut state, (json!({ "k": index }), Vec::new()));
            assert!(
                state.replay_queue.len() <= cap,
                "{} items after {} pushes, the cap is {cap}",
                state.replay_queue.len(),
                index + 1
            );
        }
        assert_eq!(
            state.replay_queue.len(),
            cap,
            "the queue is full and refuses the rest"
        );
    }
}
