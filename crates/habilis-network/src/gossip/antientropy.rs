//! Anti-entropy for the shared-state channels: a periodic digest of each
//! channel's automerge heads. A holder answers with the changes the asker lacks,
//! point-to-point to the linked neighbor that asked (see [`handle_state_digest`]).
//! Chat has no anti-entropy: a chat frame missed while partitioned is not recovered.

use crate::transport;
mod answered;
mod digest_trigger;
mod fast_rounds;
mod plane;
mod serve_budget;

use std::hash::{Hash as _, Hasher as _};

use crate::transport::MeshSender;
use serde::{Deserialize, Serialize};

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::protocol::messages::{Verified, WireFrame};
use crate::protocol::{AuthorKey, Channel, MeshId, Message, Nickname};
use crate::util::clock::Instant;
use crate::util::tuning;

use std::collections::hash_map;

pub(crate) use answered::Answered;
pub(crate) use digest_trigger::DigestTrigger;
pub(crate) use fast_rounds::FastRounds;
pub(crate) use plane::Plane;
pub(crate) use serve_budget::ServeBudget;
/// The state/meta anti-entropy digest body: this channel's automerge heads (Base58 change hashes).
/// Heads compactly represent the whole causal frontier, so a holder computes exactly what the
/// sender is missing in one step, with no windowing.
///
/// `closing` marks the heads that end a point-to-point answer: information on how far the holder
/// is, not a request. Left out when false, so a request's bytes and its heads key are what they
/// always were.
#[derive(Serialize, Deserialize)]
struct HeadsBody {
    heads: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    closing: bool,
}

/// Sweep both shared-state channels' anti-entropy digests (one tick).
///
/// Each digest advertises the channel's automerge heads — see
/// [`HeadsBody`] and [`handle_state_digest`]. Broadcast whenever the overlay
/// is reachable (see [`state_digest`]), even on an empty document, so a fresh
/// joiner advertises its empty frontier and gets backfilled.
pub(crate) async fn broadcast_state_digests(
    state: &mut EventLoopState,
    sender: &MeshSender,
    mesh: &MeshId,
    author: &Nickname,
    trigger: DigestTrigger,
) {
    let origin = DigestOrigin { mesh, author };
    broadcast_state_digest(state, sender, origin, Channel::State, trigger).await;
    broadcast_state_digest(state, sender, origin, Channel::Meta, trigger).await;
}

#[derive(Clone, Copy)]
struct DigestOrigin<'mesh> {
    mesh: &'mesh MeshId,
    author: &'mesh Nickname,
}

async fn broadcast_state_digest(
    state: &mut EventLoopState,
    sender: &MeshSender,
    origin: DigestOrigin<'_>,
    channel: Channel,
    trigger: DigestTrigger,
) {
    let now = Instant::now();
    if trigger == DigestTrigger::Event
        && (state.fast_rounds.active(channel, now)
            || state.fast_rounds.changed_recently(channel, now))
    {
        return;
    }
    let Some(digest) = state_digest(state, origin, channel) else {
        return;
    };
    state.idle.broadcasts += 1;
    tracing::debug!(me = %origin.author, ?channel, heads = heads_key(&digest), ?trigger, "broadcast a state digest on gossip");
    super::broadcast_msg(sender, &digest).await;
}

/// The signed heads digest for `channel`, or `None` while no gossip path can
/// carry it. Unlike the chat digest this does not wait for `meshed`: a node
/// whose only neighbor is the rendezvous relay still exchanges presence over
/// that link, so its documents must travel the same way. Gating on `meshed`
/// left two peers behind one relay with converged rosters and documents that
/// never met — a card published before anyone joined sat unadvertised until a
/// real-peer link happened to form, minutes later or never.
fn state_digest(
    state: &EventLoopState,
    origin: DigestOrigin<'_>,
    channel: Channel,
) -> Option<Verified> {
    heads_digest(state, origin, channel, false)
}

/// Our heads for `channel` as a digest frame, a request or, with `closing`,
/// the end of an answer.
fn heads_digest(
    state: &EventLoopState,
    origin: DigestOrigin<'_>,
    channel: Channel,
    closing: bool,
) -> Option<Verified> {
    if !state.overlay_reachable() {
        return None;
    }
    let heads: Vec<_> = state.doc(channel).heads().collect();
    let body = super::json_body(&HeadsBody { heads, closing })?;
    Some(
        Message::new_channel_digest(origin.mesh, origin.author, body, channel)
            .sign(&state.identity),
    )
}

/// Ask the author of `digest` directly for what we miss, when its heads show
/// it is ahead of us. The peer is remembered either way, so a retry can reach
/// it when this ask cannot go out or its answer is lost.
async fn ask_back(
    channel: Channel,
    digest: &Verified,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) {
    let decoded: serde_json::Result<HeadsBody> = serde_json::from_str(digest.body.as_str());
    let Ok(body) = decoded else {
        return;
    };
    if state.doc(channel).holds_heads(&body.heads) {
        return;
    }
    let key = digest.key();
    let now = Instant::now();
    state
        .fast_rounds
        .note_ahead(channel, key, digest.author.clone(), body.heads, now);
    if state.fast_rounds.may_ask(
        &key,
        channel,
        heads_key_of(state, channel),
        state.doc(channel).change_count(),
        now,
    ) {
        ask(channel, &key, &digest.author, state, context).await;
    } else {
        tracing::debug!(me = %context.author, peer = %digest.author, ?channel, "a peer is ahead, but a fast round waits");
    }
}

/// Our own heads key for `channel`, as a digest of ours would carry it (its
/// body is the heads JSON), without building and signing one.
fn heads_key_of(state: &EventLoopState, channel: Channel) -> u64 {
    let heads_list: Vec<_> = state.doc(channel).heads().collect();
    let heads = HeadsBody {
        heads: heads_list,
        closing: false,
    };
    let mut hasher = hash_map::DefaultHasher::new();
    serde_json::to_string(&heads)
        .unwrap_or_default()
        .hash(&mut hasher);
    hasher.finish()
}

/// Ask again when a round stalled: a request or its answer was lost, or the
/// peer refused us. Runs on a short timer; asks one peer that is still ahead
/// and reachable now, once nothing was asked for a retry interval.
pub(crate) async fn resume_fast_rounds(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    for channel in [Channel::State, Channel::Meta] {
        let now = Instant::now();
        let ahead = state.fast_rounds.ahead(channel);
        let doc = state.doc(channel);
        let held_peers = ahead.iter().filter(|peer| doc.holds_heads(&peer.heads));
        let held: Vec<&[String]> = held_peers.map(|peer| peer.heads.as_slice()).collect();
        let answerable = ahead
            .iter()
            .filter(|peer| transport::unicast_answer_target(&peer.key, state).is_some());
        let reachable: Vec<AuthorKey> = answerable.map(|peer| peer.key).collect();
        let ours = heads_key_of(state, channel);
        let target = state.fast_rounds.retry_target(
            channel,
            now,
            ours,
            |heads| held.contains(&heads),
            |key| reachable.contains(key),
        );
        let Some((key, author)) = target else {
            continue;
        };
        if ask(channel, &key, &author, state, context).await {
            tracing::debug!(me = %context.author, peer = %author, ?channel, "retried a fast round with a peer that is ahead");
        }
    }
}

/// Send our digest for `channel` to `author` point-to-point, if it is a linked
/// neighbor with a usable path. The caller decides whether the round allows
/// it. Returns whether it went out.
async fn ask(
    channel: Channel,
    key: &AuthorKey,
    author: &Nickname,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) -> bool {
    let Some(eid) = transport::unicast_answer_target(key, state) else {
        return false;
    };
    let origin = DigestOrigin {
        mesh: context.mesh,
        author: context.author,
    };
    let Some(ours) = state_digest(state, origin, channel) else {
        return false;
    };
    let ours_key = heads_key(&ours);
    let now = Instant::now();
    let Ok(bytes) = ours.serialize() else {
        return false;
    };
    if !state
        .unicast_pool
        .send_batch_in_background(eid, vec![bytes])
        .await
    {
        return false;
    }
    let changes = state.doc(channel).change_count();
    state
        .fast_rounds
        .note_asked(*key, channel, ours_key, changes, now);
    tracing::debug!(me = %context.author, peer = %author, ?channel, heads = ours_key, "asked a peer that is ahead for state directly (fast round)");
    true
}

/// A digest's heads as the serve budget keys them: its body is the heads. The
/// same heads in another order hash differently and get one more answer.
fn heads_key(digest: &Message) -> u64 {
    let mut hasher = hash_map::DefaultHasher::new();
    digest.body.as_str().hash(&mut hasher);
    hasher.finish()
}

/// Handle a received state digest: the sender advertised its automerge heads, so
/// re-send the signed change frames it is missing (`changes_since`), up to an
/// own resend budget; automerge's DAG collapses "what's missing" into one query.
/// The answer goes point-to-point to a linked neighbor (see
/// [`crate::transport::unicast_answer_target`]), else on gossip, where every
/// hop already holds these frames and pushing them costs a prune each; the
/// unicast plane also drops no message id as seen, so an evicted orphan can come
/// again at once. How often one asker is served is limited per channel and
/// plane by [`ServeBudget`], checked before the query; a digest with nothing
/// missing uses no serve.
pub(crate) async fn handle_state_digest(
    channel: Channel,
    message: &Verified,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) -> Answered {
    ask_back(channel, message, state, context).await;
    let decoded: serde_json::Result<HeadsBody> = serde_json::from_str(message.body.as_str());
    if decoded.is_ok_and(|body| body.closing) {
        return Answered::default();
    }
    let now = Instant::now();
    let heads = heads_key(message);
    let author = message.key();
    let serve = |plane| (author, channel, plane);
    let target = transport::unicast_answer_target(&author, state);
    let plane = if target.is_some() {
        Plane::Unicast
    } else {
        Plane::Gossip
    };
    // Before the query: a refused digest costs no `changes_since`.
    if !state.state_digest_serves.admits(&serve(plane), heads, now) {
        tracing::debug!(me = %context.author, author = %message.author, ?channel, ?plane, heads, "state digest ignored: this asker was served within the window");
        return Answered::default();
    }
    let missing = missing_frames(channel, message, state);
    let serialize = |frame: &Verified| frame.serialize().ok();
    let frames: Vec<WireFrame> = missing.iter().filter_map(serialize).collect();
    let mut answered = Answered::default();
    if frames.is_empty() {
        return answered;
    }
    let count = frames.len();
    // A point-to-point answer ends with our own heads: the asker compares them
    // with its document and asks again while it is behind (see `ask_back`).
    let origin = DigestOrigin {
        mesh: context.mesh,
        author: context.author,
    };
    let our_heads =
        heads_digest(state, origin, channel, true).and_then(|ours| ours.serialize().ok());
    let batch: Vec<WireFrame> = frames.iter().cloned().chain(our_heads).collect();
    let fallback: Option<&str> = match target {
        None => Some("asker has no proven endpoint that is a linked neighbor with a direct path"),
        Some(eid)
            if state
                .unicast_pool
                .send_batch_in_background(eid, batch)
                .await =>
        {
            None
        }
        Some(_) => Some(
            "the send could not start: a dial in flight, a dial cooldown, or a relay-only path",
        ),
    };
    if fallback.is_some() {
        if plane == Plane::Unicast
            && !state
                .state_digest_serves
                .admits(&serve(Plane::Gossip), heads, now)
        {
            tracing::debug!(me = %context.author, author = %message.author, ?channel, heads, "state digest ignored: the unicast send could not start and the gossip answers are used up for this window");
            return answered;
        }
        for bytes in frames {
            // A new name for each answer, as for the resend of a message (see `resend_one`).
            let answer = bytes.copy_with_resend_nonce(rand::random());
            let _ = context.sender.broadcast(answer).await;
        }
        answered.broadcast = count;
        state
            .state_digest_serves
            .note(serve(Plane::Gossip), heads, now);
    } else {
        answered.unicast = count;
        state
            .state_digest_serves
            .note(serve(Plane::Unicast), heads, now);
    }
    tracing::debug!(
        me = %context.author,
        asker = %message.author,
        ?channel,
        heads,
        unicast = answered.unicast,
        broadcast = answered.broadcast,
        on_gossip_because = fallback.unwrap_or("-"),
        "state anti-entropy: resent frames a peer lacked"
    );
    answered
}

/// The signed change frames the author of `digest` lacks on `channel`, up to
/// the resend budget, less the ones it signed itself: with heads we do not
/// hold we cannot tell what it has and send everything, but its own changes
/// it always has. Empty for an undecodable digest body.
fn missing_frames(channel: Channel, digest: &Verified, state: &EventLoopState) -> Vec<Verified> {
    let decoded: serde_json::Result<HeadsBody> = serde_json::from_str(digest.body.as_str());
    let Ok(body) = decoded else {
        return Vec::new();
    };
    state
        .doc(channel)
        .changes_since_not_by(
            &body.heads,
            Some(&digest.key()),
            tuning::antientropy_max_resend(),
        )
        .collect()
}

#[cfg(test)]
mod budget_tests {
    use crate::daemon::state::Standing;
    use std::time::Duration;

    use super::{FastRounds, Plane, ServeBudget};
    use crate::protocol::{AuthorKey, Channel};
    use crate::testing::{author_of, nick};
    use crate::util::clock::Instant;
    use crate::util::tuning::{
        self, ANTIENTROPY_SERVES_PER_WINDOW, FAST_ROUND_ACTIVE, FAST_ROUND_RETRY,
    };

    use crate::{protocol, testing, transport};
    use iroh::endpoint::presets;
    use iroh_gossip::{net, proto};
    fn key() -> (AuthorKey, Channel, Plane) {
        (author_of("asker"), Channel::State, Plane::Unicast)
    }

    #[test]
    fn the_serve_budget_takes_new_heads_up_to_its_count() {
        let _guard = ::habilis_network_test_tracing::init();
        let now = Instant::now();
        let mut budget = ServeBudget::default();
        let gossip = (author_of("asker"), Channel::State, Plane::Gossip);
        budget.note(gossip, 1, now);
        assert!(
            !budget.admits(&gossip, 2, now),
            "one gossip answer per window"
        );
        assert!(
            budget.admits(&key(), 1, now),
            "the budget admits a new head within its count"
        );
        budget.note(key(), 1, now);
        assert!(
            !budget.admits(&key(), 1, now),
            "the same heads again at once"
        );
        let retry = now + Duration::from_millis(250);
        assert!(
            budget.admits(&key(), 1, retry),
            "the same heads again after a lost answer"
        );
        for heads in 2..=ANTIENTROPY_SERVES_PER_WINDOW as u64 {
            assert!(budget.admits(&key(), heads, now), "new heads {heads}");
            budget.note(key(), heads, now);
        }
        assert!(
            !budget.admits(&key(), 99, now),
            "one more than {ANTIENTROPY_SERVES_PER_WINDOW} in a window"
        );
        let later = now + Duration::from_secs(6);
        assert!(budget.admits(&key(), 1, later), "a new window");
    }

    /// Every peer that showed heads we do not hold is remembered, linked or
    /// not, round or no round. When nothing was asked for a retry interval,
    /// one of them that is reachable now is asked, the round's own peer
    /// first; a peer whose heads we now hold is forgotten. One lost message
    /// then costs a retry interval, not a tick.
    #[test]
    fn a_peer_that_is_ahead_is_retried_once_asking_went_quiet() {
        let _guard = ::habilis_network_test_tracing::init();
        let now = Instant::now();
        let mut rounds = FastRounds::default();
        let channel = Channel::State;
        let early_heads = vec!["e".to_owned()];
        let alice_heads = vec!["a".to_owned()];
        rounds.note_ahead(channel, author_of("early"), nick("early"), early_heads, now);
        rounds.note_ahead(
            channel,
            author_of("alice"),
            nick("alice"),
            alice_heads.clone(),
            now,
        );
        rounds.note_asked(author_of("alice"), channel, 1, 0, now);
        let never_held = |_: &[String]| false;
        let all_reachable = |_: &AuthorKey| true;
        let moved = 2;
        let pick = |fast: &mut FastRounds,
                    at,
                    ours,
                    holds: &dyn Fn(&[String]) -> bool,
                    reachable: &dyn Fn(&AuthorKey) -> bool| {
            fast.retry_target(channel, at, ours, holds, reachable)
                .map(|(key, _)| key)
        };

        let soon = now + Duration::from_millis(100);
        assert_eq!(
            pick(&mut rounds, soon, moved, &never_held, &all_reachable),
            None,
            "asked moments ago"
        );
        let quiet = now + Duration::from_millis(500);
        assert_eq!(
            pick(&mut rounds, quiet, moved, &never_held, &all_reachable),
            Some(author_of("alice")),
            "the round's peer first, while it brings progress"
        );
        assert_eq!(
            pick(&mut rounds, quiet, 1, &never_held, &all_reachable),
            Some(author_of("early")),
            "no progress since the last ask: the next peer"
        );
        let alice_away = |key: &AuthorKey| *key != author_of("alice");
        assert_eq!(
            pick(&mut rounds, quiet, moved, &never_held, &alice_away),
            Some(author_of("early")),
            "else one reachable now"
        );
        let alice_held = |heads: &[String]| heads == alice_heads.as_slice();
        assert_eq!(
            pick(&mut rounds, quiet, moved, &alice_held, &all_reachable),
            Some(author_of("early")),
            "alice is no longer ahead"
        );
        let stale = now + Duration::from_secs(61);
        assert_eq!(
            pick(&mut rounds, stale, moved, &never_held, &all_reachable),
            None,
            "a peer noted a minute ago is forgotten"
        );
    }

    /// While a fast round runs, a digest an event sends waits, but the tick's
    /// goes out: when the round's peers never answer, the tick is the only
    /// thing left that asks the whole mesh.
    #[test]
    fn the_tick_digest_goes_out_while_a_fast_round_runs() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use super::{DigestTrigger, broadcast_state_digests};
            use crate::protocol::MeshId;

            let endpoint = iroh::Endpoint::builder(presets::Minimal)
                .bind()
                .await
                .expect("bind a local endpoint");
            let gossip = net::Gossip::builder().spawn(endpoint.clone());
            let topic = gossip
                .subscribe(proto::TopicId::from_bytes([5u8; 32]), vec![])
                .await
                .expect("subscribe to a peerless topic");
            let (gossip_sender, _receiver) = topic.split();
            let sender = transport::MeshSender::new(gossip_sender);
            let mut state = testing::fresh_state();
            state.standing.insert(Standing::Meshed);
            state
                .fast_rounds
                .note_asked(author_of("holder"), Channel::State, 1, 0, Instant::now());
            let (mesh, author) = (MeshId::from("test"), nick("late"));

            let before = state.idle.broadcasts;
            broadcast_state_digests(&mut state, &sender, &mesh, &author, DigestTrigger::Event)
                .await;
            assert_eq!(
                state.idle.broadcasts - before,
                1,
                "only the meta digest: state waits"
            );
            let before_tick = state.idle.broadcasts;
            broadcast_state_digests(&mut state, &sender, &mesh, &author, DigestTrigger::Tick).await;
            assert_eq!(
                state.idle.broadcasts - before_tick,
                2,
                "the tick sends both"
            );
            endpoint.close().await;
        });
    }

    /// A node that just got a change has a holder serving it, so a digest an
    /// event sends then waits: sent while the first answer arrives, it drew
    /// a second answer that overlapped the first. The tick still goes out.
    #[test]
    fn an_event_digest_waits_while_changes_arrive() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use super::{DigestTrigger, broadcast_state_digests};
            use crate::protocol::MeshId;

            let endpoint = iroh::Endpoint::builder(presets::Minimal)
                .bind()
                .await
                .expect("bind a local endpoint");
            let gossip = net::Gossip::builder().spawn(endpoint.clone());
            let topic = gossip
                .subscribe(proto::TopicId::from_bytes([6u8; 32]), vec![])
                .await
                .expect("subscribe to a peerless topic");
            let (gossip_sender, _receiver) = topic.split();
            let sender = transport::MeshSender::new(gossip_sender);
            let mut state = testing::fresh_state();
            state.standing.insert(Standing::Meshed);
            state
                .fast_rounds
                .note_change(Channel::State, Instant::now());
            let (mesh, author) = (MeshId::from("test"), nick("late"));

            let before = state.idle.broadcasts;
            broadcast_state_digests(&mut state, &sender, &mesh, &author, DigestTrigger::Event)
                .await;
            assert_eq!(
                state.idle.broadcasts - before,
                1,
                "only the meta digest: a state change just landed"
            );
            let before_tick = state.idle.broadcasts;
            broadcast_state_digests(&mut state, &sender, &mesh, &author, DigestTrigger::Tick).await;
            assert_eq!(
                state.idle.broadcasts - before_tick,
                2,
                "the tick sends both"
            );
            endpoint.close().await;
        });
    }

    /// The fast rounds compare our heads through two keys: the one stored
    /// when an ask goes out (the hash of the digest's body) and the one read
    /// back later (the hash of our heads). If they drift apart, every retry
    /// looks like progress and the pace and the turns stop working.
    #[test]
    fn our_heads_key_matches_the_key_of_our_digest() {
        use super::{DigestOrigin, heads_key, heads_key_of, state_digest};
        use crate::protocol::MeshId;

        let _guard = ::habilis_network_test_tracing::init();
        let mut state = testing::fresh_state();
        state.standing.insert(Standing::Meshed);
        let (mesh, author) = (MeshId::from("test"), nick("alice"));
        let seed = *state.identity.public().as_bytes();
        let state_doc = state.doc(Channel::State);
        let change = state_doc
            .build_change(&serde_json::json!({ "k": 1 }), &seed)
            .expect("a JSON object merges")
            .expect("a non-empty merge yields a change");
        let (wire, _plain) = state
            .doc(Channel::State)
            .compose_wire_body(&change, None)
            .expect("compose the wire body");
        let frame = protocol::Message::new_channel_event(&mesh, &author, wire, Channel::State)
            .sign(&state.identity);
        let _ = state.doc_mut(Channel::State).ingest(&frame);
        let origin = DigestOrigin {
            mesh: &mesh,
            author: &author,
        };
        let digest = state_digest(&state, origin, Channel::State).expect("a digest");
        assert_eq!(
            heads_key_of(&state, Channel::State),
            heads_key(&digest),
            "our heads key matches the key of our digest"
        );
    }

    /// Under load an answer's frames arrive over more than the wait, and an
    /// ask sent while they arrive draws an answer that overlaps it. The wait
    /// counts from the last change that landed, not only from the ask.
    #[test]
    fn a_round_waits_while_an_answers_frames_still_arrive() {
        let _guard = ::habilis_network_test_tracing::init();
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let state = Channel::State;
        let mut rounds = FastRounds::default();
        rounds.note_ahead(
            state,
            author_of("alice"),
            nick("alice"),
            vec!["a".to_owned()],
            t0,
        );
        rounds.note_asked(author_of("alice"), state, 1, 0, t0);
        rounds.note_change(state, t0 + ms(150));
        assert!(
            !rounds.may_ask(&author_of("alice"), state, 1, 0, t0 + ms(250)),
            "the same heads 100 ms after a change"
        );
        rounds.note_change(state, t0 + ms(300));
        let retry = |fast: &mut FastRounds, at| {
            fast.retry_target(state, at, 1, |_| false, |_| true)
                .map(|(key, _)| key)
        };
        assert_eq!(
            retry(&mut rounds, t0 + ms(450)),
            None,
            "150 ms after a change"
        );
        assert_eq!(
            retry(&mut rounds, t0 + ms(750)),
            Some(author_of("alice")),
            "quiet for 450 ms"
        );
    }

    /// A steady stream of changes, such as live writes, must not hold a stalled
    /// round forever: the wait is capped at `FAST_ROUND_ACTIVE` after the ask.
    #[test]
    fn the_wait_after_changes_is_capped() {
        let _guard = ::habilis_network_test_tracing::init();
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let state = Channel::State;
        let mut rounds = FastRounds::default();
        rounds.note_ahead(
            state,
            author_of("alice"),
            nick("alice"),
            vec!["a".to_owned()],
            t0,
        );
        rounds.note_asked(author_of("alice"), state, 1, 0, t0);
        let later = t0 + FAST_ROUND_ACTIVE + FAST_ROUND_RETRY;
        let mut at = t0;
        while at < later {
            rounds.note_change(state, at);
            at += ms(100);
        }
        let target = rounds
            .retry_target(state, later, 1, |_| false, |_| true)
            .map(|(key, _)| key);
        assert_eq!(
            target,
            Some(author_of("alice")),
            "the wait after changes is capped for the alice author"
        );
    }

    #[test]
    fn a_fast_round_waits_for_a_full_answer_or_the_interval() {
        let _guard = ::habilis_network_test_tracing::init();
        let now = Instant::now();
        let full = tuning::antientropy_max_resend();
        let mut rounds = FastRounds::default();
        let state = Channel::State;
        assert!(
            rounds.may_ask(&author_of("holder"), state, 1, 0, now),
            "a fast round may ask the holder before its answer is due"
        );
        rounds.note_asked(author_of("holder"), state, 1, 0, now);
        assert!(
            rounds.active(state, now),
            "a fast round is active on the state channel"
        );
        assert!(
            !rounds.active(Channel::Meta, now),
            "a fast round is not active on the meta channel"
        );
        assert!(
            !rounds.may_ask(&author_of("holder"), state, 1, 0, now),
            "the same heads at once"
        );
        assert!(
            !rounds.may_ask(&author_of("holder"), state, 2, 5, now),
            "new heads after a partial answer wait"
        );
        assert!(
            rounds.may_ask(&author_of("holder"), state, 2, full, now),
            "new heads after a full answer at once"
        );
        assert!(
            !rounds.may_ask(&author_of("other"), state, 2, full, now),
            "another peer while the round runs"
        );
        assert!(
            rounds.may_ask(&author_of("other"), Channel::Meta, 2, full, now),
            "another channel"
        );
        let later = now + Duration::from_millis(250);
        assert!(
            rounds.may_ask(&author_of("holder"), state, 1, 0, later),
            "the same heads after the interval"
        );
        let quiet = now + Duration::from_secs(2);
        assert!(
            !rounds.active(state, quiet),
            "a fast round is no longer active after the quiet interval"
        );
        assert!(
            rounds.may_ask(&author_of("other"), state, 2, full, quiet),
            "another peer once the round is quiet"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{DigestOrigin, HeadsBody, missing_frames, state_digest};
    use crate::daemon::state::{EventLoopState, RendezvousFlag, Standing};
    use crate::doc::Ingested;
    use crate::protocol::{Channel, Identity, MeshId, Message, MessageBody, Nickname};
    use crate::testing::{fresh_state, nick};
    use crate::util::consts;

    /// A node whose only gossip neighbor is the rendezvous relay: linked to it,
    /// never to a real peer.
    fn rendezvous_only() -> EventLoopState {
        let mut state = fresh_state();
        state.standing.remove(&Standing::Meshed);
        state.rendezvous_flags.insert(RendezvousFlag::Linked);
        state
    }

    /// Apply a meta merge locally the way `broadcast_state_merge` does, minus
    /// the wire: build, sign, ingest. What the doc holds afterwards is exactly
    /// what anti-entropy can re-serve.
    fn publish_meta(
        state: &mut EventLoopState,
        mesh: &MeshId,
        author: &Nickname,
        merge: &serde_json::Value,
    ) {
        let seed = *state.identity.public().as_bytes();
        let meta_doc = state.doc(Channel::Meta);
        let change = meta_doc
            .build_change(merge, &seed)
            .expect("a JSON object merges")
            .expect("a non-empty merge yields a change");
        let (wire, _plain) = state
            .doc(Channel::Meta)
            .compose_wire_body(&change, None)
            .expect("compose the wire body");
        let frame =
            Message::new_channel_event(mesh, author, wire, Channel::Meta).sign(&state.identity);
        assert!(
            matches!(
                state.doc_mut(Channel::Meta).ingest(&frame),
                Ingested::Applied { .. }
            ),
            "a locally-built change applies"
        );
    }

    /// One anti-entropy round on the meta channel, from `joiner`'s side:
    /// `joiner` advertises its heads, `holder` re-serves every change frame
    /// the digest shows missing, `joiner` ingests them. Returns how many frames
    /// travelled, or `None` when `joiner` sent no digest at all.
    fn round(
        joiner: &mut EventLoopState,
        joiner_nick: &Nickname,
        holder: &EventLoopState,
        mesh: &MeshId,
    ) -> Option<usize> {
        let origin = DigestOrigin {
            mesh,
            author: joiner_nick,
        };
        let digest = state_digest(joiner, origin, Channel::Meta)?;
        let frames = missing_frames(Channel::Meta, &digest, holder);
        for frame in &frames {
            joiner.doc_mut(Channel::Meta).ingest(frame);
        }
        Some(frames.len())
    }

    /// The scenario behind the fix: A publishes its meta card while alone on
    /// the mesh, B joins later, and the two only ever share the rendezvous
    /// relay as a gossip neighbor (`meshed` never flips on either side). B's
    /// meta doc must converge to A's within two anti-entropy rounds.
    #[test]
    fn late_joiner_converges_meta_over_a_rendezvous_only_link() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = MeshId::from("test");
        let alice_nick = nick("alice");
        let bob_nick = nick("bob");
        let mut alice = rendezvous_only();
        publish_meta(
            &mut alice,
            &mesh,
            &alice_nick,
            &serde_json::json!({"peers": {"alice": {"status": "idle", "model": "m"}}}),
        );
        let mut bob = rendezvous_only();
        let bob_heads: Vec<_> = bob.doc(Channel::Meta).heads().collect();
        let alice_heads: Vec<_> = alice.doc(Channel::Meta).heads().collect();
        assert_ne!(bob_heads, alice_heads, "bob joins knowing nothing");

        // Round 1: bob's empty frontier pulls alice's change; alice's digest
        // finds nothing bob holds that she lacks.
        let served = round(&mut bob, &bob_nick, &alice, &mesh)
            .expect("a rendezvous-only joiner still advertises its heads");
        assert_eq!(served, 1, "bob lacked exactly alice's one change");
        assert_eq!(
            round(&mut alice, &alice_nick, &bob, &mesh),
            Some(0),
            "alice lacks nothing"
        );
        let bob_after: Vec<_> = bob.doc(Channel::Meta).heads().collect();
        let alice_after: Vec<_> = alice.doc(Channel::Meta).heads().collect();
        assert_eq!(bob_after, alice_after, "converged within one round");
        assert_eq!(
            bob.doc(Channel::Meta).to_json(),
            alice.doc(Channel::Meta).to_json(),
            "the late joiner converges meta to the same document"
        );

        // Round 2 is a no-op: nothing left to serve either way.
        assert_eq!(
            round(&mut bob, &bob_nick, &alice, &mesh),
            Some(0),
            "bob's round over the rendezvous answers as expected"
        );
        assert_eq!(
            round(&mut alice, &alice_nick, &bob, &mesh),
            Some(0),
            "alice's round over the rendezvous answers as expected"
        );
    }

    /// The gate itself: a digest goes out when a real peer *or* the rendezvous
    /// relay is linked, and stays silent with no neighbor at all — or while
    /// degraded, when the overlay is suspected dead.
    #[test]
    fn state_digest_needs_some_gossip_path() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = MeshId::from("test");
        let author = nick("alice");
        let origin = DigestOrigin {
            mesh: &mesh,
            author: &author,
        };
        let mut state = fresh_state();
        state.standing.remove(&Standing::Meshed);
        state.rendezvous_flags.remove(&RendezvousFlag::Linked);
        assert!(
            state_digest(&state, origin, Channel::Meta).is_none(),
            "no neighbor: nobody to advertise to"
        );

        state.rendezvous_flags.insert(RendezvousFlag::Linked);
        assert!(
            state_digest(&state, origin, Channel::Meta).is_some(),
            "a rendezvous-only link carries the digest"
        );

        state.note_degraded();
        assert!(
            state_digest(&state, origin, Channel::Meta).is_none(),
            "degraded: the relay link is no proof the overlay is alive"
        );

        state.rendezvous_flags.remove(&RendezvousFlag::Linked);
        state.standing.insert(Standing::Meshed);
        state.standing.remove(&Standing::Degraded);
        assert!(
            state_digest(&state, origin, Channel::State).is_some(),
            "meshed, as before"
        );
    }

    /// A state/meta heads digest round-trips and stays tiny — automerge heads are
    /// a bounded frontier (a handful of 32-byte hashes), so unlike the windowed
    /// chat digest there is no overflow risk as the doc's history grows.
    #[test]
    fn state_heads_digest_round_trips_and_is_small() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = MeshId::from(
            "6bLvZNPGxuqnsbaPVGwf277NyTp8cYPCMiBxXED8d6TyBZpDDzZADkKHL7tTB1EjFagbCXYZ",
        );
        let author = Nickname::from("a-fairly-long-nickname");
        let heads: Vec<String> = (0..4u8)
            .map(|seed| bs58::encode([seed; 32]).into_string())
            .collect();
        let json = serde_json::to_string(&HeadsBody {
            heads: heads.clone(),
            closing: false,
        })
        .expect("serialize heads body");
        let back: HeadsBody = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(
            back.heads, heads,
            "the state heads digest round trips to the same heads"
        );

        let body = MessageBody::try_new(&json).expect("heads body has no control chars");
        let digest = Message::new_state_digest(&mesh, &author, body).sign(&Identity::generate());
        let wire = digest.serialize().expect("serialize state digest");
        assert!(
            wire.len() <= consts::MAX_MESSAGE_SIZE,
            "heads digest is {} bytes, over the {}-byte gossip cap",
            wire.len(),
            consts::MAX_MESSAGE_SIZE
        );
    }
}
