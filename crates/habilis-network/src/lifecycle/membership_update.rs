//! The **membership layer**: pure roster transitions. Decides what an
//! inbound message means for the peer roster (`peers` /
//! `quiet`) — first-sight, return-from-quiet, departure — without any
//! transport, presentation, or surfacing concern. See the Concept
//! Glossary in AGENTS.md for the layer split.

use crate::daemon::state::{EventLoopState, LiveRun, StepBack};
use crate::lifecycle::heartbeat;
use crate::protocol::{AuthorKey, MessageKind, PresenceSubtype, UnixSecs, Verified};
use crate::util::clock::Instant;
use crate::util::tuning::{self, ALIVE_INTERVAL};
use std::time::Duration;

/// Summary of how a newly received message changes our view of the
/// sender's membership. Computed from the message kind + current state
/// as a pure function; applied afterwards by the caller.
#[derive(Debug, Clone)]
pub(crate) struct MembershipUpdate {
    /// The sender was in `quiet` (evicted as silent) and this
    /// message proves they're back. Triggers `peer_return` output and
    /// re-inclusion in `peers`.
    pub returned: bool,
    /// This is the first time we've seen this author. Gates the
    /// state-file write and the `has joined` line (we suppress it
    /// when `returned` — we print `came back` instead).
    pub joined_new: bool,
    /// The message proves no presence: a key that said goodbye signed it, or it is a copy of a
    /// frame of a quiet peer that does not prove the peer is back. It adds the sender to nothing
    /// and surfaces no arrival.
    pub stale: bool,
}

/// Whether a frame proves that its author is alive now. A `left` never does. A frame of a live
/// kind does when it was stamped within the quiet TTL: after that time nothing remembers a silent
/// peer, so a relay can re-send its last frame as if it were news, and that frame is older than
/// the TTL. The bound is wide on purpose: a new peer with a slow clock still arrives on its first
/// live frame. A frame of any other kind (peer info, the durable state and meta changes, the
/// digests) does only when it was stamped within one alive timeout: a relay or an anti-entropy
/// answer re-sends stored frames of any author, a dead one too, and those are old. A frame
/// stamped within the timeout says that its author was alive within the timeout, which is all
/// that the timeout asks.
pub(crate) fn proves_presence(kind: &MessageKind, timestamp: UnixSecs) -> bool {
    let now = UnixSecs::now();
    // A stamp ahead of our clock by more than the quiet TTL is no clock skew of an honest peer: a
    // signed frame like that would pass the lower bound for as long as its stamp stays above it.
    if timestamp > now + heartbeat::QUIET_TTL {
        return false;
    }
    match kind {
        MessageKind::Presence {
            subtype: PresenceSubtype::Left,
        } => false,
        MessageKind::App { .. }
        | MessageKind::Presence {
            subtype: PresenceSubtype::Alive | PresenceSubtype::Joined,
        }
        | MessageKind::Ping
        | MessageKind::Pong { .. } => timestamp > now - heartbeat::QUIET_TTL,
        MessageKind::PeerInfo
        | MessageKind::State
        | MessageKind::Meta
        | MessageKind::Digest
        | MessageKind::StateDigest
        | MessageKind::MetaDigest
        | MessageKind::LinkState
        | _ => timestamp > now - tuning::alive_timeout(),
    }
}

/// Whether a frame is of a kind that a peer sends only while it runs: an app message, an
/// `alive`, a `joined`, a ping or a pong. A `left` is not.
pub(crate) fn is_live_kind(kind: &MessageKind) -> bool {
    match kind {
        MessageKind::App { .. }
        | MessageKind::Presence {
            subtype: PresenceSubtype::Alive | PresenceSubtype::Joined,
        }
        | MessageKind::Ping
        | MessageKind::Pong { .. } => true,
        MessageKind::Presence {
            subtype: PresenceSubtype::Left,
        }
        | MessageKind::PeerInfo
        | MessageKind::State
        | MessageKind::Meta
        | MessageKind::Digest
        | MessageKind::StateDigest
        | MessageKind::MetaDigest
        | MessageKind::LinkState
        | _ => false,
    }
}

/// Whether a frame stamped `timestamp` is stamped after the newest frame that we heard from the
/// quiet peer `key`. A copy of a frame that a relay held carries the stamp of that frame or an older
/// one, so it is not news. Both stamps come from the clock of the author, so a constant skew
/// between that clock and ours cancels. With no stamp on record every frame is news.
fn stamped_after_last_heard(key: AuthorKey, timestamp: UnixSecs, state: &EventLoopState) -> bool {
    state
        .peer_stamp
        .get(&key)
        .is_none_or(|newest| timestamp > *newest)
}

/// The number of frames that must rise in a row from a base below the newest stamp before a quiet
/// peer returns. One replayed frame, or one frame repeated, never gets there. Three is the least
/// that tells a clock that stepped back (a peer that keeps sending) from a relay that re-sends one
/// or two old frames.
const STEP_BACK_FRAMES: u8 = 3;

/// A frame of a quiet peer counts toward a step back only if it arrives this long after the last
/// one that counted, on our clock. A live peer sends a frame every alive interval, so half of it
/// is met in a second or two; a relay that answers an anti-entropy digest sends its frames in one
/// burst, so only the first counts.
pub(crate) fn step_back_spacing() -> Duration {
    ALIVE_INTERVAL / 2
}

/// A run is dropped when the next frame comes later than this after the one before, on our clock:
/// a live peer sends a frame every alive interval, so three intervals leave room for one lost
/// frame. A relay that re-sends old frames of a dead peer one by one, minutes apart, never keeps
/// a run alive.
fn step_back_window() -> Duration {
    ALIVE_INTERVAL * 3
}

/// Count a frame of the quiet peer `key` that proves presence but is stamped at or below the newest
/// stamp on record. The clock of the author may have stepped back (a laptop that woke, a clock
/// that was set right): then its stamps rise from a lower base and never pass the old stamp, which
/// would hide a live peer. When [`STEP_BACK_FRAMES`] frames, each stamped after the one before
/// and each arriving [`step_back_spacing`] after it, have counted, the old stamp is dropped and
/// the next check lets the peer return. Returns whether the run is complete.
fn note_step_back(key: AuthorKey, timestamp: UnixSecs, state: &mut EventLoopState) -> bool {
    let now = Instant::now();
    let start = StepBack {
        last: timestamp,
        at: now,
        count: 1,
    };
    let Some(run) = state.clock_evidence.step_back.get_mut(&key) else {
        state.clock_evidence.step_back.insert(key, start);
        return false;
    };
    // Frames that come far apart are not the stream of a live peer.
    if now.duration_since(run.at) > step_back_window() {
        *run = start;
        return false;
    }
    let rises = timestamp > run.last;
    let spaced = now.duration_since(run.at) >= step_back_spacing();
    if rises && spaced {
        run.last = timestamp;
        run.at = now;
        run.count += 1;
    }
    if run.count >= STEP_BACK_FRAMES {
        state.clock_evidence.step_back.remove(&key);
        return true;
    }
    false
}

/// Decide what a message from `author` means for our peer
/// tracking. Pure: takes `&` refs, no side effects.
///
/// `Left` never counts as a join (even on first sight), because a
/// farewell is not an arrival. Everything else (including `Alive`,
/// `Msg`, `PeerInfo`) participates in self-heal: if we
/// haven't seen the peer before, we treat the message as proof of
/// presence.
///
/// One rule decides a return: a quiet peer is back only when the frame proves presence (see
/// [`proves_presence`]) and is stamped after the newest frame heard from the peer (see
/// [`stamped_after_last_heard`]). Any other frame of a quiet peer is stale (see
/// [`MembershipUpdate::stale`]).
pub(crate) fn compute(
    kind: &MessageKind,
    key: AuthorKey,
    timestamp: UnixSecs,
    state: &EventLoopState,
) -> MembershipUpdate {
    let quiet = state.quiet.contains(&key);
    let proves_return =
        proves_presence(kind, timestamp) && stamped_after_last_heard(key, timestamp, state);
    if quiet && !proves_return {
        return MembershipUpdate {
            returned: false,
            joined_new: false,
            stale: true,
        };
    }
    let known = state.peers.contains(&key);
    let unseen = match kind {
        // A `Left` is explicit departure; durable state events never mark a
        // peer present either — anti-entropy backfill replays historical state
        // whose author may have long since left, and resurrecting them would
        // forge membership.
        MessageKind::Presence {
            subtype: PresenceSubtype::Left,
        }
        | MessageKind::State
        | MessageKind::Meta => false,
        MessageKind::App { .. }
        | MessageKind::Presence {
            subtype: PresenceSubtype::Alive | PresenceSubtype::Joined,
        }
        | MessageKind::PeerInfo
        | MessageKind::Digest
        | MessageKind::Ping
        | MessageKind::Pong { .. }
        | MessageKind::StateDigest
        | MessageKind::MetaDigest
        | MessageKind::LinkState
        | _ => !known,
    };
    // A first contact is an arrival only when the frame proves presence: an old durable frame
    // that a relay re-sends (a peer that left long ago, or after the quiet TTL) is no arrival.
    MembershipUpdate {
        returned: quiet,
        joined_new: unseen && proves_presence(kind, timestamp),
        stale: false,
    }
}

/// [`compute`] for a verified message, plus the one rule that needs the key's history: a message
/// signed by a key that said goodbye is stale at any timestamp. That includes a second copy of the
/// goodbye itself: the first one recorded the key. A key is minted per run, so a key that left never
/// speaks again, and nothing else is needed to tell a replay of an old run from a new one.
pub(crate) fn compute_for(message: &Verified, state: &EventLoopState) -> MembershipUpdate {
    if state.key_said_goodbye(message.key()) {
        return MembershipUpdate {
            returned: false,
            joined_new: false,
            stale: true,
        };
    }
    compute(&message.kind, message.key(), message.timestamp, state)
}

/// How far the stamps of a run may drift from our clock, from one counted frame to the next. The
/// stamps are whole seconds and a frame can wait in a queue, so a live peer is a few seconds off.
const RUN_PACE_TOLERANCE: Duration = Duration::from_secs(5);

/// Count a live frame that is stamped before our join. Say whether its sender is sending now. One such frame looks
/// like backlog. A run does not: [`STEP_BACK_FRAMES`] frames of one key, each arriving
/// [`step_back_spacing`] after the one before and no later than [`step_back_window`], with a
/// stamp that is later by the time that passed on our clock (within [`RUN_PACE_TOLERANCE`]). A
/// backlog burst arrives in one moment, a relay that answers a digest sends its frames in a burst
/// and not at the pace of the clock that made them, and a run that breaks starts again.
///
/// Limit: a relay that replays at least [`STEP_BACK_FRAMES`] frames of a peer that stopped, one by
/// one, in real time, shows that peer for up to one alive timeout. The step-back path has the
/// same limit.
pub(crate) fn note_live_run(message: &Verified, state: &mut EventLoopState) -> bool {
    if !is_live_kind(&message.kind) || !proves_presence(&message.kind, message.timestamp) {
        return false;
    }
    let now = Instant::now();
    let key = message.key();
    let start = LiveRun {
        last: message.timestamp,
        at: now,
        count: 1,
    };
    let Some(run) = state.clock_evidence.live_run.get_mut(&key) else {
        state.clock_evidence.live_run.insert(key, start);
        return false;
    };
    let waited = now.duration_since(run.at);
    if waited > step_back_window() {
        *run = start;
        return false;
    }
    if waited < step_back_spacing() {
        return run.count >= STEP_BACK_FRAMES;
    }
    let advanced = message
        .timestamp
        .as_secs()
        .saturating_sub(run.last.as_secs());
    let waited_secs: i64 = i64::try_from(waited.as_secs()).unwrap_or(i64::MAX);
    let at_our_pace = advanced.abs_diff(waited_secs) <= RUN_PACE_TOLERANCE.as_secs();
    if advanced < i64::try_from(step_back_spacing().as_secs()).unwrap_or(i64::MAX) || !at_our_pace {
        *run = start;
        return false;
    }
    run.last = message.timestamp;
    run.at = now;
    run.count = run.count.saturating_add(1).min(STEP_BACK_FRAMES);
    run.count >= STEP_BACK_FRAMES
}

/// [`compute_for`] for the receive path, which may also complete a step back (see
/// [`note_step_back`]): a live frame of a quiet peer, stale only because its stamp is not after
/// the newest one on record, that closes a run of rising frames drops the old stamp, and the
/// update is computed again. A key that said goodbye never returns this way.
pub(crate) fn compute_observed(message: &Verified, state: &mut EventLoopState) -> MembershipUpdate {
    let update = compute_for(message, state);
    let key = message.key();
    let steps_back: bool = update.stale
        && state.quiet.contains(&key)
        && !state.key_said_goodbye(key)
        && proves_presence(&message.kind, message.timestamp);
    if steps_back && note_step_back(key, message.timestamp, state) {
        state.peer_stamp.remove(&key);
        return compute_for(message, state);
    }
    update
}

/// Apply a membership update to the mutable state. Mirror of the
/// pure `compute`: all side effects live here so tests of `compute`
/// remain free of any mutation.
pub(crate) fn apply(update: &MembershipUpdate, key: AuthorKey, state: &mut EventLoopState) {
    if update.returned {
        state.quiet.remove(&key);
        // A peer that is back is not quiet any more: its old recency must not make the sweep read
        // it as a peer that outlived the quiet TTL.
        state.quiet_since.remove(&key);
        state.clock_evidence.quiet_aged.remove(&key);
        state.peers.insert(key);
    }
    if update.joined_new {
        state.peers.insert(key);
    }
    if update.returned || update.joined_new {
        state.write_peer_count();
        tracing::debug!(
            key = %key,
            returned = update.returned,
            joined_new = update.joined_new,
            peers = state.peers.len(),
            "roster changed"
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::daemon::state::EventLoopState;
    use crate::protocol::Nickname;
    use crate::testing::{fresh_state, nick, test_key};

    use crate::protocol::identity::Identity;
    use crate::protocol::{AuthorKey, MeshId, Message, Verified};

    use std::time::Duration;

    use crate::util::clock::Instant;

    use super::{
        MembershipUpdate, MessageKind, PresenceSubtype, STEP_BACK_FRAMES, UnixSecs, apply, compute,
        compute_for, compute_observed,
    };

    #[test]
    fn first_time_seeing_author_is_joined_new() {
        let _guard = ::habilis_network_test_tracing::init();
        let state = fresh_state();
        let update = compute(
            &MessageKind::app_broadcast("app_msg"),
            test_key("swift-cedar"),
            UnixSecs::now(),
            &state,
        );
        assert!(
            update.joined_new,
            "a first message from a new author is joined_new"
        );
        assert!(
            !update.returned,
            "a first message from a new author is not a return"
        );
    }

    #[test]
    fn known_author_is_not_joined_new() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.peer_for_test("swift-cedar");
        let update = compute(
            &MessageKind::app_broadcast("app_msg"),
            test_key("swift-cedar"),
            UnixSecs::from(0),
            &state,
        );
        assert!(!update.joined_new, "a known author is not joined_new");
        assert!(!update.returned, "a known author is not a return");
    }

    #[test]
    fn left_is_never_joined_new() {
        let _guard = ::habilis_network_test_tracing::init();
        let state = fresh_state();
        let update = compute(
            &MessageKind::Presence {
                subtype: PresenceSubtype::Left,
            },
            test_key("swift-cedar"),
            UnixSecs::from(0),
            &state,
        );
        assert!(!update.joined_new, "a left message is never joined_new");
    }

    #[test]
    fn quiet_peer_message_marks_returned() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.quiet_for_test("swift-cedar");
        let update = compute(
            &MessageKind::app_broadcast("app_msg"),
            test_key("swift-cedar"),
            UnixSecs::now(),
            &state,
        );
        assert!(
            update.returned,
            "a message from a quiet peer marks it returned"
        );
        assert!(
            update.joined_new,
            "a message from a quiet peer is joined_new too"
        ); // not in peers yet
    }

    #[test]
    fn alive_from_unknown_author_is_joined_new() {
        // Regression: Alive keepalives must self-heal membership.
        let _guard = ::habilis_network_test_tracing::init();
        let state = fresh_state();
        let update = compute(
            &MessageKind::Presence {
                subtype: PresenceSubtype::Alive,
            },
            test_key("swift-cedar"),
            UnixSecs::now(),
            &state,
        );
        assert!(
            update.joined_new,
            "an alive frame from an unknown author is joined_new"
        );
    }

    #[test]
    fn apply_inserts_into_peers_on_joined_new() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let update = MembershipUpdate {
            returned: false,
            joined_new: true,
            stale: false,
        };
        apply(&update, test_key("swift-cedar"), &mut state);
        assert!(
            state.peers.contains(&test_key("swift-cedar")),
            "applying a joined_new update inserts the peer"
        );
    }

    #[test]
    fn apply_removes_from_quiet_on_returned() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.quiet_for_test("swift-cedar");
        let update = MembershipUpdate {
            returned: true,
            joined_new: false,
            stale: false,
        };
        apply(&update, test_key("swift-cedar"), &mut state);
        assert!(
            !state.quiet.contains(&test_key("swift-cedar")),
            "applying a returned update removes the peer from quiet"
        );
        assert!(
            state.peers.contains(&test_key("swift-cedar")),
            "applying a returned update puts the peer in the roster"
        );
    }

    /// A quiet peer whose last frame we heard 100 s ago.
    fn quiet_since_100_secs() -> (EventLoopState, Nickname) {
        quiet_since_100_secs_of(test_key("swift-cedar"))
    }

    /// [`quiet_since_100_secs`] for the quiet peer with the key `key`.
    fn quiet_since_100_secs_of(key: AuthorKey) -> (EventLoopState, Nickname) {
        let who = nick("swift-cedar");
        let mut state = fresh_state();
        state.names.insert(key, who.clone());
        state.quiet.insert(key);
        let heard = Instant::now()
            .checked_sub(Duration::from_secs(100))
            .expect("the monotonic clock has run past 100 s since boot");
        state.quiet_since.insert(key, heard);
        // The newest stamp of the peer is the one of its last frame, on its own clock.
        state
            .peer_stamp
            .insert(key, UnixSecs::now() - Duration::from_secs(100));
        (state, who)
    }

    /// A quiet peer is back when a frame proves it is alive and was sent after its silence began.
    /// A copy that a relay held was sent before the silence, whatever its kind, and a frame of a
    /// durable kind proves life only when it is fresh.
    #[test]
    fn a_quiet_peer_returns_only_on_a_frame_sent_after_its_silence() {
        let _guard = ::habilis_network_test_tracing::init();
        let (state, who) = quiet_since_100_secs();
        let now = UnixSecs::now();
        let before = now - Duration::from_secs(200);

        for kind in [
            MessageKind::app_broadcast("app_msg"),
            MessageKind::Presence {
                subtype: PresenceSubtype::Alive,
            },
            MessageKind::PeerInfo,
            MessageKind::State,
            MessageKind::Meta,
            MessageKind::StateDigest,
            MessageKind::MetaDigest,
        ] {
            let back = compute(&kind, test_key(who.as_str()), now, &state);
            assert!(
                back.returned && !back.stale,
                "{kind:?} sent after the silence"
            );
            let copy = compute(&kind, test_key(who.as_str()), before, &state);
            assert!(
                copy.stale && !copy.returned && !copy.joined_new,
                "{kind:?} sent before the silence"
            );
        }
    }

    /// A copy of the last frame that we heard is not news, whatever the clock of its sender says.
    /// The copy carries the stamp of that frame, so it is not after the newest stamp on record,
    /// and a skew between the clock of the sender and ours cancels in the comparison.
    #[test]
    fn a_replay_of_the_last_frame_heard_does_not_return_a_quiet_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, who) = quiet_since_100_secs();
        let heard_at = UnixSecs::now() - Duration::from_secs(100);
        let alive = MessageKind::Presence {
            subtype: PresenceSubtype::Alive,
        };
        let stamps = [
            ("on time", heard_at),
            ("5 s ahead", heard_at + Duration::from_secs(5)),
            ("120 s ahead", heard_at + Duration::from_secs(120)),
            ("5 s behind", heard_at - Duration::from_secs(5)),
            ("120 s behind", heard_at - Duration::from_secs(120)),
        ];
        for (clock, stamp) in stamps {
            state.peer_stamp.insert(test_key(who.as_str()), stamp);
            let replay = compute(&alive, test_key(who.as_str()), stamp, &state);
            assert!(
                replay.stale && !replay.returned,
                "a replay of the last frame from a clock {clock}"
            );
        }
    }

    /// A first contact is an arrival only when the frame proves presence. A peer info or a digest
    /// that a relay re-sends from a peer that left an hour ago is no arrival.
    #[test]
    fn an_old_durable_frame_from_an_unknown_peer_is_no_arrival() {
        let _guard = ::habilis_network_test_tracing::init();
        let state = fresh_state();
        let who = nick("swift-cedar");
        let old = UnixSecs::now() - Duration::from_hours(2);
        for kind in [
            MessageKind::PeerInfo,
            MessageKind::StateDigest,
            MessageKind::MetaDigest,
            MessageKind::Digest,
        ] {
            let stale_copy = compute(&kind, test_key(who.as_str()), old, &state);
            assert!(
                !stale_copy.joined_new,
                "{kind:?} stamped 2 h ago made an arrival"
            );
            let fresh = compute(&kind, test_key(who.as_str()), UnixSecs::now(), &state);
            assert!(fresh.joined_new, "{kind:?} stamped now is an arrival");
        }
    }

    /// The clocks of two nodes differ, and the difference changes nothing: a replay is stale and a
    /// fresh frame returns a quiet peer, whether the clock of the peer runs 30 s ahead or behind.
    /// The skew is not a margin any more: the check compares two stamps of the clock of the peer.
    #[test]
    fn a_clock_30_secs_off_changes_nothing() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, who) = quiet_since_100_secs();
        let heard_at = UnixSecs::now() - Duration::from_secs(100);
        let alive = MessageKind::Presence {
            subtype: PresenceSubtype::Alive,
        };
        state
            .peer_stamp
            .insert(test_key(who.as_str()), heard_at + Duration::from_secs(30));
        let ahead = compute(
            &alive,
            test_key(who.as_str()),
            heard_at + Duration::from_secs(30),
            &state,
        );
        assert!(
            ahead.stale && !ahead.returned,
            "a replay from a clock 30 s ahead"
        );
        state
            .peer_stamp
            .insert(test_key(who.as_str()), heard_at - Duration::from_secs(30));
        let behind = compute(
            &MessageKind::Meta,
            test_key(who.as_str()),
            UnixSecs::now() - Duration::from_secs(30),
            &state,
        );
        assert!(
            behind.returned && !behind.stale,
            "a meta change from a clock 30 s behind"
        );
    }

    /// A sender whose clock runs 120 s ahead cannot make a replay of its last frame look like a
    /// return: the replay is stamped as the last frame was, and the stamp is not after itself.
    #[test]
    fn a_replay_from_a_clock_120_secs_ahead_is_stale() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, who) = quiet_since_100_secs();
        let heard_at = UnixSecs::now() - Duration::from_secs(100);
        let alive = MessageKind::Presence {
            subtype: PresenceSubtype::Alive,
        };
        state
            .peer_stamp
            .insert(test_key(who.as_str()), heard_at + Duration::from_secs(120));
        let replay = compute(
            &alive,
            test_key(who.as_str()),
            heard_at + Duration::from_secs(120),
            &state,
        );
        assert!(replay.stale && !replay.returned, "{replay:?}");
    }

    /// Known limit. A peer that sends only a durable frame (a meta change, a peer info) from a clock
    /// more than one alive timeout behind never proves life against our clock, so such a frame does
    /// not return it. The peer returns on its next `alive`, at most 30 s later.
    #[test]
    #[ignore = "known limit: a durable frame from a clock more than 90 s behind does not prove life; the peer returns on its next alive"]
    fn a_meta_change_from_a_clock_120_secs_behind_returns_a_quiet_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, who) = quiet_since_100_secs();
        state.peer_stamp.insert(
            test_key(who.as_str()),
            UnixSecs::now() - Duration::from_secs(100) - Duration::from_secs(120),
        );
        let update = compute(
            &MessageKind::Meta,
            test_key(who.as_str()),
            UnixSecs::now() - Duration::from_secs(120),
            &state,
        );
        assert!(update.returned && !update.stale, "{update:?}");
    }

    /// A sender whose clock runs 120 s behind stamps every frame 120 s old on our clock. A live
    /// frame still returns a quiet peer, because it is stamped after the last frame heard from that
    /// clock. A peer that sends only a meta change or a peer info (a durable kind, which proves
    /// life only within one alive timeout of our clock) returns on its next alive, 30 s later.
    #[test]
    fn a_live_frame_from_a_clock_120_secs_behind_returns_a_quiet_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, who) = quiet_since_100_secs();
        let heard_at = UnixSecs::now() - Duration::from_secs(100);
        state
            .peer_stamp
            .insert(test_key(who.as_str()), heard_at - Duration::from_secs(120));
        let alive = MessageKind::Presence {
            subtype: PresenceSubtype::Alive,
        };
        let update = compute(
            &alive,
            test_key(who.as_str()),
            UnixSecs::now() - Duration::from_secs(120),
            &state,
        );
        assert!(update.returned && !update.stale, "{update:?}");
    }

    /// An instant 20 s before `at`: the next frame of a live peer comes one alive interval later.
    fn back_20_secs(at: Instant) -> Instant {
        at.checked_sub(Duration::from_secs(20))
            .expect("the monotonic clock has run past 20 s since boot")
    }

    /// A quiet peer whose frame is signed by `by` and stamped `at`.
    fn live_frame(who: &Nickname, by: &Identity, at: UnixSecs) -> Verified {
        let mut message = Message::new_alive(&MeshId::from("test"), who);
        message.timestamp = at;
        message.sign(by)
    }

    /// The clock of a peer stepped back (a laptop woke, a clock was set right): the newest stamp on
    /// record is ahead of every new stamp. A peer that keeps sending frames that rise from the new
    /// base returns after `STEP_BACK_FRAMES` of them, each one alive interval apart, so it is not
    /// hidden until its stamps pass the old one. Tested for a step of 1 h and of 120 s.
    #[test]
    fn a_clock_that_stepped_back_returns_after_a_run_of_rising_frames() {
        let _guard = ::habilis_network_test_tracing::init();
        for step in [Duration::from_hours(1), Duration::from_secs(120)] {
            let by = Identity::generate();
            let (mut state, who) = quiet_since_100_secs_of(by.author_key());
            state
                .peer_stamp
                .insert(by.author_key(), UnixSecs::now() + step);
            for index in 0..STEP_BACK_FRAMES {
                let stamp = UnixSecs::now() + Duration::from_secs(u64::from(index) * 30);
                let update = compute_observed(&live_frame(&who, &by, stamp), &mut state);
                let counted = index + 1;
                if counted < STEP_BACK_FRAMES {
                    assert!(
                        update.stale && !update.returned,
                        "step {step:?}: frame {counted} of the run returned the peer"
                    );
                    // The next frame comes one alive interval later on our clock.
                    let run = state
                        .clock_evidence
                        .step_back
                        .get_mut(&by.author_key())
                        .expect("the run is on record");
                    run.at = back_20_secs(run.at);
                } else {
                    assert!(
                        update.returned && !update.stale,
                        "step {step:?}: the run of {STEP_BACK_FRAMES} frames did not return the peer: {update:?}"
                    );
                }
            }
            assert!(
                !state.peer_stamp.contains_key(&by.author_key()),
                "the old newest stamp is dropped when the peer returns"
            );
        }
    }

    /// A signed frame stamped far ahead of our clock would pass the lower bound for as long as its
    /// stamp stays above it, and put its author in the roster. The bound has an upper side as wide
    /// as the lower one: a frame stamped further ahead than the quiet TTL proves no presence.
    #[test]
    fn a_frame_stamped_far_in_the_future_proves_no_presence() {
        let _guard = ::habilis_network_test_tracing::init();
        let state = fresh_state();
        let who = nick("future-fern");
        let alive = MessageKind::Presence {
            subtype: PresenceSubtype::Alive,
        };
        for kind in [alive, MessageKind::PeerInfo] {
            let far = compute(
                &kind,
                test_key(who.as_str()),
                UnixSecs::now() + Duration::from_hours(2),
                &state,
            );
            assert!(
                !far.joined_new,
                "{kind:?} stamped 2 h ahead made an arrival"
            );
            let near = compute(
                &kind,
                test_key(who.as_str()),
                UnixSecs::now() + Duration::from_mins(50),
                &state,
            );
            assert!(
                near.joined_new,
                "{kind:?} stamped 50 min ahead is the clock of an honest peer"
            );
        }
    }

    /// What does not return a quiet peer whose newest stamp is ahead: one old frame, the same frame
    /// again and again, and a burst of different frames in one second (what a relay sends when it
    /// answers an anti-entropy digest). Only frames that rise and arrive one alive interval apart
    /// count.
    #[test]
    fn a_replay_does_not_pass_for_a_step_back() {
        let _guard = ::habilis_network_test_tracing::init();
        let by = Identity::generate();
        let (mut state, who) = quiet_since_100_secs_of(by.author_key());
        state
            .peer_stamp
            .insert(by.author_key(), UnixSecs::now() + Duration::from_hours(1));
        let one = live_frame(&who, &by, UnixSecs::now());
        for repeat in 0..10 {
            let update = compute_observed(&one, &mut state);
            assert!(
                update.stale && !update.returned,
                "the same frame, seen {} times, returned the peer",
                repeat + 1
            );
        }
        for index in 1..=10u64 {
            let stamp = UnixSecs::now() + Duration::from_secs(index * 30);
            let update = compute_observed(&live_frame(&who, &by, stamp), &mut state);
            assert!(
                update.stale && !update.returned,
                "burst frame {index}, with no spacing, returned the peer"
            );
        }
    }

    /// A slow series of replays is not a step back. A relay can re-send old frames of a dead peer
    /// at any time in the quiet hour. Frames that rise but come far apart on our clock are not
    /// the steady stream of a live peer, so each one starts the run again.
    #[test]
    fn a_slow_series_of_replays_does_not_return_a_dead_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let by = Identity::generate();
        let (mut state, who) = quiet_since_100_secs_of(by.author_key());
        state
            .peer_stamp
            .insert(by.author_key(), UnixSecs::now() + Duration::from_hours(1));
        for index in 0..STEP_BACK_FRAMES + 3 {
            let stamp = UnixSecs::now() + Duration::from_secs(u64::from(index) * 30);
            let update = compute_observed(&live_frame(&who, &by, stamp), &mut state);
            assert!(
                update.stale && !update.returned,
                "replay {index} of a slow series returned the peer"
            );
            if let Some(run) = state.clock_evidence.step_back.get_mut(&by.author_key()) {
                // The next replay comes 5 min later on our clock.
                run.at = run
                    .at
                    .checked_sub(Duration::from_mins(5))
                    .expect("the monotonic clock has run past 5 min since boot");
            }
        }
    }

    /// A key that said goodbye never returns through a run of rising frames.
    #[test]
    fn a_goodbye_is_not_undone_by_a_run_of_rising_frames() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut state, who) = quiet_since_100_secs();
        let by = Identity::generate();
        state.note_left(by.author_key());
        state.peer_stamp.insert(
            test_key(who.as_str()),
            UnixSecs::now() + Duration::from_hours(1),
        );
        for index in 0..STEP_BACK_FRAMES + 2 {
            let stamp = UnixSecs::now() + Duration::from_secs(u64::from(index) * 30);
            let update = compute_observed(&live_frame(&who, &by, stamp), &mut state);
            assert!(
                update.stale && !update.returned,
                "frame {index} of a key that said goodbye returned the peer"
            );
            if let Some(run) = state
                .clock_evidence
                .step_back
                .get_mut(&test_key(who.as_str()))
            {
                run.at = back_20_secs(run.at);
            }
        }
    }

    /// A goodbye is final for the key that said it, whatever the kind of the frame and whatever its
    /// timestamp says: a copy that was in flight when the peer left, or a replay, adds nothing.
    #[test]
    fn a_frame_of_a_key_that_said_goodbye_is_stale() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = MeshId::from("test");
        let who = nick("swift-cedar");
        let leaver = Identity::generate();
        let at = UnixSecs::from(1_000);
        let mut state = fresh_state();
        state.note_left(leaver.author_key());

        let mut frames = Vec::new();
        for kind in [
            MessageKind::Presence {
                subtype: PresenceSubtype::Joined,
            },
            MessageKind::PeerInfo,
            MessageKind::app_broadcast("app_msg"),
            MessageKind::Presence {
                subtype: PresenceSubtype::Alive,
            },
        ] {
            for stamp in [UnixSecs::from(990), at, UnixSecs::from(1_001)] {
                let mut message = Message::new_frame(&mesh, &who, kind.clone(), "".into());
                message.timestamp = stamp;
                frames.push((kind.clone(), stamp, message.sign(&leaver)));
            }
        }
        for (kind, stamp, frame) in frames {
            let update = compute_for(&frame, &state);
            assert!(
                update.stale && !update.joined_new,
                "{kind:?} stamped {stamp} of a key that said goodbye"
            );
        }
    }

    /// The goodbye of one key does not touch another key. A new run takes the nickname in the very
    /// second of the goodbye of the old run, and it is a real arrival.
    #[test]
    fn another_key_is_not_stale_after_a_goodbye() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = MeshId::from("test");
        let who = nick("swift-cedar");
        let at = UnixSecs::now();
        let mut state = fresh_state();
        state.note_left(Identity::generate().author_key());

        let mut joined = Message::new_joined(&mesh, &who);
        joined.timestamp = at;
        let update = compute_for(&joined.sign(&Identity::generate()), &state);
        assert!(
            !update.stale && update.joined_new,
            "a new key in the second of an old goodbye is an arrival: {update:?}"
        );
    }

    /// A second goodbye of one key (a copy that a peer still held) changes nothing: the key stays
    /// gone, and the first goodbye is the only one that the nickname loses its entry for.
    #[test]
    fn a_second_goodbye_of_one_key_is_stale() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = MeshId::from("test");
        let who = nick("swift-cedar");
        let leaver = Identity::generate();
        let mut state = fresh_state();
        let left = Message::new_left(&mesh, &who).sign(&leaver);
        assert!(
            !compute_for(&left, &state).stale,
            "the first goodbye of a key is not stale"
        );
        state.note_left(leaver.author_key());
        assert!(
            compute_for(&left, &state).stale,
            "a copy of the goodbye is stale"
        );
    }

    /// A key is minted per run, so once it has said goodbye nothing it signs is a presence, even
    /// when the timestamp lies after the goodbye. The nickname stays free for another key.
    #[test]
    fn a_key_that_said_goodbye_stays_gone_at_any_timestamp() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = MeshId::from("test");
        let who = nick("swift-cedar");
        let leaver = Identity::generate();
        let mut state = fresh_state();
        state.note_left(leaver.author_key());

        let replay = Message::new_joined(&mesh, &who).sign(&leaver);
        let update = compute_for(&replay, &state);
        assert!(update.stale && !update.joined_new, "a replay of the leaver");

        let newcomer = Message::new_joined(&mesh, &who).sign(&Identity::generate());
        let arrival = compute_for(&newcomer, &state);
        assert!(
            !arrival.stale && arrival.joined_new,
            "another key takes the nickname"
        );
    }
}
