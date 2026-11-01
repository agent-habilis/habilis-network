//! The **membership layer**: pure roster transitions. Decides what an
//! inbound message means for the peer roster (`peers` /
//! `quiet`) — first-sight, return-from-quiet, departure — without any
//! transport, presentation, or surfacing concern. See the Concept
//! Glossary in AGENTS.md for the layer split.

use crate::daemon::state::EventLoopState;
use crate::protocol::{MessageKind, Nickname, PresenceSubtype, UnixSecs, Verified};
use crate::util::clock::Instant;

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

/// Whether a frame of this kind can prove that its author is alive now. A relay or an
/// anti-entropy answer re-sends stored frames of any author, a dead one too: the peer info, the
/// durable state and meta changes, and the digests. Those prove nothing about the present.
pub(crate) const fn proves_presence(kind: &MessageKind) -> bool {
    matches!(
        kind,
        MessageKind::App { .. }
            | MessageKind::Presence {
                subtype: PresenceSubtype::Alive | PresenceSubtype::Joined
            }
            | MessageKind::Ping
            | MessageKind::Pong { .. }
    )
}

/// Whether a frame stamped `timestamp` was sent before we last heard from the quiet `author`.
/// Such a frame is a copy that a relay held, not news: the author sent nothing after it.
fn sent_before_silence(author: &Nickname, timestamp: UnixSecs, state: &EventLoopState) -> bool {
    state
        .quiet_since
        .get(author)
        .is_some_and(|heard| timestamp <= UnixSecs::now() - Instant::now().duration_since(*heard))
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
/// One rule decides a return: a quiet peer is back only when the frame is of a kind that proves
/// presence (see [`proves_presence`]) and was sent after we last heard from the peer. Any other
/// frame of a quiet peer is stale (see [`MembershipUpdate::stale`]).
pub(crate) fn compute(
    kind: &MessageKind,
    author: &Nickname,
    timestamp: UnixSecs,
    state: &EventLoopState,
) -> MembershipUpdate {
    let quiet = state.quiet.contains(author.as_str());
    let proves_return = proves_presence(kind) && !sent_before_silence(author, timestamp, state);
    if quiet && !proves_return {
        return MembershipUpdate {
            returned: false,
            joined_new: false,
            stale: true,
        };
    }
    let known = state.peers.contains(author.as_str());
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
    MembershipUpdate {
        returned: quiet,
        joined_new: unseen,
        stale: false,
    }
}

/// [`compute`] for a verified message, plus the one rule that needs the key: a message signed
/// by a key that said goodbye is stale at any timestamp. That includes a second copy of the
/// goodbye itself: the first one recorded the key, and a copy must not read as the return of
/// whoever holds the nickname now.
pub(crate) fn compute_for(message: &Verified, state: &EventLoopState) -> MembershipUpdate {
    if state.key_said_goodbye(message.key()) {
        return MembershipUpdate {
            returned: false,
            joined_new: false,
            stale: true,
        };
    }
    compute(&message.kind, &message.author, message.timestamp, state)
}

/// Apply a membership update to the mutable state. Mirror of the
/// pure `compute`: all side effects live here so tests of `compute`
/// remain free of any mutation.
pub(crate) fn apply(update: &MembershipUpdate, author: &Nickname, state: &mut EventLoopState) {
    if update.returned {
        state.quiet.remove(author.as_str());
        state.peers.insert(author.clone());
    }
    if update.joined_new {
        state.peers.insert(author.clone());
    }
    if update.returned || update.joined_new {
        state.write_peer_count();
        tracing::debug!(
            nickname = %author,
            returned = update.returned,
            joined_new = update.joined_new,
            peers = state.peers.len(),
            "roster changed"
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::{fresh_state, nick};

    use crate::protocol::identity::Identity;
    use crate::protocol::{MeshId, Message};

    use std::time::Duration;

    use crate::util::clock::Instant;

    use super::{
        MembershipUpdate, MessageKind, PresenceSubtype, UnixSecs, apply, compute, compute_for,
    };

    #[test]
    fn first_time_seeing_author_is_joined_new() {
        let _guard = ::habilis_network_test_tracing::init();
        let state = fresh_state();
        let update = compute(
            &MessageKind::app_broadcast("app_msg"),
            &nick("swift-cedar"),
            UnixSecs::from(0),
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
        state.peers.insert(nick("swift-cedar"));
        let update = compute(
            &MessageKind::app_broadcast("app_msg"),
            &nick("swift-cedar"),
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
            &nick("swift-cedar"),
            UnixSecs::from(0),
            &state,
        );
        assert!(!update.joined_new, "a left message is never joined_new");
    }

    #[test]
    fn quiet_peer_message_marks_returned() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.quiet.insert(nick("swift-cedar"));
        let update = compute(
            &MessageKind::app_broadcast("app_msg"),
            &nick("swift-cedar"),
            UnixSecs::from(0),
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
            &nick("swift-cedar"),
            UnixSecs::from(0),
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
        apply(&update, &nick("swift-cedar"), &mut state);
        assert!(
            state.peers.contains("swift-cedar"),
            "applying a joined_new update inserts the peer"
        );
    }

    #[test]
    fn apply_removes_from_quiet_on_returned() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.quiet.insert(nick("swift-cedar"));
        let update = MembershipUpdate {
            returned: true,
            joined_new: false,
            stale: false,
        };
        apply(&update, &nick("swift-cedar"), &mut state);
        assert!(
            !state.quiet.contains("swift-cedar"),
            "applying a returned update removes the peer from quiet"
        );
        assert!(
            state.peers.contains("swift-cedar"),
            "applying a returned update puts the peer in the roster"
        );
    }

    /// A quiet peer is back when a live frame is stamped after the silence began, and not before:
    /// a copy that a relay held says nothing about the present, and neither does a frame of a kind
    /// that a relay or an anti-entropy answer re-sends.
    #[test]
    fn a_quiet_peer_returns_only_on_a_live_frame_sent_after_its_silence() {
        let _guard = ::habilis_network_test_tracing::init();
        let who = nick("swift-cedar");
        let mut state = fresh_state();
        state.quiet.insert(who.clone());
        let heard = Instant::now()
            .checked_sub(Duration::from_secs(100))
            .expect("the monotonic clock has run past 100 s since boot");
        state.quiet_since.insert(who.clone(), heard);
        let now = UnixSecs::now();
        let before = now - Duration::from_secs(200);

        let app = MessageKind::app_broadcast("app_msg");
        let alive = MessageKind::Presence {
            subtype: PresenceSubtype::Alive,
        };
        for kind in [&app, &alive] {
            let back = compute(kind, &who, now, &state);
            assert!(
                back.returned && !back.stale,
                "{kind:?} sent after the silence"
            );
            let copy = compute(kind, &who, before, &state);
            assert!(
                copy.stale && !copy.returned,
                "{kind:?} sent before the silence"
            );
        }
        for kind in [
            MessageKind::PeerInfo,
            MessageKind::State,
            MessageKind::Meta,
            MessageKind::StateDigest,
            MessageKind::MetaDigest,
        ] {
            let update = compute(&kind, &who, now, &state);
            assert!(
                update.stale && !update.returned && !update.joined_new,
                "{kind:?} is no proof of presence, even stamped after the silence"
            );
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
        state.note_left(&who, leaver.author_key(), at);

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
        let at = UnixSecs::from(1_000);
        let mut state = fresh_state();
        state.note_left(&who, Identity::generate().author_key(), at);

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
        state.note_left(&who, leaver.author_key(), left.timestamp);
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
        state.note_left(&who, leaver.author_key(), UnixSecs::from(1_000));

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
