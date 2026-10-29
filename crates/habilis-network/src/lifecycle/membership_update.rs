//! The **membership layer**: pure roster transitions. Decides what an
//! inbound message means for the peer roster (`peers` /
//! `quiet`) — first-sight, return-from-quiet, departure — without any
//! transport, presentation, or surfacing concern. See the Concept
//! Glossary in AGENTS.md for the layer split.

use crate::daemon::state::EventLoopState;
use crate::protocol::{MessageKind, Nickname, PresenceSubtype, UnixSecs, Verified};

/// Summary of how a newly received message changes our view of the
/// sender's membership. Computed from the message kind + current state
/// as a pure function; applied afterwards by the caller.
pub(crate) struct MembershipUpdate {
    /// The sender was in `quiet` (evicted as silent) and this
    /// message proves they're back. Triggers `peer_return` output and
    /// re-inclusion in `peers`.
    pub returned: bool,
    /// This is the first time we've seen this author. Gates the
    /// state-file write and the `has joined` line (we suppress it
    /// when `returned` — we print `came back` instead).
    pub joined_new: bool,
    /// The sender said goodbye and this message was stamped no later than that goodbye: a copy
    /// that was sent before it and arrived after it. It proves no presence, so it adds the
    /// sender to nothing and surfaces no arrival.
    pub stale: bool,
}

/// Decide what a message from `author` means for our peer
/// tracking. Pure: takes `&` refs, no side effects.
///
/// `Left` never counts as a join (even on first sight), because a
/// farewell is not an arrival. Everything else (including `Alive`,
/// `Msg`, `PeerInfo`) participates in self-heal: if we
/// haven't seen the peer before, we treat the message as proof of
/// presence, unless the peer said goodbye and the message was stamped no later
/// than the goodbye (see [`MembershipUpdate::stale`]).
pub(crate) fn compute(
    kind: &MessageKind,
    author: &Nickname,
    timestamp: UnixSecs,
    state: &EventLoopState,
) -> MembershipUpdate {
    let is_left = matches!(
        kind,
        MessageKind::Presence {
            subtype: PresenceSubtype::Left
        }
    );
    let after_goodbye = !is_left && state.sent_before_goodbye(author, timestamp);
    let returned = !after_goodbye && state.quiet.contains(author.as_str());
    #[expect(
        clippy::match_same_arms,
        reason = "the named variants are listed on purpose, so a new variant stays visible"
    )]
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "foreign non_exhaustive enum: the compiler needs a wildcard arm; the named variants are listed before it"
    )]
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
            subtype: PresenceSubtype::Joined | PresenceSubtype::Alive,
        }
        | MessageKind::PeerInfo
        | MessageKind::Digest
        | MessageKind::StateDigest
        | MessageKind::MetaDigest
        | MessageKind::Ping
        | MessageKind::Pong { .. }
        | MessageKind::LinkState => !state.peers.contains(author.as_str()),
        _ => !state.peers.contains(author.as_str()),
    };
    MembershipUpdate {
        returned,
        joined_new: unseen && !after_goodbye,
        stale: after_goodbye,
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
    use habilis_network_test_tracing::test;

    use crate::protocol::identity::Identity;
    use crate::protocol::{AuthorKey, MeshId, Message};

    use super::{
        MembershipUpdate, MessageKind, PresenceSubtype, UnixSecs, apply, compute, compute_for,
    };

    #[test]
    fn first_time_seeing_author_is_joined_new() {
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

    /// A goodbye is final for every message that was sent before it. A re-announce of `joined` that
    /// was in flight when the peer left reaches us after the `left`, stamped with the same second:
    /// it must not bring the peer back into the roster.
    #[test]
    fn a_message_sent_in_the_second_of_a_goodbye_is_stale() {
        let at = UnixSecs::from(1_000);
        let mut state = fresh_state();
        state.note_left(&nick("swift-cedar"), AuthorKey::from_bytes([1; 32]), at);
        let joined = MessageKind::Presence {
            subtype: PresenceSubtype::Joined,
        };

        for kind in [
            joined,
            MessageKind::PeerInfo,
            MessageKind::app_broadcast("app_msg"),
            MessageKind::Presence {
                subtype: PresenceSubtype::Alive,
            },
        ] {
            let update = compute(&kind, &nick("swift-cedar"), at, &state);
            assert!(update.stale, "{kind:?} of the second of the goodbye");
            assert!(!update.joined_new, "{kind:?} brings the peer back");
            let older = compute(&kind, &nick("swift-cedar"), UnixSecs::from(990), &state);
            assert!(older.stale && !older.joined_new, "{kind:?} sent before it");
        }
    }

    /// A message stamped after the goodbye is a real return, and a stranger is not touched by the
    /// goodbye of another peer.
    #[test]
    fn a_message_stamped_after_a_goodbye_is_a_return() {
        let at = UnixSecs::from(1_000);
        let mut state = fresh_state();
        state.note_left(&nick("swift-cedar"), AuthorKey::from_bytes([1; 32]), at);
        let joined = MessageKind::Presence {
            subtype: PresenceSubtype::Joined,
        };

        let back = compute(&joined, &nick("swift-cedar"), UnixSecs::from(1_001), &state);
        assert!(
            !back.stale,
            "a message stamped after a goodbye is not stale"
        );
        assert!(back.joined_new, "a later joined is a new arrival");
        let other = compute(&joined, &nick("lost-heron"), at, &state);
        assert!(
            !other.stale && other.joined_new,
            "another peer is not stale"
        );
    }

    /// The goodbye itself is never stale, and a copy of an older goodbye does not move the mark
    /// back: a peer that left, came back and left again stays gone for the first goodbye's copies.
    #[test]
    fn the_mark_of_a_goodbye_only_moves_forward() {
        let mut state = fresh_state();
        let who = nick("swift-cedar");
        state.note_left(&who, AuthorKey::from_bytes([1; 32]), UnixSecs::from(1_000));
        state.note_left(&who, AuthorKey::from_bytes([1; 32]), UnixSecs::from(900));
        assert!(
            state.sent_before_goodbye(&who, UnixSecs::from(1_000)),
            "a goodbye marks the messages sent before it"
        );
        state.note_left(&who, AuthorKey::from_bytes([1; 32]), UnixSecs::from(1_200));
        assert!(
            state.sent_before_goodbye(&who, UnixSecs::from(1_100)),
            "messages sent just before the goodbye mark still count"
        );
        assert!(
            !state.sent_before_goodbye(&who, UnixSecs::from(1_201)),
            "a message sent after the goodbye is not marked"
        );
        let left = MessageKind::Presence {
            subtype: PresenceSubtype::Left,
        };
        assert!(
            !compute(&left, &who, UnixSecs::from(1_200), &state).stale,
            "a left message stamped after the goodbye is not stale"
        );
    }

    /// A key is minted per run, so once it has said goodbye nothing it signs is a presence, even
    /// when the timestamp lies after the goodbye. The nickname stays free for another key.
    #[test]
    fn a_key_that_said_goodbye_stays_gone_at_any_timestamp() {
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
