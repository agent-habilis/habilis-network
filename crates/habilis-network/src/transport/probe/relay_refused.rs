//! A peer closed a gossip link that we dialed, because it has no direct path to us.

use iroh::EndpointId;
use iroh::endpoint::ConnectionError;

use crate::transport::payload_path::GOSSIP_RELAY_REFUSED_CODE;

/// The peer told us, by the close code of a gossip connection that we dialed, that the pair has no
/// direct path now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RelayRefused {
    pub(crate) peer: EndpointId,
}

/// What [`crate::daemon::state::EventLoopState::note_relay_refused`] did, for the log line of the
/// loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RefusalEffect {
    pub(crate) outcome: &'static str,
    pub(crate) stamp_cleared: bool,
}

/// Whether a connection ended because the peer refused it as relay-only. Only the peer's own
/// close with this code is that fact: our own close gives `LocallyClosed`, and another code
/// (idle, eviction, shutdown) is no proof of a missing path.
pub(crate) fn is_relay_refusal(reason: &ConnectionError) -> bool {
    matches!(
        reason,
        ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == u64::from(GOSSIP_RELAY_REFUSED_CODE)
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use iroh::endpoint::{ApplicationClose, ConnectionError, VarInt};

    use super::super::grafts;
    use super::{RefusalEffect, is_relay_refusal};
    use crate::daemon::state::DirectState;
    use crate::testing::{endpoint_id, fresh_state};
    use crate::transport::payload_path::GOSSIP_RELAY_REFUSED_CODE;
    use crate::util::clock::Instant;
    use crate::util::tuning::GRAFT_REFUSED_AFTER;

    const MAX_CONNECTIONS: usize = 4;
    const SECOND: Duration = Duration::from_secs(1);

    fn closed_with(code: u32) -> ConnectionError {
        ConnectionError::ApplicationClosed(ApplicationClose {
            error_code: VarInt::from_u32(code),
            reason: Bytes::new(),
        })
    }

    /// T1: a peer that reads `Direct` and closes our gossip dial as relay-only has no direct path
    /// now. The next retry must probe it, and ask it for nothing.
    #[test]
    fn a_peer_that_closes_our_gossip_dial_as_relay_only_is_no_longer_direct() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let peer = endpoint_id(2);
        state.direct.insert(peer, DirectState::Direct);

        let effect = state.note_relay_refused(peer);

        assert_eq!(
            effect,
            RefusalEffect {
                outcome: "demoted",
                stamp_cleared: false
            },
            "a Direct peer that refuses is demoted, and no stamp is held"
        );
        assert_eq!(
            state.direct.get(&peer),
            Some(&DirectState::RelayOnly),
            "the peer is demoted"
        );
        assert!(
            !grafts::may_graft(
                state.direct.get(&peer) == Some(&DirectState::Direct),
                false,
                false
            ),
            "a RelayOnly peer is probed first and gets no graft"
        );
    }

    /// The `Join` of the starved node went to a peer that then closed the dial as relay-only: the
    /// `Join` reached nobody, so its stamp is cleared and the next retry may send another one. A
    /// close by another peer leaves the stamp.
    #[test]
    fn a_join_that_the_target_closed_as_relay_only_does_not_cost_the_next_join() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let asked_at = start + SECOND;
        let read_at = asked_at + GRAFT_REFUSED_AFTER;
        let now = read_at + SECOND;
        let (target, other) = (endpoint_id(2), endpoint_id(3));

        let mut state = fresh_state();
        state.note_link_count(MAX_CONNECTIONS, start);
        state.graft_backoff.asked(other, asked_at);
        state.settle_graft_backoff(read_at);
        assert!(state.starved_join_due(now), "the first Join is due");
        state.note_join_target(target);
        assert!(
            !state.starved_join_ready(now + SECOND),
            "the stamp holds the next Join back for STARVED"
        );

        let unrelated = state.note_relay_refused(other);
        assert!(
            !unrelated.stamp_cleared,
            "a close by a peer that was not the target keeps the stamp"
        );
        assert!(
            !state.starved_join_ready(now + SECOND),
            "the stamp of the Join to the target is still held"
        );

        let effect = state.note_relay_refused(target);
        assert!(effect.stamp_cleared, "the target closed the dial");
        assert!(
            state.starved_join_ready(now + SECOND),
            "the Join reached nobody, so a Join is due again at the next retry"
        );
    }

    /// T3, controls: no change for a peer that is linked, `Pending` or `RelayOnly`, and no
    /// refusal for any close that is not the peer's own relay-refused code.
    #[test]
    fn only_the_close_of_the_peer_with_the_relay_refused_code_is_a_refusal() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            is_relay_refusal(&closed_with(GOSSIP_RELAY_REFUSED_CODE)),
            "the peer's own close with the relay-refused code is a refusal"
        );
        assert!(
            !is_relay_refusal(&closed_with(GOSSIP_RELAY_REFUSED_CODE + 1)),
            "another code (idle, eviction, shutdown) is no proof of a missing path"
        );
        assert!(
            !is_relay_refusal(&ConnectionError::LocallyClosed),
            "our own close, with whatever code, is not the peer's word"
        );

        let mut state = fresh_state();
        let (linked, pending, unproven) = (endpoint_id(4), endpoint_id(5), endpoint_id(6));
        state.linked_endpoints.insert(linked);
        state.direct.insert(linked, DirectState::Direct);
        state.direct.insert(pending, DirectState::Pending);
        state.direct.insert(unproven, DirectState::RelayOnly);

        assert_eq!(
            state.note_relay_refused(linked).outcome,
            "ignored: linked",
            "a link is newer proof than an old close"
        );
        assert_eq!(
            state.direct.get(&linked),
            Some(&DirectState::Direct),
            "a linked peer keeps its mark"
        );
        assert_eq!(
            state.note_relay_refused(pending).outcome,
            "ignored: pending",
            "a pending peer is already unproven"
        );
        assert_eq!(
            state.direct.get(&pending),
            Some(&DirectState::Pending),
            "a pending peer keeps its mark"
        );
        assert_eq!(
            state.note_relay_refused(unproven).outcome,
            "ignored: relay-only",
            "a relay-only peer is already unproven"
        );
        assert_eq!(
            state.direct.get(&unproven),
            Some(&DirectState::RelayOnly),
            "a relay-only peer keeps its mark"
        );
    }
}
