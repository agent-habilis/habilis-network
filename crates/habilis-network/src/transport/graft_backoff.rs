//! The wait before a peer that refused a graft is asked again.
//!
//! A `Neighbor` request is low priority: a peer with a full active view refuses it and says
//! nothing. The engine sees no refusal, only that no `NeighborUp` came. A node that arrives late
//! then asks the same full peers every alive tick, and each ask costs a connection. This type
//! reads the silence as the answer: a request that brought no link in
//! [`GRAFT_REFUSED_AFTER_SECS`] was refused, and the peer is left alone for a wait that doubles
//! with each refusal in a row.
//!
//! The backoff is one-sided on purpose. A peer that frees a slot asks us itself, so a wait of
//! 15 minutes is not a risk to liveness. It is kept apart from the refusals of session offers
//! (`RefusalBackoff` in `admission.rs`) and from the eviction backoff (`EvictionBackoff` in
//! `ceiling.rs`): those are other protocols with other causes.
//!
//! The starved fallback, a `Join` once per `STARVED_SECS`, ignores this backoff. A `Join` is
//! never refused. It is also the only way out when a peer holds a tombstone for this node (it saw a
//! `Disconnect` with `left = true`): such a peer refuses every `Neighbor` request for ever, so the
//! backoff alone would leave the node without that peer for good.

use std::collections::HashMap;
use std::time::Duration;

use iroh::EndpointId;

use crate::util::clock::Instant;
use crate::util::tuning::{
    GRAFT_BACKOFF_FIRST_SECS, GRAFT_BACKOFF_MAX_SECS, GRAFT_REFUSED_AFTER_SECS,
};

/// The jitter on a wait, as a fraction either way, so that the nodes that were refused together
/// do not ask again together.
const JITTER: f64 = 0.2;

#[derive(Debug, Clone, Copy)]
struct Entry {
    /// When the last `Neighbor` request went out and no answer was read yet.
    asked_at: Option<Instant>,
    /// Until when the peer is left alone.
    until: Option<Instant>,
    /// The wait that the next refusal earns, before the jitter.
    step: Duration,
}

#[derive(Debug, Default)]
pub(crate) struct GraftBackoff {
    by_peer: HashMap<EndpointId, Entry>,
}

impl GraftBackoff {
    /// A `Neighbor` request went out to `peer` at `now`.
    pub(crate) fn asked(&mut self, peer: EndpointId, now: Instant) {
        self.by_peer
            .entry(peer)
            .and_modify(|entry| entry.asked_at = Some(now))
            .or_insert(Entry {
                asked_at: Some(now),
                until: None,
                step: Duration::from_secs(GRAFT_BACKOFF_FIRST_SECS),
            });
    }

    /// Read the answers: every peer that was asked at least [`GRAFT_REFUSED_AFTER_SECS`] ago and
    /// is not linked refused. `spread` is in `-1.0..=1.0` and scales the jitter of the wait.
    pub(crate) fn settle(
        &mut self,
        now: Instant,
        is_linked: impl Fn(&EndpointId) -> bool,
        spread: f64,
    ) {
        let refused_after = Duration::from_secs(GRAFT_REFUSED_AFTER_SECS);
        let longest = Duration::from_secs(GRAFT_BACKOFF_MAX_SECS);
        for (peer, entry) in &mut self.by_peer {
            let Some(asked_at) = entry.asked_at else {
                continue;
            };
            if is_linked(peer) {
                entry.asked_at = None;
            } else if now.saturating_duration_since(asked_at) >= refused_after {
                let wait = entry.step.mul_f64(1.0 + JITTER * spread.clamp(-1.0, 1.0));
                entry.until = Some(now + wait);
                entry.step = (entry.step * 2).min(longest);
                entry.asked_at = None;
            }
        }
    }

    /// Whether `peer` is left alone at `now`.
    pub(crate) fn is_blocked(&self, peer: &EndpointId, now: Instant) -> bool {
        self.by_peer
            .get(peer)
            .and_then(|entry| entry.until)
            .is_some_and(|until| now < until)
    }

    /// The link to `peer` came up, or the peer has a new address: it did not refuse, or it is not
    /// the peer that refused. The wait starts over.
    pub(crate) fn reset(&mut self, peer: EndpointId) {
        self.by_peer.remove(&peer);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::testing::endpoint_id;

    fn at(start: Instant, secs: u64) -> Instant {
        start + Duration::from_secs(secs)
    }

    fn unlinked(_: &EndpointId) -> bool {
        false
    }

    /// A request that brought no link in 20 s was refused, and the peer is left alone for 60 s.
    #[test]
    fn a_refused_request_blocks_the_peer_for_a_minute() {
        let (start, peer) = (Instant::now(), endpoint_id(1));
        let mut backoff = GraftBackoff::default();
        backoff.asked(peer, start);

        backoff.settle(at(start, 19), unlinked, 0.0);
        assert!(
            !backoff.is_blocked(&peer, at(start, 19)),
            "not yet read as refused"
        );

        backoff.settle(at(start, 21), unlinked, 0.0);
        assert!(backoff.is_blocked(&peer, at(start, 21 + 59)));
        assert!(!backoff.is_blocked(&peer, at(start, 21 + 61)));
        assert!(
            !backoff.is_blocked(&endpoint_id(2), at(start, 22)),
            "only that peer"
        );
    }

    /// Each refusal in a row doubles the wait, up to 15 minutes.
    #[test]
    fn each_refusal_in_a_row_doubles_the_wait_up_to_fifteen_minutes() {
        let (start, peer) = (Instant::now(), endpoint_id(1));
        let mut backoff = GraftBackoff::default();
        let mut now = start;
        let mut waits = Vec::new();
        for _ in 0..7 {
            backoff.asked(peer, now);
            now = at(now, 21);
            backoff.settle(now, unlinked, 0.0);
            let mut wait = 0;
            while backoff.is_blocked(&peer, at(now, wait)) {
                wait += 1;
            }
            waits.push(wait);
            now = at(now, wait);
        }
        assert_eq!(waits, [60, 120, 240, 480, 900, 900, 900]);
    }

    /// A link that comes up, even 15 s after the request, is not a refusal: the wait starts over.
    #[test]
    fn a_link_that_comes_up_after_the_request_is_not_backed_off() {
        let (start, peer) = (Instant::now(), endpoint_id(1));
        let mut backoff = GraftBackoff::default();
        backoff.asked(peer, start);
        backoff.reset(peer);

        backoff.settle(at(start, 40), unlinked, 0.0);
        assert!(!backoff.is_blocked(&peer, at(start, 40)));
    }

    /// A peer that is linked when the answers are read did not refuse, whatever order the events
    /// came in.
    #[test]
    fn a_linked_peer_is_not_read_as_a_refusal() {
        let (start, peer) = (Instant::now(), endpoint_id(1));
        let linked: HashSet<EndpointId> = [peer].into();
        let mut backoff = GraftBackoff::default();
        backoff.asked(peer, start);

        backoff.settle(at(start, 30), |id| linked.contains(id), 0.0);
        assert!(!backoff.is_blocked(&peer, at(start, 30)));
    }

    /// The link coming up, or a new address, takes the doubled wait back to a minute.
    #[test]
    fn a_reset_starts_the_wait_over() {
        let (start, peer) = (Instant::now(), endpoint_id(1));
        let mut backoff = GraftBackoff::default();
        backoff.asked(peer, start);
        backoff.settle(at(start, 21), unlinked, 0.0);
        backoff.asked(peer, at(start, 90));
        backoff.settle(at(start, 111), unlinked, 0.0);
        assert!(
            backoff.is_blocked(&peer, at(start, 111 + 100)),
            "the second wait is 120 s"
        );

        backoff.reset(peer);
        assert!(!backoff.is_blocked(&peer, at(start, 111 + 100)));
        backoff.asked(peer, at(start, 300));
        backoff.settle(at(start, 321), unlinked, 0.0);
        assert!(backoff.is_blocked(&peer, at(start, 321 + 59)));
        assert!(
            !backoff.is_blocked(&peer, at(start, 321 + 61)),
            "back to 60 s"
        );
    }

    /// The wait has a jitter of 20 percent either way.
    #[test]
    fn the_wait_has_a_jitter_of_twenty_percent() {
        let (start, peer) = (Instant::now(), endpoint_id(1));
        for (spread, secs) in [(-1.0, 48), (1.0, 72)] {
            let mut backoff = GraftBackoff::default();
            backoff.asked(peer, start);
            backoff.settle(at(start, 21), unlinked, spread);
            assert!(
                backoff.is_blocked(&peer, at(start, 21 + secs - 1)),
                "spread {spread}"
            );
            assert!(
                !backoff.is_blocked(&peer, at(start, 21 + secs + 1)),
                "spread {spread}"
            );
        }
    }

    /// A refusal is read once: the same silence does not extend the wait.
    #[test]
    fn a_refusal_is_read_once() {
        let (start, peer) = (Instant::now(), endpoint_id(1));
        let mut backoff = GraftBackoff::default();
        backoff.asked(peer, start);
        backoff.settle(at(start, 21), unlinked, 0.0);
        backoff.settle(at(start, 40), unlinked, 0.0);
        backoff.settle(at(start, 70), unlinked, 0.0);
        assert!(!backoff.is_blocked(&peer, at(start, 21 + 61)));
    }
}
