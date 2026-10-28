//! The backoff that spaces out the refusals of one peer.

use std::collections::HashMap;
use std::time::Duration;

use iroh::EndpointId;

use crate::util::clock::Instant;
use crate::util::tuning;


/// How long to leave a peer alone after it answered "at my cap", and how that
/// grows.
///
/// Without a wait the retry tick re-offers every 30s and every refused round
/// still costs *us* a full candidate-gathering budget before the refusal
/// arrives. The wait is per peer: the first refusal waits
/// [`tuning::CAP_REFUSAL_COOLDOWN`], each further one in a row doubles it up
/// to [`tuning::CAP_REFUSAL_COOLDOWN_MAX`], and a success resets it. One
/// rule serves both kinds of peer: the rendezvous frees a slot soon after, so
/// the first short wait finds it, while a member whose sessions are all busy
/// gossip links does not, and the wait grows to a size that makes the cost of a
/// refused round small.
#[derive(Debug, Default)]
pub(crate) struct RefusalBackoff {
    pub(crate) by_peer: HashMap<EndpointId, Backoff>,
    /// The peers that turned an offer away as not a neighbor, and when it was last: the first
    /// time in a row is a race that the next offer wins, a second one goes through [`Self::note`].
    #[cfg(any(feature = "multihop", test))]
    pub(crate) strangers: HashMap<EndpointId, Instant>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Backoff {
    pub(crate) until: Instant,
    pub(crate) window: Duration,
}

impl RefusalBackoff {
    pub(crate) fn note(&mut self, peer: EndpointId, now: Instant) {
        let first = tuning::CAP_REFUSAL_COOLDOWN;
        let max = tuning::CAP_REFUSAL_COOLDOWN_MAX;
        // Entries whose wait ended more than a longest wait ago are forgotten, so
        // that the map stays bounded by the peers refused lately.
        self.by_peer
            .retain(|_, backoff| now.saturating_duration_since(backoff.until) < max);
        let window = self
            .by_peer
            .get(&peer)
            .map_or(first, |previous| (previous.window * 2).min(max));
        self.by_peer.insert(
            peer,
            Backoff {
                until: now + window,
                window,
            },
        );
    }

    pub(crate) fn on_cooldown(&self, peer: &EndpointId, now: Instant) -> bool {
        self.by_peer
            .get(peer)
            .is_some_and(|backoff| now < backoff.until)
    }

    pub(crate) fn forget(&mut self, peer: &EndpointId) {
        self.by_peer.remove(peer);
        #[cfg(any(feature = "multihop", test))]
        self.strangers.remove(peer);
    }

    /// Forget every turn-away as not a neighbor, and the wait that a second one earned.
    #[cfg(any(feature = "multihop", test))]
    pub(crate) fn forget_strangers(&mut self) {
        for peer in self.strangers.keys() {
            self.by_peer.remove(peer);
        }
        self.strangers.clear();
    }

    /// `peer` turned an offer away as not a neighbor: its underlay does not hold our link vector
    /// yet. Whether the offer is tried again soon. The first turn-away in a row is a race of two
    /// vectors that cross, and the next offer wins it. A second one in a row (the earlier one is
    /// not older than the longest wait) is a refusal like the cap and waits as one.
    #[cfg(any(feature = "multihop", test))]
    pub(crate) fn note_stranger(&mut self, peer: EndpointId, now: Instant) -> bool {
        let max = tuning::CAP_REFUSAL_COOLDOWN_MAX;
        self.strangers
            .retain(|_, at| now.saturating_duration_since(*at) < max);
        if self.strangers.insert(peer, now).is_none() {
            return true;
        }
        self.note(peer, now);
        false
    }
}
