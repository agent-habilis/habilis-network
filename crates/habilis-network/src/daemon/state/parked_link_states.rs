use std::collections::HashMap;

use crate::protocol::AuthorKey;
use crate::util::clock::Instant;
use crate::util::tuning::PARKED_LINK_STATE_TTL;

/// Link vectors that arrived before their signer proved an endpoint, one per signing key: a newer
/// one replaces the older. The proof comes with the `PeerInfo` of the signer, which can arrive a few
/// milliseconds after its first vector, now that vectors go out when a link
/// comes up. A vector that is dropped there is waited for until the next tick, 15 s on, and the
/// session that it makes possible comes too late for the route that it carries.
#[cfg(feature = "multihop")]
#[derive(Debug, Clone)]
pub(crate) struct ParkedLinkStates {
    by_signer: HashMap<AuthorKey, Parked>,
    cap: usize,
}

/// A vector that waits, and when its signer first made it wait.
#[cfg(feature = "multihop")]
#[derive(Debug, Clone)]
struct Parked {
    vector: habilis_network_iroh_multihop_transport::LinkVector,
    since: Instant,
}

#[cfg(feature = "multihop")]
impl ParkedLinkStates {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            by_signer: HashMap::new(),
            cap,
        }
    }

    /// Park `vector` for `signer`, in place of the one that waited. Whether it was kept: the
    /// vector of a signer that does not wait yet is refused at the cap.
    pub(crate) fn park(
        &mut self,
        signer: AuthorKey,
        vector: habilis_network_iroh_multihop_transport::LinkVector,
    ) -> bool {
        if !self.by_signer.contains_key(&signer) && self.by_signer.len() >= self.cap {
            return false;
        }
        let since = self
            .by_signer
            .get(&signer)
            .map_or_else(Instant::now, |parked| parked.since);
        self.by_signer.insert(signer, Parked { vector, since });
        true
    }

    /// Drop the vectors that waited longer than `PARKED_LINK_STATE_TTL`, so the slot of a signer
    /// that never proves goes to another. The wait counts from the first vector of the signer: a
    /// vector that replaces it keeps that time, so a signer that sends again does not renew its slot.
    pub(crate) fn expire(&mut self, now: Instant) {
        self.by_signer
            .retain(|_, parked| now.duration_since(parked.since) <= PARKED_LINK_STATE_TTL);
    }

    /// The vector that waits for `signer`, if any.
    pub(crate) fn take(
        &mut self,
        signer: &AuthorKey,
    ) -> Option<habilis_network_iroh_multihop_transport::LinkVector> {
        self.by_signer.remove(signer).map(|parked| parked.vector)
    }
}

#[cfg(feature = "multihop")]
impl Default for ParkedLinkStates {
    fn default() -> Self {
        Self::new(super::MAX_PARKED_LINK_STATES)
    }
}

#[cfg(all(test, feature = "multihop"))]
mod tests {
    use crate::util::tuning::{LINKSTATE_INTERVAL, PARKED_LINK_STATE_TTL};

    #[test]
    fn a_parked_vector_waits_for_the_next_vector_tick_of_its_signer_and_one_more() {
        assert_eq!(
            PARKED_LINK_STATE_TTL,
            LINKSTATE_INTERVAL.saturating_mul(2),
            "the wait is counted in vector ticks, so the base is LINKSTATE_INTERVAL"
        );
    }
}
