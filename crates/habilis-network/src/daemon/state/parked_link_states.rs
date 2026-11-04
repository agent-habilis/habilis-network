use std::collections::HashMap;

use crate::protocol::AuthorKey;

/// Link vectors that arrived before their signer proved an endpoint, one per signing key: a newer
/// one replaces the older. The proof comes with the `PeerInfo` of the signer, which can arrive a few
/// milliseconds after its first vector, now that vectors go out when a link
/// comes up. A vector that is dropped there is waited for until the next tick, 15 s on, and the
/// session that it makes possible comes too late for the route that it carries.
#[cfg(feature = "multihop")]
#[derive(Debug, Clone)]
pub(crate) struct ParkedLinkStates {
    by_signer: HashMap<AuthorKey, habilis_network_iroh_multihop_transport::LinkVector>,
    cap: usize,
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
        self.by_signer.insert(signer, vector);
        true
    }

    /// The vector that waits for `signer`, if any.
    pub(crate) fn take(
        &mut self,
        signer: &AuthorKey,
    ) -> Option<habilis_network_iroh_multihop_transport::LinkVector> {
        self.by_signer.remove(signer)
    }
}

#[cfg(feature = "multihop")]
impl Default for ParkedLinkStates {
    fn default() -> Self {
        Self::new(super::MAX_PARKED_LINK_STATES)
    }
}
