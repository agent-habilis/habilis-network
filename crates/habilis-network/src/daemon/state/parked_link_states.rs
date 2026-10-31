use std::collections::HashMap;

use crate::protocol::Nickname;

/// Link vectors that arrived before the roster bound an endpoint to their author, one per
/// author: a newer one replaces the older. The binding comes with the `PeerInfo` of the author,
/// which can arrive a few milliseconds after its first vector, now that vectors go out when a link
/// comes up. A vector that is dropped there is waited for until the next tick, 15 s on, and the
/// session that it makes possible comes too late for the route that it carries.
#[cfg(feature = "multihop")]
#[derive(Debug, Clone)]
pub(crate) struct ParkedLinkStates {
    by_author: HashMap<Nickname, habilis_network_iroh_multihop_transport::LinkVector>,
    cap: usize,
}

#[cfg(feature = "multihop")]
impl ParkedLinkStates {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            by_author: HashMap::new(),
            cap,
        }
    }

    /// Park `vector` for `author`, in place of the one that waited. Whether it was kept: the
    /// vector of an author that does not wait yet is refused at the cap.
    pub(crate) fn park(
        &mut self,
        author: Nickname,
        vector: habilis_network_iroh_multihop_transport::LinkVector,
    ) -> bool {
        if !self.by_author.contains_key(&author) && self.by_author.len() >= self.cap {
            return false;
        }
        self.by_author.insert(author, vector);
        true
    }

    /// The vector that waits for `author`, if any.
    pub(crate) fn take(
        &mut self,
        author: &Nickname,
    ) -> Option<habilis_network_iroh_multihop_transport::LinkVector> {
        self.by_author.remove(author)
    }
}

#[cfg(feature = "multihop")]
impl Default for ParkedLinkStates {
    fn default() -> Self {
        Self::new(super::MAX_PARKED_LINK_STATES)
    }
}
