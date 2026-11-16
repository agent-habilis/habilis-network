//! What the Nostr transport of one member needs from its mesh.

use crate::protocol::meshes::NostrChoice;
use crate::protocol::nostr::NostrKeys;
use url::Url;

/// The keys of a mesh and its payload relays: the custom list, in the order every member
/// computes. The pinned public relays carry lookup and signalling only, so a mesh on them has no
/// plan, and a relay in a custom list is trusted to carry payload.
#[derive(Debug, Clone)]
pub(crate) struct NostrPlan {
    keys: NostrKeys,
    ranking: Vec<Url>,
}

impl NostrPlan {
    /// The plan of the mesh with `keys` and the Nostr lookup `choice`, or `None` when the choice
    /// has no custom list.
    pub(crate) fn for_mesh(keys: &NostrKeys, choice: &NostrChoice) -> Option<Self> {
        let NostrChoice::Custom(_) = choice else {
            return None;
        };
        Some(Self {
            keys: keys.clone(),
            ranking: keys.ranked_relays(choice).collect(),
        })
    }

    /// The payload relays in rank order.
    #[cfg(test)]
    pub(crate) fn ranking(&self) -> Vec<Url> {
        self.ranking.clone()
    }

    /// The keys and the ranking, for the transport to open.
    pub(crate) fn into_parts(self) -> (NostrKeys, Vec<Url>) {
        (self.keys, self.ranking)
    }
}
