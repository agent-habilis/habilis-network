//! The Nostr view of one mesh: its room tag, its seal key and its relay ranking.

use std::fmt;

use iroh_base::EndpointId;
use url::Url;

use super::relays::{pinned_relays, rank_relays};
use crate::crypto::{SymmetricKey, derive_secret};
use crate::meshes::NostrChoice;
use crate::topic::TopicId;

/// The Nostr view of one mesh, all derived from its topic id.
#[derive(Clone)]
pub struct NostrKeys {
    pub(super) room_tag: [u8; 32],
    pub(super) seal_key: SymmetricKey,
    relay_seed: SymmetricKey,
}

impl fmt::Debug for NostrKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("NostrKeys").finish_non_exhaustive()
    }
}

impl NostrKeys {
    /// The Nostr keys of the mesh that the topic id names.
    #[must_use]
    pub fn derive(topic: &TopicId) -> Self {
        Self {
            room_tag: *derive_secret(topic.as_bytes(), b"nostr-room"),
            seal_key: SymmetricKey::from_zeroizing(derive_secret(topic.as_bytes(), b"nostr-seal")),
            relay_seed: SymmetricKey::from_zeroizing(derive_secret(
                topic.as_bytes(),
                b"nostr-relays",
            )),
        }
    }

    /// The tag every member announces on and listens to.
    #[must_use]
    pub fn room_tag(&self) -> [u8; 32] {
        self.room_tag
    }

    /// The tag directed signals to `member` go to. Unlinkable to the member's
    /// id without the room tag.
    #[must_use]
    pub fn self_tag(&self, member: &EndpointId) -> [u8; 32] {
        *derive_secret(&self.room_tag, member.as_bytes())
    }

    /// The relays of `choice`, ranked the same way by every member.
    ///
    /// # Panics
    /// If a pinned URL does not parse; they are constants checked by a test.
    pub fn ranked_relays(&self, choice: &NostrChoice) -> impl Iterator<Item = Url> + use<> {
        let urls: Vec<Url> = match choice {
            NostrChoice::Disabled => Vec::new(),
            NostrChoice::Pinned => pinned_relays(),
            NostrChoice::Custom(custom) => custom.clone(),
        };
        rank_relays(urls, self.relay_seed.as_bytes()).into_iter()
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::NostrKeys;
    use crate::meshes::NostrChoice;
    use crate::nostr::PINNED_RELAYS;
    use crate::topic::TopicId;

    fn keys() -> NostrKeys {
        NostrKeys::derive(&TopicId::from_bytes([4u8; 32]))
    }

    #[test]
    fn the_tags_are_distinct_per_mesh_and_per_member() {
        let alice = SecretKey::generate();
        let bob = SecretKey::generate();
        let other = NostrKeys::derive(&TopicId::from_bytes([5u8; 32]));
        assert_ne!(
            keys().room_tag(),
            other.room_tag(),
            "another mesh has another room tag"
        );
        assert_ne!(
            keys().self_tag(&alice.public()),
            keys().self_tag(&bob.public()),
            "each member has its own tag"
        );
        assert_ne!(
            keys().self_tag(&alice.public()),
            other.self_tag(&alice.public()),
            "a member's tag differs between meshes"
        );
        assert_ne!(
            keys().room_tag(),
            keys().self_tag(&alice.public()),
            "a member's tag is not the room tag"
        );
    }

    #[test]
    fn every_pinned_relay_parses_as_a_websocket_url() {
        let ranked: Vec<url::Url> = keys().ranked_relays(&NostrChoice::Pinned).collect();
        assert_eq!(
            ranked.len(),
            PINNED_RELAYS.len(),
            "every pinned relay is ranked"
        );
        assert!(
            ranked.iter().all(|url| url.scheme() == "wss"),
            "every pinned relay is a wss URL"
        );
        assert_eq!(
            keys().ranked_relays(&NostrChoice::Disabled).count(),
            0,
            "no Nostr, no relays"
        );
    }
}
