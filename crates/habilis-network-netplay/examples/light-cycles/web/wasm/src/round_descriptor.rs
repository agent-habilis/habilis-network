use crate::round::{place_spawns, seed_for};
use crate::spawn::Spawn;
use crate::split_mix64::SplitMix64;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundDescriptor {
    /// Sorted, deduplicated pubkey hex — canonical order, so index `i`
    /// here is index `i` into `spawns` and handle `i` in the session.
    pub roster: Vec<String>,
    pub spawns: Vec<Spawn>,
}

impl RoundDescriptor {
    /// Derives the descriptor for `session_id` and `roster`.
    ///
    /// The roster is sorted and deduplicated here, which is also what
    /// makes index `i` in [`Self::roster`] the same player as handle `i`
    /// in the session: the lobby sorts by public key too, so the two
    /// orders coincide. Nothing downstream re-derives that mapping.
    #[must_use]
    pub fn derive(session_id: u64, mut roster: Vec<String>) -> Self {
        roster.sort_unstable();
        roster.dedup();
        let seed = seed_for(session_id, &roster);
        let mut generator = SplitMix64::new(seed);
        let spawns = place_spawns(&mut generator, roster.len());
        Self { roster, spawns }
    }
}
