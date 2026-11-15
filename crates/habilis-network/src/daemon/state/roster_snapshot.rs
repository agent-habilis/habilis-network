use std::collections::HashMap;

use super::RosterEntry;
use crate::protocol::{AuthorKey, Nickname};

use serde::Serialize;

/// Live peer roster: every known peer (active + quiet) sorted
/// most-recently-seen first, plus `count == peers.len() + 1` (the
/// `+1` is self — same definition as the statusline `peer_count`).
///
/// # Examples
///
/// A roster snapshot lists the members that a node sees. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::RosterSnapshot;
///
/// # fn demo(snapshot: RosterSnapshot) -> usize {
/// snapshot.peers.len()
/// # }
/// ```
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct RosterSnapshot {
    /// The members of the roster.
    pub peers: Vec<RosterEntry>,
    /// How many members there are.
    pub count: usize,
    /// The nickname of every live peer, shown or not, one entry per key. A peer that is not shown
    /// has no row, but a send to its nickname still counts it. Not part of the JSON.
    #[serde(skip)]
    pub(crate) live: Vec<Nickname>,
}

impl RosterSnapshot {
    /// The rows of the members that are not quiet.
    fn live_rows(&self) -> impl Iterator<Item = &RosterEntry> {
        self.peers.iter().filter(|entry| !entry.quiet)
    }

    /// How many live peers use each nickname, the peers that are not shown yet included.
    fn live_uses(&self) -> HashMap<&Nickname, usize> {
        let mut uses: HashMap<&Nickname, usize> = HashMap::new();
        for nickname in &self.live {
            *uses.entry(nickname).or_default() += 1;
        }
        uses
    }

    /// The nicknames that a directed send can name: each shown live member whose nickname no other
    /// live peer uses, shown or not. A quiet member is no addressee, because its endpoint is likely
    /// dead. A nickname of two live peers is no addressee either, because the engine refuses a send
    /// to it.
    pub fn addressees(&self) -> impl Iterator<Item = &Nickname> {
        let uses = self.live_uses();
        self.live_rows()
            .map(|entry| &entry.nickname)
            .filter(move |nickname| uses.get(nickname) == Some(&1))
    }

    /// The keys that a directed send can name: each shown live member. Two live members that use
    /// one nickname are two addressees, because a frame names the key. A quiet member is no
    /// addressee, because its endpoint is likely dead.
    pub fn addressee_keys(&self) -> impl Iterator<Item = &AuthorKey> {
        self.live_rows().map(|entry| &entry.key)
    }

    /// The nicknames that two or more live peers use, shown or not, each once, in nickname order.
    pub fn ambiguous_nicknames(&self) -> impl Iterator<Item = &Nickname> {
        let uses = self.live_uses();
        let mut shared: Vec<&Nickname> = uses
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(nickname, _)| nickname)
            .collect();
        shared.sort_by_key(|nickname| nickname.as_str());
        shared.into_iter()
    }
}
