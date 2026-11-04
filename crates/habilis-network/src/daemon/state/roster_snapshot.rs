use std::collections::HashMap;

use super::RosterEntry;
use crate::protocol::Nickname;

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
}

impl RosterSnapshot {
    /// The rows of the members that are not quiet.
    fn live_rows(&self) -> impl Iterator<Item = &RosterEntry> {
        self.peers.iter().filter(|entry| !entry.quiet)
    }

    /// How many live rows use each nickname.
    fn live_uses(&self) -> HashMap<&Nickname, usize> {
        let mut uses: HashMap<&Nickname, usize> = HashMap::new();
        let live = self.live_rows();
        for entry in live {
            *uses.entry(&entry.nickname).or_default() += 1;
        }
        uses
    }

    /// The nicknames that a directed send can name: each live member whose nickname no other live
    /// member uses. A quiet member is no addressee, because its endpoint is likely dead. A nickname
    /// of two live members is no addressee either, because the engine refuses a send to it.
    pub fn addressees(&self) -> impl Iterator<Item = &Nickname> {
        let uses = self.live_uses();
        self.live_rows()
            .map(|entry| &entry.nickname)
            .filter(move |nickname| uses.get(nickname) == Some(&1))
    }

    /// The nicknames that two or more live members use, each once, in nickname order.
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
