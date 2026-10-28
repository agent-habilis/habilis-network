use super::RosterEntry;

use serde::Serialize;

/// Live peer roster: every known peer (active + quiet) sorted
/// most-recently-seen first, plus `count == peers.len() + 1` (the
/// `+1` is self — same definition as the statusline `peer_count`).
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct RosterSnapshot {
    /// The members of the roster.
    pub peers: Vec<RosterEntry>,
    /// How many members there are.
    pub count: usize,
}
