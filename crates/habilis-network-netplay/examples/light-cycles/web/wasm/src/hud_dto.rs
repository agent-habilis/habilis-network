use crate::outcome_dto::OutcomeDto;
use crate::roster_entry_dto::RosterEntryDto;
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct HudDto {
    /// Which match this is, counting from 1; `0` before the first.
    pub(crate) match_number: u64,
    /// Peers in the lobby, us included.
    pub(crate) present: usize,
    /// No match in progress — waiting for someone to play against.
    pub(crate) waiting: bool,
    /// A peer's state checksum disagreed with ours. Should never happen;
    /// if it does, the two are no longer playing the same game.
    pub(crate) desynced: bool,
    /// Why the lobby cannot start a match, when waiting will not fix it.
    pub(crate) blocked: Option<String>,
    /// The session is up but still aligning frame numbers with its peers.
    pub(crate) syncing: bool,
    /// The authoritative match outcome, from `sim::outcome`. Sent rather
    /// than left for the frontend to re-derive from `roster`: that is the
    /// game's central rule, and a second definition of it on the
    /// frontend drifted from this one immediately.
    pub(crate) outcome: OutcomeDto,
    pub(crate) roster: Vec<RosterEntryDto>,
}
