use crate::world::World;

/// What the render loop reads each tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Which match this is, counting from 1; `0` before the first.
    pub match_number: u64,
    /// The room code, so a player can read it out to whoever is joining.
    pub room: String,
    pub world: World,
    /// Same order as `world.cycles` — index `i` is that cycle's player.
    pub roster: Vec<(String, String)>, // (pubkey, nick)
    pub my_pubkey: String,
    /// How many peers are in the lobby, us included.
    pub present: usize,
    /// No match in progress: waiting for someone to play against.
    pub waiting: bool,
    /// A peer reported a state checksum that disagrees with ours. Should
    /// never happen; if it does, the two are no longer playing the same
    /// game and the display is not to be trusted.
    pub desynced: bool,
    /// Why the lobby cannot start a match, when that is not something
    /// waiting will fix — a duplicate nickname, say. `None` while healthy.
    pub blocked: Option<String>,
    /// The session exists but is still aligning frame numbers with its
    /// peers. Distinct from both "waiting" and "playing": the arena is up
    /// but frozen, which without a word on screen reads as a hang.
    pub syncing: bool,
}
