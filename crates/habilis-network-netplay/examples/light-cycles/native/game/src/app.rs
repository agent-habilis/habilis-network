//! The `habilis-network-netplay` embedding: the [`Config`] that names this game's
//! three types, and [`Game`], which drives a lobby and one rollback
//! session per match.
//!
//! There is no `NodeApp`/`NodeDriver` here any more — `RollbackDriver` is
//! one, and it is what `main.rs` hands to `Node::spawn`. Nor is there any
//! netcode: prediction, rollback, input redundancy, acks and desync
//! detection all live in the library. What is left is a game.
//!
//! One consequence worth naming, because it deleted a whole class of bug:
//! the roster is now **fixed when the match starts**, agreed by the lobby,
//! rather than re-estimated from liveness on every tick. Two peers can no
//! longer briefly disagree about who is playing and lay out different
//! arenas.

use std::collections::BTreeMap;

use habilis_network_netplay::{
    Config, Event, Lobby, MeshTransport, P2PSession, Request, SessionState, StartedMatch,
};

use crate::grid::{Dir, Input};
use crate::round::RoundDescriptor;
use crate::sim::{self, Outcome, World};

/// How far ahead of a confirmed input the simulation may speculate before
/// it stalls instead. Eight ticks is 400ms at 20 Hz — comfortably more
/// than a loopback or same-continent round trip, and a stall is far less
/// unpleasant here than in a fighting game because a light-cycle's motion
/// is constant.
const MAX_PREDICTION_FRAMES: usize = 8;
/// Ticks between a keypress and its effect. Buys two frames of network
/// slack for free, at 100ms of input lag — under the ~200ms a player
/// notices, and it means most frames need no rollback at all.
const INPUT_DELAY_FRAMES: usize = 2;
/// How often presence is announced while waiting, in render ticks.
/// 10 ticks is 500ms, the same cadence the old hand-rolled heartbeat ran
/// at, and this replaces it.
const PRESENCE_EVERY_TICKS: u32 = 10;
/// How long a finished match is left on screen before a rematch is
/// proposed — 3s at 20 Hz.
const REMATCH_GRACE_TICKS: u32 = 60;

/// The type-level bundle the session is generic over.
#[derive(Debug)]
pub struct LightCycles;

impl Config for LightCycles {
    type Input = Input;
    type State = World;
    /// The peer's signed public key. Never the nickname — the protocol
    /// treats those as cosmetic and explicitly non-unique.
    type Address = String;
}

type Session = P2PSession<LightCycles, MeshTransport<LightCycles>>;

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

/// The whole client: a lobby, at most one live match, and the world it
/// simulates.
///
/// Owned outright by the render loop. Nothing here is shared with the
/// engine's event loop — [`MeshTransport`] is the seam, and it does the
/// locking internally — so unlike the version this replaces there is no
/// `Arc<Mutex<_>>` around the game state at all.
#[derive(Debug)]
pub struct Game {
    transport: MeshTransport<LightCycles>,
    room: String,
    lobby: Option<Lobby>,
    session: Option<Session>,
    descriptor: Option<RoundDescriptor>,
    world: World,
    my_nick: String,
    /// Public key -> nickname, learned from lobby presence. `BTreeMap`
    /// rather than `HashMap` out of habit for anything a peer might
    /// iterate — see the determinism contract.
    nicks: BTreeMap<String, String>,
    match_number: u64,
    /// The session id the live session was built against. The epoch alone
    /// cannot say: the lobby's tie-break can settle on another match at the
    /// same epoch, and then this is what disagrees with `Lobby::started`.
    playing_session_id: Option<u64>,
    /// The direction the player is steering toward. Sticky: it is held
    /// state, not an event, which is what makes the session's "predict by
    /// repeating the last input" guess the right one.
    steer: Option<Dir>,
    ticks: u32,
    /// Render ticks since the match was decided, or `None` while playing.
    decided_since: Option<u32>,
    desynced: bool,
    /// The last reason the lobby refused to start, if it still stands.
    blocked: Option<String>,
}

impl Game {
    #[must_use]
    pub fn new(transport: MeshTransport<LightCycles>, room: String, my_nick: String) -> Self {
        Self {
            transport,
            room,
            lobby: None,
            session: None,
            descriptor: None,
            world: World::default(),
            my_nick,
            nicks: BTreeMap::new(),
            match_number: 0,
            playing_session_id: None,
            steer: None,
            ticks: 0,
            decided_since: None,
            desynced: false,
            blocked: None,
        }
    }

    /// Record where the player wants to go. Legality is not checked here:
    /// a reversal is refused by the simulation, which is the only place
    /// every peer agrees on what the cycle was facing at the tick it
    /// lands on.
    pub fn steer(&mut self, dir: Dir) {
        self.steer = Some(dir);
    }

    /// One render tick: keep the lobby alive, start or retire a match,
    /// and advance the simulation by at most one frame.
    ///
    /// Called at [`crate::grid::TICK_MS`], because one frame *is* one
    /// simulation tick — the session counts frames, not seconds.
    pub fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
        self.pump_lobby();
        self.adopt_started_match();
        self.propose_if_idle();
        self.advance();
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let roster = self
            .descriptor
            .as_ref()
            .map(|desc| {
                desc.roster
                    .iter()
                    .map(|pubkey| (pubkey.clone(), self.nick_for(pubkey).to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        Snapshot {
            match_number: self.match_number,
            room: self.room.clone(),
            world: self.world.clone(),
            roster,
            my_pubkey: self.transport.local_pubkey().unwrap_or_default(),
            present: self.lobby.as_ref().map_or(1, |lobby| lobby.present().len()),
            waiting: self.session.is_none(),
            desynced: self.desynced,
            blocked: self.blocked.clone(),
            syncing: self
                .session
                .as_ref()
                .is_some_and(|session| session.state() != SessionState::Running),
        }
    }

    #[must_use]
    pub fn outcome(&self) -> Outcome {
        sim::outcome(&self.world)
    }

    fn nick_for(&self, pubkey: &str) -> &str {
        self.nicks.get(pubkey).map_or("?", String::as_str)
    }

    /// Announce ourselves, fold in whatever arrived, and remember names.
    fn pump_lobby(&mut self) {
        if self.lobby.is_none() {
            // The lobby cannot exist until the event loop has told us who
            // we are; `local_pubkey` is `None` until then.
            let Some(pubkey) = self.transport.local_pubkey() else {
                return;
            };
            self.lobby = Some(Lobby::new(pubkey, self.my_nick.clone()));
        }
        let Some(lobby) = self.lobby.as_mut() else {
            return;
        };
        let now = u64::from(self.ticks);
        for (pubkey, raw) in self.transport.drain_lobby() {
            lobby.on_message(&pubkey, &raw, now);
        }
        // A peer that has gone quiet for a dozen presence rounds is gone,
        // and a restarted one comes back under a new public key rather
        // than reclaiming its old entry. Without this the roster only
        // grows and the next match is proposed with a ghost in it.
        lobby.expire(now, u64::from(PRESENCE_EVERY_TICKS) * 12);
        // Asked of every peer, not just whichever one proposes: the other
        // would otherwise show "players ready" for a match that can never
        // start.
        self.blocked = lobby.blocker().map(|reason| reason.to_string());
        for (pubkey, nick) in lobby.present() {
            self.nicks.insert(pubkey, nick);
        }
        if self.ticks.is_multiple_of(PRESENCE_EVERY_TICKS) {
            self.transport.broadcast_lobby(&lobby.presence());
            // The match, not just our presence: `Start` crosses the same
            // lossy path, and a peer that missed the one copy would wait
            // forever for a match the rest are already playing.
            if let Some(announcement) = lobby.announcement() {
                self.transport.broadcast_lobby(&announcement);
            }
        }
    }

    /// Build a session for whatever match the lobby has settled on, if it
    /// is newer than the one we are playing.
    fn adopt_started_match(&mut self) {
        let Some(agreed) = self.lobby.as_ref().and_then(Lobby::started) else {
            return;
        };
        if agreed.epoch <= self.match_number {
            // The lobby's tie-break can swap the agreed match at the *same*
            // epoch, and this declines to follow it: the session is already
            // built against the old id. Logged because the result is a pair
            // that never synchronizes while both sides look healthy.
            if self
                .session
                .as_ref()
                .is_some_and(|session| session.state() != SessionState::Running)
                && self.playing_session_id != Some(agreed.session_id)
            {
                tracing::debug!(
                    epoch = agreed.epoch,
                    agreed = agreed.session_id,
                    playing = self.playing_session_id,
                    "the lobby moved to another match at this epoch; keeping the built one"
                );
            }
            return;
        }
        let agreed = agreed.clone();
        self.begin(&agreed);
    }

    fn begin(&mut self, agreed: &StartedMatch) {
        // Truncating to the low 32 bits is fine: this only has to
        // distinguish *this* match's packets from the previous one's, and
        // the lobby's epoch already guarantees a fresh id per match.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "deliberately the low half of the session id; see above"
        )]
        let magic = agreed.session_id as u32;
        let Ok(session) = P2PSession::new(
            agreed.players.clone(),
            agreed.local_handle,
            self.transport.clone(),
            MAX_PREDICTION_FRAMES,
            INPUT_DELAY_FRAMES,
            magic,
        ) else {
            return;
        };
        // `derive` sorts, and the lobby's player list is already sorted by
        // public key, so roster index `i` is session handle `i`. Every
        // mapping between the two downstream relies on that.
        let descriptor = RoundDescriptor::derive(agreed.session_id, agreed.players.clone());
        self.world = World::spawn(&descriptor);
        self.descriptor = Some(descriptor);
        self.session = Some(session);
        self.match_number = agreed.epoch;
        self.playing_session_id = Some(agreed.session_id);
        self.decided_since = None;
        self.desynced = false;
        self.steer = None;
    }

    /// Somebody has to press start. That somebody is the lowest public key
    /// present — an arbitrary but universally agreed choice, so normally
    /// exactly one proposal is made. The lobby's tie-break covers the case
    /// where two are anyway.
    fn propose_if_idle(&mut self) {
        if !self.ready_for_a_new_match() {
            return;
        }
        let Some(lobby) = self.lobby.as_mut() else {
            return;
        };
        // Kept, not discarded. `NotEnoughPlayers` is transient and
        // `ready_for_a_new_match` already ruled it out; the one this can
        // really return is `DuplicateNickname`, which is *permanent* —
        // the check is a pure function of a roster that never shrinks, so
        // retrying it every tick forever changes nothing. Swallowing it
        // left the screen reading "GET READY" for a match that could
        // never start, which is the worst possible direction to be wrong
        // in.
        // The reason, if there is one, was already recorded by
        // `pump_lobby`'s `blocker()` call — this only has to stop.
        let Ok(start) = lobby.propose() else {
            return;
        };
        self.transport.broadcast_lobby(&start);
        if let Some(agreed) = lobby.started() {
            let agreed = agreed.clone();
            self.begin(&agreed);
        }
    }

    fn ready_for_a_new_match(&self) -> bool {
        let Some(lobby) = self.lobby.as_ref() else {
            return false;
        };
        let idle = match self.decided_since {
            // Mid-match: leave it alone.
            None => self.session.is_none(),
            Some(since) => self.ticks.saturating_sub(since) >= REMATCH_GRACE_TICKS,
        };
        let present = lobby.present();
        let lowest = present.first().is_some_and(|(pubkey, _)| {
            self.transport.local_pubkey().as_deref() == Some(pubkey.as_str())
        });
        idle && present.len() >= 2 && lowest
    }

    /// One frame of the match, if there is one and it is still running.
    fn advance(&mut self) {
        let Some(session) = &mut self.session else {
            return;
        };
        session.poll_remote_peers();
        for event in session.drain_events() {
            if matches!(event, Event::Desync { .. }) {
                self.desynced = true;
            }
        }
        if session.state() != SessionState::Running {
            return;
        }
        if session
            .add_local_input(Input { steer: self.steer })
            .is_err()
        {
            return;
        }
        // An error here is normal pacing — a peer is behind, or we are
        // yielding a frame to let it catch up. `Desync` is the exception,
        // and it is already reported through the event stream above.
        let Ok(requests) = session.advance_frame() else {
            return;
        };
        for request in requests {
            self.handle(request);
        }
        if let Some(session) = &mut self.session {
            session.publish_checksum();
        }

        // Evaluated *after* the frame, so a rollback inside it has already
        // had its say — and deliberately not a reason to stop advancing.
        // The simulation is a fixed point once decided (see `sim::step`),
        // so carrying on costs nothing, and it is the only way a
        // mispredicted ending ever gets corrected. Not latched, either:
        // a rollback that puts the match back in play clears it.
        if sim::outcome(&self.world) == Outcome::InProgress {
            self.decided_since = None;
        } else {
            self.decided_since.get_or_insert(self.ticks);
        }
    }

    /// Fulfil one session request. This is the whole of the game's side of
    /// the rollback contract.
    fn handle(&mut self, request: Request<LightCycles>) {
        match request {
            Request::SaveState { cell, frame } => {
                let checksum = self.world.checksum();
                cell.save(frame, self.world.clone(), Some(checksum));
            }
            Request::LoadState { cell } => {
                if let Some(world) = cell.load() {
                    self.world = world;
                }
            }
            Request::AdvanceFrame { inputs } => {
                let inputs: Vec<Input> = inputs.iter().map(|(input, _)| *input).collect();
                sim::step(&mut self.world, &inputs);
            }
        }
    }
}
