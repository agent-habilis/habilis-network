//! Determinism checking, with no network involved.
//!
//! The determinism contract on [`crate::Config`] is not something the
//! compiler can enforce, and a violation of it does not show up as a crash —
//! it shows up as two players watching different games, usually only over a
//! real network, usually not reproducibly. This session exists to turn that
//! into a local, deterministic test failure.
//!
//! Every frame it deliberately rolls back `check_distance` frames and
//! re-simulates forward over the *same* inputs. A correct simulation
//! reproduces identical state, so the checksums must match. If they don't,
//! something in the simulation depends on more than its inputs — a `HashMap`
//! iteration, a float, a clock read.
//!
//! ```ignore
//! let mut session = SyncTestSession::<MyGame>::new(2, 8);
//! for _ in 0..600 {
//!     session.add_input(0, p1_input())?;
//!     session.add_input(1, p2_input())?;
//!     for request in session.advance_frame()? {   // Err on desync
//!         fulfil(request);                        // exactly as in a real session
//!     }
//! }
//! ```
//!
//! Its one blind spot: it runs a single binary, so it cannot catch divergence
//! *between* targets. Native and `wasm32` disagreeing about a transcendental
//! will pass here and desync in production. For that, run a fixed input
//! script on both targets and compare the final checksum.

use std::collections::BTreeMap;

use crate::config::Config;
use crate::frame::Frame;
use crate::player_handle::PlayerHandle;
use crate::request::Request;
use crate::rollback_error::RollbackError;
use crate::sync::Sync;

use std::fmt;
/// A local session that re-simulates every frame and compares checksums.
///
/// # Examples
///
/// A test session advances without a peer and checks that its replays match.
///
/// ```
/// use habilis_network_netplay::{Frame, PlayerHandle, SyncTestSession};
///
/// use habilis_network_netplay::Config;
///
/// struct Game;
///
/// impl Config for Game {
///     type Input = u8;
///     type State = u32;
///     type Address = u8;
/// }
///
/// let mut session = SyncTestSession::<Game>::new(2, 1);
/// session.add_input(PlayerHandle::new(0), 1).expect("player 0 exists");
/// session.add_input(PlayerHandle::new(1), 2).expect("player 1 exists");
/// session.advance_frame().expect("no desync");
/// assert_eq!(session.current_frame(), Frame::new(1));
/// ```
pub struct SyncTestSession<T: Config> {
    sync: Sync<T>,
    num_players: usize,
    check_distance: usize,
    /// Inputs supplied for the frame currently being built.
    pending: Vec<Option<T::Input>>,
    /// The checksum each frame produced the first time it was simulated.
    history: BTreeMap<Frame, u128>,
}

impl<T: Config> fmt::Debug for SyncTestSession<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SyncTestSession");
        debug
            .field("num_players", &self.num_players)
            .field("check_distance", &self.check_distance);
        debug.field("sync", &self.sync).finish_non_exhaustive()
    }
}

impl<T: Config> SyncTestSession<T> {
    /// `check_distance` is how many frames to roll back every frame. Larger
    /// exercises deeper rollbacks and costs proportionally more time; 8 is a
    /// reasonable default.
    #[must_use]
    pub fn new(num_players: usize, check_distance: usize) -> Self {
        Self {
            // The saved-state ring must span the forced rollback.
            // No delay, and every input is supplied locally, so the
            // local-handle argument is immaterial here.
            sync: Sync::new(num_players, check_distance + 1, 0, PlayerHandle::new(0)),
            num_players,
            check_distance,
            pending: vec![None; num_players],
            history: BTreeMap::new(),
        }
    }

    /// Supply one player's input for the frame about to be advanced.
    ///
    /// # Errors
    /// [`RollbackError::InvalidPlayer`] if `player` is out of range.
    pub fn add_input(
        &mut self,
        player: PlayerHandle,
        input: T::Input,
    ) -> Result<(), RollbackError> {
        let slot = self
            .pending
            .get_mut(player.index())
            .ok_or(RollbackError::InvalidPlayer(player))?;
        *slot = Some(input);
        Ok(())
    }

    /// Advance one frame, having first re-simulated the previous
    /// `check_distance` frames and checked they came out the same.
    ///
    /// Fulfil the returned requests in order, exactly as in a real session.
    ///
    /// # Errors
    /// [`RollbackError::Desync`] if a re-simulated frame produced a different
    /// checksum than it did originally — the failure this session exists to
    /// surface. [`RollbackError::InvalidPlayer`] if a player's input was not
    /// supplied for this frame.
    pub fn advance_frame(
        &mut self,
    ) -> Result<impl Iterator<Item = Request<T>> + use<T>, RollbackError> {
        // Read back what the *previous* call's requests produced, before this
        // call's rollback overwrites those cells.
        self.harvest_checksums()?;

        if let Some(missing) = self.pending.iter().position(Option::is_none) {
            return Err(RollbackError::InvalidPlayer(PlayerHandle::new(missing)));
        }
        // Infallible after the check above, and written without an `expect`
        // so this function has no panicking path at all.
        let frame = self.sync.current_frame();
        let supplied: Vec<T::Input> = self.pending.iter_mut().filter_map(Option::take).collect();
        for (player, input) in supplied.into_iter().enumerate() {
            self.sync
                .add_remote_input(PlayerHandle::new(player), frame, input)?;
        }
        // Every player's real input is present every frame, so nothing is
        // ever predicted here — the rollback below is forced, not provoked.
        self.sync.confirm_through(frame);

        let mut requests = Vec::new();
        let rollback_to = frame - i32::try_from(self.check_distance).unwrap_or(i32::MAX);
        if rollback_to >= Frame::ZERO {
            self.sync.force_rollback(rollback_to, &mut requests);
        }
        requests.push(self.sync.save_current_state());
        requests.push(Request::AdvanceFrame {
            inputs: self.sync.synchronize_inputs(),
        });
        self.sync.advance_frame();
        Ok(requests.into_iter())
    }

    /// Compare every saved cell's checksum against what that frame produced
    /// the first time, recording it if this is the first time.
    fn harvest_checksums(&mut self) -> Result<(), RollbackError> {
        let current = self.sync.current_frame();
        let oldest = current - i32::try_from(self.check_distance + 1).unwrap_or(i32::MAX);
        for number in oldest.max(Frame::ZERO).get()..=current.get() {
            let frame = Frame::new(number);
            let Some(cell) = self.sync.saved_state(frame) else {
                continue;
            };
            let Some(checksum) = cell.checksum() else {
                continue;
            };
            match self.history.get(&frame) {
                Some(previous) if *previous != checksum => {
                    return Err(RollbackError::Desync {
                        frame,
                        local: *previous,
                        remote: checksum,
                    });
                }
                Some(_) => {}
                None => {
                    self.history.insert(frame, checksum);
                }
            }
        }
        // Frames older than the rollback window can never be re-simulated,
        // so their checksums are dead weight.
        self.history = self.history.split_off(&oldest.max(Frame::ZERO));
        Ok(())
    }

    /// The frame the simulation is currently at.
    #[must_use]
    pub fn current_frame(&self) -> Frame {
        self.sync.current_frame()
    }
}
