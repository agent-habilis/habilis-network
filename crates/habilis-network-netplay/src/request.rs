//! What the session asks the game to do.
//!
//! The session never calls into the game. It hands back a list of
//! [`Request`]s and the game fulfils them in order — the same shape
//! [GGRS](https://github.com/gschup/ggrs) uses, and the reason is
//! Rust-specific: a callback interface would force the game's state behind a
//! trait object or a closure the session holds, and every rollback would
//! fight the borrow checker. Returning requests keeps the game's state owned
//! by the game.
//!
//! Fulfil them **in the order given** and fulfil **all** of them; skipping a
//! `SaveState` breaks the next rollback, and skipping a `LoadState` desyncs
//! immediately.

use std::sync::{Arc, Mutex};

use crate::config::Config;
use crate::frame::{Frame, InputStatus};

use std::fmt;
/// A slot the game saves a frame's state into, and the session loads it back
/// out of.
///
/// Cheap to clone — it is a handle to one shared slot, not a copy of the
/// state.
///
/// # Examples
///
/// A cell keeps the state that a save request stored, with its frame.
///
/// ```
/// use habilis_network_netplay::{Frame, StateCell};
///
/// let cell: StateCell<u32> = StateCell::default();
/// cell.save(Frame::new(1), 7, Some(9));
/// assert_eq!(cell.frame(), Frame::new(1));
/// assert_eq!(cell.load(), Some(7));
/// ```
pub struct StateCell<S>(Arc<Mutex<CellInner<S>>>);

struct CellInner<S> {
    frame: Frame,
    state: Option<S>,
    checksum: Option<u128>,
}

impl<S> Clone for StateCell<S> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<S> Default for StateCell<S> {
    fn default() -> Self {
        // each clone of the cell shares this state
        Self(Arc::new(Mutex::new(CellInner {
            frame: Frame::NULL,
            state: None,
            checksum: None,
        })))
    }
}

impl<S> fmt::Debug for StateCell<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.0.lock().map_err(|_| fmt::Error)?;
        let mut debug = formatter.debug_struct("StateCell");
        debug
            .field("frame", &inner.frame)
            .field("has_state", &inner.state.is_some());
        debug.field("checksum", &inner.checksum).finish()
    }
}

impl<S> StateCell<S> {
    /// Fulfil a [`Request::SaveState`]: store this frame's state.
    ///
    /// `checksum` is optional but strongly recommended — it is what lets
    /// [`crate::SyncTestSession`] and the session's own desync detection
    /// notice that two peers have diverged. Any deterministic hash of the
    /// state will do, as long as every peer computes it the same way.
    ///
    /// # Panics
    /// If the cell's lock is poisoned by a panic in another thread while it
    /// was held.
    pub fn save(&self, frame: Frame, state: S, checksum: Option<u128>) {
        let mut inner = self.0.lock().expect("state cell lock poisoned");
        inner.frame = frame;
        inner.state = Some(state);
        inner.checksum = checksum;
    }

    /// The frame this cell holds, or [`Frame::NULL`] if it is empty.
    ///
    /// # Panics
    /// If the cell's lock is poisoned.
    #[must_use]
    pub fn frame(&self) -> Frame {
        self.0.lock().expect("state cell lock poisoned").frame
    }

    /// The checksum stored alongside the state, if the game supplied one.
    ///
    /// # Panics
    /// If the cell's lock is poisoned.
    #[must_use]
    pub fn checksum(&self) -> Option<u128> {
        self.0.lock().expect("state cell lock poisoned").checksum
    }
}

impl<S: Clone> StateCell<S> {
    /// Fulfil a [`Request::LoadState`]: take back the state to restore.
    ///
    /// `None` means the session asked to load a frame that was never saved,
    /// which is a bug in the caller's request handling rather than a normal
    /// outcome.
    ///
    /// # Panics
    /// If the cell's lock is poisoned.
    #[must_use]
    pub fn load(&self) -> Option<S> {
        self.0
            .lock()
            .expect("state cell lock poisoned")
            .state
            .clone()
    }
}

/// One instruction from the session to the game.
///
/// See the module docs: fulfil in order, fulfil all of them.
///
/// # Examples
///
/// The session asks for a save, which the caller fulfils, and then it advances.
///
/// ```
/// use habilis_network_netplay::{Frame, PlayerHandle, Request, SyncTestSession};
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
/// for request in session.advance_frame().expect("no desync") {
///     if let Request::SaveState { cell, frame } = request {
///         cell.save(frame, 0, Some(0));
///     }
/// }
/// assert_eq!(session.current_frame(), Frame::new(1));
/// ```
#[non_exhaustive]
pub enum Request<T: Config> {
    /// Save the current state into `cell`, tagged with `frame`.
    ///
    /// Call [`StateCell::save`] with a checksum if you can compute one
    /// cheaply — desync detection depends on it.
    SaveState {
        /// Where to put it.
        cell: StateCell<T::State>,
        /// The frame the state represents.
        frame: Frame,
    },
    /// Restore the state in `cell`, discarding the current one. The next
    /// `AdvanceFrame` continues from there.
    LoadState {
        /// Where to take it from.
        cell: StateCell<T::State>,
    },
    /// Advance the simulation exactly one frame using `inputs`, indexed by
    /// player handle.
    AdvanceFrame {
        /// One entry per player, in handle order. The [`InputStatus`] says
        /// whether each is real or predicted.
        inputs: Vec<(T::Input, InputStatus)>,
    },
}

impl<T: Config> fmt::Debug for Request<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SaveState { frame, .. } => formatter
                .debug_struct("SaveState")
                .field("frame", frame)
                .finish_non_exhaustive(),
            Self::LoadState { cell } => formatter
                .debug_struct("LoadState")
                .field("frame", &cell.frame())
                .finish_non_exhaustive(),
            Self::AdvanceFrame { inputs } => formatter
                .debug_struct("AdvanceFrame")
                .field("players", &inputs.len())
                .finish_non_exhaustive(),
        }
    }
}
