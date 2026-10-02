//! The rollback window: the last N frames of saved state.
//!
//! Rollback can only reach as far back as there is a saved state to reach,
//! so this ring is what actually bounds `max_prediction`. Sized two larger
//! than the prediction window: one for the frame currently being simulated,
//! one so the oldest confirmed frame is still reachable while the newest is
//! being written.

use crate::frame::{Frame, NULL_FRAME};
use crate::request::StateCell;

pub(crate) struct SavedStates<S> {
    cells: Vec<StateCell<S>>,
    head: usize,
}

impl<S> std::fmt::Debug for SavedStates<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SavedStates")
            .field("capacity", &self.cells.len())
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

impl<S> SavedStates<S> {
    pub(crate) fn new(max_prediction: usize) -> Self {
        let capacity = max_prediction + 2;
        Self {
            cells: (0..capacity).map(|_| StateCell::default()).collect(),
            head: 0,
        }
    }

    /// The cell `frame`'s state should be written into.
    ///
    /// Reuses the cell already holding `frame` if there is one, rather than
    /// advancing the ring. That matters during a rollback: re-simulating a
    /// frame must *replace* its saved state, not leave a second cell
    /// claiming the same frame for [`Self::by_frame`] to pick between.
    pub(crate) fn push(&mut self, frame: Frame) -> StateCell<S> {
        if let Some(existing) = self.by_frame(frame) {
            return existing;
        }
        let cell = self.cells[self.head].clone();
        self.head = (self.head + 1) % self.cells.len();
        cell
    }

    /// The cell holding `frame`, if it is still inside the window.
    pub(crate) fn by_frame(&self, frame: Frame) -> Option<StateCell<S>> {
        if frame == NULL_FRAME {
            return None;
        }
        self.cells
            .iter()
            .find(|cell| cell.frame() == frame)
            .cloned()
    }
}
