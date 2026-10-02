//! The rollback engine: predict, detect, roll back, re-simulate.
//!
//! This owns one [`InputQueue`] per player and the ring of saved states, and
//! knows nothing about networking — inputs arrive by whatever means the layer
//! above chooses. That split is deliberate: everything here is exercised
//! offline by [`crate::SyncTestSession`], so the hard part is testable without
//! a socket.
//!
//! The cycle each frame:
//!
//! 1. [`Sync::save_current_state`] — snapshot before advancing, so this frame
//!    is reachable if a later input contradicts a guess made now.
//! 2. [`Sync::synchronize_inputs`] — gather one input per player, real where
//!    known and predicted where not.
//! 3. the game advances one frame.
//! 4. [`Sync::check_simulation`] — if a real input has since contradicted a
//!    prediction, load the state from the frame it went wrong at and
//!    re-simulate forward to where we were.

// Part of the rollback core's API for the peer session that arrives in the
// next stage; today only this crate's own tests reach it. Scoped to non-test
// builds so the suppression lapses on its own once there is a real consumer.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the peer session in the next stage")
)]

use crate::config::Config;
use crate::error::RollbackError;
use crate::frame::{Frame, InputStatus, NULL_FRAME};
use crate::input_queue::InputQueue;
use crate::request::{Request, StateCell};
use crate::saved_states::SavedStates;

pub(crate) struct Sync<T: Config> {
    input_queues: Vec<InputQueue<T>>,
    saved_states: SavedStates<T::State>,
    max_prediction: usize,
    /// The frame the simulation is currently at.
    current_frame: Frame,
    /// Highest frame every player's real input is known for.
    last_confirmed_frame: Frame,
}

impl<T: Config> std::fmt::Debug for Sync<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sync")
            .field("current_frame", &self.current_frame)
            .field("last_confirmed_frame", &self.last_confirmed_frame)
            .field("max_prediction", &self.max_prediction)
            .field("players", &self.input_queues.len())
            .finish_non_exhaustive()
    }
}

impl<T: Config> Sync<T> {
    /// `input_delay` applies to **`local_handle`'s queue only**.
    ///
    /// It is a local responsiveness tradeoff — hold our own input back a few
    /// frames so remote input has time to arrive and we predict less often.
    /// Applying it to remote queues too would delay each input twice: the
    /// sender already shifted it before transmitting, so the receiver would
    /// file the same input at a later frame than the sender did, and the two
    /// would be simulating different games.
    pub(crate) fn new(
        num_players: usize,
        max_prediction: usize,
        input_delay: usize,
        local_handle: usize,
    ) -> Self {
        let mut input_queues: Vec<InputQueue<T>> =
            (0..num_players).map(|_| InputQueue::new()).collect();
        if let Some(local) = input_queues.get_mut(local_handle) {
            local.set_frame_delay(input_delay);
        }
        Self {
            input_queues,
            saved_states: SavedStates::new(max_prediction),
            max_prediction,
            current_frame: 0,
            last_confirmed_frame: NULL_FRAME,
        }
    }

    pub(crate) fn current_frame(&self) -> Frame {
        self.current_frame
    }

    pub(crate) fn last_confirmed_frame(&self) -> Frame {
        self.last_confirmed_frame
    }

    /// How far ahead of the last fully-confirmed frame we have simulated.
    /// Once this reaches `max_prediction` the session must stall rather than
    /// guess further — there would be no saved state left to roll back to.
    pub(crate) fn frames_ahead(&self) -> usize {
        if self.last_confirmed_frame == NULL_FRAME {
            return usize::try_from(self.current_frame).unwrap_or(0);
        }
        usize::try_from(self.current_frame - self.last_confirmed_frame).unwrap_or(0)
    }

    /// Record this peer's own input for the current frame.
    ///
    /// # Errors
    /// [`RollbackError::PredictionLimit`] if we are already `max_prediction`
    /// frames ahead of confirmation — the caller must stop advancing and let
    /// remote inputs catch up.
    pub(crate) fn add_local_input(
        &mut self,
        player: usize,
        input: T::Input,
    ) -> Result<Frame, RollbackError> {
        if self.frames_ahead() >= self.max_prediction {
            return Err(RollbackError::PredictionLimit);
        }
        let queue = self
            .input_queues
            .get_mut(player)
            .ok_or(RollbackError::InvalidPlayer(player))?;
        Ok(queue.add_input(self.current_frame, input))
    }

    /// Record a remote peer's real input for a specific frame.
    ///
    /// # Errors
    /// [`RollbackError::InvalidPlayer`] if `player` is out of range.
    pub(crate) fn add_remote_input(
        &mut self,
        player: usize,
        frame: Frame,
        input: T::Input,
    ) -> Result<(), RollbackError> {
        let queue = self
            .input_queues
            .get_mut(player)
            .ok_or(RollbackError::InvalidPlayer(player))?;
        queue.add_input(frame, input);
        Ok(())
    }

    /// One input per player for the current frame — real where known,
    /// predicted where not.
    pub(crate) fn synchronize_inputs(&mut self) -> Vec<(T::Input, InputStatus)> {
        let frame = self.current_frame;
        self.input_queues
            .iter_mut()
            .map(|queue| queue.input(frame))
            .collect()
    }

    /// A `SaveState` request for the frame about to be advanced past.
    pub(crate) fn save_current_state(&mut self) -> Request<T> {
        let cell = self.saved_states.push(self.current_frame);
        Request::SaveState {
            cell,
            frame: self.current_frame,
        }
    }

    /// Roll back to `seek_to` and re-simulate forward to the current frame,
    /// without a misprediction having occurred. Used by
    /// [`crate::SyncTestSession`] to exercise the rollback path deliberately.
    pub(crate) fn force_rollback(&mut self, seek_to: Frame, requests: &mut Vec<Request<T>>) {
        self.adjust_simulation(seek_to, requests);
    }

    pub(crate) fn advance_frame(&mut self) {
        self.current_frame += 1;
    }

    /// Mark every frame through `frame` as having every player's real input,
    /// so the prediction window is measured from there.
    pub(crate) fn confirm_through(&mut self, frame: Frame) {
        self.last_confirmed_frame = self.last_confirmed_frame.max(frame);
    }

    /// The earliest frame any player's real input contradicted our guess, or
    /// [`NULL_FRAME`] if every guess is still holding.
    fn first_incorrect_frame(&self) -> Frame {
        self.input_queues
            .iter()
            .map(InputQueue::first_incorrect_frame)
            .filter(|frame| *frame != NULL_FRAME)
            .min()
            .unwrap_or(NULL_FRAME)
    }

    /// If a prediction turned out wrong, emit the requests that undo and
    /// redo the affected frames. Appends nothing when everything held up.
    pub(crate) fn check_simulation(&mut self, requests: &mut Vec<Request<T>>) {
        let seek_to = self.first_incorrect_frame();
        if seek_to == NULL_FRAME {
            return;
        }
        self.adjust_simulation(seek_to, requests);
    }

    /// Roll back to `seek_to` and re-simulate up to where we were.
    ///
    /// The re-simulated frames use the *real* inputs that are now known, so
    /// the state they produce differs from the one being discarded — that is
    /// the entire point.
    fn adjust_simulation(&mut self, seek_to: Frame, requests: &mut Vec<Request<T>>) {
        let resume_at = self.current_frame;
        let Some(cell) = self.saved_states.by_frame(seek_to) else {
            // Nothing to roll back to. Only reachable if `max_prediction` was
            // exceeded without stalling, which `add_local_input` prevents.
            debug_assert!(
                false,
                "rollback target {seek_to} is outside the saved window"
            );
            return;
        };

        requests.push(Request::LoadState { cell });
        self.current_frame = seek_to;
        for queue in &mut self.input_queues {
            queue.reset_prediction(seek_to);
        }

        while self.current_frame < resume_at {
            let inputs = self.synchronize_inputs();
            requests.push(self.save_current_state());
            requests.push(Request::AdvanceFrame { inputs });
            self.advance_frame();
        }
        debug_assert_eq!(self.current_frame, resume_at);
    }

    /// The saved state for `frame`, for checksum comparison.
    pub(crate) fn saved_state(&self, frame: Frame) -> Option<StateCell<T::State>> {
        self.saved_states.by_frame(frame)
    }

    /// Highest frame each player has a real input for. Used by the layer
    /// above to decide what is confirmed across the whole session.
    pub(crate) fn last_added_frames(&self) -> impl Iterator<Item = Frame> + '_ {
        self.input_queues.iter().map(InputQueue::last_added_frame)
    }
}

#[cfg(test)]
mod tests {
    use super::Sync;
    use crate::error::RollbackError;
    use crate::frame::{InputStatus, NULL_FRAME};
    use crate::request::Request;
    use crate::testutil::{TestGame, TestInput, TestRunner};

    /// Two players, generous prediction window, no input delay.
    fn session() -> Sync<TestGame> {
        Sync::<TestGame>::new(2, 8, 0, 0)
    }

    /// Advance one frame the way a real caller does.
    fn step(sync: &mut Sync<TestGame>, runner: &mut TestRunner) {
        let mut requests = vec![sync.save_current_state()];
        requests.push(Request::AdvanceFrame {
            inputs: sync.synchronize_inputs(),
        });
        sync.advance_frame();
        runner.handle_all(requests);
    }

    #[test]
    fn a_correct_prediction_never_rolls_back() {
        let mut sync = session();
        let mut runner = TestRunner::new();

        for frame in 0..4 {
            sync.add_local_input(0, TestInput(1))
                .expect("under the limit");
            // Player 1's input arrives on time and is always the same, so
            // every prediction holds.
            sync.add_remote_input(1, frame, TestInput(2))
                .expect("valid player");
            step(&mut sync, &mut runner);
        }

        let mut requests = Vec::new();
        sync.check_simulation(&mut requests);
        assert!(requests.is_empty(), "nothing was mispredicted");
        assert_eq!(runner.advanced, vec![0, 1, 2, 3], "each frame ran once");
        assert_eq!(runner.state.value, 4 * (1 + 2));
    }

    #[test]
    fn a_wrong_prediction_rolls_back_and_re_simulates_with_the_truth() {
        let mut sync = session();
        let mut runner = TestRunner::new();

        // Frame 0 with both real inputs.
        sync.add_local_input(0, TestInput(1))
            .expect("under the limit");
        sync.add_remote_input(1, 0, TestInput(10))
            .expect("valid player");
        step(&mut sync, &mut runner);

        // Frames 1 and 2 run with player 1 predicted as 10.
        for _ in 0..2 {
            sync.add_local_input(0, TestInput(1))
                .expect("under the limit");
            step(&mut sync, &mut runner);
        }
        assert_eq!(runner.state.value, 11 + 11 + 11);
        assert_eq!(runner.advanced, vec![0, 1, 2]);

        // Player 1's real frame-1 input turns out different.
        sync.add_remote_input(1, 1, TestInput(20))
            .expect("valid player");
        let mut requests = Vec::new();
        sync.check_simulation(&mut requests);
        runner.handle_all(requests);

        // Frames 1 and 2 were re-simulated, and the total now reflects the
        // real input rather than the guess.
        assert_eq!(runner.advanced, vec![0, 1, 2, 1, 2]);
        assert_eq!(runner.state.value, 11 + 21 + 21);
        assert_eq!(sync.current_frame(), 3, "we end up where we started");
    }

    #[test]
    fn re_simulation_uses_a_fresh_prediction_for_frames_still_unknown() {
        let mut sync = session();
        let mut runner = TestRunner::new();

        sync.add_local_input(0, TestInput(0))
            .expect("under the limit");
        sync.add_remote_input(1, 0, TestInput(1))
            .expect("valid player");
        step(&mut sync, &mut runner);
        for _ in 0..2 {
            sync.add_local_input(0, TestInput(0))
                .expect("under the limit");
            step(&mut sync, &mut runner);
        }

        // Correct frame 1 only; frame 2 is still unknown and must be
        // re-predicted from the *corrected* frame 1, not the old guess.
        sync.add_remote_input(1, 1, TestInput(5))
            .expect("valid player");
        let mut requests = Vec::new();
        sync.check_simulation(&mut requests);
        runner.handle_all(requests);

        // frame 0 = 1 (real), frame 1 = 5 (real), frame 2 = 5 (predicted from 1)
        assert_eq!(runner.state.value, 1 + 5 + 5);
    }

    #[test]
    fn the_prediction_limit_stops_the_caller_rather_than_guessing_further() {
        let mut sync = Sync::<TestGame>::new(2, 3, 0, 0);
        let mut runner = TestRunner::new();

        // Player 1 never sends anything, so nothing is ever confirmed.
        for _ in 0..3 {
            sync.add_local_input(0, TestInput(1))
                .expect("within the window");
            step(&mut sync, &mut runner);
        }
        assert_eq!(
            sync.add_local_input(0, TestInput(1)),
            Err(RollbackError::PredictionLimit),
            "past the window the session must stall, not guess deeper"
        );
    }

    #[test]
    fn confirming_frames_reopens_the_prediction_window() {
        let mut sync = Sync::<TestGame>::new(2, 3, 0, 0);
        let mut runner = TestRunner::new();

        for _ in 0..3 {
            sync.add_local_input(0, TestInput(1))
                .expect("within the window");
            step(&mut sync, &mut runner);
        }
        assert!(sync.add_local_input(0, TestInput(1)).is_err());

        sync.confirm_through(1);
        assert_eq!(sync.last_confirmed_frame(), 1);
        assert_eq!(sync.frames_ahead(), 2);
        sync.add_local_input(0, TestInput(1))
            .expect("confirmation made room again");
    }

    #[test]
    fn an_unknown_player_handle_is_an_error_not_a_panic() {
        let mut sync = session();
        assert_eq!(
            sync.add_local_input(9, TestInput(0)),
            Err(RollbackError::InvalidPlayer(9))
        );
        assert_eq!(
            sync.add_remote_input(9, 0, TestInput(0)),
            Err(RollbackError::InvalidPlayer(9))
        );
    }

    #[test]
    fn inputs_are_reported_as_confirmed_or_predicted_honestly() {
        let mut sync = session();
        sync.add_local_input(0, TestInput(1))
            .expect("under the limit");
        let inputs = sync.synchronize_inputs();
        assert_eq!(inputs[0].1, InputStatus::Confirmed, "our own input is real");
        assert_eq!(
            inputs[1].1,
            InputStatus::Predicted,
            "the absent peer's is a guess"
        );
        assert_eq!(
            sync.last_added_frames().collect::<Vec<_>>(),
            vec![0, NULL_FRAME]
        );
    }
}
