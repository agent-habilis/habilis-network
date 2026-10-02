//! One player's inputs, indexed by frame, with prediction.
//!
//! This is the piece that makes rollback possible. When the simulation asks
//! for a frame we don't have an input for yet — the normal case for a remote
//! player — the queue *predicts* by repeating that player's last known input
//! and remembers that it did. When the real input eventually arrives, the
//! queue compares it against what it guessed; the first frame where they
//! disagree is [`InputQueue::first_incorrect_frame`], and that is the frame
//! the session must roll back to.
//!
//! Ported from GGPO's `InputQueue`, keeping its structure (a frame-indexed
//! ring buffer, a single in-flight prediction) because the invariants are
//! subtle and worth inheriting rather than rediscovering.

use crate::config::Config;
use crate::frame::{Frame, InputStatus, NULL_FRAME};

/// Ring-buffer capacity, in frames.
///
/// Bounds how far back a late input can still be filed. Must comfortably
/// exceed any sane `max_prediction`; GGPO uses the same 128.
const QUEUE_LEN: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot<I> {
    frame: Frame,
    input: I,
}

impl<I: Default> Default for Slot<I> {
    fn default() -> Self {
        Self {
            frame: NULL_FRAME,
            input: I::default(),
        }
    }
}

/// One player's input history, with prediction for the frames not yet known.
pub(crate) struct InputQueue<T: Config> {
    /// Frame-indexed ring. A slot is live iff its frame is within
    /// `[tail_frame, last_added_frame]`.
    inputs: Vec<Slot<T::Input>>,
    /// Next write position.
    head: usize,
    /// Oldest live position.
    tail: usize,
    /// Live slot count.
    length: usize,
    /// Nothing added yet — distinguishes "empty" from "wrapped".
    first_frame: bool,
    /// Highest frame accepted *after* frame delay — the ring's own
    /// numbering, and what [`Self::confirmed`] indexes against.
    last_added_frame: Frame,
    /// Highest frame accepted *before* frame delay — the caller's numbering.
    ///
    /// Tracked separately because the two live in different frame spaces
    /// once `frame_delay` is non-zero: the caller adds frame N and the ring
    /// stores it at N + delay. Checking arrival order against the ring's
    /// numbering would compare the two and reject every ordinary input.
    last_user_added_frame: Frame,
    /// Earliest frame where a real input contradicted our guess, or
    /// [`NULL_FRAME`] if every guess so far held up.
    first_incorrect_frame: Frame,
    /// Last frame the simulation asked for, so we know when a prediction has
    /// caught up with reality.
    last_requested_frame: Frame,
    /// Frames of deliberate local input delay. Trades responsiveness for a
    /// lower chance of ever needing to predict.
    frame_delay: usize,
    /// The guess currently in flight. `frame == NULL_FRAME` means we are not
    /// predicting — everything asked for so far was real.
    prediction: Slot<T::Input>,
}

impl<T: Config> std::fmt::Debug for InputQueue<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InputQueue")
            .field("length", &self.length)
            .field("last_added_frame", &self.last_added_frame)
            .field("first_incorrect_frame", &self.first_incorrect_frame)
            .field("predicting", &(self.prediction.frame != NULL_FRAME))
            .finish_non_exhaustive()
    }
}

impl<T: Config> InputQueue<T> {
    pub(crate) fn new() -> Self {
        Self {
            inputs: vec![Slot::default(); QUEUE_LEN],
            head: 0,
            tail: 0,
            length: 0,
            first_frame: true,
            last_added_frame: NULL_FRAME,
            last_user_added_frame: NULL_FRAME,
            first_incorrect_frame: NULL_FRAME,
            last_requested_frame: NULL_FRAME,
            frame_delay: 0,
            prediction: Slot::default(),
        }
    }

    pub(crate) fn set_frame_delay(&mut self, delay: usize) {
        self.frame_delay = delay;
    }

    pub(crate) fn first_incorrect_frame(&self) -> Frame {
        self.first_incorrect_frame
    }

    pub(crate) fn last_added_frame(&self) -> Frame {
        self.last_added_frame
    }

    /// The oldest frame still held, or [`NULL_FRAME`] when empty.
    fn tail_frame(&self) -> Frame {
        if self.length == 0 {
            NULL_FRAME
        } else {
            self.inputs[self.tail].frame
        }
    }

    /// Abandon the current prediction from `frame` on, after the session has
    /// rolled back and re-simulated. Everything before `frame` is settled.
    pub(crate) fn reset_prediction(&mut self, frame: Frame) {
        debug_assert!(
            self.first_incorrect_frame == NULL_FRAME || frame <= self.first_incorrect_frame
        );
        self.prediction.frame = NULL_FRAME;
        self.first_incorrect_frame = NULL_FRAME;
        self.last_requested_frame = NULL_FRAME;
    }

    /// The input for `frame`: the real one if we have it, otherwise a guess.
    ///
    /// Asking for a frame we are already known to have mispredicted is a
    /// caller bug — the session must roll back first.
    pub(crate) fn input(&mut self, frame: Frame) -> (T::Input, InputStatus) {
        debug_assert!(
            self.first_incorrect_frame == NULL_FRAME,
            "asked for an input while a misprediction is outstanding; roll back first"
        );
        self.last_requested_frame = frame;

        if self.prediction.frame == NULL_FRAME {
            if let Some(input) = self.confirmed(frame) {
                return (input, InputStatus::Confirmed);
            }
            // We don't have it — start predicting by repeating the last
            // known input (the default, if there is no history yet).
            //
            // The prediction is stamped with the frame the *next real input
            // will fill*, which is not necessarily the frame being asked
            // for. A peer that finished its handshake later than us starts
            // sending from its frame 0 while we are already several frames
            // in, so its first real input arrives for a frame we have
            // already predicted past. Stamping the requested frame here
            // would then mismatch that arrival and lose the misprediction
            // — which is exactly the case rollback exists to handle.
            let fills_at = if self.last_added_frame == NULL_FRAME {
                0
            } else {
                self.last_added_frame + 1
            };
            self.prediction = Slot {
                frame: fills_at,
                input: if self.last_added_frame == NULL_FRAME {
                    T::Input::default()
                } else {
                    self.inputs[self.prev_head()].input
                },
            };
        }
        (self.prediction.input, InputStatus::Predicted)
    }

    /// The real input for `frame`, if it is in the ring.
    fn confirmed(&self, frame: Frame) -> Option<T::Input> {
        if self.length == 0 {
            return None;
        }
        let tail_frame = self.tail_frame();
        if frame < tail_frame || frame > self.last_added_frame {
            return None;
        }
        let offset = usize::try_from(frame - tail_frame).ok()?;
        if offset >= self.length {
            return None;
        }
        let slot = self.inputs[(self.tail + offset) % QUEUE_LEN];
        debug_assert_eq!(slot.frame, frame);
        Some(slot.input)
    }

    fn prev_head(&self) -> usize {
        (self.head + QUEUE_LEN - 1) % QUEUE_LEN
    }

    /// Record a real input for `frame`, applying this queue's frame delay.
    ///
    /// Returns the frame it was actually filed under, or [`NULL_FRAME`] if it
    /// was dropped (which happens when the delay shrinks and the input lands
    /// behind what we already have).
    pub(crate) fn add_input(&mut self, frame: Frame, input: T::Input) -> Frame {
        debug_assert!(
            self.last_user_added_frame == NULL_FRAME || frame == self.last_user_added_frame + 1,
            "inputs must be added in consecutive frame order"
        );
        self.last_user_added_frame = frame;
        let target = self.advance_queue_head(frame);
        if target == NULL_FRAME {
            return NULL_FRAME;
        }
        self.add_delayed_input(target, input);
        target
    }

    /// Apply `frame_delay` and fill any gap the delay opened, returning the
    /// frame the caller's input should occupy.
    fn advance_queue_head(&mut self, frame: Frame) -> Frame {
        let mut expected = if self.first_frame {
            0
        } else {
            self.inputs[self.prev_head()].frame + 1
        };
        let delayed = frame + i32::try_from(self.frame_delay).unwrap_or(0);

        if expected > delayed {
            // The delay shrank and this input belongs in the past. Drop it;
            // the frame it would have occupied already has an input.
            return NULL_FRAME;
        }
        // The delay grew: repeat the last input to bridge the gap so the
        // queue stays frame-contiguous. Filed through `add_delayed_input`
        // rather than pushed straight in, because a filler settles any
        // prediction standing on its frame exactly as a real input would —
        // skipping that leaves the prediction cursor behind and the next
        // real input arrives against the wrong frame.
        while expected < delayed {
            let filler = self.inputs[self.prev_head()].input;
            self.add_delayed_input(expected, filler);
            expected += 1;
        }
        delayed
    }

    /// Append a slot, ageing out the oldest frame once the ring is full.
    ///
    /// Self-trimming is why there is no explicit "discard confirmed frames"
    /// step: [`QUEUE_LEN`] frames of history is far more than any rollback
    /// can reach, so anything that falls off the back was unreachable anyway.
    fn push(&mut self, slot: Slot<T::Input>) {
        self.inputs[self.head] = slot;
        self.head = (self.head + 1) % QUEUE_LEN;
        if self.length == QUEUE_LEN {
            self.tail = (self.tail + 1) % QUEUE_LEN;
        } else {
            self.length += 1;
        }
        self.first_frame = false;
    }

    /// File a real input and check it against any prediction it settles.
    fn add_delayed_input(&mut self, frame: Frame, input: T::Input) {
        self.push(Slot { frame, input });
        self.last_added_frame = frame;

        if self.prediction.frame == NULL_FRAME {
            return;
        }
        debug_assert_eq!(frame, self.prediction.frame);
        // The guess was wrong: remember the earliest frame it went wrong at.
        if self.first_incorrect_frame == NULL_FRAME && self.prediction.input != input {
            self.first_incorrect_frame = frame;
        }
        if self.prediction.frame == self.last_requested_frame
            && self.first_incorrect_frame == NULL_FRAME
        {
            // Reality caught up and we were right the whole way. Stop
            // predicting.
            self.prediction.frame = NULL_FRAME;
        } else {
            self.prediction.frame += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InputQueue;
    use crate::frame::{InputStatus, NULL_FRAME};
    use crate::testutil::{TestGame, TestInput};

    fn queue() -> InputQueue<TestGame> {
        InputQueue::<TestGame>::new()
    }

    #[test]
    fn a_known_input_comes_back_confirmed() {
        let mut queue = queue();
        queue.add_input(0, TestInput(7));
        assert_eq!(queue.input(0), (TestInput(7), InputStatus::Confirmed));
        assert_eq!(queue.first_incorrect_frame(), NULL_FRAME);
    }

    #[test]
    fn an_unknown_input_is_predicted_by_repeating_the_last_one() {
        let mut queue = queue();
        queue.add_input(0, TestInput(7));
        let _ = queue.input(0);
        // Frame 1 hasn't arrived; the guess is "same as frame 0".
        assert_eq!(queue.input(1), (TestInput(7), InputStatus::Predicted));
    }

    #[test]
    fn the_very_first_frame_predicts_the_default_input() {
        let mut queue = queue();
        assert_eq!(
            queue.input(0),
            (TestInput::default(), InputStatus::Predicted)
        );
    }

    #[test]
    fn a_prediction_that_turns_out_right_reports_no_misprediction() {
        let mut queue = queue();
        queue.add_input(0, TestInput(7));
        let _ = queue.input(0);
        let _ = queue.input(1); // predicts 7
        queue.add_input(1, TestInput(7)); // and 7 is what actually happened
        assert_eq!(queue.first_incorrect_frame(), NULL_FRAME);
    }

    #[test]
    fn a_prediction_that_turns_out_wrong_reports_the_frame_it_broke_at() {
        let mut queue = queue();
        queue.add_input(0, TestInput(7));
        let _ = queue.input(0);
        let _ = queue.input(1); // predicts 7
        queue.add_input(1, TestInput(9)); // but the player did something else
        assert_eq!(queue.first_incorrect_frame(), 1);
    }

    #[test]
    fn only_the_earliest_misprediction_is_reported() {
        let mut queue = queue();
        queue.add_input(0, TestInput(1));
        let _ = queue.input(0);
        let _ = queue.input(1);
        let _ = queue.input(2);
        queue.add_input(1, TestInput(2)); // wrong here
        queue.add_input(2, TestInput(3)); // and here, but 1 is what we roll back to
        assert_eq!(queue.first_incorrect_frame(), 1);
    }

    #[test]
    fn resetting_prediction_clears_the_misprediction() {
        let mut queue = queue();
        queue.add_input(0, TestInput(1));
        let _ = queue.input(0);
        let _ = queue.input(1);
        queue.add_input(1, TestInput(2));
        assert_eq!(queue.first_incorrect_frame(), 1);

        queue.reset_prediction(1);
        assert_eq!(queue.first_incorrect_frame(), NULL_FRAME);
        // The real input is still there — the rollback re-reads it as truth.
        assert_eq!(queue.input(1), (TestInput(2), InputStatus::Confirmed));
    }

    #[test]
    fn frame_delay_files_an_input_later_than_it_was_made() {
        let mut queue = queue();
        queue.set_frame_delay(3);
        assert_eq!(queue.add_input(0, TestInput(5)), 3);
        // A second add must be accepted too: the caller counts from 0 while
        // the ring counts from 0 + delay, and conflating the two rejects
        // every input after the first.
        assert_eq!(queue.add_input(1, TestInput(6)), 4);
        // The delayed frames before it are filled so the queue stays
        // contiguous, and they read as the default input.
        assert_eq!(
            queue.input(0),
            (TestInput::default(), InputStatus::Confirmed)
        );
        assert_eq!(queue.input(3), (TestInput(5), InputStatus::Confirmed));
    }

    #[test]
    fn the_ring_ages_out_old_frames_instead_of_corrupting() {
        let mut queue = queue();
        // Push well past the ring's capacity.
        let span = i32::try_from(super::QUEUE_LEN).expect("the ring length fits an i32") * 2;
        for frame in 0..span {
            queue.add_input(frame, TestInput(frame));
        }
        let newest = span - 1;
        assert_eq!(queue.last_added_frame(), newest);
        // Recent frames survive intact...
        assert_eq!(
            queue.input(newest),
            (TestInput(newest), InputStatus::Confirmed)
        );
        // ...and an ancient one is simply gone, not silently wrong.
        assert!(queue.confirmed(0).is_none());
    }
}
