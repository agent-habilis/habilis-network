//! Frame numbering.

/// A simulation frame number.
///
/// Signed, so [`NULL_FRAME`] can be a sentinel and so "how far ahead am I"
/// arithmetic can go negative without wrapping. The simulation itself starts
/// at frame `0`.
pub type Frame = i32;

/// "No frame" — an empty slot, an un-started queue, or the absence of a
/// misprediction. Distinct from frame `0`, which is a real frame.
pub const NULL_FRAME: Frame = -1;

/// Whether the input handed to the simulation for a frame is the real thing
/// or a guess.
///
/// A predicted input is not an error: it is the normal case for a remote
/// player whose input has not arrived yet, and the session will roll back and
/// re-simulate if the guess turns out wrong. Apps mostly ignore this, but it
/// is worth honouring for effects that shouldn't fire twice — a sound cue on
/// a predicted input may be re-triggered after a rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputStatus {
    /// The player's real input for this frame, received and confirmed.
    Confirmed,
    /// A guess. The session predicts by repeating the player's last known
    /// input, which is GGPO's own strategy and the right one for held-button
    /// controls.
    Predicted,
    /// The player has disconnected; this is the neutral default input.
    Disconnected,
}
