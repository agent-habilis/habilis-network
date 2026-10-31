#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    InProgress,
    /// Roster index of the sole survivor.
    Winner(usize),
    Draw,
}
