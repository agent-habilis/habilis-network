use crate::dir::Dir;
use serde::{Deserialize, Serialize};

/// One player's input for one tick.
///
/// State, not an event, which is what the rollback session's prediction
/// assumes: a missing input is guessed by repeating the last one, and
/// repeating "steering toward `Up`" is harmless (the cycle is already
/// facing `Up` by then) where repeating a "turned!" event would not be.
///
/// `None` — the [`Default`], and so also what a peer is predicted to have
/// sent before it has sent anything — means "hold course".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Input {
    pub steer: Option<Dir>,
}
