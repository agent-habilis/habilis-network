//! Grid constants and the per-tick input type. Pure — no habilis-network, no
//! async, no networking. This crate's own copy, independent of
//! `web/wasm`'s (see the plan's "Workspace layout": the two clients
//! deliberately share no code).

use serde::{Deserialize, Serialize};

pub const GRID_W: u8 = 64;
pub const GRID_H: u8 = 48;
/// 20 Hz — generous for a terminal, and the rate the rollback session's
/// frames are counted in, since one frame is one simulation tick.
pub const TICK_MS: u32 = 50;
/// Hard cap so a round always ends even with no collisions — 90s.
pub const ROUND_MAX_TICKS: u16 = 1800;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Dir {
    Up = 0,
    Right = 1,
    Down = 2,
    Left = 3,
}

impl Dir {
    #[must_use]
    pub fn is_reverse_of(self, other: Dir) -> bool {
        matches!(
            (self, other),
            (Dir::Up, Dir::Down)
                | (Dir::Down, Dir::Up)
                | (Dir::Left, Dir::Right)
                | (Dir::Right, Dir::Left)
        )
    }

    #[must_use]
    pub fn delta(self) -> (i16, i16) {
        match self {
            Dir::Up => (0, -1),
            Dir::Right => (1, 0),
            Dir::Down => (0, 1),
            Dir::Left => (-1, 0),
        }
    }
}

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
