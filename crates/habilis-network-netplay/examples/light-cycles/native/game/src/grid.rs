//! Grid constants and the per-tick input type. Pure — no habilis-network, no
//! async, no networking. This crate's own copy, independent of
//! `web/wasm`'s (see the plan's "Workspace layout": the two clients
//! deliberately share no code).

pub const GRID_W: u8 = 64;

pub const GRID_H: u8 = 48;

/// 20 Hz — generous for a terminal, and the rate the rollback session's
/// frames are counted in, since one frame is one simulation tick.
pub const TICK_MS: u32 = 50;

/// Hard cap so a round always ends even with no collisions — 90s.
pub const ROUND_MAX_TICKS: u16 = 1800;
