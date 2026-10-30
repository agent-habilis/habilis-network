use crate::cycle_dto::CycleDto;
use serde::Serialize;

/// A `visage-canvas` scene is built from exactly this every rAF — see the
/// plan's "Rendering approach".
#[derive(Serialize)]
pub(crate) struct FrameDto {
    pub(crate) grid_w: u8,
    pub(crate) grid_h: u8,
    /// Row-major, `grid_w * grid_h`. `0` = empty, else roster index + 1 —
    /// same encoding `world::World::grid` uses internally.
    pub(crate) grid: Vec<u8>,
    pub(crate) cycles: Vec<CycleDto>,
}
