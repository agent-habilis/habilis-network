use std::time::Duration;

/// A tick's elapsed-time gap on both clocks: monotonic (throttle-blind) and
/// wall (the only one a macOS suspend shows up on) — see `is_resume` /
/// `is_wall_resume`.
#[derive(Clone, Copy, Debug)]
pub(in crate::daemon) struct TickGap {
    pub(in crate::daemon) mono: Duration,
    pub(in crate::daemon) wall: Duration,
}
