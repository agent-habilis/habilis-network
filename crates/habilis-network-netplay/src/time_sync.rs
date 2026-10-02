//! Keeping two peers running at the same pace.
//!
//! Rollback tolerates one peer being *briefly* ahead — that is what
//! prediction is for. What it cannot absorb is one peer being *persistently*
//! ahead: the leader burns its whole prediction window, hits the limit and
//! stalls hard, while the follower never predicts at all. The result is one
//! player stuttering and the other perfectly smooth, which reads as "the
//! netcode is broken" rather than "the clocks differ".
//!
//! The fix, from GGPO: each peer measures how far ahead of its peers it is
//! and, when that lead is consistent, *voluntarily skips a frame* to give
//! them time. Small, frequent corrections instead of rare violent ones.

use crate::frame::Frame;

/// How many samples to average over. A couple of seconds at 60fps — long
/// enough that a single late packet doesn't trigger a stall, short enough to
/// track a real drift.
const WINDOW: usize = 40;

/// Don't correct below this much lead, in frames. Under it the advantage is
/// jitter rather than drift, and correcting would make the stutter it is
/// meant to prevent.
const MIN_ADVANTAGE_TO_CORRECT: i64 = 2;

/// Never recommend skipping more than this many frames at once — a large
/// correction is more visible than the drift it fixes.
const MAX_SKIP: u32 = 8;

/// Rolling measurement of how far ahead of its peers this peer is running.
#[derive(Debug)]
pub(crate) struct TimeSync {
    /// Our frame minus the last frame we have input for, sampled per frame.
    local: [i32; WINDOW],
    /// The same figure as reported *by* the peer, about itself.
    remote: [i32; WINDOW],
    next: usize,
}

impl Default for TimeSync {
    fn default() -> Self {
        Self {
            local: [0; WINDOW],
            remote: [0; WINDOW],
            next: 0,
        }
    }
}

impl TimeSync {
    /// Record this frame's advantage figures.
    pub(crate) fn advance(&mut self, local_advantage: i32, remote_advantage: i32) {
        let slot = self.next % WINDOW;
        self.local[slot] = local_advantage;
        self.remote[slot] = remote_advantage;
        self.next = self.next.wrapping_add(1);
    }

    /// How many frames to skip to let peers catch up; `0` to keep going.
    ///
    /// Two conditions, both required. The averaged lead must exceed
    /// [`MIN_ADVANTAGE_TO_CORRECT`], *and* we must be ahead of the peer
    /// rather than merely both being ahead of confirmation — otherwise two
    /// peers each seeing a lead would both stall and neither would gain.
    ///
    /// Computed entirely in integers. Averages are kept as sums scaled by
    /// [`WINDOW`] rather than divided down to a float: the comparisons are
    /// exact, and it keeps this crate's "no floats" advice true of its own
    /// code as well as its consumers'.
    pub(crate) fn recommend_skip(&self) -> u32 {
        let local = sum(&self.local);
        let remote = sum(&self.remote);

        // The peer is at least as far ahead as us: not our turn to yield.
        if remote >= local {
            return 0;
        }
        // Half the difference, still scaled by WINDOW. Halved because both
        // sides correct: yielding the whole gap would overshoot into being
        // the one behind.
        let lead_scaled = (local - remote) / 2;
        let window = i64::try_from(WINDOW).unwrap_or(i64::MAX);
        if lead_scaled < MIN_ADVANTAGE_TO_CORRECT * window {
            return 0;
        }
        let whole_frames = lead_scaled / window;
        u32::try_from(whole_frames)
            .unwrap_or(MAX_SKIP)
            .min(MAX_SKIP)
    }
}

/// The window's total, in `i64` so a burst of large advantages cannot
/// overflow the accumulator.
fn sum(samples: &[i32; WINDOW]) -> i64 {
    samples.iter().map(|sample| i64::from(*sample)).sum()
}

/// How far ahead `current_frame` is of the last frame a peer's input is known
/// for. Negative means we are *behind* them.
pub(crate) fn frame_advantage(current_frame: Frame, last_received_frame: Frame) -> i32 {
    current_frame - last_received_frame
}

#[cfg(test)]
mod tests {
    use super::TimeSync;

    #[test]
    fn a_steady_state_recommends_no_correction() {
        let mut sync = TimeSync::default();
        for _ in 0..super::WINDOW {
            sync.advance(0, 0);
        }
        assert_eq!(sync.recommend_skip(), 0);
    }

    #[test]
    fn a_small_lead_is_treated_as_jitter_not_drift() {
        let mut sync = TimeSync::default();
        for _ in 0..super::WINDOW {
            sync.advance(2, 0);
        }
        // Lead of 1 after halving — below the correction floor.
        assert_eq!(sync.recommend_skip(), 0);
    }

    #[test]
    fn a_persistent_lead_recommends_yielding() {
        let mut sync = TimeSync::default();
        for _ in 0..super::WINDOW {
            sync.advance(10, 0);
        }
        assert_eq!(sync.recommend_skip(), 5);
    }

    #[test]
    fn the_peer_being_further_ahead_is_never_our_turn_to_yield() {
        let mut sync = TimeSync::default();
        for _ in 0..super::WINDOW {
            sync.advance(4, 12);
        }
        assert_eq!(
            sync.recommend_skip(),
            0,
            "both peers stalling for each other would deadlock the pace"
        );
    }

    #[test]
    fn a_correction_is_capped_so_it_is_never_more_visible_than_the_drift() {
        let mut sync = TimeSync::default();
        for _ in 0..super::WINDOW {
            sync.advance(1000, 0);
        }
        assert_eq!(sync.recommend_skip(), super::MAX_SKIP);
    }
}
