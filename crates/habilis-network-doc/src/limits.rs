//! The lines that bound a state document: how large it can grow before a cut, before a write that
//! adds a value is refused, and before a frame is refused. All of them come from one constructor,
//! so values that must agree cannot differ, and a test can build the same lines for a small seed.

use habilis_network_util::consts::{
    DOC_EPOCH_FRAME_MARGIN, DOC_REFUSED_FRAMES_MAX, DOC_RESTORES_MAX, DOC_SEED_FRAMES_MAX,
    DOC_SEED_TOMBSTONES_MAX, DOC_STATE_DEPTH_MAX, DOC_STATE_PATHS_BREAK_EVEN,
    DOC_STATE_SEED_RATIO_PERCENT, DOC_STATE_STAMP_BYTES_BASE, MAX_MESSAGE_SIZE,
};

/// The lines of one axis (the bytes of the frames, or the operations of the changes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Axis {
    /// The size at which a seed of this axis uses all the frames that the axis may take.
    pub break_even: usize,
    /// A cut is due when the projected seed reaches this size.
    pub ceiling: usize,
    /// A local write that adds a value is refused when the projected seed passes this size.
    pub refuse_add: usize,
    /// A local write of any kind is refused when the frames pass this size or the seed plus a
    /// tenth of the break-even, whichever is larger.
    pub memory: usize,
    /// What a remote frame may add on top of the memory line.
    pub remote_extra: usize,
    /// How much the document must grow after its seed before a cut is due again.
    pub growth: usize,
}

impl Axis {
    /// The lines of an axis of `break_even`: the cut at 0.75 of it, the refusal of an add at 0.85,
    /// the memory line at 1.0, the room of a remote frame 0.05 above it, and a growth of 1/16 for a
    /// cut (below the tenth of the break-even that a delete has above the seed).
    #[must_use]
    pub fn from_break_even(break_even: usize) -> Self {
        Self {
            break_even,
            ceiling: break_even * 75 / 100,
            refuse_add: break_even * 85 / 100,
            memory: break_even,
            remote_extra: (break_even / 20).max(1),
            growth: (break_even / 16).max(1),
        }
    }
}

/// The lines of a state document, and the sizes of the collections that it keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// The most frames that a seed has.
    pub seed_frames_max: usize,
    /// The most tombstones that the document keeps.
    pub tombstones_max: usize,
    /// The most restores that the document keeps.
    pub restores_max: usize,
    /// The most hashes of refused frames that the document remembers.
    pub refused_max: usize,
    /// The bytes of the frames.
    pub bytes: Axis,
    /// The operations of the changes.
    pub ops: Axis,
}

impl Limits {
    /// The lines for a seed of at most `seed_frames_max` frames. The real constants give
    /// [`Self::real`]; a test passes a small number and gets the same shape.
    #[must_use]
    pub fn from_seed_frames(seed_frames_max: usize) -> Self {
        let frame = MAX_MESSAGE_SIZE - DOC_EPOCH_FRAME_MARGIN;
        // Each axis may take half of the frames of a seed, so the two together fit. A merge that
        // the byte limit closes holds at least half a frame, so the bytes of a seed are at most a
        // quarter of its frames in bytes; a merge that the path limit closes holds
        // `130 - 2 x depth` paths that no other merge holds.
        let bytes_break_even = seed_frames_max * frame / 4;
        let paths_per_frame = 130 - 2 * DOC_STATE_DEPTH_MAX;
        let ops_by_frames = paths_per_frame * seed_frames_max / 2;
        let ops_break_even = ops_by_frames.min(DOC_STATE_PATHS_BREAK_EVEN);
        Self {
            seed_frames_max,
            tombstones_max: (DOC_SEED_TOMBSTONES_MAX * seed_frames_max / DOC_SEED_FRAMES_MAX)
                .max(1),
            restores_max: (DOC_RESTORES_MAX * seed_frames_max / DOC_SEED_FRAMES_MAX).max(1),
            refused_max: (DOC_REFUSED_FRAMES_MAX * seed_frames_max / DOC_SEED_FRAMES_MAX).max(8),
            bytes: Axis::from_break_even(bytes_break_even),
            ops: Axis::from_break_even(ops_break_even),
        }
    }

    /// The bytes that the stamp of one path adds to a seed frame when the clock is at `clock`: the
    /// digits of the clock and `DOC_STATE_STAMP_BYTES_BASE`. The Lamport time is below `2^53`, so
    /// the figure is at most 25.
    #[must_use]
    pub fn stamp_bytes(clock: u64) -> usize {
        let digits = usize::try_from(clock.checked_ilog10().unwrap_or(0)).unwrap_or(0) + 1;
        digits + DOC_STATE_STAMP_BYTES_BASE
    }

    /// The bytes of the next seed, at most: the seed that this document holds, plus the growth in
    /// frame bytes at the ratio of a seed to its history, plus a stamp for each operation of the
    /// growth. The lines of the byte axis measure this number.
    #[must_use]
    pub fn projected_bytes(
        seed_bytes: usize,
        growth_bytes: usize,
        growth_ops: usize,
        clock: u64,
    ) -> usize {
        let content = growth_bytes * DOC_STATE_SEED_RATIO_PERCENT / 100;
        seed_bytes + content + growth_ops * Self::stamp_bytes(clock)
    }

    /// The lines for the real constants.
    #[must_use]
    pub fn real() -> Self {
        Self::from_seed_frames(DOC_SEED_FRAMES_MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::{Axis, Limits};
    use habilis_network_util::consts::{
        DOC_EPOCH_FRAME_MARGIN, DOC_SEED_FRAMES_MAX, DOC_STATE_DEPTH_MAX,
        DOC_STATE_EPOCH_FRAME_CAP_BYTES, DOC_STATE_PATHS_BREAK_EVEN, MAX_MESSAGE_SIZE,
    };

    /// The order that a cut needs on one axis: the cut comes before the refusal of an add, the
    /// refusal before the memory line, and the growth that makes a cut due is smaller than the room
    /// that a delete has above the seed (a tenth of the break-even), so deletes always reach it.
    fn assert_order(axis: &Axis, name: &str) {
        assert!(
            axis.ceiling < axis.refuse_add,
            "{name}: the cut ({}) comes before the refusal of an add ({})",
            axis.ceiling,
            axis.refuse_add
        );
        assert!(
            axis.refuse_add < axis.memory,
            "{name}: the refusal of an add ({}) is below the memory line ({})",
            axis.refuse_add,
            axis.memory
        );
        assert!(
            axis.growth * 10 <= axis.break_even,
            "{name}: the growth ({}) is at most a tenth of the break-even ({})",
            axis.growth,
            axis.break_even
        );
        assert!(
            axis.remote_extra > 0,
            "{name}: a remote frame has some room"
        );
    }

    /// The frames that a seed at `bytes` bytes and `ops` operations needs, at most: the bound of
    /// `pack_entry` for the path limit plus the one for the byte limit, plus the last frame.
    fn frames_needed(bytes: usize, ops: usize) -> usize {
        let new_paths = 130 - 2 * DOC_STATE_DEPTH_MAX;
        let frame = MAX_MESSAGE_SIZE - DOC_EPOCH_FRAME_MARGIN;
        ops.div_ceil(new_paths) + (2 * bytes).div_ceil(frame) + 1
    }

    #[test]
    fn a_stamp_costs_the_digits_of_the_clock_and_a_base_up_to_25_bytes() {
        assert_eq!(Limits::stamp_bytes(0), 10, "the clock at 0 has 1 digit");
        assert_eq!(Limits::stamp_bytes(5_000_000), 16, "7 digits");
        assert_eq!(Limits::stamp_bytes(999_999_999), 18, "9 digits");
        assert_eq!(
            Limits::stamp_bytes((1 << 53) - 1),
            25,
            "the bound of the Lamport time has 16 digits"
        );
    }

    #[test]
    fn the_projected_seed_is_the_seed_plus_the_growth_with_its_stamps() {
        assert_eq!(
            Limits::projected_bytes(0, 1_000, 100, 5_000_000),
            1_050 + 1_600,
            "1000 bytes of growth at 105 percent, and 100 stamps of 16 bytes"
        );
        assert_eq!(
            Limits::projected_bytes(4_000, 0, 0, 5_000_000),
            4_000,
            "a document that did not grow projects its seed"
        );
    }

    #[test]
    fn the_real_lines_keep_the_order_that_a_cut_needs_on_both_axes() {
        let limits = Limits::real();
        assert_order(&limits.bytes, "bytes");
        assert_order(&limits.ops, "ops");
    }

    #[test]
    fn the_break_evens_follow_from_the_constants() {
        let limits = Limits::real();
        let frame = MAX_MESSAGE_SIZE - DOC_EPOCH_FRAME_MARGIN;
        assert_eq!(
            limits.bytes.break_even,
            DOC_SEED_FRAMES_MAX * frame / 4,
            "the byte break-even is a quarter of the bytes of a full seed"
        );
        let epoch_cap = DOC_STATE_EPOCH_FRAME_CAP_BYTES;
        assert!(
            limits.bytes.break_even.abs_diff(epoch_cap) * 100 < epoch_cap,
            "the byte break-even is the epoch cap of the state channel, within 1 percent"
        );
        assert_eq!(
            limits.ops.break_even, DOC_STATE_PATHS_BREAK_EVEN,
            "the path line binds before the frame line at the real size"
        );
        assert_eq!(
            limits.ops.ceiling, 20_000,
            "the cut is due at 20 000 operations"
        );
    }

    #[test]
    fn a_seed_at_the_refusal_line_of_both_axes_and_the_room_of_a_flood_fits_the_frames_of_a_seed() {
        let limits = Limits::real();
        let top_bytes = limits.bytes.refuse_add + limits.bytes.remote_extra;
        let top_ops = limits.ops.refuse_add + limits.ops.remote_extra;
        let needed = frames_needed(top_bytes, top_ops);
        assert!(
            needed <= limits.seed_frames_max,
            "{needed} frames at the refusal line of both axes, a seed may have {}",
            limits.seed_frames_max
        );
    }

    #[test]
    fn a_small_seed_gets_the_same_shape_and_scales_the_other_collections() {
        // Below about 30 frames the 2 frames of rounding and the last frame are a large part of a
        // seed, so a small seed for a test has at least 40 frames.
        for frames in [40, 200, 1_000, DOC_SEED_FRAMES_MAX] {
            let limits = Limits::from_seed_frames(frames);
            assert_order(&limits.bytes, "bytes");
            assert_order(&limits.ops, "ops");
            assert!(
                limits.tombstones_max >= 1 && limits.restores_max >= 1,
                "{frames} frames: the collections keep at least one entry"
            );
            let needed = frames_needed(
                limits.bytes.refuse_add + limits.bytes.remote_extra,
                limits.ops.refuse_add + limits.ops.remote_extra,
            );
            assert!(
                needed <= frames,
                "{frames} frames: {needed} needed at the refusal line of both axes"
            );
        }
        let small = Limits::from_seed_frames(40);
        let real = Limits::real();
        assert!(
            small.tombstones_max < real.tombstones_max
                && small.restores_max < real.restores_max
                && small.refused_max < real.refused_max,
            "the tombstones, the restores and the refused hashes shrink with the seed"
        );
        assert_eq!(
            real.refused_max, 4_096,
            "the real set holds 4 096 hashes of refused frames"
        );
    }
}
