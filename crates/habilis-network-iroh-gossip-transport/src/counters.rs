//! What a handle counted: the volume the flood puts on a member, and why a frame
//! or a datagram was dropped. A measurement reads it, and so does a test.

use std::sync::atomic::{AtomicU64, Ordering};

/// A copy of the counters at one moment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Frames this member put on the topic, and their bytes (header included).
    pub frames_out: u64,
    pub bytes_out: u64,
    /// Frames that arrived from the topic, for any member, and their bytes. This
    /// is the flood volume that this member pays for.
    pub frames_in: u64,
    pub bytes_in: u64,
    /// Of `frames_in`: queued for iroh, for another member, not a frame this
    /// build reads, and refused because iroh was not reading fast enough.
    pub queued: u64,
    pub not_for_us: u64,
    pub malformed: u64,
    pub queue_full: u64,
    /// Datagrams that were not sent: no sink was attached, it did not fit a
    /// frame, it was empty, or the sink refused the frame.
    pub dropped_no_sink: u64,
    pub dropped_too_large: u64,
    pub dropped_empty: u64,
    pub dropped_sink_refused: u64,
    /// Datagrams to a destination that the engine does not allow: a higher rung
    /// carries that pair.
    pub dropped_not_allowed: u64,
    /// Datagrams over the byte budget, to a destination with a connection.
    pub dropped_budget: u64,
    /// Packets that arrived queued for iroh but were larger than the buffer iroh
    /// offered, and were dropped.
    pub dropped_oversized_in: u64,
    /// Times the topic told this member that it missed messages, because the
    /// receive loop was not reading fast enough (`Event::Lagged`).
    pub topic_lagged: u64,
    /// Frames sent without a charge on the budget, because the destination has
    /// no established connection: a handshake.
    pub exempt_frames: u64,
}

#[derive(Debug, Default)]
pub(crate) struct Counters {
    frames_out: AtomicU64,
    bytes_out: AtomicU64,
    frames_in: AtomicU64,
    bytes_in: AtomicU64,
    queued: AtomicU64,
    not_for_us: AtomicU64,
    malformed: AtomicU64,
    queue_full: AtomicU64,
    dropped_no_sink: AtomicU64,
    dropped_too_large: AtomicU64,
    dropped_empty: AtomicU64,
    dropped_sink_refused: AtomicU64,
    dropped_not_allowed: AtomicU64,
    dropped_budget: AtomicU64,
    dropped_oversized_in: AtomicU64,
    exempt_frames: AtomicU64,
    topic_lagged: AtomicU64,
}

impl Counters {
    pub(crate) fn snapshot(&self) -> Stats {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        Stats {
            frames_out: read(&self.frames_out),
            bytes_out: read(&self.bytes_out),
            frames_in: read(&self.frames_in),
            bytes_in: read(&self.bytes_in),
            queued: read(&self.queued),
            not_for_us: read(&self.not_for_us),
            malformed: read(&self.malformed),
            queue_full: read(&self.queue_full),
            dropped_no_sink: read(&self.dropped_no_sink),
            dropped_too_large: read(&self.dropped_too_large),
            dropped_empty: read(&self.dropped_empty),
            dropped_sink_refused: read(&self.dropped_sink_refused),
            dropped_not_allowed: read(&self.dropped_not_allowed),
            dropped_budget: read(&self.dropped_budget),
            dropped_oversized_in: read(&self.dropped_oversized_in),
            exempt_frames: read(&self.exempt_frames),
            topic_lagged: read(&self.topic_lagged),
        }
    }

    /// A frame of `bytes` left for the topic.
    pub(crate) fn sent(&self, bytes: usize) {
        bump(&self.frames_out, 1);
        bump(&self.bytes_out, bytes);
    }

    /// A frame of `bytes` arrived from the topic, whoever it is for.
    pub(crate) fn arrived(&self, bytes: usize) {
        bump(&self.frames_in, 1);
        bump(&self.bytes_in, bytes);
    }

    pub(crate) fn queued(&self) {
        bump(&self.queued, 1);
    }

    pub(crate) fn not_for_us(&self) {
        bump(&self.not_for_us, 1);
    }

    pub(crate) fn malformed(&self) {
        bump(&self.malformed, 1);
    }

    pub(crate) fn queue_full(&self) {
        bump(&self.queue_full, 1);
    }

    pub(crate) fn dropped_no_sink(&self) {
        bump(&self.dropped_no_sink, 1);
    }

    pub(crate) fn dropped_too_large(&self) {
        bump(&self.dropped_too_large, 1);
    }

    pub(crate) fn dropped_empty(&self) {
        bump(&self.dropped_empty, 1);
    }

    pub(crate) fn dropped_sink_refused(&self) {
        bump(&self.dropped_sink_refused, 1);
    }

    pub(crate) fn dropped_not_allowed(&self) {
        bump(&self.dropped_not_allowed, 1);
    }

    pub(crate) fn dropped_budget(&self) {
        bump(&self.dropped_budget, 1);
    }

    pub(crate) fn dropped_oversized_in(&self) {
        bump(&self.dropped_oversized_in, 1);
    }

    pub(crate) fn lagged(&self) {
        bump(&self.topic_lagged, 1);
    }

    pub(crate) fn exempt(&self) {
        bump(&self.exempt_frames, 1);
    }
}

fn bump(counter: &AtomicU64, by: usize) {
    counter.fetch_add(by as u64, Ordering::Relaxed);
}
