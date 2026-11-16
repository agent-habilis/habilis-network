//! What a data socket does between "a node has a datagram" and "a frame goes to the relay":
//! batches for each destination, a flush rule, a pacer under the relay limits, and a bounded
//! queue that drops its oldest frames. It holds no socket and reads no clock: every call takes
//! `now`, so a test drives it in virtual time.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use n0_future::time::Instant;

use crate::batch::{Batch, ID_LEN, MAX_DATAGRAM};
use crate::event::{Event, Keys};
use crate::lane::Lane;
use crate::wire;

/// A batch waits at most this long for more datagrams. One tick serves every destination of the
/// socket.
pub(crate) const FLUSH_TICK: Duration = Duration::from_millis(5);

/// The bytes a socket may send each second: `1 MiB`, the budget of a node. A relay limits by
/// connection or by address, so the pacer sits at the socket and every mesh of the process shares it.
pub(crate) const BUDGET_BYTES_PER_SEC: f64 = 1024.0 * 1024.0;

/// The bytes the pacer lets out at once after a quiet spell.
pub(crate) const BURST_BYTES: f64 = 64.0 * 1024.0;

/// The frames a socket may send each second, well under the 500 a busy relay allows.
pub(crate) const FRAMES_PER_SEC: f64 = 200.0;

/// The frames the pacer lets out at once after a quiet spell.
pub(crate) const BURST_FRAMES: f64 = 20.0;

/// The frames the socket holds for the pacer. Past this the oldest go: QUIC recovers a loss, and
/// an old datagram is the one it has already given up on.
pub(crate) const QUEUE_BYTES: usize = 256 * 1024;

/// A browser socket with more than this many bytes unsent is behind: a data frame is dropped
/// rather than added to the browser's own queue, which has no bound.
#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) const WEB_BUFFERED_BOUND: usize = 256 * 1024;

/// A frame length as a count of bytes of budget. A frame is a few kilobytes: a length that does
/// not fit 32 bits is clamped, and still more than any budget.
pub(crate) fn weigh(bytes: usize) -> f64 {
    f64::from(u32::try_from(bytes).unwrap_or(u32::MAX))
}

/// Whether a socket with `buffered` bytes unsent takes no more data.
#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn over_buffer_bound(buffered: usize) -> bool {
    buffered > WEB_BUFFERED_BOUND
}

/// One datagram for the queue, with what it needs to become an event.
#[derive(Debug)]
pub(crate) struct Outgoing {
    // Shared with every datagram a pool queues: one key signs them all.
    pub(crate) keys: Arc<Keys>,
    /// The tag of the destination: its self tag.
    pub(crate) tag: [u8; 32],
    /// The endpoint id of the sender, for the batch header.
    pub(crate) from: [u8; ID_LEN],
    pub(crate) bytes: Vec<u8>,
}

/// A frame for the writer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    /// A REQ, a CLOSE: never paced, never dropped.
    Control(String),
    /// An EVENT with payload: paced, and dropped under pressure.
    Data(String),
}

struct Pending {
    // Shared with the datagrams of the pool that queued them.
    keys: Arc<Keys>,
    batch: Batch,
    since: Instant,
}

pub(crate) struct DataQueue {
    pending: HashMap<[u8; 32], Pending>,
    control: VecDeque<String>,
    frames: VecDeque<String>,
    queued_bytes: usize,
    byte_tokens: f64,
    frame_tokens: f64,
    refilled: Instant,
    last_flush: Option<Instant>,
    /// The serial of the next batch: two batches with the same datagrams still make two events.
    next_serial: u32,
    dropped: u64,
}

impl DataQueue {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            pending: HashMap::new(),
            control: VecDeque::new(),
            frames: VecDeque::new(),
            queued_bytes: 0,
            byte_tokens: BURST_BYTES,
            frame_tokens: BURST_FRAMES,
            refilled: now,
            last_flush: None,
            next_serial: 0,
            dropped: 0,
        }
    }

    /// The frames dropped for want of room.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The bytes of data frames queued.
    #[cfg(test)]
    pub(crate) fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Add a datagram to the batch of its destination. The first datagram after an idle spell
    /// goes at once; the rest wait for the tick, or for a full batch.
    pub(crate) fn push_datagram(&mut self, now: Instant, outgoing: Outgoing) {
        let Outgoing {
            keys,
            tag,
            from,
            bytes,
        } = outgoing;
        if bytes.len() > MAX_DATAGRAM {
            self.dropped += 1;
            tracing::debug!(target: "habilis_network::lookup", bytes = bytes.len(), "a datagram over the batch limit is dropped");
            return;
        }
        let idle = self.is_idle(now);
        if self
            .pending
            .get(&tag)
            .is_some_and(|pending| !pending.batch.fits(&bytes))
        {
            self.flush(now, &tag);
        }
        let pending = match self.pending.entry(tag) {
            Entry::Occupied(slot) => slot.into_mut(),
            Entry::Vacant(slot) => {
                let serial = self.next_serial;
                self.next_serial = serial.wrapping_add(1);
                slot.insert(Pending {
                    keys,
                    batch: Batch::new(&from, serial),
                    since: now,
                })
            }
        };
        pending.batch.push(&bytes);
        if idle || !pending.batch.fits(&[]) {
            self.flush(now, &tag);
        }
    }

    /// Add a frame that is ready to send. It is paced and can be dropped.
    pub(crate) fn push_frame(&mut self, frame: String) {
        self.queued_bytes += frame.len();
        self.frames.push_back(frame);
        while self.queued_bytes > QUEUE_BYTES {
            let Some(oldest) = self.frames.pop_front() else {
                break;
            };
            self.queued_bytes -= oldest.len();
            self.dropped += 1;
        }
    }

    /// Add a frame that is neither paced nor dropped.
    pub(crate) fn push_control(&mut self, frame: String) {
        self.control.push_back(frame);
    }

    /// Flush the batches whose tick has come.
    pub(crate) fn flush_due(&mut self, now: Instant) {
        let due: Vec<[u8; 32]> = self
            .pending
            .iter()
            .filter(|(_, pending)| now >= pending.since + FLUSH_TICK)
            .map(|(tag, _)| *tag)
            .collect();
        for tag in due {
            self.flush(now, &tag);
        }
    }

    /// The next frame the pacer lets out at `now`: a control frame first, then the oldest data
    /// frame if the budgets cover it.
    pub(crate) fn pop_ready(&mut self, now: Instant) -> Option<Frame> {
        self.refill(now);
        if let Some(frame) = self.control.pop_front() {
            return Some(Frame::Control(frame));
        }
        let cost = self.frames.front()?.len();
        if self.byte_tokens < weigh(cost) || self.frame_tokens < 1.0 {
            return None;
        }
        let frame = self.frames.pop_front()?;
        self.queued_bytes -= frame.len();
        self.byte_tokens -= weigh(cost);
        self.frame_tokens -= 1.0;
        Some(Frame::Data(frame))
    }

    /// When the socket next has something to do: flush a batch, or send a frame.
    pub(crate) fn next_wake(&mut self, now: Instant) -> Option<Instant> {
        self.refill(now);
        let flush = self
            .pending
            .values()
            .map(|pending| pending.since + FLUSH_TICK)
            .min();
        let send: Option<Instant> = if self.control.is_empty() {
            self.frames
                .front()
                .map(|frame| now + self.wait_for(frame.len()))
        } else {
            Some(now)
        };
        match (flush, send) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        }
    }

    /// How long until the budgets cover a frame of `cost` bytes, as of the last refill.
    fn wait_for(&self, cost: usize) -> Duration {
        let bytes = (weigh(cost) - self.byte_tokens).max(0.0) / BUDGET_BYTES_PER_SEC;
        let frames = (1.0 - self.frame_tokens).max(0.0) / FRAMES_PER_SEC;
        Duration::from_secs_f64(bytes.max(frames))
    }

    fn is_idle(&self, now: Instant) -> bool {
        self.pending.is_empty()
            && self.frames.is_empty()
            && self
                .last_flush
                .is_none_or(|at| now.saturating_duration_since(at) >= FLUSH_TICK)
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.refilled).as_secs_f64();
        self.refilled = self.refilled.max(now);
        self.byte_tokens = (self.byte_tokens + elapsed * BUDGET_BYTES_PER_SEC).min(BURST_BYTES);
        self.frame_tokens = (self.frame_tokens + elapsed * FRAMES_PER_SEC).min(BURST_FRAMES);
    }

    /// Sign the batch of `tag` into one event and queue its frame.
    fn flush(&mut self, now: Instant, tag: &[u8; 32]) {
        let Some(pending) = self.pending.remove(tag) else {
            return;
        };
        let content = pending.batch.encode();
        let event = Event::sign(Lane::Data, &pending.keys, crate::unix_now(), tag, content);
        self.push_frame(wire::event(&event));
        self.last_flush = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use n0_future::time::Instant;

    use super::{
        BUDGET_BYTES_PER_SEC, BURST_BYTES, BURST_FRAMES, DataQueue, FLUSH_TICK, FRAMES_PER_SEC,
        Frame, Outgoing, QUEUE_BYTES, WEB_BUFFERED_BOUND, over_buffer_bound, weigh,
    };
    use crate::batch::{self, ID_LEN};
    use crate::event::{Event, Keys};

    const FROM: [u8; ID_LEN] = [3u8; ID_LEN];

    // The key of a test pool, shared by the datagrams it queues.
    fn shared_keys() -> Arc<Keys> {
        // Shared as a pool shares its key with the datagrams it queues.
        Arc::new(Keys::generate())
    }

    // One key signs every datagram a test queues, as one pool does.
    fn outgoing(keys: &Arc<Keys>, tag: u8, bytes: &[u8]) -> Outgoing {
        Outgoing {
            keys: Arc::clone(keys),
            tag: [tag; 32],
            from: FROM,
            bytes: bytes.to_vec(),
        }
    }

    /// The datagrams of a frame the queue let out.
    fn datagrams(frame: &Frame) -> Vec<Vec<u8>> {
        let Frame::Data(text) = frame else {
            panic!("a data frame");
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("an EVENT frame");
        let event: Event = serde_json::from_value(parsed[1].clone()).expect("an event");
        event.verify().expect("one valid signature");
        batch::decode(&event.content).expect("a batch").datagrams
    }

    /// The id of the event in a frame the queue let out.
    fn event_id(frame: &Frame) -> String {
        let Frame::Data(text) = frame else {
            panic!("a data frame");
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("an EVENT frame");
        let event: Event = serde_json::from_value(parsed[1].clone()).expect("an event");
        event.id
    }

    /// Two batches with the same datagrams, signed in the same second, are two events: a relay and
    /// a receiver dedupe by id, and would drop the second.
    #[test]
    fn two_equal_batches_in_one_second_get_two_event_ids() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        queue.push_datagram(start, outgoing(&keys, 1, b"same"));
        let first = queue.pop_ready(start).expect("the first goes at once");
        let soon = start + Duration::from_millis(1);
        queue.push_datagram(soon, outgoing(&keys, 1, b"same"));
        let tick = soon + FLUSH_TICK;
        queue.flush_due(tick);
        let second = queue.pop_ready(tick).expect("the second goes at the tick");
        assert_ne!(
            event_id(&first),
            event_id(&second),
            "two equal batches make two events"
        );
    }

    /// The frame core of the gossip transport allows a frame of 3840 bytes, and a datagram
    /// reaches this queue as that frame.
    #[test]
    fn a_datagram_the_frame_core_allows_is_carried() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        let frame_core_limit = vec![6u8; 3840];
        queue.push_datagram(start, outgoing(&keys, 1, &frame_core_limit));
        let frame = queue.pop_ready(start).expect("the datagram goes out");
        assert_eq!(datagrams(&frame), vec![frame_core_limit], "carried whole");
        assert_eq!(queue.dropped(), 0, "nothing was dropped");
    }

    /// A datagram no batch can carry is counted, not lost without a trace.
    #[test]
    fn a_datagram_over_the_limit_is_counted_as_dropped() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        queue.push_datagram(start, outgoing(&keys, 1, &vec![6u8; 3841]));
        assert!(queue.pop_ready(start).is_none(), "nothing goes out");
        assert_eq!(queue.dropped(), 1, "the datagram is counted");
    }

    #[test]
    fn the_first_datagram_after_idle_goes_at_once() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        queue.push_datagram(start, outgoing(&keys, 1, b"first"));
        let frame = queue
            .pop_ready(start)
            .expect("sent with no wait for the tick");
        assert_eq!(datagrams(&frame), vec![b"first".to_vec()], "alone");
    }

    #[test]
    fn the_rest_wait_for_the_tick_and_go_in_one_event() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        queue.push_datagram(start, outgoing(&keys, 1, b"first"));
        queue.pop_ready(start).expect("the first goes");
        let soon = start + Duration::from_millis(1);
        for text in [&b"a"[..], b"b", b"c"] {
            queue.push_datagram(soon, outgoing(&keys, 1, text));
        }
        assert!(queue.pop_ready(soon).is_none(), "held until the tick");
        let tick = soon + FLUSH_TICK;
        queue.flush_due(tick);
        let frame = queue.pop_ready(tick).expect("flushed at the tick");
        assert_eq!(
            datagrams(&frame),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            "one event, in order"
        );
    }

    #[test]
    fn a_full_batch_goes_without_the_tick() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        queue.push_datagram(start, outgoing(&keys, 1, b"first"));
        queue.pop_ready(start).expect("the first goes");
        let big = vec![0u8; 1500];
        let mut sent = 0;
        for _ in 0..40 {
            queue.push_datagram(start, outgoing(&keys, 1, &big));
            if queue.pop_ready(start).is_some() {
                sent += 1;
            }
        }
        assert!(
            sent >= 1,
            "a batch that reached 16 KiB went before any tick"
        );
    }

    #[test]
    fn destinations_never_share_a_batch_and_one_tick_serves_all() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        queue.push_datagram(start, outgoing(&keys, 1, b"idle breaker"));
        queue.pop_ready(start).expect("the first goes");
        let soon = start + Duration::from_millis(1);
        queue.push_datagram(soon, outgoing(&keys, 1, b"to one"));
        queue.push_datagram(soon, outgoing(&keys, 2, b"to two"));
        let tick = soon + FLUSH_TICK;
        queue.flush_due(tick);
        let mut seen: Vec<Vec<Vec<u8>>> = Vec::new();
        while let Some(frame) = queue.pop_ready(tick) {
            seen.push(datagrams(&frame));
        }
        seen.sort();
        assert_eq!(
            seen,
            vec![vec![b"to one".to_vec()], vec![b"to two".to_vec()]],
            "two events, one for each destination"
        );
    }

    /// The pacer: over two seconds of flat-out pushing, the socket lets out no more than a burst
    /// and the budget of two seconds, in bytes and in frames.
    #[test]
    fn the_pacer_holds_the_byte_and_frame_budgets() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        let datagram = vec![9u8; 1400];
        let (mut bytes, mut frames) = (0.0_f64, 0.0_f64);
        for millisecond in 0..2_000u64 {
            let now = start + Duration::from_millis(millisecond);
            for _ in 0..4 {
                queue.push_datagram(now, outgoing(&keys, 1, &datagram));
            }
            queue.flush_due(now);
            while let Some(Frame::Data(frame)) = queue.pop_ready(now) {
                bytes += weigh(frame.len());
                frames += 1.0;
            }
        }
        assert!(
            bytes <= BURST_BYTES + 2.0 * BUDGET_BYTES_PER_SEC,
            "{bytes} bytes in 2 s"
        );
        assert!(
            frames <= BURST_FRAMES + 2.0 * FRAMES_PER_SEC,
            "{frames} frames in 2 s"
        );
        assert!(bytes > BUDGET_BYTES_PER_SEC, "the pacer sent: {bytes}");
    }

    /// A slow uplink: nothing leaves the queue, and it still holds no more than its ceiling,
    /// with the oldest frame the first to go.
    #[test]
    fn a_queue_nobody_drains_stays_bounded_and_drops_the_oldest() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        let datagram = vec![5u8; 1400];
        for index in 0..5_000u64 {
            let now = start + Duration::from_millis(index);
            queue.push_datagram(now, outgoing(&keys, 1, &datagram));
            queue.flush_due(now);
            assert!(
                queue.queued_bytes() <= QUEUE_BYTES,
                "{} bytes queued after {index} pushes",
                queue.queued_bytes()
            );
        }
        assert!(queue.dropped() > 0, "frames were dropped");
    }

    /// The wake time counts the tokens earned since the last pop: a socket that emptied its
    /// budget and then sat idle for a second wakes at once, not a second after.
    #[test]
    fn the_wake_time_counts_the_budget_earned_while_waiting() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        let datagram = vec![4u8; 1400];
        for _ in 0..200 {
            queue.push_datagram(start, outgoing(&keys, 1, &datagram));
            queue.flush_due(start + FLUSH_TICK);
            while queue.pop_ready(start).is_some() {}
        }
        assert!(
            queue.queued_bytes() > 0,
            "frames wait for a budget that is spent"
        );
        let later = start + Duration::from_secs(1);
        let wake = queue.next_wake(later).expect("a frame waits");
        assert!(
            wake <= later,
            "a second of budget was earned: wake is {:?} late",
            wake - later
        );
    }

    #[test]
    fn a_control_frame_is_not_paced_and_goes_first() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        queue.push_datagram(start, outgoing(&keys, 1, b"data"));
        queue.push_control("REQ".to_owned());
        assert_eq!(
            queue.pop_ready(start),
            Some(Frame::Control("REQ".to_owned())),
            "control before data"
        );
    }

    #[test]
    fn a_browser_socket_with_too_much_unsent_drops_data() {
        assert!(!over_buffer_bound(0), "an empty buffer takes data");
        assert!(
            !over_buffer_bound(WEB_BUFFERED_BOUND),
            "the bound itself is allowed"
        );
        assert!(
            over_buffer_bound(WEB_BUFFERED_BOUND + 1),
            "past the bound the frame is dropped"
        );
    }
}
