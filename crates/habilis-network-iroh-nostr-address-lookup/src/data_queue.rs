//! What a data socket does between "a node has a datagram" and "a frame goes to the relay":
//! batches for each sender and destination, one flush tick for the socket, a pacer under the relay
//! limits, and a bounded queue that drops its oldest frames. It signs an event only when the pacer
//! lets it out, so a batch the queue drops costs no signature. It holds no socket and reads no
//! clock: every call takes `now`, so a test drives it in virtual time.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use n0_future::time::Instant;

use crate::batch::{Batch, ID_LEN, MAX_DATAGRAM};
use crate::event::{Event, Keys};
use crate::lane::Lane;
use crate::wire;

/// The one tick of a socket: the open batches wait at most this long for more datagrams, then all
/// go together.
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

/// The bytes the socket holds for the pacer. Past this the oldest frames go: QUIC recovers a
/// loss, and an old datagram is the one it has already given up on.
pub(crate) const QUEUE_BYTES: usize = 256 * 1024;

/// The frames the socket holds for the pacer, and the open batches it holds. At the frame rate of
/// the pacer this is a third of a second: a bound in bytes alone would let small frames wait
/// seconds.
pub(crate) const MAX_QUEUED_FRAMES: usize = 64;

/// The longest a datagram waits for the pacer in an open batch. An older batch is dropped: the
/// writer is slow, and QUIC has sent that data again by now.
pub(crate) const MAX_AGE: Duration = Duration::from_millis(250);

/// What an EVENT frame adds to the text of its content: the id, the key, the signature, the kind,
/// the time and the tag. The pacer charges a batch this much on top of its content before the
/// batch is signed, so the charge is never below the frame.
pub(crate) const FRAME_OVERHEAD: usize = 512;

/// A browser socket with more than this many bytes unsent is behind: a data frame is dropped
/// rather than added to the browser's own queue, which has no bound.
pub(crate) const WEB_BUFFERED_BOUND: usize = 256 * 1024;

/// A frame length as a count of bytes of budget. A frame is a few kilobytes: a length that does
/// not fit 32 bits is clamped, and still more than any budget.
pub(crate) fn weigh(bytes: usize) -> f64 {
    f64::from(u32::try_from(bytes).unwrap_or(u32::MAX))
}

/// Whether a socket with `buffered` bytes unsent takes no more data.
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

/// Who a batch is from and for. Two pools of one process that send to one tag do not share a
/// batch: the header of a batch names its sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Destination {
    from: [u8; ID_LEN],
    tag: [u8; 32],
}

/// A batch that is still open: datagrams can join it.
struct Pending {
    // Shared with the datagrams of the pool that queued them.
    keys: Arc<Keys>,
    batch: Batch,
    since: Instant,
}

/// A frame in the queue, with the time it joined.
struct Waiting {
    since: Instant,
    queued: Queued,
}

/// Data that waits for the pacer.
enum Queued {
    /// A closed batch, not yet signed: it is signed when the pacer lets it out.
    Batch {
        // Shared with the datagrams of the pool that queued them.
        keys: Arc<Keys>,
        tag: [u8; 32],
        content: String,
    },
    /// An event that the caller signed.
    Signed(String),
}

impl Queued {
    /// The bytes of budget this frame costs. For a batch that is an upper bound of its event.
    fn cost(&self) -> usize {
        match self {
            Self::Batch { content, .. } => content.len() + FRAME_OVERHEAD,
            Self::Signed(frame) => frame.len(),
        }
    }
}

pub(crate) struct DataQueue {
    pending: HashMap<Destination, Pending>,
    /// When the oldest open batch began: the one tick of the socket counts from it.
    round_start: Option<Instant>,
    control: VecDeque<String>,
    ready: VecDeque<Waiting>,
    ready_bytes: usize,
    byte_tokens: f64,
    frame_tokens: f64,
    refilled: Instant,
    last_flush: Option<Instant>,
    /// The serial of the next batch: two batches with the same datagrams still make two events.
    next_serial: u32,
    dropped: u64,
    #[cfg(test)]
    signed: u64,
}

impl DataQueue {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            pending: HashMap::new(),
            round_start: None,
            control: VecDeque::new(),
            ready: VecDeque::new(),
            ready_bytes: 0,
            byte_tokens: BURST_BYTES,
            frame_tokens: BURST_FRAMES,
            refilled: now,
            last_flush: None,
            next_serial: 0,
            dropped: 0,
            #[cfg(test)]
            signed: 0,
        }
    }

    /// The frames and datagrams dropped for want of room, or for a size no batch carries.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The bytes of data frames queued.
    #[cfg(test)]
    pub(crate) fn queued_bytes(&self) -> usize {
        self.ready_bytes
    }

    /// The data frames queued.
    #[cfg(test)]
    pub(crate) fn queued_frames(&self) -> usize {
        self.ready.len()
    }

    /// The events signed so far.
    #[cfg(test)]
    pub(crate) fn signed(&self) -> u64 {
        self.signed
    }

    /// Add a datagram to the open batch of its sender and destination. The first datagram after
    /// an idle spell goes at once; the rest wait for the tick of the socket, or for a full batch.
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
        self.flush_due(now);
        let destination = Destination { from, tag };
        if self
            .pending
            .get(&destination)
            .is_some_and(|pending| !pending.batch.fits(&bytes))
        {
            self.close(now, destination);
        }
        if self.pending.is_empty() {
            self.round_start = Some(now);
        }
        let pending = match self.pending.entry(destination) {
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
        let full = !pending.batch.fits(&[]);
        if idle || full {
            self.close(now, destination);
        }
        self.bound_open();
    }

    /// Add an event that the caller signed. It is paced and can be dropped.
    pub(crate) fn push_frame(&mut self, now: Instant, frame: String) {
        if weigh(frame.len()) > BURST_BYTES {
            // No pacer budget ever covers it, so it would stay at the head of the queue.
            self.dropped += 1;
            tracing::debug!(target: "habilis_network::lookup", bytes = frame.len(), "a data frame over the burst is dropped");
            return;
        }
        self.queue(now, Queued::Signed(frame));
    }

    /// Add a frame that is neither paced nor dropped.
    pub(crate) fn push_control(&mut self, frame: String) {
        self.control.push_back(frame);
    }

    /// Drop the open batches that are too old, and close them all at the tick of the socket if
    /// nothing waits for the pacer: a batch that is held back grows, and one frame then carries
    /// more.
    pub(crate) fn flush_due(&mut self, now: Instant) {
        let old: Vec<Destination> = self
            .pending
            .iter()
            .filter(|(_, pending)| now >= pending.since + MAX_AGE)
            .map(|(destination, _)| *destination)
            .collect();
        for destination in old {
            self.pending.remove(&destination);
            self.dropped += 1;
        }
        if self.pending.is_empty() {
            self.round_start = None;
        }
        let tick_due = self
            .round_start
            .is_some_and(|start| now >= start + FLUSH_TICK);
        if tick_due && self.ready.is_empty() {
            let mut open: Vec<(Instant, Destination)> = self
                .pending
                .iter()
                .map(|(destination, pending)| (pending.since, *destination))
                .collect();
            open.sort_unstable_by_key(|(since, _)| *since);
            for (_, destination) in open {
                self.close(now, destination);
            }
        }
    }

    /// The next frame the pacer lets out at `now`: a control frame first, then the oldest data
    /// frame if the budgets cover it. A frame that waited past [`MAX_AGE`] is dropped, not sent
    /// late. A batch is signed here, not before.
    pub(crate) fn pop_ready(&mut self, now: Instant) -> Option<Frame> {
        self.refill(now);
        if let Some(frame) = self.control.pop_front() {
            return Some(Frame::Control(frame));
        }
        self.drop_aged(now);
        let cost = self.ready.front()?.queued.cost();
        if self.byte_tokens < weigh(cost) || self.frame_tokens < 1.0 {
            return None;
        }
        let queued = self.ready.pop_front()?.queued;
        self.ready_bytes -= cost;
        self.byte_tokens -= weigh(cost);
        self.frame_tokens -= 1.0;
        #[cfg(test)]
        {
            self.signed += u64::from(matches!(queued, Queued::Batch { .. }));
        }
        Some(Frame::Data(sign(queued)))
    }

    /// When the socket next has something to do: close the open batches, or send a frame.
    pub(crate) fn next_wake(&mut self, now: Instant) -> Option<Instant> {
        self.refill(now);
        let flush: Option<Instant> = if self.ready.is_empty() {
            self.round_start.map(|start| start + FLUSH_TICK)
        } else {
            None
        };
        let send: Option<Instant> = if self.control.is_empty() {
            self.ready
                .front()
                .map(|waiting| now + self.wait_for(waiting.queued.cost()))
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
            && self.ready.is_empty()
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

    /// Close the open batch of `destination`: it waits for the pacer as one frame, unsigned.
    fn close(&mut self, now: Instant, destination: Destination) {
        let Some(pending) = self.pending.remove(&destination) else {
            return;
        };
        if self.pending.is_empty() {
            self.round_start = None;
        }
        self.last_flush = Some(now);
        let batch = Queued::Batch {
            keys: pending.keys,
            tag: destination.tag,
            content: pending.batch.encode(),
        };
        self.queue(now, batch);
    }

    /// Add to the queue for the pacer, then drop the oldest while it is over its bounds.
    fn queue(&mut self, now: Instant, queued: Queued) {
        self.ready_bytes += queued.cost();
        self.ready.push_back(Waiting { since: now, queued });
        while self.ready_bytes > QUEUE_BYTES || self.ready.len() > MAX_QUEUED_FRAMES {
            let Some(oldest) = self.ready.pop_front() else {
                break;
            };
            self.ready_bytes -= oldest.queued.cost();
            self.dropped += 1;
        }
    }

    /// Drop the frames at the head of the queue that waited past [`MAX_AGE`].
    fn drop_aged(&mut self, now: Instant) {
        while let Some(front) = self.ready.front()
            && now >= front.since + MAX_AGE
        {
            self.ready_bytes -= front.queued.cost();
            self.ready.pop_front();
            self.dropped += 1;
        }
    }

    /// Drop the oldest open batches while there are more than the bound.
    fn bound_open(&mut self) {
        while self.pending.len() > MAX_QUEUED_FRAMES {
            let oldest: Option<Destination> = self
                .pending
                .iter()
                .min_by_key(|(_, pending)| pending.since)
                .map(|(destination, _)| *destination);
            let Some(destination) = oldest else {
                break;
            };
            self.pending.remove(&destination);
            self.dropped += 1;
        }
    }
}

/// The text of the frame for `queued`: a batch is signed now.
fn sign(queued: Queued) -> String {
    match queued {
        Queued::Signed(frame) => frame,
        Queued::Batch { keys, tag, content } => {
            let event = Event::sign(Lane::Data, &keys, crate::unix_now(), &tag, content);
            wire::event(&event)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use n0_future::time::Instant;

    use super::{
        BUDGET_BYTES_PER_SEC, BURST_BYTES, BURST_FRAMES, DataQueue, FLUSH_TICK, FRAME_OVERHEAD,
        FRAMES_PER_SEC, Frame, MAX_AGE, MAX_QUEUED_FRAMES, Outgoing, QUEUE_BYTES,
        WEB_BUFFERED_BOUND, over_buffer_bound, weigh,
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

    /// The pacer charges a batch `FRAME_OVERHEAD` bytes above its content before it signs it, so
    /// the charge must never be below what the event adds around any content.
    #[test]
    fn the_overhead_charged_before_signing_covers_the_event() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        let datagram = vec![0u8; 1];
        queue.push_datagram(start, outgoing(&keys, 1, &datagram));
        let frame = queue.pop_ready(start).expect("the first goes at once");
        let Frame::Data(text) = &frame else {
            panic!("a data frame");
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("an EVENT frame");
        let content = parsed[1]["content"].as_str().expect("a content").len();
        assert!(
            text.len() <= content + FRAME_OVERHEAD,
            "the event is {} bytes over its content, the charge is {FRAME_OVERHEAD}",
            text.len() - content
        );
    }

    /// While a frame waits for the pacer, the open batch is not closed at the tick: it keeps
    /// growing, and goes as one frame when the pacer has caught up.
    #[test]
    fn an_open_batch_grows_while_a_frame_waits_for_the_pacer() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        queue.push_datagram(start, outgoing(&keys, 1, b"idle breaker"));
        queue.push_datagram(start + Duration::from_millis(1), outgoing(&keys, 1, b"x"));
        queue.push_datagram(start + Duration::from_millis(3), outgoing(&keys, 1, b"y"));
        let tick = start + Duration::from_millis(1) + FLUSH_TICK;
        queue.flush_due(tick);
        assert_eq!(queue.queued_frames(), 1, "the open batch was held back");
        queue.pop_ready(tick).expect("the waiting frame goes");
        queue.flush_due(tick);
        let frame = queue
            .pop_ready(tick)
            .expect("the batch goes once nothing waits");
        assert_eq!(
            datagrams(&frame),
            vec![b"x".to_vec(), b"y".to_vec()],
            "one frame with both datagrams"
        );
    }

    /// A frame that waited past the age limit is old data: the pacer was held up, for instance
    /// by a rate limit, and QUIC has sent it again. It is dropped, not sent late.
    #[test]
    fn a_frame_that_waited_past_the_age_limit_is_dropped_when_it_comes_up() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        queue.push_datagram(start, outgoing(&keys, 1, b"old"));
        let late = start + MAX_AGE + Duration::from_millis(1);
        assert!(queue.pop_ready(late).is_none(), "the old frame is not sent");
        assert_eq!(queue.dropped(), 1, "and it is counted");
        queue.push_datagram(late, outgoing(&keys, 1, b"new"));
        assert!(queue.pop_ready(late).is_some(), "a new frame goes");
    }

    /// A frame over `from`, as the queue lets it out.
    fn sender_of(frame: &Frame) -> [u8; ID_LEN] {
        let Frame::Data(text) = frame else {
            panic!("a data frame");
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("an EVENT frame");
        let event: Event = serde_json::from_value(parsed[1].clone()).expect("an event");
        batch::decode(&event.content).expect("a batch").from
    }

    /// Two pools of one process that send to one tag do not share a batch: each datagram goes
    /// out with the sender id of the pool that queued it.
    #[test]
    fn a_batch_belongs_to_a_sender_and_a_destination() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        queue.push_datagram(start, outgoing(&keys, 9, b"idle breaker"));
        queue.pop_ready(start).expect("the first goes");
        let soon = start + Duration::from_millis(1);
        let mut other = outgoing(&keys, 1, b"from other");
        other.from = [4u8; ID_LEN];
        queue.push_datagram(soon, outgoing(&keys, 1, b"from first"));
        queue.push_datagram(soon, other);
        let tick = soon + FLUSH_TICK;
        queue.flush_due(tick);
        let mut senders: Vec<[u8; ID_LEN]> = Vec::new();
        while let Some(frame) = queue.pop_ready(tick) {
            senders.push(sender_of(&frame));
        }
        senders.sort_unstable();
        assert_eq!(
            senders,
            vec![FROM, [4u8; ID_LEN]],
            "one event for each sender"
        );
    }

    /// One tick serves the socket: a destination that queued 1 ms after the first goes out at
    /// the tick of the first, not at a tick of its own.
    #[test]
    fn one_tick_per_socket_flushes_every_destination_together() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        queue.push_datagram(start, outgoing(&keys, 9, b"idle breaker"));
        queue.pop_ready(start).expect("the first goes");
        let first_at = start + Duration::from_millis(1);
        let second_at = start + Duration::from_millis(4);
        queue.push_datagram(first_at, outgoing(&keys, 1, b"to one"));
        queue.push_datagram(second_at, outgoing(&keys, 2, b"to two"));
        let tick = first_at + FLUSH_TICK;
        queue.flush_due(tick);
        let mut count = 0;
        while queue.pop_ready(tick).is_some() {
            count += 1;
        }
        assert_eq!(count, 2, "both destinations went at the first tick");
    }

    /// With many destinations the frames, not only the bytes, stay under a ceiling: 500-byte
    /// frames would otherwise queue seconds of delay.
    #[test]
    fn the_queue_holds_a_bounded_number_of_frames() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        for index in 0..2_000u64 {
            let now = start + Duration::from_millis(index);
            for tag in 0..8u8 {
                queue.push_datagram(now, outgoing(&keys, tag, &[tag; 300]));
            }
            queue.flush_due(now);
            assert!(
                queue.queued_frames() <= MAX_QUEUED_FRAMES,
                "{} frames queued after {index} pushes",
                queue.queued_frames()
            );
        }
        assert!(queue.dropped() > 0, "frames were dropped");
    }

    /// A batch the queue drops is never signed: under overload the socket task would otherwise
    /// spend its time on signatures of events it throws away.
    #[test]
    fn a_dropped_batch_costs_no_signature() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        for index in 0..1_000u64 {
            let now = start + Duration::from_millis(index);
            for tag in 0..8u8 {
                queue.push_datagram(now, outgoing(&keys, tag, &[tag; 300]));
            }
            queue.flush_due(now);
        }
        let mut out = 0;
        while queue.pop_ready(start + Duration::from_secs(1)).is_some() {
            out += 1;
        }
        assert!(
            queue.signed() <= out + 1,
            "{} events signed for {out} sent",
            queue.signed()
        );
    }

    /// An event larger than the burst can never pass the pacer: refused and counted, not left
    /// at the head of the queue.
    #[test]
    fn a_frame_larger_than_the_burst_is_refused_and_does_not_block_the_queue() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        queue.push_frame(start, "x".repeat(70 * 1024));
        assert_eq!(queue.dropped(), 1, "the oversize frame is counted");
        queue.push_frame(start, "small".to_owned());
        assert_eq!(
            queue.pop_ready(start),
            Some(Frame::Data("small".to_owned())),
            "the next frame is not stuck behind it"
        );
        let _ = keys;
    }

    /// A batch that waits behind a writer that is slow is dropped when it is old, as a frame in
    /// the queue is: an old datagram is the one QUIC has given up on.
    #[test]
    fn a_batch_older_than_the_limit_is_dropped_while_the_writer_is_slow() {
        let keys = shared_keys();
        let start = Instant::now();
        let mut queue = DataQueue::new(start);
        queue.push_datagram(start, outgoing(&keys, 9, b"the writer holds this"));
        let soon = start + Duration::from_millis(1);
        queue.push_datagram(soon, outgoing(&keys, 1, b"old"));
        let later = soon + Duration::from_secs(1);
        queue.push_datagram(later, outgoing(&keys, 2, b"new"));
        assert!(queue.dropped() >= 1, "the old batch was dropped");
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
