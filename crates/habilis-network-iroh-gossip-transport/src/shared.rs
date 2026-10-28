//! The state a handle and its iroh-facing parts share.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use iroh::EndpointId;
use iroh_base::CustomAddr;
use n0_future::time::Instant;

use crate::budget::Budget;
use crate::counters::Counters;
use crate::frame::{EncodeError, Frame};
use crate::frame_sink::FrameSink;

/// Packets waiting for iroh to read them.
pub(crate) const INBOUND_CAP: usize = 256;

/// The guard of `mutex`. A poisoned lock means a panic happened while it was held,
/// so this function panics too.
pub(crate) fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().expect("the lock is poisoned")
}

/// A packet from another member, on its way to iroh.
#[derive(Debug)]
pub(crate) struct Packet {
    pub(crate) remote: CustomAddr,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) app_id: EndpointId,
    pub(crate) local_addr: CustomAddr,
    pub(crate) sink: Mutex<Option<Arc<dyn FrameSink>>>,
    pub(crate) attached: AtomicBool,
    /// Destinations that the engine stopped, because a higher rung carries them.
    pub(crate) blocked: Mutex<HashSet<EndpointId>>,
    /// The byte budget of this node, if one is set.
    pub(crate) budget: Mutex<Option<Budget>>,
    /// Destinations that have an established connection. A frame to any other
    /// destination is a handshake and is not charged to the budget.
    pub(crate) established: Mutex<HashSet<EndpointId>>,
    pub(crate) counters: Counters,
}

impl Shared {
    /// A path is valid while a sink is attached and alive.
    pub(crate) fn path_is_valid(&self) -> bool {
        if !self.attached.load(Ordering::SeqCst) {
            return false;
        }
        let sink = locked(&self.sink).clone();
        sink.is_some_and(|sink| sink.is_alive())
    }

    /// One QUIC datagram to `dst`: framed and handed to the sink. A datagram that
    /// does not fit a frame, or that has no sink to go to, is dropped and the call
    /// still succeeds, as a NIC drops what it cannot carry. QUIC recovers.
    pub(crate) fn send_datagram(&self, dst: EndpointId, datagram: &[u8]) {
        if locked(&self.blocked).contains(&dst) {
            return self.counters.dropped_not_allowed();
        }
        let frame = match (Frame {
            dst,
            src: self.app_id,
            datagram,
        })
        .encode()
        {
            Ok(frame) => frame,
            Err(EncodeError::Empty) => return self.counters.dropped_empty(),
            Err(EncodeError::TooLarge { .. }) => return self.counters.dropped_too_large(),
        };
        let sink = locked(&self.sink).clone().filter(|sink| sink.is_alive());
        let Some(sink) = sink else {
            return self.counters.dropped_no_sink();
        };
        let bytes = frame.len();
        // A frame to a destination with a connection is charged to the budget. A
        // frame to any other is a handshake and passes: a new pair must not be
        // starved by a bulk flow that has used the budget up.
        let charged = locked(&self.established).contains(&dst);
        let mut budgeted = false;
        if let Some(budget) = locked(&self.budget).as_mut() {
            budgeted = true;
            if charged && !budget.take(Instant::now(), bytes as u64) {
                return self.counters.dropped_budget();
            }
        }
        if sink.try_send(frame) {
            self.counters.sent(bytes);
            if budgeted && !charged {
                self.counters.exempt();
            }
        } else {
            self.counters.dropped_sink_refused();
        }
    }
}
