//! Bounded, nonblocking admission for the command channel of a stage that holds datagrams. A
//! channel with no bound would keep every datagram a caller can queue before the next stage runs;
//! this counts the bytes in the channel, and a datagram that would pass the bound is refused
//! before anything holds its payload.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The bytes one stage holds in its channel: the size of the queue behind it.
pub(crate) const ADMISSION_BYTES: usize = 256 * 1024;

/// The least a datagram is charged, whatever its length: each one costs the channel an entry,
/// and the allocation behind it. Without a floor, a burst of empty datagrams charges nothing.
const MIN_CHARGE: usize = 64;

/// What a datagram of `len` bytes costs the channel.
fn charge(len: usize) -> usize {
    len.max(MIN_CHARGE)
}

/// The bytes in a channel, and the datagrams refused.
#[derive(Debug, Default)]
pub(crate) struct Admission {
    bytes: AtomicUsize,
    rejected: AtomicU64,
}

impl Admission {
    /// Take room for a datagram of `len` bytes. `false`, and it is counted, when the channel
    /// would hold more than `limit`.
    pub(crate) fn admit(&self, len: usize, limit: usize) -> bool {
        let cost = charge(len);
        let held = self.bytes.fetch_add(cost, Ordering::Relaxed);
        if held > 0 && held + cost > limit {
            self.bytes.fetch_sub(cost, Ordering::Relaxed);
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// The datagram left the channel.
    pub(crate) fn release(&self, len: usize) {
        self.bytes.fetch_sub(charge(len), Ordering::Relaxed);
    }

    /// The datagrams refused.
    pub(crate) fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::Admission;

    /// An empty datagram still costs the channel an entry. A burst of them must reach the bound.
    #[test]
    fn a_burst_of_empty_datagrams_is_refused_past_the_bound_and_counted() {
        let admission = Admission::default();
        let admitted = (0..10_000)
            .filter(|_| admission.admit(0, super::ADMISSION_BYTES))
            .count();
        assert!(
            admitted < 10_000,
            "{admitted} of 10000 empty datagrams admitted"
        );
        assert_eq!(
            admission.rejected(),
            u64::try_from(10_000 - admitted).unwrap_or(0),
            "each refusal is counted"
        );
    }

    #[test]
    fn admission_takes_room_up_to_the_limit_and_gives_it_back() {
        let admission = Admission::default();
        assert!(admission.admit(60, 100), "room for the first");
        assert!(!admission.admit(60, 100), "no room for a second");
        assert_eq!(admission.rejected(), 1, "the refusal is counted");
        admission.release(60);
        assert!(admission.admit(60, 100), "room again after a release");
    }
}
