//! Bounded, nonblocking admission for the command channel of a stage that holds datagrams. A
//! channel with no bound would keep every datagram a caller can queue before the next stage runs;
//! this counts the bytes in the channel, and a datagram that would pass the bound is refused
//! before anything holds its payload.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The bytes one stage holds in its channel: the size of the queue behind it.
pub(crate) const ADMISSION_BYTES: usize = 256 * 1024;

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
        let held = self.bytes.fetch_add(len, Ordering::Relaxed);
        if held > 0 && held + len > limit {
            self.bytes.fetch_sub(len, Ordering::Relaxed);
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// The datagram left the channel.
    pub(crate) fn release(&self, len: usize) {
        self.bytes.fetch_sub(len, Ordering::Relaxed);
    }

    /// The datagrams refused.
    pub(crate) fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::Admission;

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
