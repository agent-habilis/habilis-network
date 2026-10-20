//! The per-node byte budget: a token bucket of one second.
//!
//! Every frame is cached for 30 s on every member by the topic, so the bytes a node
//! may put on it per second bound the cache of the whole mesh at 30 s times the
//! budget. A frame over the budget is dropped, and QUIC retransmits it.

use n0_future::time::Instant;

/// The first value of the budget, to be replaced by what the Phase 3 gossip cells
/// measure.
pub const DEFAULT_BUDGET_BYTES_PER_SEC: u64 = 1 << 20;

/// A token bucket: `rate` bytes per second, and a burst of one second.
#[derive(Debug)]
pub(crate) struct Budget {
    rate: u64,
    tokens: f64,
    last: Instant,
}

impl Budget {
    pub(crate) fn new(rate: u64, now: Instant) -> Self {
        Self {
            rate,
            tokens: float(rate),
            last: now,
        }
    }

    /// Spend `bytes` if the budget has them.
    pub(crate) fn take(&mut self, now: Instant, bytes: u64) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now.max(self.last);
        self.tokens = (self.tokens + elapsed * float(self.rate)).min(float(self.rate));
        let wanted = float(bytes);
        if self.tokens < wanted {
            return false;
        }
        self.tokens -= wanted;
        true
    }
}

/// A byte count as a float. A budget is bytes per second, far below 2^52.
#[expect(clippy::cast_precision_loss, reason = "a byte budget is below 2^52")]
fn float(count: u64) -> f64 {
    count as f64
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_budget_admits_one_second_of_burst_and_then_refuses() {
        let t0 = Instant::now();
        let mut budget = Budget::new(1000, t0);

        assert!(budget.take(t0, 600));
        assert!(!budget.take(t0, 600), "600 more is over the burst");
        assert!(budget.take(t0, 400), "the rest of the burst");
        assert!(!budget.take(t0, 1), "nothing is left");
    }

    #[test]
    fn a_budget_refills_with_time_up_to_the_burst_and_no_more() {
        let t0 = Instant::now();
        let mut budget = Budget::new(1000, t0);
        assert!(budget.take(t0, 1000));

        let half = t0 + Duration::from_millis(500);
        assert!(budget.take(half, 500), "half a second refilled 500");
        assert!(!budget.take(half, 1));

        let long = half + Duration::from_secs(10);
        assert!(budget.take(long, 1000), "refilled to the burst");
        assert!(!budget.take(long, 1), "but not to ten seconds of it");
    }

    /// Under overload the bytes that pass in 10 s are the burst plus 10 s of rate,
    /// and the budget does not starve: it passes close to that much.
    #[test]
    fn under_overload_a_budget_passes_the_rate_and_no_more() {
        let t0 = Instant::now();
        let mut budget = Budget::new(1000, t0);
        let mut admitted = 0u64;

        for step in 0..1000u64 {
            let now = t0 + Duration::from_millis(step * 10);
            if budget.take(now, 200) {
                admitted += 200;
            }
        }

        assert!(admitted <= 1000 + 10 * 1000, "{admitted} bytes in 10 s");
        assert!(admitted >= 10 * 1000 - 200, "{admitted} bytes in 10 s");
    }
}
