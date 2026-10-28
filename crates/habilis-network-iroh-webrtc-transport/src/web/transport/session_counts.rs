/// A snapshot of [`SessionCounters`], since the counters themselves are not
/// `Clone` and reading four atomics separately would not be one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionCounts {
    /// Frames sent.
    pub sent: u64,
    /// Frames dropped because the queue was full.
    pub dropped_queue_full: u64,
    /// Frames dropped because the channel was congested.
    pub dropped_congested: u64,
    /// Frames refused by the channel.
    pub dropped_refused: u64,
}

impl SessionCounts {
    /// Total datagrams discarded on this lane, by any of the three routes.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped_queue_full + self.dropped_congested + self.dropped_refused
    }
}
