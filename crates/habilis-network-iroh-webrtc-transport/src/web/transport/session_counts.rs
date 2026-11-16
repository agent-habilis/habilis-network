/// A snapshot of [`SessionCounters`](super::SessionCounters), since the counters themselves are not
/// `Clone` and reading four atomics separately would not be one moment.
///
/// # Examples
///
/// The dropped count adds the frames dropped for each reason. The web module is private, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_webrtc_transport::SessionCounts;
///
/// # fn demo(counts: SessionCounts) -> u64 {
/// counts.dropped()
/// # }
/// ```
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
