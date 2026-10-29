/// A snapshot of [`SessionCounters`](super::SessionCounters), since the counters themselves are not
/// `Clone` and reading four atomics separately would not be one moment.
///
/// # Examples
///
/// The dropped count adds the frames dropped for each reason. The web module is private, so this is not compiled.
///
/// ```ignore
/// use habilis_network_iroh_webrtc_transport::web::SessionCounts;
///
/// let counts = SessionCounts { sent: 3, dropped_queue_full: 1, dropped_congested: 0, dropped_refused: 0 };
/// assert_eq!(counts.dropped(), 1);
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
