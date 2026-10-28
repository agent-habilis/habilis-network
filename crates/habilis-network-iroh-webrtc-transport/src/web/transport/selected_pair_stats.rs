/// What crossed the selected ICE candidate pair, for the same reason
/// [`DataChannelCounters`] is named: the byte counters share one type, so a
/// swapped pair would compile silently.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[non_exhaustive]
pub struct SelectedPairStats {
    /// Bytes sent on the selected candidate pair.
    pub bytes_sent: f64,
    /// Bytes received on the selected candidate pair.
    pub bytes_received: f64,
    /// `None` when the browser reports no round-trip time yet — distinct from a
    /// real 0 ms, which should not render alike.
    pub round_trip: Option<f64>,
}
