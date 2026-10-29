/// What crossed the selected ICE candidate pair, for the same reason
/// [`DataChannelCounters`](super::DataChannelCounters) is named: the byte counters share one type, so a
/// swapped pair would compile silently.
///
/// # Examples
///
/// A new set of pair statistics has no round trip yet. The web module is private, so this is not compiled.
///
/// ```ignore
/// use habilis_network_iroh_webrtc_transport::web::SelectedPairStats;
///
/// let stats = SelectedPairStats::default();
/// assert!(stats.round_trip.is_none());
/// ```
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
