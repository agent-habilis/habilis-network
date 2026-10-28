/// Cumulative counters from the session's `data-channel` stats row, `f64`
/// because that is what `getStats` reports. Named fields rather than a
/// positional tuple: every value shares one type, so a swapped pair would
/// compile silently.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[non_exhaustive]
pub struct DataChannelCounters {
    /// Bytes sent on the data channel.
    pub bytes_sent: f64,
    /// Bytes received on the data channel.
    pub bytes_received: f64,
    /// Messages sent on the data channel.
    pub messages_sent: f64,
    /// Messages received on the data channel.
    pub messages_received: f64,
}
