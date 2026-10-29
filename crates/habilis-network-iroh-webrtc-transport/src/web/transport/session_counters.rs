use std::sync::atomic::AtomicU64;

/// What one session's outbound lane did with the datagrams QUIC handed it.
///
/// Every drop on this lane is silent by construction: `poll_send` must not
/// park (it would stall iroh's shared send loop across every transport), so it
/// discards and reports success, and the pump discards again when the channel
/// is congested or refuses the write. That is a defensible design and an
/// undiagnosable one — a stalled transfer and a healthy idle one produce the
/// same absence of evidence.
///
/// These are that evidence. Read them through
/// [`BrowserHubTransport::session_counters`](super::BrowserHubTransport::session_counters); a consumer deciding whether to
/// demote a peer to the relay can then say *why* rather than inferring it from
/// a transfer that did not finish.
///
/// # Examples
///
/// It counts the frames of a live session, so this is not compiled.
///
/// ```ignore
/// let counters = SessionCounters::default();
/// ```
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct SessionCounters {
    /// Datagrams handed to `RTCDataChannel.send` without it throwing.
    pub sent: AtomicU64,
    /// Dropped by `poll_send`: the outbound queue was full, which means the
    /// pump had not been scheduled since the queue drained. QUIC is told the
    /// send succeeded, so these are invisible above.
    pub dropped_queue_full: AtomicU64,
    /// Dropped by the pump: `bufferedAmount` was at or over `BUFFER_CAP`.
    pub dropped_congested: AtomicU64,
    /// Dropped by the pump: `send` threw. A non-zero count here means the
    /// channel is refusing traffic, not merely slow.
    pub dropped_refused: AtomicU64,
}
