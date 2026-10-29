use std::net::SocketAddr;

use str0m::Rtc;
use str0m::channel::ChannelId;
use tokio::net::UdpSocket;

/// A `WebRTC` data channel negotiated via JSEP and ready to carry datagrams —
/// the value handed to [`crate::WebRtcTransport::attach`].
///
/// # Examples
///
/// It is the open data channel that a finished negotiation produces, so this is not compiled.
///
/// ```ignore
/// let session = pending.complete(answer)?;
/// ```
pub struct NegotiatedSession {
    pub(crate) rtc: Rtc,
    pub(crate) socket: UdpSocket,
    pub(crate) channel_id: ChannelId,
    pub(crate) advertised: SocketAddr,
}

impl std::fmt::Debug for NegotiatedSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NegotiatedSession")
            .field("advertised", &self.advertised)
            .finish_non_exhaustive()
    }
}
