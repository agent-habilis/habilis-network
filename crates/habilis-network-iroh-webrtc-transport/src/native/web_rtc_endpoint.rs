use std::io;
use std::sync::Arc;
use std::task::{Context, Poll};

use iroh::endpoint::transports::{CustomEndpoint, CustomSender, RecvInfo};
use iroh_base::CustomAddr;
use n0_watcher::Watchable;
use tokio::sync::mpsc;

use super::inbound_packet::InboundPacket;
use super::session_registry::SessionRegistry;
use super::web_rtc_sender::WebRtcSender;

pub(crate) struct WebRtcEndpoint {
    local_addr: CustomAddr,
    watchable: Watchable<Vec<CustomAddr>>,
    receiver: mpsc::Receiver<InboundPacket>,
    // the endpoint and its senders share the session registry
    registry: Arc<SessionRegistry>,
}

impl WebRtcEndpoint {
    pub(crate) fn new(
        local_addr: CustomAddr,
        watchable: Watchable<Vec<CustomAddr>>,
        receiver: mpsc::Receiver<InboundPacket>,
        // the endpoint and its senders share the session registry
        registry: Arc<SessionRegistry>,
    ) -> Self {
        Self {
            local_addr,
            watchable,
            receiver,
            registry,
        }
    }
}

impl std::fmt::Debug for WebRtcEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebRtcEndpoint")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl CustomEndpoint for WebRtcEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.watchable.watch()
    }

    // trait object: the endpoint calls the sender through this Arc
    fn create_sender(&self) -> Arc<dyn CustomSender> {
        // the sender is shared with the endpoint, which calls it from its tasks
        Arc::new(WebRtcSender::new(Arc::clone(&self.registry)))
    }

    /// No limit of our own: the sender splits any batch into one message per
    /// datagram. iroh sends with the smallest limit of every registered
    /// transport, so the default of 1 turned UDP GSO off for the whole
    /// endpoint, halving its UDP throughput on Linux. noq caps batches at 10.
    fn max_transmit_segments(&self) -> std::num::NonZeroUsize {
        std::num::NonZeroUsize::MAX
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        let slots: usize = bufs.len().min(metas.len());
        let slots = slots.min(recv_infos.len());
        if slots == 0 {
            return Poll::Ready(Ok(0));
        }

        let mut filled = 0usize;
        while filled < slots {
            match self.receiver.poll_recv(cx) {
                Poll::Pending => {
                    if filled == 0 {
                        return Poll::Pending;
                    }
                    break;
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::other("inbound packet channel closed")));
                }
                Poll::Ready(Some(packet)) => {
                    if bufs[filled].len() < packet.payload.len() {
                        // UDP-like semantics: an oversized datagram is lost,
                        // not an error.
                        continue;
                    }
                    bufs[filled][..packet.payload.len()].copy_from_slice(&packet.payload);
                    metas[filled].len = packet.payload.len();
                    metas[filled].stride = packet.payload.len();
                    recv_infos[filled] = RecvInfo::new(
                        crate::custom_addr(packet.from),
                        Some(self.local_addr.clone()),
                    );
                    filled += 1;
                }
            }
        }

        Poll::Ready(Ok(filled))
    }
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;
    use iroh::endpoint::transports::CustomTransport as _;

    use crate::WebRtcTransport;

    /// Linux's cap on segments in one GSO send (`UDP_MAX_SEGMENTS`).
    const LINUX_GSO_MAX: usize = 64;

    #[test]
    fn the_webrtc_endpoint_does_not_cap_udp_gso() {
        let _guard = ::habilis_network_test_tracing::init();
        let endpoint = WebRtcTransport::new(SecretKey::generate().public())
            .bind()
            .expect("a fresh transport binds");
        assert!(
            endpoint.max_transmit_segments().get() >= LINUX_GSO_MAX,
            "iroh sends with the smallest limit of any registered transport, so {} turns UDP GSO off",
            endpoint.max_transmit_segments()
        );
    }
}
