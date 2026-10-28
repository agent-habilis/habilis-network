use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use bytes::Bytes;
use iroh::endpoint::transports::{CustomSender, Transmit};
use iroh_base::CustomAddr;
use tokio::sync::mpsc::error::TrySendError;

use super::session::SessionRegistry;
use crate::{WEBRTC_TRANSPORT_ID, parse_custom_addr};

pub(crate) struct WebRtcSender {
    registry: Arc<SessionRegistry>,
}

impl WebRtcSender {
    pub(crate) fn new(registry: Arc<SessionRegistry>) -> Self {
        Self { registry }
    }
}

impl std::fmt::Debug for WebRtcSender {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebRtcSender")
            .finish_non_exhaustive()
    }
}

impl CustomSender for WebRtcSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        addr.id() == WEBRTC_TRANSPORT_ID && addr.data().len() == 32
    }

    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let remote = parse_custom_addr(dst)?;
        let Some((out_tx, dropped_tx)) = self.registry.with_live(&remote, |handle| {
            (handle.out_tx.clone(), Arc::clone(&handle.dropped_tx))
        }) else {
            // No negotiated session: report the path dead rather than
            // buffering — signaling is out of band and iroh should fall
            // back to other paths meanwhile.
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected)));
        };

        // Undo any GSO batching: one QUIC datagram per data-channel message.
        for chunk in habilis_network_iroh_transport_util::datagrams(transmit) {
            match out_tx.try_send(Bytes::copy_from_slice(chunk)) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    // Never return `Pending`: that would stall iroh's shared
                    // send loop for every transport. Drop and let QUIC
                    // retransmit.
                    let total = dropped_tx.fetch_add(1, Ordering::Relaxed) + 1;
                    super::session::note_dropped(&remote, total, "outbound queue full");
                }
                Err(TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected)));
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}
