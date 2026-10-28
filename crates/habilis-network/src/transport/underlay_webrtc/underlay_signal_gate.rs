//! The signal gate of the WebRTC underlay: which signals it admits.

use super::allowed::Allowed;
use crate::transport::{LOG_TARGET, WebRtcSignalAcceptor};

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};

use crate::transport::webrtc::close_code::NOT_A_NEIGHBOR;

/// The signal acceptor of the underlay. It answers only a neighbor: a signal
/// proves the underlay id and nothing more, and the signed link-vector of a
/// neighbor is what binds that id to a member.
#[derive(Debug, Clone)]
pub(crate) struct UnderlaySignalGate {
    inner: WebRtcSignalAcceptor,
    allowed: Allowed,
}

impl UnderlaySignalGate {
    pub(crate) fn new(inner: WebRtcSignalAcceptor, allowed: Allowed) -> Self {
        Self { inner, allowed }
    }
}

impl ProtocolHandler for UnderlaySignalGate {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        if !self.allowed.contains(&connection.remote_id()) {
            tracing::debug!(target: LOG_TARGET, peer = %connection.remote_id(), "underlay signal refused: not a neighbor");
            connection.close(NOT_A_NEIGHBOR.into(), b"not a neighbor");
            return Ok(());
        }
        self.inner.accept(connection).await
    }
}
