use anyhow::{Context, Result};
use habilis_network_iroh_webrtc_transport::{PendingAnswer, SignalEnvelope, WebRtcHandle};
use iroh::EndpointId;

use crate::transport::webrtc::consts::JSEP_DEADLINE;

/// An answer whose envelope is ready to send, with the negotiation still to
/// be driven. Split so the caller can put the SDP on the wire first.
pub(crate) struct Answer {
    pub(super) pending: PendingAnswer,
    pub(super) envelope: SignalEnvelope,
}

impl Answer {
    pub(crate) fn envelope(&self) -> &SignalEnvelope {
        &self.envelope
    }

    pub(crate) async fn complete(self, remote: EndpointId, handle: &WebRtcHandle) -> Result<()> {
        let session = Box::pin(self.pending.complete(JSEP_DEADLINE))
            .await
            .context("complete WebRTC answer")?;
        handle.attach(remote, session).context("attach session")
    }
}
