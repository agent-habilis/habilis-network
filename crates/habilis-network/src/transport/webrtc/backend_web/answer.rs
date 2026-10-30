use anyhow::Result;
use habilis_network_iroh_webrtc_transport::{BrowserPendingAnswer, SignalEnvelope, WebRtcHandle};
use iroh::EndpointId;

#[derive(Debug, Clone)]
pub(crate) struct Answer {
    pub(super) pending: BrowserPendingAnswer,
    pub(super) envelope: SignalEnvelope,
}

impl Answer {
    pub(crate) fn envelope(&self) -> &SignalEnvelope {
        &self.envelope
    }

    pub(crate) async fn complete(self, remote: EndpointId, handle: &WebRtcHandle) -> Result<()> {
        // Keyed on the TLS-proven id the caller passed, not the envelope
        // claim.
        self.pending
            .complete(&handle.transport(), remote)
            .await
            .map_err(|error| anyhow::anyhow!("complete WebRTC answer: {error:?}"))?;
        Ok(())
    }
}
