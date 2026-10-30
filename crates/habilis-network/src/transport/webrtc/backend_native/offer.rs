use anyhow::{Context, Result};
use habilis_network_iroh_webrtc_transport::{PendingOffer, SignalEnvelope, WebRtcHandle};
use iroh::EndpointId;

use crate::transport::webrtc::consts::JSEP_DEADLINE;

/// An offer awaiting its answer, plus the envelope to put on the wire.
#[derive(Debug)]
pub(crate) struct Offer {
    pub(super) pending: PendingOffer,
    pub(super) envelope: SignalEnvelope,
    pub(super) answer: Option<SignalEnvelope>,
}

impl Offer {
    pub(crate) fn envelope(&self) -> &SignalEnvelope {
        &self.envelope
    }

    pub(crate) async fn complete(
        mut self,
        remote: EndpointId,
        handle: &WebRtcHandle,
    ) -> Result<()> {
        let answer = self.answer.take().context("answer not supplied")?;
        // Boxed: the pending session carries the whole sans-io str0m state,
        // large enough to be worth keeping off this future's stack.
        let session = Box::pin(self.pending.complete(&answer, JSEP_DEADLINE))
            .await
            .context("complete WebRTC offer")?;
        handle.attach(remote, session).context("attach session")
    }

    pub(crate) fn answer(mut self, answer: SignalEnvelope) -> Self {
        self.answer = Some(answer);
        self
    }
}
