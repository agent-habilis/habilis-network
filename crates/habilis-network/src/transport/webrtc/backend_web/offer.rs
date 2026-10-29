use anyhow::{Context, Result};
use habilis_network_iroh_webrtc_transport::{BrowserPendingOffer, SignalEnvelope, WebRtcHandle};
use iroh::EndpointId;

pub(crate) struct Offer {
    pub(super) pending: BrowserPendingOffer,
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
        // The browser `complete` attaches into the hub itself, keyed on the
        // id the *answer envelope claims*. We hold the TLS-proven id, so
        // reject a mismatch before it can plant a session under the wrong
        // peer.
        let claimed = answer
            .claimed_endpoint()
            .context("answer carries no usable endpoint id")?;
        anyhow::ensure!(
            claimed == remote,
            "signal answer claims {claimed}, but the connection is with {remote}"
        );
        self.pending
            .complete(&handle.transport(), &answer)
            .await
            .map_err(|error| anyhow::anyhow!("complete WebRTC offer: {error:?}"))?;
        Ok(())
    }

    pub(crate) fn answer(mut self, answer: SignalEnvelope) -> Self {
        self.answer = Some(answer);
        self
    }
}
