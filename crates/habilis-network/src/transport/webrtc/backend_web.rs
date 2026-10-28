//! The browser backend of the JSEP exchange.

use super::ice_profile::IceProfile;

use anyhow::{Context, Result};
use habilis_network_iroh_webrtc_transport::{SignalEnvelope, WebRtcHandle};
use iroh::EndpointId;

use habilis_network_iroh_webrtc_transport::{
    BrowserPendingAnswer, BrowserPendingOffer, IceServers, browser_answer, browser_offer,
};

pub(super) struct Offer {
    pending: BrowserPendingOffer,
    envelope: SignalEnvelope,
    answer: Option<SignalEnvelope>,
}

impl Offer {
    pub(super) fn envelope(&self) -> &SignalEnvelope {
        &self.envelope
    }

    pub(super) async fn complete(
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

    pub(super) fn with_answer(mut self, answer: SignalEnvelope) -> Self {
        self.answer = Some(answer);
        self
    }
}

/// `_profile` is ignored: a tab is never a loopback peer — it has no
/// loopback peers to reach — so there is no host-only case here.
pub(super) async fn build_offer(
    local: EndpointId,
    _handle: &WebRtcHandle,
    _profile: IceProfile,
) -> Result<Offer> {
    // STUN only: TURN is refused by `habilis-network-iroh-webrtc-transport`.
    let ice = IceServers::default();
    let (pending, envelope) = browser_offer(local, &ice)
        .await
        .map_err(|error| anyhow::anyhow!("build WebRTC offer: {error:?}"))?;
    Ok(Offer {
        pending,
        envelope,
        answer: None,
    })
}

pub(super) struct Answer {
    pending: BrowserPendingAnswer,
    envelope: SignalEnvelope,
}

impl Answer {
    pub(super) fn envelope(&self) -> &SignalEnvelope {
        &self.envelope
    }

    pub(super) async fn complete(self, remote: EndpointId, handle: &WebRtcHandle) -> Result<()> {
        // Keyed on the TLS-proven id the caller passed, not the envelope
        // claim.
        self.pending
            .complete(&handle.transport(), remote)
            .await
            .map_err(|error| anyhow::anyhow!("complete WebRTC answer: {error:?}"))?;
        Ok(())
    }
}

pub(super) async fn build_answer(
    local: EndpointId,
    offer: &SignalEnvelope,
    _profile: IceProfile,
) -> Result<Answer> {
    // STUN only: TURN is refused by `habilis-network-iroh-webrtc-transport`.
    let ice = IceServers::default();
    let (pending, envelope) = browser_answer(local, offer, &ice)
        .await
        .map_err(|error| anyhow::anyhow!("build WebRTC answer: {error:?}"))?;
    Ok(Answer { pending, envelope })
}
