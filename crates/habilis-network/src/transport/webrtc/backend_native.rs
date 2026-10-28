//! The native backend of the JSEP exchange.

use super::consts::JSEP_DEADLINE;
use super::ice_profile::IceProfile;

use anyhow::{Context, Result};
use habilis_network_iroh_webrtc_transport::{SignalEnvelope, WebRtcHandle};
use iroh::EndpointId;

use habilis_network_iroh_webrtc_transport::{
    IceConfig, PendingAnswer, PendingOffer, answer_with, offer_with,
};

/// An offer awaiting its answer, plus the envelope to put on the wire.
pub(super) struct Offer {
    pending: PendingOffer,
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
        // Boxed: the pending session carries the whole sans-io str0m state,
        // large enough to be worth keeping off this future's stack.
        let session = Box::pin(self.pending.complete(&answer, JSEP_DEADLINE))
            .await
            .context("complete WebRTC offer")?;
        handle.attach(remote, session).context("attach session")
    }

    pub(super) fn with_answer(mut self, answer: SignalEnvelope) -> Self {
        self.answer = Some(answer);
        self
    }
}

pub(super) async fn build_offer(
    local: EndpointId,
    _handle: &WebRtcHandle,
    profile: IceProfile,
) -> Result<Offer> {
    let ice = ice_config(profile);
    let (pending, envelope) = offer_with(local, &ice)
        .await
        .context("build WebRTC offer")?;
    Ok(Offer {
        pending,
        envelope,
        answer: None,
    })
}

/// An answer whose envelope is ready to send, with the negotiation still to
/// be driven. Split so the caller can put the SDP on the wire first.
pub(super) struct Answer {
    pending: PendingAnswer,
    envelope: SignalEnvelope,
}

impl Answer {
    pub(super) fn envelope(&self) -> &SignalEnvelope {
        &self.envelope
    }

    pub(super) async fn complete(self, remote: EndpointId, handle: &WebRtcHandle) -> Result<()> {
        let session = Box::pin(self.pending.complete(JSEP_DEADLINE))
            .await
            .context("complete WebRTC answer")?;
        handle.attach(remote, session).context("attach session")
    }
}

/// Host candidates only when the mesh is loopback: `IceConfig::default()`
/// queries two public STUN servers, which a loopback mesh promises not to.
pub(crate) fn ice_config(profile: IceProfile) -> IceConfig {
    if profile.host_only {
        IceConfig::host_only()
    } else {
        IceConfig::default()
    }
}

pub(super) async fn build_answer(
    local: EndpointId,
    offer: &SignalEnvelope,
    profile: IceProfile,
) -> Result<Answer> {
    let ice = ice_config(profile);
    let (pending, envelope) = answer_with(local, offer, &ice)
        .await
        .context("build WebRTC answer")?;
    Ok(Answer { pending, envelope })
}
