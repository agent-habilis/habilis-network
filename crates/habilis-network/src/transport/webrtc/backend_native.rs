//! The native backend of the JSEP exchange.

use super::ice_profile::IceProfile;

mod answer;
mod offer;

pub(super) use answer::Answer;
pub(super) use offer::Offer;

use anyhow::{Context, Result};
use habilis_network_iroh_webrtc_transport::{SignalEnvelope, WebRtcHandle};
use iroh::EndpointId;

use habilis_network_iroh_webrtc_transport::{IceConfig, answer_with, offer_with};

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
