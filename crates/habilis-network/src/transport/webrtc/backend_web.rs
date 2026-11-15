//! The browser backend of the JSEP exchange.

use super::ice_profile::IceProfile;

mod answer;
mod offer;

pub(super) use answer::Answer;
pub(super) use offer::Offer;

use anyhow::Result;
use habilis_network_iroh_webrtc_transport::{SignalEnvelope, WebRtcHandle};
use iroh::EndpointId;

use habilis_network_iroh_webrtc_transport::{IceServers, browser_answer, browser_offer};

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
