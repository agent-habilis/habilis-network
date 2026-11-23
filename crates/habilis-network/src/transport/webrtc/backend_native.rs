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

/// A node that stays on this host gathers host candidates only and binds the socket of the
/// session on loopback: `IceConfig::default()` queries two public STUN servers, which such a node
/// promises not to, and a socket on every interface lets another machine send to it.
pub(crate) fn ice_config(profile: IceProfile) -> IceConfig {
    if profile.host_only {
        IceConfig::loopback_only()
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

#[cfg(test)]
mod tests {
    use super::ice_config;
    use crate::transport::webrtc::ice_profile::IceProfile;

    /// **A node that stays on this host asks no STUN server and binds its session socket on
    /// loopback; any other node keeps the default.**
    #[test]
    fn the_profile_of_a_node_on_this_host_gives_a_loopback_session_without_stun() {
        let on_this_host = ice_config(IceProfile::default().host_only(true));
        assert!(
            on_this_host.stun_servers.is_empty(),
            "a STUN server is asked"
        );
        assert!(
            on_this_host.bind_ip.is_loopback(),
            "the session socket listens beyond the host: {}",
            on_this_host.bind_ip
        );

        let elsewhere = ice_config(IceProfile::default().host_only(false));
        assert!(
            !elsewhere.stun_servers.is_empty(),
            "the default asks no STUN server"
        );
        assert!(
            elsewhere.bind_ip.is_unspecified(),
            "the default binds loopback only"
        );
    }
}
