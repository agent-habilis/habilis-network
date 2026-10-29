//! The answerer side of a JSEP negotiation.

use iroh::EndpointId;
use std::time::Duration;
use str0m::change::SdpOffer;

use super::channel_ready_target::ChannelReadyTarget;
use super::driver;
use super::ice_config::IceConfig;
use super::jsep_error::JsepError;
use super::negotiated_session::NegotiatedSession;
use super::negotiating::{Negotiating, start};
use crate::SignalEnvelope;

/// Answerer-side JSEP state between sending the answer and the channel
/// opening.
#[derive(Debug)]
pub struct PendingAnswer {
    inner: Negotiating,
}

/// Answers a remote offer. Send the returned envelope back over the same
/// carrier, then await [`PendingAnswer::complete`].
///
/// # Errors
/// # Errors
/// [`JsepError::Envelope`] for a non-offer envelope, [`JsepError::Sdp`] for a bad
/// SDP, or [`JsepError::Bind`] when the socket cannot bind.
pub async fn answer(
    local: EndpointId,
    offer: &SignalEnvelope,
) -> Result<(PendingAnswer, SignalEnvelope), JsepError> {
    answer_with(local, offer, &IceConfig::default()).await
}

/// [`answer`] with an explicit ICE configuration — pass
/// [`IceConfig::host_only`] to stay offline.
///
/// # Errors
/// # Errors
/// [`JsepError::Envelope`] for a non-offer envelope, [`JsepError::Sdp`] for a bad
/// SDP, or [`JsepError::Bind`] when the socket cannot bind.
pub async fn answer_with(
    local: EndpointId,
    offer: &SignalEnvelope,
    ice: &IceConfig,
) -> Result<(PendingAnswer, SignalEnvelope), JsepError> {
    let SignalEnvelope::Offer { sdp, .. } = offer else {
        return Err(JsepError::Envelope {
            expected: "offer",
            got: format!("{offer:?}"),
        });
    };
    let mut inner = start(ice).await?;
    let sdp_offer = SdpOffer::from_sdp_string(sdp).map_err(JsepError::sdp("parse SDP offer"))?;
    let sdp_answer = inner
        .rtc
        .sdp_api()
        .accept_offer(sdp_offer)
        .map_err(JsepError::sdp("accept SDP offer"))?;
    let envelope = SignalEnvelope::answer(local, &sdp_answer.to_sdp_string());
    Ok((PendingAnswer { inner }, envelope))
}

impl PendingAnswer {
    /// Drives ICE/DTLS/SCTP until the offerer's data channel opens here.
    ///
    /// # Errors
    /// # Errors
    /// [`JsepError::Engine`] when str0m fails, or [`JsepError::Timeout`] when the
    /// data channel does not open before `deadline`.
    pub async fn complete(self, deadline: Duration) -> Result<NegotiatedSession, JsepError> {
        let Self { mut inner } = self;
        let channel_id = driver::drive_until_channel_ready(
            &mut inner.rtc,
            &inner.socket,
            inner.advertised,
            &ChannelReadyTarget::Answerer,
            deadline,
        )
        .await?;
        Ok(NegotiatedSession {
            rtc: inner.rtc,
            socket: inner.socket,
            channel_id,
            advertised: inner.advertised,
        })
    }
}
