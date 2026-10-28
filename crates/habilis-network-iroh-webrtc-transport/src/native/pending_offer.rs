//! The offerer side of a JSEP negotiation.

use iroh::EndpointId;
use std::time::Duration;
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};

use super::driver::{ChannelReadyTarget, NegotiatedSession, drive_until_channel_ready};
use super::ice_config::IceConfig;
use super::jsep_error::JsepError;
use super::negotiating::{Negotiating, start};
use crate::{DATA_CHANNEL_LABEL, SignalEnvelope};

/// Offerer-side JSEP state between sending the offer and applying the
/// remote answer.
#[derive(Debug)]
pub struct PendingOffer {
    inner: Negotiating,
    pending: SdpPendingOffer,
    channel_id: ChannelId,
}

/// Starts a JSEP negotiation as the offerer. Send the returned envelope to
/// the remote over any carrier, then feed its answer to
/// [`PendingOffer::complete`].
///
/// # Errors
/// # Errors
/// [`JsepError::Bind`] when the UDP socket cannot bind, or [`JsepError::Engine`]
/// when str0m rejects the setup.
pub async fn offer(local: EndpointId) -> Result<(PendingOffer, SignalEnvelope), JsepError> {
    offer_with(local, &IceConfig::default()).await
}

/// [`offer`] with an explicit ICE configuration — pass
/// [`IceConfig::host_only`] to stay offline.
///
/// # Errors
/// # Errors
/// [`JsepError::Bind`] when the UDP socket cannot bind, or [`JsepError::Engine`]
/// when str0m rejects the setup.
pub async fn offer_with(
    local: EndpointId,
    ice: &IceConfig,
) -> Result<(PendingOffer, SignalEnvelope), JsepError> {
    let mut inner = start(ice).await?;
    let mut change = inner.rtc.sdp_api();
    // Unreliable + unordered: the channel carries QUIC datagrams, and QUIC
    // already owns loss recovery and congestion control. Reliable ordered
    // SCTP underneath it would stack a second retransmission loop and
    // head-of-line-block unrelated QUIC streams. The answerer adopts this
    // config from DCEP, so the offerer is the only place it is declared.
    let channel_id = change.add_channel_with_config(ChannelConfig {
        label: DATA_CHANNEL_LABEL.into(),
        ordered: false,
        reliability: Reliability::MaxRetransmits { retransmits: 0 },
        ..ChannelConfig::default()
    });
    let (sdp_offer, pending) = change.apply().ok_or(JsepError::NoOffer)?;
    let envelope = SignalEnvelope::offer(local, sdp_offer.to_sdp_string());
    Ok((
        PendingOffer {
            inner,
            pending,
            channel_id,
        },
        envelope,
    ))
}

impl PendingOffer {
    /// Applies the remote answer and drives ICE/DTLS/SCTP until the data
    /// channel is open.
    ///
    /// # Errors
    /// # Errors
    /// [`JsepError::Envelope`] for a non-answer envelope, [`JsepError::Sdp`] for a bad
    /// SDP, [`JsepError::Engine`] when str0m fails, or [`JsepError::Timeout`] when the
    /// data channel does not open before `deadline`.
    pub async fn complete(
        self,
        answer: &SignalEnvelope,
        deadline: Duration,
    ) -> Result<NegotiatedSession, JsepError> {
        let Self {
            mut inner,
            pending,
            channel_id,
        } = self;
        let SignalEnvelope::Answer { sdp, .. } = answer else {
            return Err(JsepError::Envelope {
                expected: "answer",
                got: format!("{answer:?}"),
            });
        };
        let sdp_answer =
            SdpAnswer::from_sdp_string(sdp).map_err(JsepError::sdp("parse SDP answer"))?;
        inner
            .rtc
            .sdp_api()
            .accept_answer(pending, sdp_answer)
            .map_err(JsepError::sdp("accept SDP answer"))?;
        let target = ChannelReadyTarget::Offerer(channel_id);
        let opened = drive_until_channel_ready(
            &mut inner.rtc,
            &inner.socket,
            inner.advertised,
            &target,
            deadline,
        )
        .await?;
        Ok(NegotiatedSession {
            rtc: inner.rtc,
            socket: inner.socket,
            channel_id: opened,
            advertised: inner.advertised,
        })
    }
}
