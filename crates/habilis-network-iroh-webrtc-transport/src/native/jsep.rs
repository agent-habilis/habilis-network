use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use iroh::EndpointId;
use str0m::Rtc;
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use tokio::net::UdpSocket;

use super::driver::{
    ChannelReadyTarget, NegotiatedSession, add_host_candidate, add_reflexive_candidate,
    bind_ephemeral_udp, build_rtc, drive_until_channel_ready,
};
use super::stun::IceConfig;
use crate::SignalEnvelope;

// The channel label is crate-root protocol, shared with the browser backend.
use crate::DATA_CHANNEL_LABEL;

/// Offerer-side JSEP state between sending the offer and applying the
/// remote answer.
#[derive(Debug)]
pub struct PendingOffer {
    inner: Negotiating,
    pending: SdpPendingOffer,
    channel_id: ChannelId,
}

/// Answerer-side JSEP state between sending the answer and the channel
/// opening.
#[derive(Debug)]
pub struct PendingAnswer {
    inner: Negotiating,
}

struct Negotiating {
    rtc: Rtc,
    socket: UdpSocket,
    advertised: SocketAddr,
}

impl std::fmt::Debug for Negotiating {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Negotiating")
            .field("advertised", &self.advertised)
            .finish_non_exhaustive()
    }
}

/// Bind the session's socket and gather its candidates.
///
/// Both roles funnel through here, which is what keeps the offerer and the
/// answerer advertising the same *kinds* of candidate. Gathering must happen
/// before the SDP is produced: this is vanilla ICE, so candidates ride inside
/// the SDP and there is no trickle message to add them later.
async fn start(ice: &IceConfig) -> anyhow::Result<Negotiating> {
    let mut rtc = build_rtc(Instant::now());
    let (socket, advertised) = bind_ephemeral_udp()
        .await
        .context("bind WebRTC UDP socket")?;
    add_host_candidate(&mut rtc, advertised)?;
    // Same socket as the media, or the NAT mapping we learn describes a hole
    // the data will not arrive through.
    add_reflexive_candidate(&mut rtc, &socket, advertised, ice).await;
    Ok(Negotiating {
        rtc,
        socket,
        advertised,
    })
}

/// Starts a JSEP negotiation as the offerer. Send the returned envelope to
/// the remote over any carrier, then feed its answer to
/// [`PendingOffer::complete`].
///
/// # Errors
///
/// Fails if the UDP socket can't bind or str0m rejects the setup.
pub async fn offer(local: EndpointId) -> anyhow::Result<(PendingOffer, SignalEnvelope)> {
    offer_with(local, &IceConfig::default()).await
}

/// [`offer`] with an explicit ICE configuration — pass
/// [`IceConfig::host_only`] to stay offline.
///
/// # Errors
///
/// Fails if the UDP socket can't bind or str0m rejects the setup.
pub async fn offer_with(
    local: EndpointId,
    ice: &IceConfig,
) -> anyhow::Result<(PendingOffer, SignalEnvelope)> {
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
    let (sdp_offer, pending) = change
        .apply()
        .context("str0m produced no offer for the pending change")?;
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
    ///
    /// Fails on a non-answer envelope, a bad SDP, or `deadline` expiry.
    pub async fn complete(
        self,
        answer: &SignalEnvelope,
        deadline: Duration,
    ) -> anyhow::Result<NegotiatedSession> {
        let Self {
            mut inner,
            pending,
            channel_id,
        } = self;
        let SignalEnvelope::Answer { sdp, .. } = answer else {
            anyhow::bail!("expected an answer envelope, got {answer:?}");
        };
        let sdp_answer = SdpAnswer::from_sdp_string(sdp)
            .map_err(|error| anyhow::anyhow!("parse SDP answer: {error}"))?;
        inner
            .rtc
            .sdp_api()
            .accept_answer(pending, sdp_answer)
            .context("accept SDP answer")?;
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

/// Answers a remote offer. Send the returned envelope back over the same
/// carrier, then await [`PendingAnswer::complete`].
///
/// # Errors
///
/// Fails on a non-offer envelope, a bad SDP, or socket setup errors.
pub async fn answer(
    local: EndpointId,
    offer: &SignalEnvelope,
) -> anyhow::Result<(PendingAnswer, SignalEnvelope)> {
    answer_with(local, offer, &IceConfig::default()).await
}

/// [`answer`] with an explicit ICE configuration — pass
/// [`IceConfig::host_only`] to stay offline.
///
/// # Errors
///
/// Fails on a non-offer envelope, a bad SDP, or socket setup errors.
pub async fn answer_with(
    local: EndpointId,
    offer: &SignalEnvelope,
    ice: &IceConfig,
) -> anyhow::Result<(PendingAnswer, SignalEnvelope)> {
    let SignalEnvelope::Offer { sdp, .. } = offer else {
        anyhow::bail!("expected an offer envelope, got {offer:?}");
    };
    let mut inner = start(ice).await?;
    let sdp_offer = SdpOffer::from_sdp_string(sdp)
        .map_err(|error| anyhow::anyhow!("parse SDP offer: {error}"))?;
    let sdp_answer = inner
        .rtc
        .sdp_api()
        .accept_offer(sdp_offer)
        .context("accept SDP offer")?;
    let envelope = SignalEnvelope::answer(local, sdp_answer.to_sdp_string());
    Ok((PendingAnswer { inner }, envelope))
}

impl PendingAnswer {
    /// Drives ICE/DTLS/SCTP until the offerer's data channel opens here.
    ///
    /// # Errors
    ///
    /// Fails on str0m errors or `deadline` expiry.
    pub async fn complete(self, deadline: Duration) -> anyhow::Result<NegotiatedSession> {
        let Self { mut inner } = self;
        let channel_id = drive_until_channel_ready(
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
