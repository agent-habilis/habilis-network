use std::net::SocketAddr;
use std::time::{Duration, Instant};

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

/// Why a JSEP negotiation failed. Each variant names the step that failed, so
/// a caller can tell a bad envelope from a dead socket from a missed deadline.
#[derive(Debug)]
#[non_exhaustive]
pub enum JsepError {
    /// The UDP socket for the negotiation could not bind.
    Bind(std::io::Error),
    /// str0m had no pending change to turn into an offer.
    NoOffer,
    /// The envelope is not the kind this step takes.
    Envelope {
        /// The kind this step takes: `offer` or `answer`.
        expected: &'static str,
        /// The envelope it was given, in debug form.
        got: String,
    },
    /// An SDP string does not parse, or str0m does not accept it.
    Sdp {
        /// The step that failed, for example `parse SDP answer`.
        step: &'static str,
        /// The error from the SDP parser or from str0m.
        source: BoxedError,
    },
    /// str0m failed while it drove the negotiation.
    Engine {
        /// The step that failed, for example `str0m poll_output`.
        step: &'static str,
        /// The error from str0m.
        source: BoxedError,
    },
    /// The data channel did not open before the deadline.
    Timeout {
        /// What the handshake loop ignored on the way, or nothing.
        detail: String,
    },
}

type BoxedError = Box<dyn std::error::Error + Send + Sync>;

impl JsepError {
    pub(crate) fn engine<E>(step: &'static str) -> impl FnOnce(E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        move |source| Self::Engine {
            step,
            source: Box::new(source),
        }
    }

    fn sdp<E>(step: &'static str) -> impl FnOnce(E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        move |source| Self::Sdp {
            step,
            source: Box::new(source),
        }
    }
}

impl std::fmt::Display for JsepError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(_) => formatter.write_str("could not bind the WebRTC UDP socket"),
            Self::NoOffer => formatter.write_str("str0m produced no offer for the pending change"),
            Self::Envelope { expected, got } => {
                write!(formatter, "expected an {expected} envelope, got {got}")
            }
            Self::Sdp { step, .. } | Self::Engine { step, .. } => formatter.write_str(step),
            Self::Timeout { detail } => write!(
                formatter,
                "timed out waiting for the WebRTC data channel to open{detail}"
            ),
        }
    }
}

impl std::error::Error for JsepError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind(error) => Some(error),
            Self::Sdp { source, .. } | Self::Engine { source, .. } => Some(source.as_ref()),
            Self::NoOffer | Self::Envelope { .. } | Self::Timeout { .. } => None,
        }
    }
}

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
async fn start(ice: &IceConfig) -> Result<Negotiating, JsepError> {
    let mut rtc = build_rtc(Instant::now());
    let (socket, advertised) = bind_ephemeral_udp().await.map_err(JsepError::Bind)?;
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
pub async fn offer(local: EndpointId) -> Result<(PendingOffer, SignalEnvelope), JsepError> {
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
    ///
    /// Fails on a non-answer envelope, a bad SDP, or `deadline` expiry.
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

/// Answers a remote offer. Send the returned envelope back over the same
/// carrier, then await [`PendingAnswer::complete`].
///
/// # Errors
///
/// Fails on a non-offer envelope, a bad SDP, or socket setup errors.
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
///
/// Fails on a non-offer envelope, a bad SDP, or socket setup errors.
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
    let envelope = SignalEnvelope::answer(local, sdp_answer.to_sdp_string());
    Ok((PendingAnswer { inner }, envelope))
}

impl PendingAnswer {
    /// Drives ICE/DTLS/SCTP until the offerer's data channel opens here.
    ///
    /// # Errors
    ///
    /// Fails on str0m errors or `deadline` expiry.
    pub async fn complete(self, deadline: Duration) -> Result<NegotiatedSession, JsepError> {
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
