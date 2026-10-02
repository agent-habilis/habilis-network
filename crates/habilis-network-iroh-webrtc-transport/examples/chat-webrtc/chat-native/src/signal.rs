//! The JSEP exchange, carried by the iroh relay.
//!
//! **The relay is the rendezvous, not the data path.** One short-lived
//! connection on [`chat_proto::SIGNAL_ALPN`] carries one
//! [`SignalEnvelope`] each way and closes. Nothing of the chat ever crosses it;
//! it exists to introduce two peers who cannot yet reach each other, and the
//! data channel that introduction produces carries everything after.
//!
//! That is the whole reason this example has no signaling server to deploy. A
//! conventional WebRTC demo needs a `WebSocket` broker with its own address, its
//! own TLS and its own uptime; iroh already runs an authenticated,
//! NAT-traversing rendezvous, and an ALPN on it is enough.
//!
//! Three rules here are load-bearing, and each is a bug that was paid for
//! upstream:
//!
//! 1. **The remote's identity comes from the connection, never the envelope.**
//!    `SignalEnvelope` carries a claimed endpoint id; over an authenticated
//!    carrier the TLS-proven [`Connection::remote_id`] is the real one. Keying
//!    a session by the claim would let any peer attach a session under someone
//!    else's name — impersonation, on a registry keyed by peer.
//! 2. **The answerer writes its answer before completing the negotiation.**
//!    Completing first waits for a data channel the offerer cannot open until
//!    it has the answer, and both sides sit there until a deadline fires.
//! 3. **Negotiation happens off the accept future.** Candidate gathering plus
//!    the DTLS/SCTP handshake takes seconds; holding the Router's accept task
//!    that long serialises inbound offers, so two tabs joining at once would
//!    queue.

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use chat_proto::SIGNAL_ALPN;
use habilis_network_iroh_webrtc_transport::iroh::endpoint::Connection;
use habilis_network_iroh_webrtc_transport::iroh::protocol::{AcceptError, ProtocolHandler};
use habilis_network_iroh_webrtc_transport::iroh::{Endpoint, EndpointAddr, EndpointId};
use habilis_network_iroh_webrtc_transport::{
    IceConfig, MAX_ENVELOPE_BYTES, SignalEnvelope, WebRtcHandle, answer_with, offer_with,
};

/// How long one JSEP round may take.
///
/// It covers candidate gathering on both sides plus the DTLS/SCTP handshake. A
/// browser answerer spends up to ten seconds on vanilla-ICE gathering alone —
/// candidates ride inside the SDP, there is no trickle message — so a tighter
/// bound would time out honest peers.
const JSEP_DEADLINE: Duration = Duration::from_secs(20);

/// Close codes, so a refusal is legible in a log instead of arriving as a bare
/// connection reset.
const SIGNAL_FAILED: u32 = 1;

/// Answers offers on [`SIGNAL_ALPN`] and attaches the resulting session.
#[derive(Debug, Clone)]
pub struct SignalAcceptor {
    handle: WebRtcHandle,
    local: EndpointId,
    ice: IceConfig,
}

impl SignalAcceptor {
    #[must_use]
    pub fn new(handle: WebRtcHandle, local: EndpointId, ice: IceConfig) -> Self {
        Self { handle, local, ice }
    }
}

impl ProtocolHandler for SignalAcceptor {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // Rule 1: the TLS-proven id, not the envelope's claim.
        let remote = connection.remote_id();
        let handle = self.handle.clone();
        let local = self.local;
        let ice = self.ice.clone();

        // Rule 3: off the accept future, so a second peer offering while this
        // one gathers is not made to wait for it.
        //
        // Boxed because the answer future carries the whole sans-io str0m
        // state, which is large enough to be worth keeping off a task's stack.
        tokio::spawn(Box::pin(async move {
            let round = Box::pin(answer_one(&connection, local, remote, &handle, &ice));
            match tokio::time::timeout(JSEP_DEADLINE, round).await {
                Ok(Ok(())) => {
                    tracing::info!(%remote, "attached a WebRTC session");
                }
                Ok(Err(error)) => {
                    tracing::warn!(%remote, %error, "the JSEP round failed");
                    connection.close(SIGNAL_FAILED.into(), b"signal failed");
                }
                Err(_elapsed) => {
                    tracing::warn!(%remote, ?JSEP_DEADLINE, "the JSEP round timed out");
                    connection.close(SIGNAL_FAILED.into(), b"signal timed out");
                }
            }
        }));

        Ok(())
    }
}

async fn answer_one(
    connection: &Connection,
    local: EndpointId,
    remote: EndpointId,
    handle: &WebRtcHandle,
    ice: &IceConfig,
) -> Result<()> {
    let (mut send, mut recv) = connection.accept_bi().await?;

    // `finish()` on the peer's side is the frame boundary — there is exactly
    // one envelope per direction, so the stream's end delimits it and no length
    // prefix is needed.
    let raw = recv
        .read_to_end(MAX_ENVELOPE_BYTES)
        .await
        .context("read the offer")?;
    let offer: SignalEnvelope = serde_json::from_slice(&raw).context("decode the offer")?;
    match &offer {
        SignalEnvelope::Offer { .. } => {}
        SignalEnvelope::Answer { .. } => bail!("peer sent an answer where an offer belongs"),
        SignalEnvelope::Error { reason, .. } => bail!("peer reported: {reason}"),
    }

    let (pending, answer) = answer_with(local, &offer, ice)
        .await
        .context("build the answer")?;

    // Rule 2: the answer goes out *before* we wait for the channel. The offerer
    // cannot open one until it has this.
    send.write_all(&serde_json::to_vec(&answer).context("encode the answer")?)
        .await
        .context("write the answer")?;
    send.finish().context("finish the answer stream")?;

    // Boxed: the completion future carries the whole sans-io str0m state, which
    // clippy flags as too large to leave on a task's stack.
    let session = Box::pin(pending.complete(JSEP_DEADLINE))
        .await
        .context("complete the negotiation")?;

    // A duplicate is refused rather than swapped in: the live session is
    // carrying traffic and the new one has proved nothing yet.
    handle
        .attach(remote, session)
        .context("attach the session")?;

    connection.close(0u32.into(), b"jsep done");
    Ok(())
}

/// Offer a session to `host` and attach it. The native mirror of what a tab
/// does.
///
/// # Errors
/// The dial fails, the peer answers with an error or a malformed envelope, the
/// negotiation does not complete, or a session for this peer already exists.
pub async fn dial(
    endpoint: &Endpoint,
    host: EndpointAddr,
    local: EndpointId,
    handle: &WebRtcHandle,
    ice: &IceConfig,
) -> Result<EndpointId> {
    let connection = endpoint
        .connect(host, SIGNAL_ALPN)
        .await
        .context("dial the signalling lane")?;
    let remote = connection.remote_id();
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("open the signal stream")?;

    let (pending, offer) = offer_with(local, ice).await.context("build the offer")?;
    send.write_all(&serde_json::to_vec(&offer).context("encode the offer")?)
        .await
        .context("write the offer")?;
    send.finish().context("finish the offer stream")?;

    let raw = recv
        .read_to_end(MAX_ENVELOPE_BYTES)
        .await
        .context("read the answer")?;
    let answer: SignalEnvelope = serde_json::from_slice(&raw).context("decode the answer")?;
    match &answer {
        SignalEnvelope::Answer { .. } => {}
        SignalEnvelope::Offer { .. } => bail!("peer sent an offer where an answer belongs"),
        SignalEnvelope::Error { reason, .. } => bail!("the room refused: {reason}"),
    }

    let session = Box::pin(pending.complete(&answer, JSEP_DEADLINE))
        .await
        .context("complete the negotiation")?;
    handle
        .attach(remote, session)
        .context("attach the session")?;

    connection.close(0u32.into(), b"jsep done");
    Ok(remote)
}
