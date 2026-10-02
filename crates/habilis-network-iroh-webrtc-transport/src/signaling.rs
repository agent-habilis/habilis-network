use anyhow::Context as _;
use iroh_base::EndpointId;
use serde::{Deserialize, Serialize};

/// Envelope wire version, carried in every message so a future incompatible
/// change can be detected without a new ALPN/route.
pub const SIGNAL_VERSION: u32 = 1;

/// Cap on a serialized envelope (an SDP is a few kilobytes; this bounds hostile
/// input on the HTTP signaling path and the iroh stream framing alike).
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

/// One JSEP signal message (vanilla ICE: candidates ride inside the SDP,
/// there is no trickle message).
///
/// `endpoint_id` lets the receiving transport key the session. Over an
/// authenticated carrier (an iroh bidi stream) the receiver MUST ignore it
/// and use the TLS-proven remote id instead; over an unauthenticated one
/// (the browser HTTP endpoint) it is a claim — the QUIC handshake above the
/// data channel authenticates the real identity, so a false claim only
/// breaks the liar's own session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SignalEnvelope {
    Offer {
        #[serde(rename = "v")]
        version: u32,
        endpoint_id: String,
        sdp: String,
    },
    Answer {
        #[serde(rename = "v")]
        version: u32,
        endpoint_id: String,
        sdp: String,
    },
    Error {
        #[serde(rename = "v")]
        version: u32,
        reason: String,
    },
}

impl SignalEnvelope {
    /// An offer carrying `sdp`, stamped with the current [`SIGNAL_VERSION`].
    #[must_use]
    pub fn offer(local: EndpointId, sdp: impl Into<String>) -> Self {
        Self::Offer {
            version: SIGNAL_VERSION,
            endpoint_id: local.to_string(),
            sdp: sdp.into(),
        }
    }

    /// The reply to an [`offer`](Self::offer), same shape.
    #[must_use]
    pub fn answer(local: EndpointId, sdp: impl Into<String>) -> Self {
        Self::Answer {
            version: SIGNAL_VERSION,
            endpoint_id: local.to_string(),
            sdp: sdp.into(),
        }
    }

    #[must_use]
    pub fn error(reason: impl Into<String>) -> Self {
        Self::Error {
            version: SIGNAL_VERSION,
            reason: reason.into(),
        }
    }

    /// The endpoint id the remote side claims in this envelope.
    ///
    /// # Errors
    ///
    /// Fails on an `Error` envelope or an unparseable id.
    pub fn claimed_endpoint(&self) -> anyhow::Result<EndpointId> {
        match self {
            Self::Offer { endpoint_id, .. } | Self::Answer { endpoint_id, .. } => endpoint_id
                .parse()
                .context("unparseable endpoint id in signal envelope"),
            Self::Error { reason, .. } => anyhow::bail!("remote signaling error: {reason}"),
        }
    }
}
