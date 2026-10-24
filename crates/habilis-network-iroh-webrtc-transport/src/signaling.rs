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
#[non_exhaustive]
pub enum SignalEnvelope {
    /// A session offer, with the SDP of the caller.
    Offer {
        /// The protocol version of the envelope.
        #[serde(rename = "v")]
        version: u32,
        /// The endpoint id of the sender, in hex.
        endpoint_id: String,
        /// The session description.
        sdp: String,
    },
    /// A session answer, with the SDP of the callee.
    Answer {
        /// The protocol version of the envelope.
        #[serde(rename = "v")]
        version: u32,
        /// The endpoint id of the sender, in hex.
        endpoint_id: String,
        /// The session description.
        sdp: String,
    },
    /// A failure to set the session up, with the reason.
    Error {
        /// The protocol version of the envelope.
        #[serde(rename = "v")]
        version: u32,
        /// Why the session failed.
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

    /// An error envelope with the given reason.
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
    pub fn claimed_endpoint(&self) -> Result<EndpointId, SignalError> {
        match self {
            Self::Offer { endpoint_id, .. } | Self::Answer { endpoint_id, .. } => endpoint_id
                .parse()
                .map_err(|error| SignalError::EndpointId(Box::new(error))),
            Self::Error { reason, .. } => Err(SignalError::Remote {
                reason: reason.clone(),
            }),
        }
    }
}

/// Why a signal envelope does not name a usable endpoint.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignalError {
    /// The remote side answered with an error envelope.
    Remote {
        /// The reason the remote side gave.
        reason: String,
    },
    /// The endpoint id in the envelope does not parse.
    EndpointId(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for SignalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Remote { reason } => write!(formatter, "remote signaling error: {reason}"),
            Self::EndpointId(_) => {
                formatter.write_str("unparseable endpoint id in signal envelope")
            }
        }
    }
}

impl std::error::Error for SignalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Remote { .. } => None,
            Self::EndpointId(source) => Some(source.as_ref()),
        }
    }
}
