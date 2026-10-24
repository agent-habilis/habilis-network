//! The error of an endpoint: building one, and dialling a peer's WebRTC signal.

use std::fmt;

use iroh::EndpointId;

/// Why an endpoint cannot be built, or a WebRTC signal cannot be exchanged.
///
/// [`EndpointError::CapRefused`] and [`EndpointError::NotANeighbor`] are the refusals a
/// caller acts on: the peer is at its direct-peer cap, or it is not yet a neighbor of
/// the multihop underlay. [`EndpointError::Internal`] holds the other causes, which no
/// caller acts on; it keeps their text and their chain.
#[derive(Debug)]
#[non_exhaustive]
pub enum EndpointError {
    /// The peer is at its direct-peer cap and turned the offer away.
    CapRefused(EndpointId),
    /// The underlay of the peer turned us away: we are not a neighbor of it yet.
    NotANeighbor(EndpointId),
    /// A cause no caller acts on. It keeps its text and its chain.
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

impl EndpointError {
    /// Wraps a cause no caller acts on, keeping its text and its chain.
    pub(crate) fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapRefused(remote) => write!(formatter, "{remote} is at its direct-peer cap"),
            Self::NotANeighbor(remote) => write!(
                formatter,
                "{remote} holds no link vector of ours yet: not a neighbor"
            ),
            Self::Internal(error) => fmt::Display::fmt(error.as_ref(), formatter),
        }
    }
}

impl std::error::Error for EndpointError {}
