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

impl std::error::Error for EndpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(error) => error.source(),
            Self::CapRefused(_) | Self::NotANeighbor(_) => None,
        }
    }
}

#[cfg(test)]
mod chain_tests {
    use habilis_network_test_tracing::test;

    use super::EndpointError;

    #[test]
    fn an_internal_cause_keeps_its_chain() {
        let io = std::io::Error::new(std::io::ErrorKind::AddrInUse, "Address already in use");
        let cause = anyhow::Error::new(io).context("bind the endpoint");
        let error = anyhow::Error::new(EndpointError::internal(cause));
        let text = format!("{error:#}");
        assert!(
            text.contains("Address already in use"),
            "the io cause of EndpointError is lost: {text}"
        );
    }
}
