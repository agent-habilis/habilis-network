use std::fmt;

use iroh::EndpointId;

use std::error;
/// Why an endpoint cannot be built, or a `WebRTC` signal cannot be exchanged.
///
/// [`EndpointError::CapRefused`] and [`EndpointError::NotANeighbor`] are the refusals a
/// caller acts on: the peer is at its direct-peer cap, or it is not yet a neighbor of
/// the multihop underlay. [`EndpointError::Internal`] holds the other causes, which no
/// caller acts on; it keeps their text and their chain.
///
/// # Examples
///
/// A peer at its direct-peer cap turns the offer away with this error. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::net::EndpointError;
///
/// # fn demo(error: &EndpointError) -> bool {
/// matches!(error, EndpointError::CapRefused { .. })
/// # }
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum EndpointError {
    /// The peer is at its direct-peer cap and turned the offer away. `source` is the
    /// exchange error the refusal came from.
    CapRefused {
        /// The peer that refused.
        remote: EndpointId,
        /// The exchange error.
        source: Box<dyn error::Error + Send + Sync>,
    },
    /// The underlay of the peer turned us away: we are not a neighbor of it yet. `source` is
    /// the exchange error the refusal came from.
    NotANeighbor {
        /// The peer that refused.
        remote: EndpointId,
        /// The exchange error.
        source: Box<dyn error::Error + Send + Sync>,
    },
    /// A cause no caller acts on. It keeps its text and its chain.
    Internal(Box<dyn error::Error + Send + Sync>),
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
            Self::CapRefused { remote, .. } => {
                write!(formatter, "{remote} is at its direct-peer cap")
            }
            Self::NotANeighbor { remote, .. } => write!(
                formatter,
                "{remote} holds no link vector of ours yet: not a neighbor"
            ),
            Self::Internal(error) => fmt::Display::fmt(error.as_ref(), formatter),
        }
    }
}

impl error::Error for EndpointError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::CapRefused { source, .. } | Self::NotANeighbor { source, .. } => {
                Some(source.as_ref())
            }
            Self::Internal(error) => error.source(),
        }
    }
}
