//! Why a signal envelope does not name a usable endpoint.

/// Why a signal envelope does not name a usable endpoint.
///
/// # Examples
///
/// A remote error envelope returns the reason that the remote side gave.
///
/// ```
/// use habilis_network_iroh_webrtc_transport::SignalError;
///
/// let error = SignalError::Remote { reason: "busy".to_owned() };
/// assert!(error.to_string().contains("busy"));
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
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
