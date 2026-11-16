//! Why a JSEP negotiation failed.

use std::{error, fmt};
/// Why a JSEP negotiation failed. Each variant names the step that failed, so
/// a caller can tell a bad envelope from a dead socket from a missed deadline.
///
/// # Examples
///
/// An answer with no offer to answer returns this error.
///
/// ```
/// use habilis_network_iroh_webrtc_transport::JsepError;
///
/// let error = JsepError::NoOffer;
/// assert!(matches!(error, JsepError::NoOffer));
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum JsepError {
    /// The UDP socket for the negotiation could not bind.
    Bind(BoxedError),
    /// Str0m had no pending change to turn into an offer.
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
    /// Str0m failed while it drove the negotiation.
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

type BoxedError = Box<dyn error::Error + Send + Sync>;

impl JsepError {
    pub(crate) fn engine<E>(step: &'static str) -> impl FnOnce(E) -> Self
    where
        E: error::Error + Send + Sync + 'static,
    {
        move |source| Self::Engine {
            step,
            source: Box::new(source),
        }
    }

    pub(super) fn sdp<E>(step: &'static str) -> impl FnOnce(E) -> Self
    where
        E: error::Error + Send + Sync + 'static,
    {
        move |source| Self::Sdp {
            step,
            source: Box::new(source),
        }
    }
}

impl fmt::Display for JsepError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl error::Error for JsepError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Bind(source) | Self::Sdp { source, .. } | Self::Engine { source, .. } => {
                Some(source.as_ref())
            }
            Self::NoOffer | Self::Envelope { .. } | Self::Timeout { .. } => None,
        }
    }
}
