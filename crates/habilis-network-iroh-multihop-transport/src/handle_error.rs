//! The error of building a multihop handle over an underlay endpoint.

use std::fmt;

/// Why a multihop handle could not be built over its underlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum HandleError {
    /// A protocol was registered on the forwarder's own ALPN, which the forwarder keeps.
    ForwarderAlpn,
    /// The underlay is not bound to the key derived from the application secret.
    UnderlayKey,
}

impl fmt::Display for HandleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ForwarderAlpn => "the forwarder keeps its own ALPN on the underlay",
            Self::UnderlayKey => {
                "the underlay must be bound to `underlay_secret(secret)`, not another key"
            }
        })
    }
}

impl std::error::Error for HandleError {}
