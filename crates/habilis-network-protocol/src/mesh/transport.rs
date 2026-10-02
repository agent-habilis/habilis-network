//! The mesh-wide transport policy carried in the mesh id: which paths may
//! carry **payload**. How members find each other is the lookup side
//! (`lookup.rs`); which relay servers exist is the ladder inside it. This
//! module names neither: the one rule that needs both — letting the relay
//! carry payload needs a relay lookup — lives in `MeshConfig`.

use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};
use serde::Deserialize;

use super::ChoiceError;

/// One path a mesh's members may carry payload over — an entry of the
/// `transport` list a create names. Mesh-wide: every joiner inherits it from
/// the mesh id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// QUIC on a direct or hole-punched UDP socket. A browser has none.
    Udp,
    /// QUIC over a `WebRTC` data channel: a browser's only direct path, and a
    /// native pair's when its UDP punch fails.
    #[serde(rename = "webrtc")]
    WebRtc,
    /// Let payload also fall back to the relay when no direct path exists.
    Relay,
}

impl Transport {
    const NAMES: &[&str] = &["udp", "webrtc", "relay"];

    /// The name the list spells this transport by.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::WebRtc => "webrtc",
            Self::Relay => "relay",
        }
    }
}

impl FromStr for Transport {
    type Err = ChoiceError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "udp" => Ok(Self::Udp),
            "webrtc" => Ok(Self::WebRtc),
            "relay" => Ok(Self::Relay),
            other => Err(ChoiceError::new("transport", other, Self::NAMES)),
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Which transports may carry mesh **payload**, baked into the mesh id beside
/// [`LookupOpts`](crate::LookupOpts). Lookups say how members find each
/// other; this says what their traffic may ride once they have. Mesh-wide, so
/// every member runs the same paths; the engine's `TransportOpts` follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportPolicy {
    /// QUIC on UDP. Off, no native member binds a UDP path, and a mesh with
    /// `webrtc` rides the data channel alone.
    pub udp: bool,
    /// QUIC over a `WebRTC` data channel. Off, no member opens or answers an
    /// offer, browsers included.
    pub webrtc: bool,
    /// Whether the iroh relay may carry payload. Off by default: the relay is
    /// kept for lookup alone — the bootstrap dial, JSEP signalling and the
    /// NAT-traversal frames of a freshly opened connection still cross it —
    /// and every payload lane refuses to send while the relay is the only
    /// path to a peer. A pair with no direct path stays unlinked for payload
    /// rather than relayed. `true` lets payload fall back to the relay;
    /// meaningless without a relay lookup, so rejected together with
    /// [`RelayChoice::Disabled`](crate::RelayChoice).
    pub relay_transport: bool,
}

impl Default for TransportPolicy {
    /// `udp,webrtc`: every direct path, the relay for lookup alone.
    fn default() -> Self {
        Self {
            udp: true,
            webrtc: true,
            relay_transport: false,
        }
    }
}

impl TransportPolicy {
    /// The policy a `transport` list names. Empty ⇒ the default, `udp,webrtc`.
    ///
    /// # Errors
    /// The list is non-empty and names neither `udp` nor `webrtc`.
    pub fn from_transports(transports: &[Transport]) -> Result<Self> {
        if transports.is_empty() {
            return Ok(Self::default());
        }
        let policy = Self {
            udp: transports.contains(&Transport::Udp),
            webrtc: transports.contains(&Transport::WebRtc),
            relay_transport: transports.contains(&Transport::Relay),
        };
        if !policy.udp && !policy.webrtc {
            bail!("a transport list needs a direct path: name `udp`, `webrtc`, or both");
        }
        Ok(policy)
    }
}
