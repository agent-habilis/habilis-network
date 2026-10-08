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
    /// Source-routed multi-hop: reach a peer with no direct path through other
    /// members. It forwards over a direct path, so the list names `udp` or `webrtc` next to it.
    Multihop,
    /// Reach a peer with no other path through the frames of the mesh's own gossip topic. It
    /// rides the links that other paths carry, so the list names `udp` or `webrtc` next to it.
    Gossip,
    /// Let payload also fall back to the relay when no direct path exists.
    Relay,
}

/// The error for `multihop` with no direct transport next to it: it forwards
/// over a direct path, so it cannot stand alone, and `relay` is not one. The
/// direct path it needs is `udp` or `webrtc`.
pub(super) const MULTIHOP_ALONE: &str = "transport `multihop` cannot be the only transport: it forwards over a direct path, name `udp` or `webrtc`";

impl Transport {
    const NAMES: &[&str] = &["udp", "webrtc", "multihop", "gossip", "relay"];

    /// The name the list spells this transport by.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::WebRtc => "webrtc",
            Self::Multihop => "multihop",
            Self::Gossip => "gossip",
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
            "multihop" => Ok(Self::Multihop),
            "gossip" => Ok(Self::Gossip),
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "one independent on/off per path; the id writes them as one bitset byte"
)]
pub struct TransportPolicy {
    /// QUIC on UDP. Off, no native member binds a UDP path, and a mesh with
    /// `webrtc` rides the data channel alone.
    pub udp: bool,
    /// QUIC over a `WebRTC` data channel. Off, no member opens or answers an
    /// offer, browsers included.
    pub webrtc: bool,
    /// Source-routed multi-hop over a UDP underlay: a peer with no direct path
    /// is reached through other members. Native only; a browser ignores it, as
    /// it ignores `udp`. Needs `udp`, because its underlay is a UDP endpoint.
    pub multihop: bool,
    /// Gossip as a path: a peer with no other path is reached through the frames of the mesh's
    /// gossip topic. It rides the links of the direct paths, so it needs `udp` or `webrtc`.
    pub gossip: bool,
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
    /// `udp,webrtc,multihop`: every direct path and multi-hop, the relay for
    /// lookup alone. Gossip is off until the engine uses it.
    fn default() -> Self {
        Self {
            udp: true,
            webrtc: true,
            multihop: true,
            gossip: false,
            relay_transport: false,
        }
    }
}

impl TransportPolicy {
    /// The policy a `transport` list names. Empty ⇒ the default,
    /// `udp,webrtc,multihop`.
    ///
    /// # Errors
    /// The list is non-empty and names neither `udp` nor `webrtc`; with
    /// `multihop` in it, the message says that multihop needs a direct path.
    pub fn from_transports(transports: &[Transport]) -> Result<Self> {
        if transports.is_empty() {
            return Ok(Self::default());
        }
        let policy = Self {
            udp: transports.contains(&Transport::Udp),
            webrtc: transports.contains(&Transport::WebRtc),
            multihop: transports.contains(&Transport::Multihop),
            gossip: transports.contains(&Transport::Gossip),
            relay_transport: transports.contains(&Transport::Relay),
        };
        if policy.multihop_has_no_direct_path() {
            bail!(MULTIHOP_ALONE);
        }
        if !policy.udp && !policy.webrtc {
            bail!("a transport list needs a direct path: name `udp`, `webrtc`, or both");
        }
        Ok(policy)
    }
}

impl TransportPolicy {
    /// `multihop` is on and neither `udp` nor `webrtc` is: the one rule that
    /// [`MULTIHOP_ALONE`] reports, for a list a create names and for a mesh id
    /// that is decoded alike.
    pub(super) fn multihop_has_no_direct_path(self) -> bool {
        self.multihop && !self.udp && !self.webrtc
    }

    /// The policy as the one byte the mesh id carries.
    pub(crate) fn to_byte(self) -> u8 {
        let mut byte = 0u8;
        if self.udp {
            byte |= super::lookup::TRANSPORT_UDP;
        }
        if self.webrtc {
            byte |= super::lookup::TRANSPORT_WEBRTC;
        }
        if self.multihop {
            byte |= super::lookup::TRANSPORT_MULTIHOP;
        }
        if self.gossip {
            byte |= super::lookup::TRANSPORT_GOSSIP;
        }
        if self.relay_transport {
            byte |= super::lookup::TRANSPORT_RELAY;
        }
        byte
    }

    /// The policy a mesh id's byte names.
    ///
    /// # Errors
    /// The byte sets a bit this build does not know.
    pub(crate) fn from_byte(byte: u8) -> Result<Self> {
        if byte & !super::lookup::KNOWN_TRANSPORT_BITS != 0 {
            bail!("unsupported transport policy bits {byte:#04x}: upgrade to a newer build");
        }
        Ok(Self {
            udp: byte & super::lookup::TRANSPORT_UDP != 0,
            webrtc: byte & super::lookup::TRANSPORT_WEBRTC != 0,
            multihop: byte & super::lookup::TRANSPORT_MULTIHOP != 0,
            gossip: byte & super::lookup::TRANSPORT_GOSSIP != 0,
            relay_transport: byte & super::lookup::TRANSPORT_RELAY != 0,
        })
    }
}
