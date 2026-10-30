//! The mesh-wide transport policy carried in the mesh id: which paths may
//! carry **payload**. How members find each other is the lookup side
//! (`lookup.rs`); which relay servers exist is the ladder inside it. This
//! module names neither: the one rule that needs both — letting the relay
//! carry payload needs a relay lookup — lives in `MeshConfig`.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

use super::{ChoiceError, ConfigError};

/// One path a mesh's members may carry payload over — an entry of the
/// `transport` list a create names. Mesh-wide: every joiner inherits it from
/// the mesh id.
///
/// # Examples
///
/// Each transport has the name that the wire and the config use.
///
/// ```
/// use habilis_network_protocol::meshes::Transport;
///
/// assert_eq!(Transport::WebRtc.as_str(), "webrtc");
/// assert_eq!(Transport::Udp.as_str(), "udp");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Transport {
    /// QUIC on a direct or hole-punched UDP socket. A browser has none. Off, no
    /// native member binds a UDP path, and a mesh with `webrtc` rides the data
    /// channel alone.
    Udp,
    /// QUIC over a `WebRTC` data channel: a browser's only direct path, and a
    /// native pair's when its UDP punch fails. Off, no member opens or answers
    /// an offer, browsers included.
    #[serde(rename = "webrtc")]
    WebRtc,
    /// Source-routed multi-hop: reach a peer with no direct path through other
    /// members. It forwards over a direct path, so the list names `udp` or `webrtc` next to it.
    /// Native only; a browser ignores it, as it ignores `udp`.
    Multihop,
    /// Reach a peer with no other path through the frames of the mesh's own gossip topic. It
    /// rides the links that other paths carry, so the list names `udp` or `webrtc` next to it.
    Gossip,
    /// Let payload also fall back to the relay when no direct path exists. Off by default: the
    /// relay is kept for lookup alone — the bootstrap dial, JSEP signalling and the NAT-traversal
    /// frames of a freshly opened connection still cross it — and every payload lane refuses to
    /// send while the relay is the only path to a peer. A pair with no direct path stays unlinked
    /// for payload rather than relayed. Meaningless without a relay lookup, so rejected together
    /// with [`RelayChoice::Disabled`](crate::RelayChoice).
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

    /// The bit this transport takes in the mesh id's transport byte.
    fn bit(self) -> u8 {
        match self {
            Self::Udp => super::lookup::TRANSPORT_UDP,
            Self::WebRtc => super::lookup::TRANSPORT_WEBRTC,
            Self::Multihop => super::lookup::TRANSPORT_MULTIHOP,
            Self::Gossip => super::lookup::TRANSPORT_GOSSIP,
            Self::Relay => super::lookup::TRANSPORT_RELAY,
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
///
/// # Examples
///
/// A policy turns each transport on or off, and the default keeps the usual ones on.
///
/// ```
/// use habilis_network_protocol::meshes::{Transport, TransportPolicy};
///
/// let policy = TransportPolicy::default().udp(false);
/// assert!(!policy.allows(Transport::Udp));
/// assert!(policy.allows(Transport::WebRtc));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TransportPolicy {
    transports: BTreeSet<Transport>,
}

impl Default for TransportPolicy {
    /// `udp,webrtc,multihop,gossip`: every direct path, multi-hop and gossip, the relay for
    /// lookup alone.
    fn default() -> Self {
        Self {
            transports: BTreeSet::from([
                Transport::Udp,
                Transport::WebRtc,
                Transport::Multihop,
                Transport::Gossip,
            ]),
        }
    }
}

impl TransportPolicy {
    /// Whether members may carry payload over `transport`.
    #[must_use]
    pub fn allows(&self, transport: Transport) -> bool {
        self.transports.contains(&transport)
    }

    /// Turn `transport` on or off.
    #[must_use]
    fn set(mut self, transport: Transport, on: bool) -> Self {
        if on {
            self.transports.insert(transport);
        } else {
            self.transports.remove(&transport);
        }
        self
    }

    /// Set the UDP transport. Start from `default()` and chain the setters.
    #[must_use]
    pub fn udp(
        self,
        // true enables the UDP transport
        udp: bool,
    ) -> Self {
        self.set(Transport::Udp, udp)
    }

    /// Set the `WebRTC` transport.
    #[must_use]
    pub fn webrtc(
        self,
        // true enables the WebRTC transport
        webrtc: bool,
    ) -> Self {
        self.set(Transport::WebRtc, webrtc)
    }

    /// Set the multihop transport.
    #[must_use]
    pub fn multihop(
        self,
        // true enables the multihop transport
        multihop: bool,
    ) -> Self {
        self.set(Transport::Multihop, multihop)
    }

    /// Set the gossip transport.
    #[must_use]
    pub fn gossip(
        self,
        // true enables the gossip transport
        gossip: bool,
    ) -> Self {
        self.set(Transport::Gossip, gossip)
    }

    /// Set whether the relay carries payload.
    #[must_use]
    pub fn relay_transport(
        self,
        // true enables the relay transport
        relay_transport: bool,
    ) -> Self {
        self.set(Transport::Relay, relay_transport)
    }
}

impl TransportPolicy {
    /// `multihop` is on and neither `udp` nor `webrtc` is: the one rule that
    /// [`MULTIHOP_ALONE`] reports, for a list a create names and for a mesh id
    /// that is decoded alike.
    pub(super) fn multihop_has_no_direct_path(&self) -> bool {
        self.allows(Transport::Multihop)
            && !self.allows(Transport::Udp)
            && !self.allows(Transport::WebRtc)
    }

    /// The policy as the one byte the mesh id carries.
    pub(crate) fn to_byte(&self) -> u8 {
        self.transports
            .iter()
            .fold(0, |byte, transport| byte | transport.bit())
    }
}

impl TryFrom<&[Transport]> for TransportPolicy {
    type Error = ConfigError;

    /// The policy a `transport` list names. Empty ⇒ the default,
    /// `udp,webrtc,multihop,gossip`. A list names exactly what it carries: `udp,webrtc,multihop`
    /// has no gossip.
    ///
    /// # Errors
    /// A [`ConfigError::Invalid`] when the list is non-empty and names neither `udp`
    /// nor `webrtc`. With `multihop` in it, the message says that multihop needs a direct
    /// path.
    fn try_from(transports: &[Transport]) -> Result<Self, Self::Error> {
        if transports.is_empty() {
            return Ok(Self::default());
        }
        let policy = Self {
            transports: transports.iter().copied().collect(),
        };
        if policy.multihop_has_no_direct_path() {
            return Err(ConfigError::Invalid(MULTIHOP_ALONE.to_owned()));
        }
        if !policy.allows(Transport::Udp) && !policy.allows(Transport::WebRtc) {
            return Err(ConfigError::Invalid(
                "a transport list needs a direct path: name `udp`, `webrtc`, or both".to_owned(),
            ));
        }
        Ok(policy)
    }
}

impl TryFrom<u8> for TransportPolicy {
    type Error = ConfigError;

    /// The policy a mesh id's byte names.
    ///
    /// # Errors
    /// A [`ConfigError::Invalid`] when the byte sets a bit this build does not know.
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        if byte & !super::lookup::KNOWN_TRANSPORT_BITS != 0 {
            return Err(ConfigError::Invalid(format!(
                "unsupported transport policy bits {byte:#04x}: upgrade to a newer build"
            )));
        }
        let transports: BTreeSet<Transport> = [
            Transport::Udp,
            Transport::WebRtc,
            Transport::Multihop,
            Transport::Gossip,
            Transport::Relay,
        ]
        .into_iter()
        .filter(|transport| byte & transport.bit() != 0)
        .collect();
        Ok(Self { transports })
    }
}

impl<const N: usize> TryFrom<&[Transport; N]> for TransportPolicy {
    type Error = ConfigError;

    fn try_from(transports: &[Transport; N]) -> Result<Self, Self::Error> {
        Self::try_from(transports.as_slice())
    }
}
