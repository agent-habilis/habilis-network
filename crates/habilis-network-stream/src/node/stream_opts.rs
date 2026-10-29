//! The stream opts: how a node finds peers and what may carry its bytes.

use habilis_network::protocol::{Lookup, Transport};
use serde::Deserialize;

/// How a node finds peers and what may carry its bytes — the same three lists
/// a mesh create takes, so a producer and a tab agree on them.
///
/// `Deserialize` so a browser hands its constructor a plain object;
/// `deny_unknown_fields` so a typo is an error, not a silent loopback node.
///
/// # Examples
///
/// The default options can be changed one value at a time.
///
/// ```
/// use habilis_network_stream::StreamOpts;
///
/// let opts = StreamOpts::default().with_relay_urls(Vec::<String>::new());
/// assert!(!format!("{opts:?}").is_empty());
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
#[non_exhaustive]
pub struct StreamOpts {
    /// How peers find each other: any of `mdns`, `dht`, `relay`. None is a
    /// loopback node.
    pub lookup: Vec<Lookup>,
    /// What may carry bytes: any of `udp`, `webrtc`, `relay`, with `udp` or
    /// `webrtc` among them. Empty ⇒ `udp,webrtc`. `multihop` and `gossip` are refused: a
    /// stream is one direct lane, and its node never joins a gossip mesh.
    pub transport: Vec<Transport>,
    /// A custom relay ladder, first preferred. Empty is the default ladder.
    pub relay_urls: Vec<String>,
}

impl StreamOpts {
    /// Set the lookups.
    #[must_use]
    pub fn with_lookup(mut self, lookup: impl IntoIterator<Item = Lookup>) -> Self {
        self.lookup = lookup.into_iter().collect();
        self
    }

    /// Set the transports.
    #[must_use]
    pub fn with_transport(mut self, transport: impl IntoIterator<Item = Transport>) -> Self {
        self.transport = transport.into_iter().collect();
        self
    }

    /// The relay URLs to dial, in the order given.
    #[must_use]
    pub fn with_relay_urls(mut self, relay_urls: impl IntoIterator<Item = String>) -> Self {
        self.relay_urls = relay_urls.into_iter().collect();
        self
    }
}
