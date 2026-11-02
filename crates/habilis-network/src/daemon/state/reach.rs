use serde::Serialize;

/// How we currently reach a peer: `Direct` when we hold a live gossip
/// link to its self-advertised endpoint, else `Gossip` (relayed). Derived
/// from `linked_endpoints` without surfacing the node id — see
/// `peer_endpoints`.
///
/// # Examples
///
/// A direct path and a gossip path are different reaches.
///
/// ```
/// use habilis_network::embed::Reach;
///
/// assert_ne!(Reach::Direct, Reach::Gossip);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Reach {
    /// A direct path.
    Direct,
    /// No direct link: the peer is heard over the gossip topic, through other members or the relay.
    Gossip,
}
