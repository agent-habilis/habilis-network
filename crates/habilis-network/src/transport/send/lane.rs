//! The plane a message takes: gossip or unicast.

/// The lane a directed frame to `nick` would take right now — `Route`
/// stripped of its endpoint payload so the roster can serialize it. Sharing
/// `directed_endpoint` keeps the surfaced column from ever drifting from the
/// real send decision.
///
/// # Examples
///
/// A lane says which path a frame takes to its peer.
///
/// ```
/// use habilis_network::embed::Lane;
///
/// assert!(matches!(Lane::Unicast, Lane::Unicast));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Lane {
    /// A direct unicast send.
    Unicast,
    /// A send through other members.
    Multihop,
    /// The peer's only path is the relay. Only reported on a mesh whose relay
    /// is lookup only, where that path carries no payload; elsewhere it reads
    /// `unicast`.
    #[serde(rename = "relay-only")]
    RelayOnly,
    /// No path to the peer.
    Unreachable,
}
