use super::Reach;

use serde::Serialize;

use crate::protocol::Nickname;

use crate::transport;
/// One peer in a [`RosterSnapshot`](super::RosterSnapshot). `last_seen_secs_ago` is
/// `None` until the peer's first heartbeat is timed; `quiet` marks a
/// peer heartbeat-evicted past `ALIVE_TIMEOUT` (still returnable);
/// `reach` is `direct` only while we hold a live link to it; `transport`
/// is the lane a directed frame to this peer would take right now (the
/// live `crate::transport` send decision — distinct from `reach`, which
/// is a gossip-overlay link fact). Serialized directly into the
/// consumer's roster surfaces.
///
/// # Examples
///
/// A roster entry names a member and how long since it was last heard from. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::RosterEntry;
///
/// # fn demo(entry: &RosterEntry) {
/// let _nickname = &entry.nickname;
/// # }
/// ```
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct RosterEntry {
    /// The nickname of the member.
    pub nickname: Nickname,
    /// Seconds since the member was last heard from.
    pub last_seen_secs_ago: Option<u64>,
    /// Whether the member has been silent past the alive timeout.
    pub quiet: bool,
    /// How the member is reached.
    pub reach: Reach,
    /// The transport that carries the member's traffic.
    pub transport: transport::Lane,
}
