//! The presence subtype of a presence message: joined, left, or alive.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Presence subtype.
/// `Joined`/`Left` are user-visible; `Alive` is a silent keepalive used
/// by the heartbeat-based peer tracker.
///
/// # Examples
///
/// A join and a leave are different presence events.
///
/// ```
/// use habilis_network_protocol::messages::PresenceSubtype;
///
/// assert_ne!(PresenceSubtype::Joined, PresenceSubtype::Left);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum PresenceSubtype {
    /// A member joined.
    Joined,
    /// A member left.
    Left,
    /// A member is still here.
    Alive,
}

impl fmt::Display for PresenceSubtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PresenceSubtype::Joined => write!(f, "joined"),
            PresenceSubtype::Left => write!(f, "left"),
            PresenceSubtype::Alive => write!(f, "alive"),
        }
    }
}
