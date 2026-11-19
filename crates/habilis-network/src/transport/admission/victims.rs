//! The peers that are picked to be evicted.

use crate::transport::webrtc;
use std::fmt;
use std::sync::Arc;

use iroh::EndpointId;
use iroh::endpoint::Connection;

use super::Sessions;

use crate::transport;
/// What an eviction ends: the connections, closed with the `EVICTED` code, and the sessions.
#[derive(Default, Clone)]
pub(crate) struct Victims {
    pub(crate) conns: Vec<Connection>,
    // trait object: the sessions are shared with the table that hands them out
    pub(crate) sessions: Vec<(EndpointId, Arc<dyn Sessions>)>,
    /// What made the ceiling evict: a connection, a session or a gossip neighbor took the unit.
    pub(crate) cause: &'static str,
    /// The peers that took the units: the connection, the session or the gossip neighbors. A
    /// victim is never one of them.
    pub(crate) newcomers: String,
    /// The node that evicts, as its short endpoint id, or `unknown`: a process that holds several
    /// nodes tells the lines of one from another by it.
    pub(crate) local: String,
}

impl fmt::Debug for Victims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Victims").finish_non_exhaustive()
    }
}

impl Victims {
    pub(crate) fn end(self) {
        for victim in self.conns {
            tracing::info!(
                target: transport::LOG_TARGET,
                victim = %victim.remote_id().fmt_short(),
                newcomers = %self.newcomers,
                local = %self.local,
                cause = self.cause,
                "evicting a direct connection at the ceiling"
            );
            victim.close(webrtc::close_code::EVICTED.into(), b"evicted at capacity");
        }
        for (peer, hub) in self.sessions {
            tracing::info!(
                target: transport::LOG_TARGET,
                victim = %peer.fmt_short(),
                newcomers = %self.newcomers,
                local = %self.local,
                cause = self.cause,
                "evicting a session at the ceiling"
            );
            let _ = hub.detach(&peer);
        }
    }
}
