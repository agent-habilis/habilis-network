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
                peer = %victim.remote_id().fmt_short(),
                "evicting a direct connection at the ceiling"
            );
            victim.close(webrtc::close_code::EVICTED.into(), b"evicted at capacity");
        }
        for (peer, hub) in self.sessions {
            tracing::info!(
                target: transport::LOG_TARGET,
                peer = %peer.fmt_short(),
                "evicting a session at the ceiling"
            );
            let _ = hub.detach(&peer);
        }
    }
}
