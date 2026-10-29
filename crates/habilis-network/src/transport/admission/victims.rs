//! The peers that are picked to be evicted.

use crate::transport::webrtc;
use std::sync::Arc;

use iroh::EndpointId;
use iroh::endpoint::Connection;

use super::Sessions;

/// What an eviction ends: the connections, closed with the `EVICTED` code, and the sessions.
#[derive(Default)]
pub(crate) struct Victims {
    pub(crate) conns: Vec<Connection>,
    // trait object: the sessions are shared with the table that hands them out
    pub(crate) sessions: Vec<(EndpointId, Arc<dyn Sessions>)>,
}

impl Victims {
    pub(crate) fn end(self) {
        for victim in self.conns {
            tracing::info!(
                target: crate::transport::LOG_TARGET,
                peer = %victim.remote_id().fmt_short(),
                "evicting a direct connection at the ceiling"
            );
            victim.close(webrtc::close_code::EVICTED.into(), b"evicted at capacity");
        }
        for (peer, hub) in self.sessions {
            tracing::info!(
                target: crate::transport::LOG_TARGET,
                peer = %peer.fmt_short(),
                "evicting a session at the ceiling"
            );
            let _ = hub.detach(&peer);
        }
    }
}
