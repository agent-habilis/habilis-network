//! The gossip accept gate: on a mesh whose relay is lookup only, an inbound
//! `GOSSIP_ALPN` connection is handed to iroh-gossip only once iroh has
//! selected a direct path on it. Nothing is read from the connection while
//! it is held, so no gossip frame — membership or payload — crosses the
//! relay. The rendezvous link is gated like every other: it starts on the
//! relay by construction and punches a direct path inside the connection
//! like any peer link. iroh-gossip's dialer has no handshake timeout, so the
//! far side simply waits.

use habilis_network_iroh_webrtc_transport::WebRtcHandle;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh_gossip::net::Gossip;

use super::path::{GOSSIP_RELAY_REFUSED_CODE, PROBE_DEADLINE, refuse_unless_direct};

#[derive(Debug, Clone)]
pub(crate) struct DirectOnlyGossip {
    inner: Gossip,
    relay_transport: bool,
    /// Set on a node with no UDP path, whose only direct path to anyone is a
    /// `WebRTC` session. See [`DirectOnlyGossip::accept`]. The third element is
    /// this node's own id: the lower id of a pair offers, and the gate treats
    /// the offerer and the answerer differently.
    session_gate: Option<(WebRtcHandle, super::SignalAdmission, iroh::EndpointId)>,
}

impl DirectOnlyGossip {
    pub(crate) fn new(
        inner: Gossip,
        relay_transport: bool,
        session_gate: Option<(WebRtcHandle, super::SignalAdmission, iroh::EndpointId)>,
    ) -> Self {
        Self {
            inner,
            relay_transport,
            session_gate,
        }
    }
}

impl ProtocolHandler for DirectOnlyGossip {
    /// On a node without UDP, a connection from a peer it holds no session
    /// with is refused at once rather than held. It can only go direct once a
    /// session attaches, and the session's offerer (the lower id) grafts the
    /// pair over it the moment it does. The answerer holds a dial during a
    /// round in flight: the offerer attaches first and may dial before this
    /// side has. The offerer never holds one, because its own graft is the
    /// dial the pair needs. Held, it would be a second connection for the same
    /// pair: iroh-gossip dedups a pair by closing the connection each side
    /// dialed, and the HyParView reply already sent on the closed one is
    /// lost, which leaves the pair half-linked until a heal re-grafts it.
    /// This connection is typically the far side's `ForwardJoin` dial, sent
    /// through the rendezvous before any session exists.
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        if !self.relay_transport
            && let Some((webrtc, admission, local)) = &self.session_gate
            && refuse_before_session(
                webrtc.has_session(&remote),
                admission.negotiating(remote),
                *local < remote,
            )
        {
            tracing::debug!(target: super::LOG_TARGET, remote = %conn.remote_id(), "gossip dial before its webrtc session refused");
            conn.close(GOSSIP_RELAY_REFUSED_CODE.into(), b"no webrtc session yet");
            return Ok(());
        }
        if !refuse_unless_direct(
            &conn,
            self.relay_transport,
            PROBE_DEADLINE,
            GOSSIP_RELAY_REFUSED_CODE,
        )
        .await
        {
            return Ok(());
        }
        self.inner
            .handle_connection(conn)
            .await
            .map_err(AcceptError::from_err)
    }

    async fn shutdown(&self) {
        if let Err(error) = self.inner.shutdown().await {
            tracing::warn!(target: super::LOG_TARGET, %error, "error while shutting down gossip");
        }
    }
}

/// Whether the gate refuses a gossip dial at once rather than holding it,
/// from what this node knows about the dialer's `WebRTC` session.
fn refuse_before_session(has_session: bool, negotiating: bool, we_offer: bool) -> bool {
    !has_session && (we_offer || !negotiating)
}

#[cfg(test)]
mod tests {
    use super::refuse_before_session;

    // The offerer attaches one DTLS trip before the answerer does, and grafts
    // the moment it attaches, so its dial can reach the answerer mid-round.
    #[test]
    fn a_dial_during_the_round_is_held_not_refused() {
        assert!(
            refuse_before_session(false, false, false),
            "no session, no round"
        );
        assert!(
            !refuse_before_session(false, true, false),
            "the round is finishing"
        );
        assert!(
            !refuse_before_session(true, false, false),
            "the session is up"
        );
    }

    // The offerer grafts the pair itself the moment its session attaches, so
    // a dial from the answerer before then is the answerer's own `ForwardJoin`
    // dial. Held, it outlives the graft, and the dedup that follows loses the
    // answerer's HyParView reply.
    #[test]
    fn the_offerer_refuses_a_dial_before_its_session() {
        assert!(
            refuse_before_session(false, true, true),
            "mid-round, as the offerer"
        );
        assert!(
            refuse_before_session(false, false, true),
            "no round, as the offerer"
        );
        assert!(
            !refuse_before_session(true, false, true),
            "the session is up"
        );
    }
}
