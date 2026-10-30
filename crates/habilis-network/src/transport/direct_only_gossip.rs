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
use n0_future::time::Instant;

use super::PayloadPath;
use super::payload_path::{
    GOSSIP_RELAY_REFUSED_CODE, PROBE_DEADLINE, refuse_unless_direct, selected_is_direct,
};

use n0_future::{task, time as n0future_time};
use std::future;
use tokio::sync::mpsc;
#[derive(Debug, Clone)]
pub(crate) struct DirectOnlyGossip {
    inner: Gossip,
    relay_transport: PayloadPath,
    /// Set on a node with no UDP path, whose only direct path to anyone is a
    /// `WebRTC` session. See [`DirectOnlyGossip::accept`]. The third element is
    /// this node's own id: the lower id of a pair offers, and the gate treats
    /// the offerer and the answerer differently.
    session_gate: Option<(WebRtcHandle, super::SignalAdmission, iroh::EndpointId)>,
}

impl DirectOnlyGossip {
    pub(crate) fn new(
        inner: Gossip,
        relay_transport: PayloadPath,
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
    /// dialed, and the `HyParView` reply already sent on the closed one is
    /// lost, which leaves the pair half-linked until a heal re-grafts it.
    /// This connection is typically the far side's `ForwardJoin` dial, sent
    /// through the rendezvous before any session exists.
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        if !self.relay_transport.relay_allowed()
            && let Some((webrtc, admission, local)) = &self.session_gate
            && refuse_before_session(
                webrtc.has_session(&remote),
                admission.negotiating(remote),
                *local < remote,
            )
        {
            tracing::debug!(target: super::LOG_TARGET, remote = %connection.remote_id(), "gossip dial before its webrtc session refused");
            connection.close(GOSSIP_RELAY_REFUSED_CODE.into(), b"no webrtc session yet");
            return Ok(());
        }
        if !refuse_unless_direct(
            &connection,
            self.relay_transport,
            PROBE_DEADLINE,
            GOSSIP_RELAY_REFUSED_CODE,
        )
        .await
        {
            return Ok(());
        }
        if !self.relay_transport.relay_allowed() {
            watch_relay_policy(&connection, None);
        }
        self.inner
            .handle_connection(connection)
            .await
            .map_err(AcceptError::from_err)
    }

    async fn shutdown(&self) {
        if let Err(error) = self.inner.shutdown().await {
            tracing::warn!(target: super::LOG_TARGET, %error, "error while shutting down gossip");
        }
    }
}

/// Keep the relay policy on a gossip connection, whichever end dialed it: one whose selected
/// path has been the relay for longer than [`PROBE_DEADLINE`], the wait of the accept gate, is closed with
/// [`GOSSIP_RELAY_REFUSED_CODE`], on a mesh whose relay is lookup only.
///
/// The accept gate checks the path once, at the start. A path that is lost
/// later (a session detached, a NAT mapping gone) leaves a link that is still
/// up on the relay, and nothing then says that no payload may ride it. The
/// close gives both ends a `NeighborDown`, and the heal or the come-back rule
/// of each end decides whether to link again. The wait restarts at every
/// return to a direct path, so a path that flaps is left alone.
///
/// The links to the rendezvous are closed too, and each costs a `NeighborDown`:
/// the rendezvous has no path watcher, and a session to it is offered only while
/// the node is not linked to it (`negotiate_rendezvous_session`), so the session
/// comes after this close, whatever the deadline. A wait of 60 s gave the same
/// two downs, later. Only the host and a node with fewer than the release count
/// of links hold that link, so the cost is one re-graft each.
///
/// Holds the connection weakly: the watcher must not keep a link open that
/// gossip has dropped.
pub(super) fn watch_relay_policy(
    gossip_conn: &Connection,
    path_sink: Option<mpsc::UnboundedSender<super::probe::PathChange>>,
) {
    use futures_util::StreamExt as _;
    let weak = gossip_conn.weak_handle();
    let mut events = gossip_conn.path_events();
    task::spawn(async move {
        let mut on_relay_since: Option<Instant> = None;
        loop {
            let Some(connection) = weak.upgrade() else {
                return;
            };
            if connection.close_reason().is_some() {
                return;
            }
            if selected_is_direct(&connection) {
                on_relay_since = None;
            } else {
                if on_relay_since.is_none()
                    && let Some(sink) = &path_sink
                {
                    let _ = sink.send(super::probe::PathChange {
                        peer: connection.remote_id(),
                        kind: super::probe::PathKind::Relay,
                        conn_id: connection.stable_id(),
                    });
                }
                let since = *on_relay_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= PROBE_DEADLINE {
                    tracing::info!(
                        target: super::LOG_TARGET,
                        remote = %connection.remote_id(),
                        dialed = connection.side().is_client(),
                        "gossip link on the relay path past the deadline: closing it"
                    );
                    connection.close(GOSSIP_RELAY_REFUSED_CODE.into(), b"relay path refused");
                    return;
                }
            }
            let wait = on_relay_since.map(|since| PROBE_DEADLINE.saturating_sub(since.elapsed()));
            drop(connection);
            tokio::select! {
                next = events.next() => {
                    if next.is_none() {
                        return;
                    }
                }
                () = async {
                    match wait {
                        Some(wait) => n0future_time::sleep(wait).await,
                        None => future::pending().await,
                    }
                } => {}
            }
        }
    });
}

/// Whether the gate refuses a gossip dial at once rather than holding it,
/// from what this node knows about the dialer's `WebRTC` session.
fn refuse_before_session(has_session: bool, negotiating: bool, we_offer: bool) -> bool {
    !has_session && (we_offer || !negotiating)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod watcher_tests {
    use std::time::Duration;

    use iroh::endpoint::Connection;
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};

    use crate::lookup;
    #[cfg(feature = "iroh-test-utils")]
    use crate::lookup::test_relay;
    use iroh::endpoint::presets;
    #[cfg(feature = "iroh-test-utils")]
    use tokio::sync::mpsc;
    #[cfg(feature = "iroh-test-utils")]
    use tokio::time;
    use tokio::time as tokio_time;
    /// The watcher must not keep a link open that gossip has dropped. A handler
    /// that starts the watch and returns drops the last strong handle, so the
    /// connection must close, and the dialer sees it close. A watcher that held
    /// the connection, or a path stream that did, would leave it up.
    #[test]
    fn the_relay_watcher_does_not_keep_a_connection_alive() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                const ALPN: &[u8] = b"habilis-mesh/test-watch/0";

                #[derive(Debug, Clone)]
                struct WatchAndDrop;
                impl ProtocolHandler for WatchAndDrop {
                    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                        super::watch_relay_policy(&connection, None);
                        Ok(())
                    }
                }
                let bind = || async {
                    iroh::Endpoint::builder(presets::Minimal)
                        .relay_mode(iroh::RelayMode::Disabled)
                        .bind()
                        .await
                        .expect("bind a loopback endpoint")
                };
                let server = bind().await;
                let router = Router::builder(server.clone())
                    .accept(ALPN, WatchAndDrop)
                    .spawn();
                let client = bind().await;
                lookup::add_peer_addr(&lookup::address_book(&client), server.addr());

                let connection = client.connect(server.id(), ALPN).await.expect("connect");
                let closed =
                    tokio_time::timeout(Duration::from_secs(10), connection.closed()).await;

                assert!(
                    closed.is_ok(),
                    "the connection stayed up after its handler dropped it: the watcher holds it"
                );
                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    /// A watch that starts on a link already off a direct path reports the relay
    /// at once, not after the deadline. The link is relay-only: neither end has an
    /// IP transport.
    #[cfg(feature = "iroh-test-utils")]
    #[test]
    fn a_watch_that_starts_on_a_relay_link_reports_the_relay() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::transport::probe::{PathChange, PathKind};

                const ALPN: &[u8] = b"habilis-mesh/test-watch-relay/0";

                #[derive(Debug, Clone)]
                struct WatchAndHold(mpsc::UnboundedSender<PathChange>);
                impl ProtocolHandler for WatchAndHold {
                    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                        super::watch_relay_policy(&connection, Some(self.0.clone()));
                        connection.closed().await;
                        Ok(())
                    }
                }
                let (relay_url, _relay_server) =
                    test_relay::spawn_plain().await.expect("local relay");
                let bind = || {
                    let relay_url = relay_url.clone();
                    async move {
                        iroh::Endpoint::builder(presets::Minimal)
                            .relay_mode(iroh::RelayMode::custom([relay_url]))
                            .clear_ip_transports()
                            .bind()
                            .await
                            .expect("bind a relay-only endpoint")
                    }
                };
                let (sink, mut reports) = mpsc::unbounded_channel();
                let server = bind().await;
                let router = Router::builder(server.clone())
                    .accept(ALPN, WatchAndHold(sink))
                    .spawn();
                let client = bind().await;

                let relayed =
                    iroh::EndpointAddr::new(server.id()).with_relay_url(relay_url.clone());
                let _conn = client.connect(relayed, ALPN).await.expect("connect");
                let report = time::timeout(Duration::from_secs(5), reports.recv())
                    .await
                    .expect("no report inside 5 s: the watch waits for the deadline")
                    .expect("the sink stays open");

                assert_eq!(
                    report.kind,
                    PathKind::Relay,
                    "the report names the relay path kind"
                );
                assert_eq!(report.peer, client.id(), "the report names the client peer");
                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }
}

#[cfg(test)]
mod tests {

    // The offerer attaches one DTLS trip before the answerer does, and grafts
    // the moment it attaches, so its dial can reach the answerer mid-round.
    #[test]
    fn a_dial_during_the_round_is_held_not_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            super::refuse_before_session(false, false, false),
            "no session, no round"
        );
        assert!(
            !super::refuse_before_session(false, true, false),
            "the round is finishing"
        );
        assert!(
            !super::refuse_before_session(true, false, false),
            "the session is up"
        );
    }

    // The offerer grafts the pair itself the moment its session attaches, so
    // a dial from the answerer before then is the answerer's own `ForwardJoin`
    // dial. Held, it outlives the graft, and the dedup that follows loses the
    // answerer's HyParView reply.
    #[test]
    fn the_offerer_refuses_a_dial_before_its_session() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            super::refuse_before_session(false, true, true),
            "mid-round, as the offerer"
        );
        assert!(
            super::refuse_before_session(false, false, true),
            "no round, as the offerer"
        );
        assert!(
            !super::refuse_before_session(true, false, true),
            "the session is up"
        );
    }
}
