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
    GOSSIP_RELAY_REFUSED_CODE, PROBE_DEADLINE, log_accept_refused, refuse_unless_direct,
    selected_is_direct,
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
    /// This node's own id, for the log line of a refusal.
    local: Option<iroh::EndpointId>,
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
            local: None,
        }
    }

    /// Name the node that this acceptor serves, for the log.
    pub(crate) fn local(mut self, local: iroh::EndpointId) -> Self {
        self.local = Some(local);
        self
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
            log_accept_refused("gossip", self.local, &connection);
            return Ok(());
        }
        if !self.relay_transport.relay_allowed() {
            let refused_sink = self
                .session_gate
                .as_ref()
                .and_then(|(_, admission, _)| admission.relay_refused_sink());
            watch_relay_policy_and_refusal(&connection, None, refused_sink);
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

/// The watch of [`watch_relay_policy_and_refusal`] with no report of a refusal.
#[cfg(test)]
pub(super) fn watch_relay_policy(
    gossip_conn: &Connection,
    path_sink: Option<mpsc::UnboundedSender<super::probe::PathChange>>,
) {
    watch_relay_policy_and_refusal(gossip_conn, path_sink, None);
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
///
/// With a `refused_sink`, the watch also reports a peer's relay-refused close. When the peer ends
/// the link with that code, the pair has no direct path now, and the sink tells the loop. The fact
/// is the same at both ends of the pair, so the end that dialed and the end that accepted both
/// report it. The close comes from `WeakConnectionHandle::closed`, taken while the caller still
/// holds the connection: it gets the close and its reason even when every handle is dropped before
/// the close, so the report does not depend on who drops first, and the future keeps no link
/// alive. A close that is not the peer's own relay-refused close (ours, idle, eviction, shutdown)
/// reports nothing.
pub(super) fn watch_relay_policy_and_refusal(
    gossip_conn: &Connection,
    path_sink: Option<mpsc::UnboundedSender<super::probe::PathChange>>,
    refused_sink: Option<mpsc::UnboundedSender<super::probe::RelayRefused>>,
) {
    use futures_util::StreamExt as _;
    let weak = gossip_conn.weak_handle();
    let mut events = gossip_conn.path_events();
    if let Some(sink) = refused_sink {
        let peer = gossip_conn.remote_id();
        let closed = weak.closed();
        task::spawn(async move {
            if let Some(closed) = closed.await
                && super::probe::is_relay_refusal(&closed.reason)
            {
                let _ = sink.send(super::probe::RelayRefused { peer });
            }
        });
    }
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
    use crate::transport::probe;
    use iroh::endpoint::presets;
    use std::future::{self, Future};
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
                    fn accept(
                        &self,
                        connection: Connection,
                    ) -> impl Future<Output = Result<(), AcceptError>> + Send {
                        super::watch_relay_policy(&connection, None);
                        future::ready(Ok(()))
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

    /// A link that we dialed and that the peer ends with the relay-refused code is reported once,
    /// and a link that the peer ends with another code is not. The watch holds the connection
    /// weakly, so that the caller's handle decides how long the link lives.
    #[test]
    fn a_peer_that_ends_our_link_with_the_relay_refused_code_is_reported_and_no_other_close_is() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::transport::probe::RelayRefused;

                const ALPN: &[u8] = b"habilis-mesh/test-refusal/0";

                #[derive(Debug, Clone)]
                struct CloseWith(u32);
                impl ProtocolHandler for CloseWith {
                    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                        tokio_time::sleep(Duration::from_millis(300)).await;
                        connection.close(self.0.into(), b"test");
                        connection.closed().await;
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
                for (code, reported) in [(super::GOSSIP_RELAY_REFUSED_CODE, true), (5, false)] {
                    let server = bind().await;
                    let router = Router::builder(server.clone())
                        .accept(ALPN, CloseWith(code))
                        .spawn();
                    let client = bind().await;
                    lookup::add_peer_addr(&lookup::address_book(&client), server.addr());
                    let connection = client.connect(server.id(), ALPN).await.expect("connect");
                    let (sink, mut reports) = mpsc::unbounded_channel();
                    super::watch_relay_policy_and_refusal(&connection, None, Some(sink));
                    // The caller holds its handle only inside a read that ends at the close and
                    // then drops it, as the gossip transport does: the report must not depend on
                    // who drops first.
                    tokio::spawn(async move {
                        connection.closed().await;
                        drop(connection);
                    });

                    let report = tokio_time::timeout(Duration::from_secs(3), reports.recv()).await;
                    match (reported, report) {
                        (true, Ok(Some(RelayRefused { peer }))) => assert_eq!(
                            peer,
                            server.id(),
                            "the report names the peer that ended the link"
                        ),
                        // The watch ended and dropped its sink with nothing sent.
                        (false, Ok(None) | Err(_)) => {}
                        (_, other) => {
                            panic!("code {code}: expected reported = {reported}, got {other:?}")
                        }
                    }
                    router.shutdown().await.expect("shutdown");
                    client.close().await;
                }
            },
        );
    }

    /// The end that accepted a gossip link reports the relay-refused close of the peer, as the end
    /// that dialed it does, and reports no other close: the fact that the pair has no direct path
    /// is the same at both ends. In the run of 2026-11-24 the far member accepted a link that its
    /// peer had dialed and closed on the relay path, and it got no report, so it kept that peer as
    /// `Direct`. The cases are the peer's relay-refused code, the peer's other codes, and a close
    /// of our own with the relay-refused code.
    ///
    /// No timer decides a case. The dialer closes after the acceptor says that its watch runs. The
    /// watch owns the only sink, and drops it when the connection is closed, so the end of the
    /// reports is the proof that none was sent.
    #[test]
    fn the_end_that_accepted_a_link_reports_the_relay_refused_close_of_the_peer_and_no_other_close()
    {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use std::sync::{Arc, Mutex};

                use crate::transport::probe::RelayRefused;

                const ALPN: &[u8] = b"habilis-mesh/test-refusal-accepted/0";

                #[derive(Debug, Clone)]
                struct WatchAndHold {
                    // Arc: the router clones the handler, and the sink is taken once, by the first accept.
                    sink: Arc<Mutex<Option<mpsc::UnboundedSender<RelayRefused>>>>,
                    watching: mpsc::UnboundedSender<()>,
                    close_here: Option<u32>,
                }
                impl ProtocolHandler for WatchAndHold {
                    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                        let sink = self.sink.lock().expect("sink lock").take();
                        super::watch_relay_policy_and_refusal(&connection, None, sink);
                        let _ = self.watching.send(());
                        if let Some(code) = self.close_here {
                            connection.close(code.into(), b"test");
                        }
                        connection.closed().await;
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
                let refused = super::GOSSIP_RELAY_REFUSED_CODE;
                // (code the dialer closes with, code the acceptor closes with, reported)
                let cases = [
                    (Some(refused), None, true),
                    (Some(0), None, false),
                    (Some(5), None, false),
                    (None, Some(refused), false),
                ];
                for (dialer_code, acceptor_code, reported) in cases {
                    let (sink, mut reports) = mpsc::unbounded_channel();
                    let (watching, mut watching_rx) = mpsc::unbounded_channel();
                    let server = bind().await;
                    let router = Router::builder(server.clone())
                        .accept(
                            ALPN,
                            WatchAndHold {
                                // Arc: see the field; the one sink is shared by the clones of the handler.
                                sink: Arc::new(Mutex::new(Some(sink))),
                                watching,
                                close_here: acceptor_code,
                            },
                        )
                        .spawn();
                    let client = bind().await;
                    lookup::add_peer_addr(&lookup::address_book(&client), server.addr());
                    let connection = client.connect(server.id(), ALPN).await.expect("connect");
                    // The watch runs on the acceptor before the dialer closes.
                    watching_rx
                        .recv()
                        .await
                        .expect("the acceptor watches the link");
                    if let Some(code) = dialer_code {
                        connection.close(code.into(), b"test");
                    }
                    // The bound is a fail-safe for a hung test: a report or the end of the reports
                    // comes as soon as the close is read.
                    let report = tokio_time::timeout(Duration::from_secs(30), reports.recv())
                        .await
                        .expect("the watch ends when the link is closed");
                    match (reported, report) {
                        (true, Some(RelayRefused { peer })) => assert_eq!(
                            peer,
                            client.id(),
                            "the report names the peer that ended the link"
                        ),
                        (false, None) => {}
                        (_, other) => panic!(
                            "dialer {dialer_code:?}, acceptor {acceptor_code:?}: expected \
                             reported = {reported}, got {other:?}"
                        ),
                    }
                    router.shutdown().await.expect("shutdown");
                    client.close().await;
                }
            },
        );
    }

    /// The contract that the report of a refusal rests on, pinned so that a later bump of iroh
    /// cannot break it without a failing test: a future taken from `weak.closed()` while a strong
    /// handle exists gets the close and its reason after the caller dropped its last handle. (In
    /// this iroh the endpoint still holds the closed connection then, so `weak.upgrade()` still
    /// gives a connection: the report does not depend on that, and a read through an upgrade
    /// would depend on it.)
    #[test]
    fn a_weak_close_future_keeps_the_reason_after_the_last_handle_is_dropped() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                const ALPN: &[u8] = b"habilis-mesh/test-weak-closed/0";

                #[derive(Debug, Clone)]
                struct CloseRefused;
                impl ProtocolHandler for CloseRefused {
                    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                        tokio_time::sleep(Duration::from_millis(300)).await;
                        connection.close(super::GOSSIP_RELAY_REFUSED_CODE.into(), b"test");
                        connection.closed().await;
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
                    .accept(ALPN, CloseRefused)
                    .spawn();
                let client = bind().await;
                lookup::add_peer_addr(&lookup::address_book(&client), server.addr());
                let connection = client.connect(server.id(), ALPN).await.expect("connect");

                let weak = connection.weak_handle();
                let closed = weak.closed();
                connection.closed().await;
                drop(connection);

                let closed = closed
                    .await
                    .expect("the future was taken with a strong handle, so it gets the close");
                assert!(
                    probe::is_relay_refusal(&closed.reason),
                    "the reason of the peer's close is kept: {:?}",
                    closed.reason
                );
                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    /// The reporting watch, as the plain one, keeps no link open that gossip has dropped.
    #[test]
    fn the_refusal_watcher_does_not_keep_a_connection_alive() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                const ALPN: &[u8] = b"habilis-mesh/test-refusal-watch/0";

                #[derive(Debug, Clone)]
                struct WatchAndDrop;
                impl ProtocolHandler for WatchAndDrop {
                    fn accept(
                        &self,
                        connection: Connection,
                    ) -> impl Future<Output = Result<(), AcceptError>> + Send {
                        let (sink, _reports) = mpsc::unbounded_channel();
                        super::watch_relay_policy_and_refusal(&connection, None, Some(sink));
                        future::ready(Ok(()))
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
