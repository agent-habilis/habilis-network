//! The accept side of the unicast plane: the `ProtocolHandler` the Router runs
//! for `UNICAST_ALPN`. It reads one serialized `Message` per unidirectional
//! stream and forwards the raw bytes to the event loop over a bounded channel —
//! doing **no** validation itself, so the shared `gossip::ingest` path stays the
//! single authority on signature, mesh-gate, and dedup.

use std::time::Duration;

use bytes::Bytes;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::sync::mpsc;

use crate::transport::ceiling::EXTRA_IDLE;
use crate::util::consts::MAX_MESSAGE_SIZE;
use crate::util::tuning::DIRECT_IDLE_BACKSTOP;

use super::payload_path::{PROBE_DEADLINE, refuse_unless_direct};
use super::webrtc::close_code::{IDLE, UNICAST_RELAY_REFUSED};
use super::{LOG_TARGET, PayloadPath};

use n0_future::time as n0future_time;
use std::fmt;
/// Per-frame read cap: one wire message plus gossip's envelope headroom (the
/// same slack the size assertion reserves). Bounds allocation against a peer
/// that opens a stream and never stops writing.
const MAX_UNICAST_FRAME: usize = MAX_MESSAGE_SIZE + 256;

/// The code that resets the acknowledgement side of a stream whose frame the loop did not take.
pub(crate) const NOT_TAKEN: u8 = 1;

/// One frame that a peer sent on a unidirectional stream, and the endpoint of the connection that
/// carried it. The connection is authenticated, so `from` is the peer that opened the stream.
#[derive(Debug, Clone)]
pub(crate) struct UnicastFrame {
    pub(crate) from: iroh::EndpointId,
    pub(crate) bytes: Bytes,
}

#[derive(Debug, Clone)]
pub(crate) struct UnicastAcceptor {
    tx: mpsc::Sender<UnicastFrame>,
    relay_transport: PayloadPath,
    /// How long an accepted connection may carry no new stream before it is
    /// closed. The time counts from the end of the path check, not from the accept. The dialing
    /// pool has the same timeout, so this is the backstop for a dialer that is gone.
    idle: Duration,
    /// The table whose ceiling the accepted connections count against: a stream that is being
    /// read marks its connection busy.
    admission: Option<super::admission::SignalAdmission>,
}

impl UnicastAcceptor {
    /// Report the streams of this acceptor to `admission`.
    pub(crate) fn admission(mut self, admission: super::admission::SignalAdmission) -> Self {
        self.admission = Some(admission);
        self
    }

    pub(crate) fn new(tx: mpsc::Sender<UnicastFrame>, relay_transport: PayloadPath) -> Self {
        Self::with_idle(tx, relay_transport, DIRECT_IDLE_BACKSTOP)
    }

    /// How long `peer` may send nothing before its connection closes. A peer whose connection took
    /// no unit (an extra) goes after [`EXTRA_IDLE`], sooner than the timeout of a direct one.
    fn idle_for(&self, peer: iroh::EndpointId) -> Duration {
        let extra: bool = self
            .admission
            .as_ref()
            .is_some_and(|table| table.is_extra(peer));
        if extra {
            self.idle.min(EXTRA_IDLE)
        } else {
            self.idle
        }
    }

    /// [`Self::new`] with the idle timeout spelled out, for tests that must not
    /// wait the real one.
    pub(crate) fn with_idle(
        tx: mpsc::Sender<UnicastFrame>,
        relay_transport: PayloadPath,
        idle: Duration,
    ) -> Self {
        Self {
            tx,
            relay_transport,
            idle,
            admission: None,
        }
    }
}

impl UnicastAcceptor {
    /// Forward one frame read outcome to the event loop. Split out of
    /// `accept` so the match arms aren't nested inside its `while let`. It says whether the
    /// loop took the frame: only then does the sender get its acknowledgement.
    fn handle_frame<Error: fmt::Display>(
        &self,
        from: iroh::EndpointId,
        result: Result<Vec<u8>, Error>,
    ) -> bool {
        match result {
            Ok(bytes) => {
                // Bounded, non-blocking: a flooding peer can't back-pressure
                // the event loop, and a dropped frame is not repaired until the loss repair lands.
                let frame = UnicastFrame {
                    from,
                    bytes: Bytes::from(bytes),
                };
                if self.tx.try_send(frame).is_err() {
                    tracing::debug!(target: LOG_TARGET, "unicast inbox full or closed; frame dropped");
                    false
                } else {
                    tracing::debug!(target: LOG_TARGET, "unicast frame accepted");
                    true
                }
            }
            Err(error) => {
                tracing::debug!(target: LOG_TARGET, %error, "unicast frame read failed");
                false
            }
        }
    }
}

impl ProtocolHandler for UnicastAcceptor {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // The sender checks its own selected path, but an old build or a
        // hostile peer may not: hold until this side has proof too.
        if !refuse_unless_direct(
            &connection,
            self.relay_transport,
            PROBE_DEADLINE,
            UNICAST_RELAY_REFUSED,
        )
        .await
        {
            return Ok(());
        }
        // Each accepted bidirectional stream carries exactly one message, and the acknowledgement
        // goes back on the same stream; loop until the peer closes the connection (`accept_bi`
        // errors), or nothing arrives for the idle timeout.
        loop {
            let idle = self.idle_for(connection.remote_id());
            match n0future_time::timeout(idle, connection.accept_bi()).await {
                Ok(Ok((mut acknowledgement, mut recv))) => {
                    let admission = self.admission.as_ref();
                    let _busy = admission.map(|table| table.busy(connection.remote_id()));
                    let taken = self.handle_frame(
                        connection.remote_id(),
                        recv.read_to_end(MAX_UNICAST_FRAME).await,
                    );
                    // The end of the stream is the acknowledgement, and only a frame that the loop
                    // took gets one: a reset tells the sender that the frame was not taken.
                    if taken {
                        let _ = acknowledgement.finish();
                    } else {
                        let _ = acknowledgement.reset(NOT_TAKEN.into());
                    }
                }
                Ok(Err(_closed)) => break,
                Err(_idle) => {
                    tracing::debug!(target: LOG_TARGET, "closing an idle accepted unicast connection");
                    connection.close(IDLE.into(), b"idle");
                    break;
                }
            }
        }
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::time::Duration;

    use iroh::endpoint::{Connection, ConnectionError};
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};

    use super::super::UNICAST_ALPN;
    use super::super::admission::SignalAdmission;
    use super::{
        DIRECT_IDLE_BACKSTOP, EXTRA_IDLE, IDLE, PayloadPath, UnicastAcceptor, UnicastFrame, mpsc,
    };
    use crate::transport::UnicastPool;
    use crate::{lookup, testing};
    use iroh::endpoint::presets;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;
    use tokio::sync::Notify;
    use tokio::{task, time, time as tokio_time};
    /// A server accepting unicast with the given idle timeout, and a client
    /// connected to it.
    async fn connected(
        idle: Duration,
    ) -> (
        Connection,
        Router,
        iroh::Endpoint,
        mpsc::Receiver<UnicastFrame>,
    ) {
        let (tx, frames) = mpsc::channel(8);
        let handler = UnicastAcceptor::with_idle(tx, PayloadPath::RelayAllowed, idle);
        let (connection, router, client) = connected_to(handler).await;
        (connection, router, client, frames)
    }

    /// A server that runs `handler` for the unicast ALPN, and a client connected to it.
    async fn connected_to<Handler: ProtocolHandler>(
        handler: Handler,
    ) -> (Connection, Router, iroh::Endpoint) {
        let bind = || async {
            iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .expect("bind a loopback endpoint")
        };
        let server = bind().await;
        let router = Router::builder(server.clone())
            .accept(UNICAST_ALPN, handler)
            .spawn();
        let client = bind().await;
        lookup::add_peer_addr(&lookup::address_book(&client), server.addr());
        let connection = client
            .connect(server.id(), UNICAST_ALPN)
            .await
            .expect("connect");
        (connection, router, client)
    }

    /// A handler that starts the acceptor only when `start` is notified: a loaded machine starts the
    /// accept task late, after the client has connected.
    #[derive(Debug, Clone)]
    struct LateStart {
        inner: UnicastAcceptor,
        // The test holds the other handle and releases the start; the router holds this one.
        start: Arc<Notify>,
    }

    impl ProtocolHandler for LateStart {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            self.start.notified().await;
            self.inner.accept(connection).await
        }
    }

    async fn advance_secs(seconds: u64) {
        for _ in 0..seconds {
            tokio_time::advance(Duration::from_secs(1)).await;
            task::yield_now().await;
        }
    }

    /// Advance the paused clock in steps of 1 s until the close reaches us. The bound of 5 s is
    /// real time, and the steps are paused time. The accept task arms its idle timer only after
    /// its path check, which a loaded machine delays past a fixed advance, so a fixed advance
    /// can end before the timer exists.
    async fn closed_after_advancing(connection: &Connection) -> bool {
        let started = Instant::now();
        while connection.close_reason().is_none() {
            if started.elapsed() > Duration::from_secs(5) {
                return false;
            }
            advance_secs(1).await;
        }
        true
    }

    /// Wait in real time for the close to reach us. The server closes inside the
    /// paused clock, but the close frame travels over real I/O, so a check right
    /// after `advance_secs` races it.
    async fn closed_soon(connection: &Connection) -> bool {
        let started = Instant::now();
        while connection.close_reason().is_none() {
            if started.elapsed() > Duration::from_secs(5) {
                return false;
            }
            task::yield_now().await;
        }
        true
    }

    /// Closed by the server with its idle reason: not by us, not by QUIC.
    fn closed_by_the_acceptor(connection: &Connection) -> bool {
        matches!(
            connection.close_reason(),
            Some(ConnectionError::ApplicationClosed(ref close))
                if close.reason.as_ref() == b"idle"
                    && close.error_code.into_inner() == u64::from(IDLE)
        )
    }

    #[test]
    fn an_accepted_connection_that_gets_no_stream_is_closed_after_the_idle_timeout() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (connection, router, client, _frames) = connected(Duration::from_secs(8)).await;
            tokio_time::pause();

            advance_secs(6).await;
            assert!(
                connection.close_reason().is_none(),
                "inside the idle timeout"
            );

            assert!(closed_after_advancing(&connection).await, "never closed");
            assert!(
                closed_by_the_acceptor(&connection),
                "{:?}",
                connection.close_reason()
            );

            tokio_time::resume();
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// A peer whose connection took no unit (an extra) idles out after the extra idle, a minute,
    /// though the timeout of the acceptor is ten times longer. Any other peer keeps the timeout.
    #[test]
    fn an_extra_idles_out_after_the_extra_idle_and_another_peer_keeps_the_timeout() {
        let _guard = ::habilis_network_test_tracing::init();
        let admission = SignalAdmission::new(1);
        admission.note_success(testing::endpoint_id(7));
        let _busy = admission.busy(testing::endpoint_id(7));
        let extra = testing::endpoint_id(8);
        admission.note_success(extra);
        assert!(admission.is_extra(extra), "no unit was free or evictable");
        let (tx, _frames) = mpsc::channel(8);
        let timeout = Duration::from_mins(10);
        let acceptor =
            UnicastAcceptor::with_idle(tx, PayloadPath::RelayAllowed, timeout).admission(admission);
        assert_eq!(
            acceptor.idle_for(extra),
            EXTRA_IDLE,
            "an extra goes after the extra idle"
        );
        assert_eq!(
            acceptor.idle_for(testing::endpoint_id(7)),
            timeout,
            "a unit keeps the timeout"
        );
    }

    #[test]
    fn an_accept_task_that_starts_late_still_closes_an_idle_connection() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (tx, _frames) = mpsc::channel(8);
            // Shared by the test, which releases the start, and the handler, which the router owns.
            let start = Arc::new(Notify::new());
            let handler = LateStart {
                inner: UnicastAcceptor::with_idle(
                    tx,
                    PayloadPath::RelayAllowed,
                    Duration::from_secs(8),
                ),
                start: Arc::clone(&start),
            };
            let (connection, router, client) = connected_to(handler).await;
            tokio_time::pause();

            advance_secs(12).await;
            start.notify_one();
            assert!(closed_after_advancing(&connection).await, "never closed");

            tokio_time::resume();
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    #[test]
    fn a_stream_restarts_the_accept_side_idle_timeout() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (connection, router, client, mut frames) = connected(Duration::from_secs(8)).await;
            tokio_time::pause();

            advance_secs(5).await;
            let (mut stream, _acknowledgement) = connection.open_bi().await.expect("open a stream");
            stream.write_all(b"frame").await.expect("write");
            stream.finish().expect("finish");
            // Real I/O carries the frame to the acceptor: yield until it lands.
            while frames.try_recv().is_err() {
                task::yield_now().await;
            }

            advance_secs(5).await;
            assert!(
                connection.close_reason().is_none(),
                "five seconds after a stream is inside the timeout"
            );

            advance_secs(7).await;
            assert!(closed_soon(&connection).await, "never closed");
            assert!(
                closed_by_the_acceptor(&connection),
                "{:?}",
                connection.close_reason()
            );

            time::resume();
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// The idle close of an accepted connection is the one backstop of the direct connections.
    #[test]
    fn an_acceptor_closes_an_idle_connection_after_the_one_backstop() {
        let _guard = ::habilis_network_test_tracing::init();
        let (tx, _frames) = mpsc::channel(1);
        assert_eq!(
            UnicastAcceptor::new(tx, PayloadPath::RelayAllowed).idle,
            DIRECT_IDLE_BACKSTOP,
            "an idle acceptor connection is closed after the one backstop"
        );
    }

    /// A handler that runs the acceptor for every connection but the first. It holds the first
    /// one without reading a stream until the test says that the peer evicted it, and then closes it.
    #[derive(Debug, Clone)]
    struct EvictFirst {
        inner: UnicastAcceptor,
        // Shared by every clone of the handler, one for each connection.
        first: Arc<AtomicBool>,
        // Shared by the test, which waits for the eviction, and the handler.
        evict: Arc<Notify>,
    }

    impl ProtocolHandler for EvictFirst {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            if self.first.swap(false, Ordering::SeqCst) {
                self.evict.notified().await;
                connection.close(0u32.into(), b"evicted");
                return Ok(());
            }
            self.inner.accept(connection).await
        }
    }

    /// The frames that the loop got, after the sends ended.
    async fn frames_taken(frames: &mut mpsc::Receiver<UnicastFrame>) -> usize {
        time::sleep(Duration::from_secs(1)).await;
        let mut taken = 0;
        while frames.try_recv().is_ok() {
            taken += 1;
        }
        taken
    }

    /// Send one frame to a peer that evicts the first connection before it reads the stream, and
    /// say how the send ended and how many frames the loop of the peer got. A warm send finds the
    /// connection in the pool; a cold send dials it through a registration, as `deliver` does.
    async fn send_to_a_peer_that_evicts(warm: bool) -> (anyhow::Result<()>, usize) {
        let (tx, mut frames) = mpsc::channel(8);
        // Shared by the test, which waits for the eviction, and the handler.
        let evict = Arc::new(Notify::new());
        let handler = EvictFirst {
            inner: UnicastAcceptor::new(tx, PayloadPath::RelayAllowed),
            // Shared by every clone of the handler, one for each connection.
            first: Arc::new(AtomicBool::new(true)),
            evict: Arc::clone(&evict),
        };
        let bind = || async {
            iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .expect("bind a loopback endpoint")
        };
        let server = bind().await;
        let router = Router::builder(server.clone())
            .accept(UNICAST_ALPN, handler)
            .spawn();
        let client = bind().await;
        lookup::add_peer_addr(&lookup::address_book(&client), server.addr());
        let pool = UnicastPool::new(client.clone(), true);
        if warm {
            pool.warm_or_dial(server.id())
                .await
                .expect("a warm connection");
        }

        let sending = {
            let pool = pool.clone();
            let id = server.id();
            task::spawn(async move {
                let frame = bytes::Bytes::from_static(b"frame");
                if warm {
                    pool.dial_or_warm_send(id, frame).await
                } else {
                    pool.send_registered(pool.register_dial(id), id, frame)
                        .await
                }
            })
        };
        // The frame is written and finished by now, and the peer has read nothing.
        time::sleep(Duration::from_millis(300)).await;
        evict.notify_one();
        // The second send takes its own registration while the first one is still held: it must not
        // wait for the dial of the first.
        let verdict = time::timeout(Duration::from_secs(10), sending)
            .await
            .expect("the send ends: it does not wait on its own dial")
            .expect("the send task");

        let taken = frames_taken(&mut frames).await;
        router.shutdown().await.expect("shutdown");
        client.close().await;
        (verdict, taken)
    }

    /// **A send that answers ok was taken by the loop of the peer.** A frame is written on a warm
    /// connection, and the peer closes the connection (an eviction at its ceiling) before it reads
    /// the stream. The send must not answer ok with no frame at the peer: the connection is lost, the
    /// send goes again on a new connection, and the loop gets the frame exactly 1 time.
    #[test]
    fn a_send_that_answers_ok_was_taken_by_the_loop_of_the_peer_also_when_the_peer_evicts_the_connection()
     {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (verdict, taken) = send_to_a_peer_that_evicts(true).await;
            assert!(
                verdict.is_ok(),
                "the peer is there, so the send on a new connection ends ok: {verdict:?}"
            );
            assert_eq!(
                taken, 1,
                "the send answered ok and the loop of the peer got {taken} frames"
            );
        });
    }

    /// **The same on the cold path**, which every directed send takes at the ceiling: no warm
    /// connection, the send dials through a registration, and the peer evicts the connection that
    /// the dial made. The send goes again through a second registration and the loop gets the frame
    /// exactly 1 time.
    #[test]
    fn a_cold_send_that_answers_ok_was_taken_by_the_loop_of_the_peer_also_when_the_peer_evicts_the_connection()
     {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (verdict, taken) = send_to_a_peer_that_evicts(false).await;
            assert!(
                verdict.is_ok(),
                "the peer is there, so the send on a new connection ends ok: {verdict:?}"
            );
            assert_eq!(
                taken, 1,
                "the send answered ok and the loop of the peer got {taken} frames"
            );
        });
    }

    /// **A frame that the loop did not take is not acknowledged.** The inbox of the peer is full,
    /// so the acceptor drops the frame. The send ends with an error, and never with ok.
    #[test]
    fn a_send_to_a_peer_whose_inbox_is_full_ends_with_an_error() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (tx, mut frames) = mpsc::channel(1);
            tx.try_send(UnicastFrame {
                from: testing::endpoint_id(1),
                bytes: bytes::Bytes::from_static(b"fills the inbox"),
            })
            .expect("fill the inbox");
            let handler = UnicastAcceptor::new(tx, PayloadPath::RelayAllowed);
            let bind = || async {
                iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind a loopback endpoint")
            };
            let server = bind().await;
            let router = Router::builder(server.clone())
                .accept(UNICAST_ALPN, handler)
                .spawn();
            let client = bind().await;
            lookup::add_peer_addr(&lookup::address_book(&client), server.addr());
            let pool = UnicastPool::new(client.clone(), true);
            pool.warm_or_dial(server.id())
                .await
                .expect("a warm connection");

            let verdict = pool
                .dial_or_warm_send(server.id(), bytes::Bytes::from_static(b"frame"))
                .await;

            let taken = frames_taken(&mut frames).await;
            assert_eq!(taken, 1, "only the frame that filled the inbox is in it");
            assert!(
                verdict.is_err(),
                "the send answered ok for a frame that the loop did not take"
            );
            assert!(
                pool.connection(server.id()).is_some(),
                "a peer that said no is there: its connection stays and no second send follows"
            );

            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }
}
