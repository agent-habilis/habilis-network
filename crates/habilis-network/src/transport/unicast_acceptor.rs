//! The accept side of the unicast plane: the `ProtocolHandler` the Router runs
//! for `UNICAST_ALPN`. It reads one serialized `Message` per bidirectional
//! stream and forwards the raw bytes to the event loop over a bounded channel —
//! doing **no** validation itself, so the shared `gossip::ingest` path stays the
//! single authority on signature, mesh-gate, and dedup.
//!
//! A frame takes two steps, so that a frame that the sender gave up on is never taken. The sender
//! writes the length and the frame and does not finish. The receiver takes a place in its inbox and
//! writes [`HELD`]. The sender then commits by finishing its side, and only then does the receiver
//! hand the frame to its loop and end its side, which is the acknowledgement. A stream that is
//! reset, or a connection that ends, before the commit gives no frame. The phase is the phase of
//! the sender: an error before its commit is "not delivered", and after it "not confirmed".

use std::time::Duration;

use bytes::Bytes;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::transport::ceiling::EXTRA_IDLE;
use crate::util::consts::MAX_MESSAGE_SIZE;
use crate::util::tuning::DIRECT_IDLE_BACKSTOP;

use super::acknowledgement::Acknowledgement;
use super::admission::SignalAdmission;
use super::payload_path::{self, PROBE_DEADLINE, refuse_unless_direct};
use super::webrtc::close_code::{IDLE, UNICAST_RELAY_REFUSED};
use super::{LOG_TARGET, PayloadPath};

use n0_future::time as n0future_time;
/// Per-frame read cap: one wire message plus gossip's envelope headroom (the
/// same slack the size assertion reserves). Bounds allocation against a peer
/// that opens a stream and never stops writing.
const MAX_UNICAST_FRAME: usize = MAX_MESSAGE_SIZE + 256;

/// The code that resets the acknowledgement side of a stream whose frame the receiver did not
/// hold: the inbox is full, or the frame is too long. It is sent only before [`HELD`].
pub(crate) const NOT_TAKEN: u8 = 1;

/// The code with which a sender resets the stream of a frame that it did not commit.
pub(crate) const UNCOMMITTED: u8 = 2;

/// The code with which a receiver resets its side of a stream that it let go without a verdict: its
/// task was cancelled, or it ended early.
pub(crate) const DROPPED: u8 = 3;

/// The byte with which the receiver says that it holds the frame, and a place in its inbox for it.
/// After it, the sender can commit.
pub(crate) const HELD: u8 = 1;

/// How many frames of one connection the receiver holds at once. The loop of the connection takes
/// no new stream while it holds this many, which is back pressure by a rule and not by a timer. A
/// held frame is up to [`MAX_UNICAST_FRAME`] bytes, so the memory of one connection is at most
/// this number times that, and it takes this many places of the inbox. A sender that waits for
/// each frame to be delivered holds one at a time. The idle timeout ends a connection whose held
/// frames never commit: `SEND_ANSWER_TIMEOUT` (18 s) bounds the wait of a correct sender for the
/// commit, and the idle timeout (15 min) is far above it. A peer that sends frames and never commits
/// holds these places for the idle timeout at most, and no other frame of that connection takes
/// them.
const MAX_HELD_FRAMES: usize = 16;

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
    admission: Option<SignalAdmission>,
}

impl UnicastAcceptor {
    /// Report the streams of this acceptor to `admission`.
    pub(crate) fn admission(mut self, admission: SignalAdmission) -> Self {
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

/// The receiver's half of one frame, up to the commit. It reads the length and the frame, asks
/// `reserve` for a place for it, says [`HELD`], and waits for the commit. It gives the frame and the
/// place after the commit, and nothing on any fault: a reset of the sender, a lost connection, or
/// bytes after the frame. A frame that is too long, or a full inbox, is reset with [`NOT_TAKEN`]
/// before `HELD`.
async fn receive<Place>(
    acknowledgement: &mut Acknowledgement,
    recv: &mut RecvStream,
    reserve: impl FnOnce() -> Option<Place>,
) -> Option<(Vec<u8>, Place)> {
    let mut prefix = [0u8; 4];
    recv.read_exact(&mut prefix).await.ok()?;
    let length = usize::try_from(u32::from_be_bytes(prefix)).unwrap_or(usize::MAX);
    if length > MAX_UNICAST_FRAME {
        tracing::debug!(target: LOG_TARGET, length, "unicast frame too long; refused");
        acknowledgement.refuse();
        return None;
    }
    let mut frame = vec![0u8; length];
    recv.read_exact(&mut frame).await.ok()?;
    let Some(place) = reserve() else {
        tracing::debug!(target: LOG_TARGET, "unicast inbox full or closed; frame refused");
        acknowledgement.refuse();
        return None;
    };
    acknowledgement.hold().await.ok()?;
    // The commit is the end of the stream with no byte after the frame.
    if let Err(error) = recv.read_to_end(0).await {
        tracing::debug!(target: LOG_TARGET, %error, "unicast frame not committed; dropped");
        return None;
    }
    Some((frame, place))
}

/// [`receive`] for a test peer that always has room: the frame after the commit, with the end of
/// the stream sent.
#[cfg(test)]
pub(crate) async fn receive_for_test(
    acknowledgement: SendStream,
    mut recv: RecvStream,
) -> Option<Vec<u8>> {
    let mut acknowledgement = Acknowledgement::new(acknowledgement);
    let (frame, ()) = receive(&mut acknowledgement, &mut recv, || Some(())).await?;
    acknowledgement.deliver();
    Some(frame)
}

impl UnicastAcceptor {
    /// One accepted stream: take a place, hold the frame, wait for the commit, and hand the frame to
    /// the loop. The end of the stream is the acknowledgement, and only a frame that the loop took gets it.
    async fn take_frame(
        tx: mpsc::Sender<UnicastFrame>,
        from: iroh::EndpointId,
        acknowledgement: SendStream,
        mut recv: RecvStream,
    ) {
        let mut acknowledgement = Acknowledgement::new(acknowledgement);
        // The place is reserved before `HELD`, so a full inbox is known before the commit and the
        // hand-over after it cannot fail.
        let reserve = || tx.try_reserve_owned().ok();
        let Some((frame, place)) = receive(&mut acknowledgement, &mut recv, reserve).await else {
            return;
        };
        // At the shutdown of the node the loop can be gone, and the place then gives the frame to
        // nobody: the sender hears "delivered" for a frame that no loop takes. It is a race at the
        // end of the node, and the frame was not durable before it either.
        place.send(UnicastFrame {
            from,
            bytes: Bytes::from(frame),
        });
        tracing::debug!(target: LOG_TARGET, "unicast frame accepted");
        acknowledgement.deliver();
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
            payload_path::log_accept_refused(
                "unicast",
                self.admission.as_ref().and_then(SignalAdmission::local),
                &connection,
            );
            return Ok(());
        }
        // Each accepted bidirectional stream carries exactly one frame, and its two steps go back
        // and forth on the same stream. The loop works on [`MAX_HELD_FRAMES`] streams at once and
        // takes no new one beyond that. It ends when the peer closes the connection (`accept_bi`
        // errors), or when nothing arrives for the idle timeout: a held frame is no traffic, so a
        // peer that opens streams and never commits is ended by the same rule. Two frames of one
        // sender reach the loop in the order of their commits; a sender that waits for the end of
        // a frame before the next keeps its order.
        let mut streams: JoinSet<()> = JoinSet::new();
        loop {
            while streams.try_join_next().is_some() {}
            let idle = self.idle_for(connection.remote_id());
            if streams.len() >= MAX_HELD_FRAMES {
                if n0future_time::timeout(idle, streams.join_next())
                    .await
                    .is_err()
                {
                    tracing::debug!(target: LOG_TARGET, "closing an idle accepted unicast connection");
                    connection.close(IDLE.into(), b"idle");
                    break;
                }
                continue;
            }
            match n0future_time::timeout(idle, connection.accept_bi()).await {
                Ok(Ok((acknowledgement, recv))) => {
                    let remote = connection.remote_id();
                    let busy = self.admission.as_ref().map(|table| table.busy(remote));
                    let tx = self.tx.clone();
                    streams.spawn(async move {
                        let _busy = busy;
                        Self::take_frame(tx, remote, acknowledgement, recv).await;
                    });
                }
                Ok(Err(_closed)) => break,
                Err(_idle) => {
                    tracing::debug!(target: LOG_TARGET, "closing an idle accepted unicast connection");
                    connection.close(IDLE.into(), b"idle");
                    break;
                }
            }
        }
        // A frame that committed before the connection ended still reaches the loop.
        while streams.join_next().await.is_some() {}
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::time::Duration;

    use iroh::endpoint::{Connection, ConnectionError, RecvStream, SendStream};
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};

    use super::super::UNICAST_ALPN;
    use super::super::admission::SignalAdmission;
    use super::super::pool::SEND_ANSWER_TIMEOUT;
    use super::{
        DIRECT_IDLE_BACKSTOP, EXTRA_IDLE, HELD, IDLE, MAX_HELD_FRAMES, PayloadPath, UNCOMMITTED,
        UnicastAcceptor, UnicastFrame, mpsc,
    };
    use crate::transport::{SendVerdict, UnicastPool};
    use crate::{lookup, testing};
    use iroh::endpoint::presets;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;
    use tokio::sync::Notify;
    use tokio::{task, time, time as tokio_time};

    /// A reply of 16 shards is the largest burst of frames to one peer.
    const BURST: usize = 16;
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

    /// Send one frame on the wire of this module, by hand: the length and the frame, then `HELD`,
    /// the commit, and the end. It says whether the end came.
    async fn send_by_hand(connection: &Connection, bytes: &[u8]) -> bool {
        let (mut stream, mut held) = connection.open_bi().await.expect("open a stream");
        let length = u32::try_from(bytes.len()).expect("a short frame");
        stream
            .write_all(&length.to_be_bytes())
            .await
            .expect("write the length");
        stream.write_all(bytes).await.expect("write the frame");
        let mut byte = [0u8; 1];
        if held.read_exact(&mut byte).await.is_err() {
            return false;
        }
        stream.finish().expect("commit");
        held.read_to_end(0).await.is_ok()
    }

    /// A frame by hand, up to `HELD`: the length and the frame, and the byte of the receiver. The
    /// stream is not committed. `None` if the receiver did not say `HELD`.
    async fn hold_by_hand(
        connection: &Connection,
        bytes: &[u8],
    ) -> Option<(SendStream, RecvStream)> {
        let (mut stream, mut held) = connection.open_bi().await.expect("open a stream");
        let length = u32::try_from(bytes.len()).expect("a short frame");
        stream.write_all(&length.to_be_bytes()).await.ok()?;
        stream.write_all(bytes).await.ok()?;
        let mut byte = [0u8; 1];
        held.read_exact(&mut byte).await.ok()?;
        (byte[0] == HELD).then_some((stream, held))
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
            let _sending = {
                let connection = connection.clone();
                task::spawn(async move { send_by_hand(&connection, b"frame").await })
            };
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

    /// **A receiver that is cancelled after it said `HELD` never acknowledges.** A stream that is
    /// dropped finishes by itself, and the finish of the side of the receiver is the
    /// acknowledgement: a task that was cancelled, or that returned early, then told the sender that
    /// the frame was delivered. The side of the receiver is reset unless the frame went to the loop.
    #[test]
    fn a_receiver_that_is_cancelled_after_held_never_acknowledges_the_frame() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            /// Takes a frame as the acceptor does, and cancels it while it waits for the commit.
            #[derive(Debug, Clone)]
            struct CancelWhileHeld(mpsc::Sender<UnicastFrame>);
            impl ProtocolHandler for CancelWhileHeld {
                async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                    let (acknowledgement, recv) = connection
                        .accept_bi()
                        .await
                        .map_err(AcceptError::from_err)?;
                    let taking = UnicastAcceptor::take_frame(
                        self.0.clone(),
                        connection.remote_id(),
                        acknowledgement,
                        recv,
                    );
                    let _ = time::timeout(Duration::from_millis(300), taking).await;
                    connection.closed().await;
                    Ok(())
                }
            }
            let (tx, mut frames) = mpsc::channel(8);
            let (connection, router, client) = connected_to(CancelWhileHeld(tx)).await;
            let (mut stream, mut held) = connection.open_bi().await.expect("open a stream");
            stream.write_all(&5u32.to_be_bytes()).await.expect("length");
            stream.write_all(b"frame").await.expect("frame");
            let mut byte = [0u8; 1];
            held.read_exact(&mut byte)
                .await
                .expect("the receiver holds the frame");

            // The sender does not commit. The receiver is cancelled after 300 ms.
            let end = time::timeout(Duration::from_secs(5), held.read_to_end(0))
                .await
                .expect("the cancelled receiver ends its side");

            assert!(
                end.is_err(),
                "the receiver was cancelled and its side finished: the sender reads a success"
            );
            assert_eq!(
                frames_taken(&mut frames).await,
                0,
                "no frame reached the loop"
            );
            drop(stream);
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// **A frame whose send ended with an error never reaches the loop of the peer.** The peer is
    /// there but reads nothing for longer than the send timeout, as a stopped process does: it
    /// never says `HELD`, so the sender never commits, and the send ends "not delivered". The peer
    /// then starts to read: the frame is in its buffers, and it must not take it.
    #[test]
    fn a_frame_whose_send_timed_out_never_reaches_the_loop_of_a_peer_that_reads_late() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, peer, router, client, start, mut frames) = late_peer().await;

            let (verdict, _waited) = send_on_the_paused_clock(&pool, peer).await;
            start.notify_one();
            let taken = frames_taken(&mut frames).await;

            assert!(
                matches!(SendVerdict::of(verdict), SendVerdict::NotDelivered(_)),
                "the peer never held the frame: the sender did not commit, so the verdict is certain"
            );
            assert_eq!(
                taken, 0,
                "the send answered an error, and the peer took the frame later"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// A late peer: a server that starts its acceptor only when `start` is notified, a pool
    /// connected to it, and the frames that it takes.
    async fn late_peer() -> (
        UnicastPool,
        iroh::EndpointId,
        Router,
        iroh::Endpoint,
        // Shared by the test, which starts the peer late, and the handler that waits for it.
        Arc<Notify>,
        mpsc::Receiver<UnicastFrame>,
    ) {
        let (tx, frames) = mpsc::channel(8);
        // Shared by the test, which starts the peer late, and the handler.
        let start = Arc::new(Notify::new());
        let handler = LateStart {
            inner: UnicastAcceptor::new(tx, PayloadPath::RelayAllowed),
            start: Arc::clone(&start),
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
        pool.warm_or_dial(server.id())
            .await
            .expect("a warm connection");
        (pool, server.id(), router, client, start, frames)
    }

    /// Send one frame on a paused clock, and how long the send took on that clock. The open of the
    /// stream and the write of the frame need no network, so the clock jumps only to a timer of the
    /// send when the send waits for its peer. The peer here starts never.
    async fn send_on_the_paused_clock(
        pool: &UnicastPool,
        peer: iroh::EndpointId,
    ) -> (anyhow::Result<()>, Duration) {
        tokio_time::pause();
        let started = tokio_time::Instant::now();
        let verdict = pool
            .dial_or_warm_send(peer, bytes::Bytes::from_static(b"frame"))
            .await;
        (verdict, started.elapsed())
    }

    /// **A send that starts in a failover hole is delivered when the peer holds the frame.** The
    /// path of the hop is dead, and the transport under it needs about 5 s to move to another path,
    /// and up to its path idle timeout (15 s) when nothing tells it that the path is dead. The send
    /// starts at once and the peer holds the frame 4 s later, 1 s past the old wait of 3 s. The wait of
    /// a send for the peer is not shorter than the transport needs, so the frame is delivered once.
    /// The clock is the real one: a paused clock jumps to the next timer while a packet is still on
    /// its way, and on a loaded host it would reach the end of the wait before the peer answers.
    #[test]
    fn a_frame_that_the_peer_holds_after_a_failover_hole_is_delivered_once() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, peer, router, client, start, mut frames) = late_peer().await;

            let send = pool.dial_or_warm_send(peer, bytes::Bytes::from_static(b"frame"));
            let hole = async {
                time::sleep(Duration::from_secs(4)).await;
                start.notify_one();
            };
            let (verdict, ()) = tokio::join!(send, hole);
            let taken = frames_taken(&mut frames).await;

            assert!(
                matches!(SendVerdict::of(verdict), SendVerdict::Delivered),
                "the peer held the frame 4 s after the send started, inside the wait of a send"
            );
            assert_eq!(taken, 1, "the frame arrives once");
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// **A send to a peer that never holds the frame answers "not delivered" after the wait of a
    /// send, and not before, and not never.** It is the cost of a wait that is as long as the
    /// failover of the path: a peer that is gone answers after the whole wait. The time is the paused
    /// clock.
    #[test]
    fn a_send_to_a_peer_that_never_holds_the_frame_ends_after_the_wait_of_a_send() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, peer, router, client, _start, _frames) = late_peer().await;

            let (verdict, waited) = send_on_the_paused_clock(&pool, peer).await;

            assert!(
                matches!(SendVerdict::of(verdict), SendVerdict::NotDelivered(_)),
                "the peer never held the frame, so the verdict is certain"
            );
            assert!(
                waited >= SEND_ANSWER_TIMEOUT,
                "the send ended after {waited:?}, before the wait of a send"
            );
            assert!(
                waited < SEND_ANSWER_TIMEOUT * 2,
                "the send ended after {waited:?}, long after the wait of a send"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// **A frame that the sender resets after `HELD` never reaches the loop, and its place is free
    /// again.** The sender gave up between `HELD` and the commit. The receiver keeps no frame, and
    /// the inbox, which has one place, takes the next frame.
    #[test]
    fn a_frame_that_the_sender_resets_after_held_never_reaches_the_loop_and_frees_its_place() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (tx, mut frames) = mpsc::channel(1);
            let (connection, router, client) =
                connected_to(UnicastAcceptor::new(tx, PayloadPath::RelayAllowed)).await;

            let (mut stream, _held) = hold_by_hand(&connection, b"gave up")
                .await
                .expect("the receiver holds the frame");
            stream.reset(UNCOMMITTED.into()).expect("reset");
            assert_eq!(frames_taken(&mut frames).await, 0, "no commit, no frame");

            assert!(
                send_by_hand(&connection, b"next").await,
                "the place of the frame that was given up is free again"
            );
            assert_eq!(frames_taken(&mut frames).await, 1, "the next frame arrives");
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// **The receiver holds as many frames as the bound before any of them commits.** With a loop that
    /// handles one stream at a time, the second sender waits for the commit of the first, and a
    /// burst of frames costs one round trip for each. The 17th stream waits until one ends.
    #[test]
    fn the_receiver_holds_as_many_frames_as_the_bound_and_no_more_before_any_commit() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (tx, mut frames) = mpsc::channel(64);
            let (connection, router, client) =
                connected_to(UnicastAcceptor::new(tx, PayloadPath::RelayAllowed)).await;

            assert_eq!(
                MAX_HELD_FRAMES, BURST,
                "the bound holds one burst of shards"
            );
            let mut held = Vec::new();
            for index in 0..BURST {
                let frame = format!("frame {index}");
                let both = time::timeout(
                    Duration::from_secs(5),
                    hold_by_hand(&connection, frame.as_bytes()),
                )
                .await
                .expect("the receiver holds this frame before any commit");
                held.push(both.expect("HELD"));
            }
            let beyond = time::timeout(
                Duration::from_millis(500),
                hold_by_hand(&connection, b"one too many"),
            )
            .await;
            assert!(
                beyond.is_err(),
                "the receiver took a stream beyond the bound before any frame ended"
            );

            for (mut stream, mut end) in held {
                stream.finish().expect("commit");
                end.read_to_end(0).await.expect("the end of the frame");
            }
            assert_eq!(
                frames_taken(&mut frames).await,
                BURST,
                "every committed frame reached the loop"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// **A peer that holds a frame and never commits is ended by the idle rule.** The held frame is
    /// no traffic, so the idle timeout that exists ends the connection, and no frame is taken.
    #[test]
    fn a_peer_that_holds_a_frame_and_never_commits_is_ended_by_the_idle_rule() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (connection, router, client, mut frames) = connected(Duration::from_secs(2)).await;

            let held = hold_by_hand(&connection, b"never committed").await;
            assert!(held.is_some(), "the receiver holds the frame");
            let reason = time::timeout(Duration::from_secs(8), connection.closed())
                .await
                .expect("the idle rule ends the connection");

            assert!(
                matches!(&reason, ConnectionError::ApplicationClosed(close)
                    if close.error_code.into_inner() == u64::from(IDLE)),
                "closed by the idle rule: {reason:?}"
            );
            assert_eq!(frames_taken(&mut frames).await, 0, "no commit, no frame");
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// Takes the first frame into the loop, then closes the connection with no end.
    #[derive(Debug, Clone)]
    struct CloseBeforeTheEnd {
        inner: UnicastAcceptor,
        // Shared by every clone of the handler, one for each connection.
        first: Arc<AtomicBool>,
    }
    impl ProtocolHandler for CloseBeforeTheEnd {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            if !self.first.swap(false, Ordering::SeqCst) {
                return self.inner.accept(connection).await;
            }
            take_and_close(&self.inner, &connection).await
        }
    }
    /// Takes the first frame into the loop, closes the connection with no end, and closes
    /// every later connection at once: the second send cannot even hold a frame.
    #[derive(Debug, Clone)]
    struct CloseBeforeTheEndThenRefuse {
        inner: UnicastAcceptor,
        // Shared by every clone of the handler, one for each connection.
        first: Arc<AtomicBool>,
    }
    impl ProtocolHandler for CloseBeforeTheEndThenRefuse {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            if !self.first.swap(false, Ordering::SeqCst) {
                connection.close(0u32.into(), b"no more frames");
                return Ok(());
            }
            take_and_close(&self.inner, &connection).await
        }
    }
    async fn take_and_close(
        inner: &UnicastAcceptor,
        connection: &Connection,
    ) -> Result<(), AcceptError> {
        let (acknowledgement, mut recv) = connection
            .accept_bi()
            .await
            .map_err(AcceptError::from_err)?;
        let mut acknowledgement = super::Acknowledgement::new(acknowledgement);
        let tx = inner.tx.clone();
        let taken = super::receive(&mut acknowledgement, &mut recv, || {
            tx.try_reserve_owned().ok()
        })
        .await;
        if let Some((frame, place)) = taken {
            place.send(UnicastFrame {
                from: connection.remote_id(),
                bytes: bytes::Bytes::from(frame),
            });
        }
        connection.close(0u32.into(), b"gone before the end");
        Ok(())
    }

    /// A server that runs `handler`, a client with a pool dialed to it, and the server that the pool
    /// knows. The pool reads the relay as a payload path, so no path wait runs.
    async fn pool_served_by<Handler: ProtocolHandler>(
        handler: Handler,
    ) -> (UnicastPool, iroh::Endpoint, Router, iroh::Endpoint) {
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
        (pool, server, router, client)
    }

    /// **A frame that the peer took before the connection ended is not confirmed, and one more send
    /// delivers it.** The peer commits to its loop and closes the connection before it ends its
    /// side. The sender had committed and did not hear the end: "not confirmed". The send that
    /// follows a lost connection carries the same bytes, and the loop of the peer drops a copy by
    /// the dedup key (`mark_seen`, see `a_directed_frame_that_arrives_twice_by_unicast_reaches_the_app_once`).
    #[test]
    fn a_frame_that_the_peer_took_before_the_connection_ended_is_not_confirmed_and_one_more_send_delivers_it()
     {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (tx, mut frames) = mpsc::channel(8);
            let handler = CloseBeforeTheEnd {
                inner: UnicastAcceptor::new(tx, PayloadPath::RelayAllowed),
                // Shared by every clone of the handler, one for each connection.
                first: Arc::new(AtomicBool::new(true)),
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
            pool.warm_or_dial(server.id())
                .await
                .expect("a warm connection");

            let first = pool
                .send_without_redial(server.id(), bytes::Bytes::from_static(b"frame"))
                .await;
            assert!(
                matches!(SendVerdict::of(first), SendVerdict::Unconfirmed(_)),
                "the sender committed and did not hear the end"
            );

            let second = pool
                .dial_or_warm_send(server.id(), bytes::Bytes::from_static(b"frame"))
                .await;
            assert!(
                second.is_ok(),
                "one more send delivers the frame: {second:?}"
            );
            assert_eq!(
                frames_taken(&mut frames).await,
                2,
                "the loop got the frame from the first send and from the second: it drops one copy by the dedup key"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// **A send that failed after its commit is "not confirmed" whatever the second send says.** The
    /// peer takes the frame and closes the connection. The send goes once more, and the second send
    /// cannot even hold a frame: its own fault is certain, but the first frame can be in the loop of
    /// the peer. The result of the whole send must not claim "not delivered".
    #[test]
    fn a_send_whose_first_frame_was_committed_is_not_confirmed_when_the_second_send_fails() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (tx, mut frames) = mpsc::channel(8);
            let handler = CloseBeforeTheEndThenRefuse {
                inner: UnicastAcceptor::new(tx, PayloadPath::RelayAllowed),
                // Shared by every clone of the handler, one for each connection.
                first: Arc::new(AtomicBool::new(true)),
            };
            let (pool, server, router, client) = pool_served_by(handler).await;
            pool.warm_or_dial(server.id())
                .await
                .expect("a warm connection");

            let verdict = pool
                .dial_or_warm_send(server.id(), bytes::Bytes::from_static(b"frame"))
                .await;

            assert!(
                matches!(SendVerdict::of(verdict), SendVerdict::Unconfirmed(_)),
                "the first frame was committed and the peer can have it: the verdict cannot be certain"
            );
            assert_eq!(frames_taken(&mut frames).await, 1, "the peer did take it");
            router.shutdown().await.expect("shutdown");
            client.close().await;
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
                matches!(SendVerdict::of(verdict), SendVerdict::NotDelivered(_)),
                "the send answered ok, or not confirmed, for a frame that the peer never held"
            );
            // The inbox has room again: the frame that was refused does not come after all.
            while frames.try_recv().is_ok() {}
            assert_eq!(
                frames_taken(&mut frames).await,
                0,
                "a refused frame arrived later"
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
