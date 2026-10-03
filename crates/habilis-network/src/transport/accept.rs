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

use crate::util::consts::MAX_MESSAGE_SIZE;
use crate::util::tuning::UNICAST_ACCEPT_IDLE_SECS;

use super::LOG_TARGET;
use super::path::{PROBE_DEADLINE, refuse_unless_direct};
use super::webrtc::close_code::{IDLE, UNICAST_RELAY_REFUSED};

/// Per-frame read cap: one wire message plus gossip's envelope headroom (the
/// same slack the size assertion reserves). Bounds allocation against a peer
/// that opens a stream and never stops writing.
const MAX_UNICAST_FRAME: usize = MAX_MESSAGE_SIZE + 256;

#[derive(Debug, Clone)]
pub(crate) struct UnicastAcceptor {
    tx: mpsc::Sender<Bytes>,
    relay_transport: bool,
    /// How long an accepted connection may carry no new stream before it is
    /// closed. The dialing pool closes its own end after half this time, so the
    /// acceptor's timeout is a backstop for a dialer that is gone.
    idle: Duration,
}

impl UnicastAcceptor {
    pub(crate) fn new(tx: mpsc::Sender<Bytes>, relay_transport: bool) -> Self {
        Self::with_idle(
            tx,
            relay_transport,
            Duration::from_secs(UNICAST_ACCEPT_IDLE_SECS),
        )
    }

    /// [`Self::new`] with the idle timeout spelled out, for tests that must not
    /// wait the real one.
    pub(crate) fn with_idle(
        tx: mpsc::Sender<Bytes>,
        relay_transport: bool,
        idle: Duration,
    ) -> Self {
        Self {
            tx,
            relay_transport,
            idle,
        }
    }
}

impl UnicastAcceptor {
    /// Forward one frame read outcome to the event loop. Split out of
    /// `accept` so the match arms aren't nested inside its `while let`.
    fn handle_frame<Error: std::fmt::Display>(&self, result: Result<Vec<u8>, Error>) {
        match result {
            Ok(bytes) => {
                // Bounded, non-blocking: a flooding peer can't back-pressure
                // the event loop, and a dropped frame heals via anti-entropy.
                if self.tx.try_send(Bytes::from(bytes)).is_err() {
                    tracing::debug!(target: LOG_TARGET, "unicast inbox full or closed; frame dropped");
                } else {
                    tracing::debug!(target: LOG_TARGET, "unicast frame accepted");
                }
            }
            Err(error) => {
                tracing::debug!(target: LOG_TARGET, %error, "unicast frame read failed");
            }
        }
    }
}

impl ProtocolHandler for UnicastAcceptor {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        // The sender checks its own selected path, but an old build or a
        // hostile peer may not: hold until this side has proof too.
        if !refuse_unless_direct(
            &conn,
            self.relay_transport,
            PROBE_DEADLINE,
            UNICAST_RELAY_REFUSED,
        )
        .await
        {
            return Ok(());
        }
        // Each accepted uni-stream carries exactly one message; loop until the
        // peer closes the connection (`accept_uni` errors), or nothing arrives
        // for the idle timeout.
        loop {
            match n0_future::time::timeout(self.idle, conn.accept_uni()).await {
                Ok(Ok(mut recv)) => self.handle_frame(recv.read_to_end(MAX_UNICAST_FRAME).await),
                Ok(Err(_closed)) => break,
                Err(_idle) => {
                    tracing::debug!(target: LOG_TARGET, "closing an idle accepted unicast connection");
                    conn.close(IDLE.into(), b"idle");
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
    use iroh::protocol::Router;

    use super::super::UNICAST_ALPN;
    use super::*;

    /// A server accepting unicast with the given idle timeout, and a client
    /// connected to it.
    async fn connected(
        idle: Duration,
    ) -> (Connection, Router, iroh::Endpoint, mpsc::Receiver<Bytes>) {
        let bind = || async {
            iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .expect("bind a loopback endpoint")
        };
        let (tx, frames) = mpsc::channel(8);
        let server = bind().await;
        let router = Router::builder(server.clone())
            .accept(UNICAST_ALPN, UnicastAcceptor::with_idle(tx, true, idle))
            .spawn();
        let client = bind().await;
        crate::lookup::add_peer_addr(&client, server.addr()).expect("register the server");
        let conn = client
            .connect(server.id(), UNICAST_ALPN)
            .await
            .expect("connect");
        (conn, router, client, frames)
    }

    async fn advance_secs(seconds: u64) {
        for _ in 0..seconds {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
    }

    /// Wait in real time for the close to reach us. The server closes inside the
    /// paused clock, but the close frame travels over real I/O, so a check right
    /// after `advance_secs` races it.
    async fn closed_soon(conn: &Connection) -> bool {
        let started = std::time::Instant::now();
        while conn.close_reason().is_none() {
            if started.elapsed() > Duration::from_secs(5) {
                return false;
            }
            tokio::task::yield_now().await;
        }
        true
    }

    /// Closed by the server with its idle reason: not by us, not by QUIC.
    fn closed_by_the_acceptor(conn: &Connection) -> bool {
        matches!(
            conn.close_reason(),
            Some(ConnectionError::ApplicationClosed(ref close))
                if close.reason.as_ref() == b"idle"
                    && close.error_code.into_inner() == u64::from(IDLE)
        )
    }

    #[tokio::test]
    async fn an_accepted_connection_that_gets_no_stream_is_closed_after_the_idle_timeout() {
        let (conn, router, client, _frames) = connected(Duration::from_secs(8)).await;
        tokio::time::pause();

        advance_secs(6).await;
        assert!(conn.close_reason().is_none(), "inside the idle timeout");

        advance_secs(6).await;
        assert!(closed_soon(&conn).await, "never closed");
        assert!(closed_by_the_acceptor(&conn), "{:?}", conn.close_reason());

        tokio::time::resume();
        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    #[tokio::test]
    async fn a_stream_restarts_the_accept_side_idle_timeout() {
        let (conn, router, client, mut frames) = connected(Duration::from_secs(8)).await;
        tokio::time::pause();

        advance_secs(5).await;
        let mut stream = conn.open_uni().await.expect("open a stream");
        stream.write_all(b"frame").await.expect("write");
        stream.finish().expect("finish");
        // Real I/O carries the frame to the acceptor: yield until it lands.
        while frames.try_recv().is_err() {
            tokio::task::yield_now().await;
        }

        advance_secs(5).await;
        assert!(
            conn.close_reason().is_none(),
            "five seconds after a stream is inside the timeout"
        );

        advance_secs(7).await;
        assert!(closed_soon(&conn).await, "never closed");
        assert!(closed_by_the_acceptor(&conn), "{:?}", conn.close_reason());

        tokio::time::resume();
        router.shutdown().await.expect("shutdown");
        client.close().await;
    }
}
