//! The accept side of the unicast plane: the `ProtocolHandler` the Router runs
//! for `UNICAST_ALPN`. It reads one serialized `Message` per unidirectional
//! stream and forwards the raw bytes to the event loop over a bounded channel —
//! doing **no** validation itself, so the shared `gossip::ingest` path stays the
//! single authority on signature, mesh-gate, and dedup.

use bytes::Bytes;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::sync::mpsc;

use crate::util::consts::MAX_MESSAGE_SIZE;

use super::LOG_TARGET;
use super::path::{PROBE_DEADLINE, refuse_unless_direct};

/// Close code an inbound unicast connection gets when the relay is lookup
/// only and no direct path was selected within the deadline.
const UNICAST_RELAY_REFUSED_CODE: u32 = 5;

/// Per-frame read cap: one wire message plus gossip's envelope headroom (the
/// same slack the size assertion reserves). Bounds allocation against a peer
/// that opens a stream and never stops writing.
const MAX_UNICAST_FRAME: usize = MAX_MESSAGE_SIZE + 256;

#[derive(Debug, Clone)]
pub(crate) struct UnicastAcceptor {
    tx: mpsc::Sender<Bytes>,
    relay_transport: bool,
}

impl UnicastAcceptor {
    pub(crate) fn new(tx: mpsc::Sender<Bytes>, relay_transport: bool) -> Self {
        Self {
            tx,
            relay_transport,
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
            UNICAST_RELAY_REFUSED_CODE,
        )
        .await
        {
            return Ok(());
        }
        // Each accepted uni-stream carries exactly one message; loop until the
        // peer closes the connection (`accept_uni` errors).
        while let Ok(mut recv) = conn.accept_uni().await {
            self.handle_frame(recv.read_to_end(MAX_UNICAST_FRAME).await);
        }
        Ok(())
    }
}
