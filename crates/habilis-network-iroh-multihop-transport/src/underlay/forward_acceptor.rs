use std::sync::{Arc, Mutex};

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};

use crate::app_id::UnderlayId;
use crate::cell;

use super::forwarder::Forwarder;
use super::{GateRole, RelayGate};

/// The `FORWARD_ALPN` accept side: read cells off each incoming uni-stream and
/// hand them to the [`Forwarder`].
#[derive(Debug, Clone)]
pub(crate) struct ForwardAcceptor {
    forwarder: Arc<Forwarder>,
}

impl ForwardAcceptor {
    pub(crate) fn new(forwarder: Arc<Forwarder>) -> Self {
        Self { forwarder }
    }

    async fn read_loop(
        self,
        upstream: UnderlayId,
        connection: Connection,
        gate: Arc<Mutex<RelayGate>>,
        mut recv: iroh::endpoint::RecvStream,
    ) {
        while let Ok(cell) = cell::read_cell(&mut recv).await {
            let admitted = gate
                .lock()
                .expect("relay gate poisoned")
                .admits(&connection);
            if admitted {
                self.forwarder.handle_cell(cell, upstream);
            } else {
                self.forwarder.note_inbound_refusal(upstream, &connection);
            }
        }
    }
}

impl ProtocolHandler for ForwardAcceptor {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // The peer's QUIC-TLS identity: the one thing about a cell's origin its
        // sender cannot choose, and constant across every stream on this
        // connection. Every cell that arrives here is checked against it.
        let upstream = UnderlayId::new(connection.remote_id());
        let gate = Arc::new(Mutex::new(RelayGate::new(
            self.forwarder.rule.allow_relay,
            self.forwarder.underlay.id(),
            GateRole::Inbound,
        )));
        // Loop ends when the upstream hop closes the connection: normal teardown.
        while let Ok(recv) = connection.accept_uni().await {
            n0_future::task::spawn(self.clone().read_loop(
                upstream,
                connection.clone(),
                Arc::clone(&gate),
                recv,
            ));
        }
        Ok(())
    }
}
