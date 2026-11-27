//! The question "who serves this beacon?". Two holders share one endpoint id, so a dial that
//! connects cannot tell them apart. The answer can: it names the member that serves the beacon
//! that was reached.

use iroh::EndpointId;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use n0_future::time;

use crate::util::tuning::HEAL_PROBE;

/// ALPN of the question. Wire-load-bearing: both ends must agree, so it moves only with a
/// deliberate protocol break.
pub(crate) const BEACON_WHO_ALPN: &[u8] = b"habilis-mesh/beacon-who/1";

/// The `ProtocolHandler` of a beacon: it names the member that serves it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BeaconWho {
    holder: EndpointId,
}

impl BeaconWho {
    pub(crate) const fn new(holder: EndpointId) -> Self {
        Self { holder }
    }
}

impl ProtocolHandler for BeaconWho {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let Ok(mut send) = connection.open_uni().await else {
            return Ok(());
        };
        let id = self.holder.as_bytes();
        let written = send.write_all(id).await;
        if written.is_ok() && send.finish().is_ok() {
            // The asker closes the connection once it has read the id; a drop here would cut the
            // stream before it is delivered. The wait ends at the budget of a probe.
            let _ = time::timeout(HEAL_PROBE, connection.closed()).await;
        }
        Ok(())
    }
}
