//! The question "who serves this beacon?". Two holders share one endpoint id, so a dial that
//! connects cannot tell them apart. The answer can: it names the member that serves the beacon
//! that was reached.

use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use n0_future::time;

use crate::util::clock::Instant;

use crate::util::tuning::HEAL_PROBE;

/// ALPN of the question. Wire-load-bearing: both ends must agree, so it moves only with a
/// deliberate protocol break.
pub(crate) const BEACON_WHO_ALPN: &[u8] = b"habilis-mesh/beacon-who/1";

/// The most bytes of a frame that the ask reads. The frame is 32 bytes, so a longer one is not an
/// id and is not read to its end.
const MAX_FRAME_BYTES: usize = 33;

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

/// What a dial to the rendezvous id found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WhoAnswer {
    /// The beacon that answered is served by the member that asked.
    Ours,
    /// The beacon that answered is served by another member.
    Rival(EndpointId),
    /// A connection came up and no valid frame followed: someone is there, and it did not say who
    /// (a slow beacon, a frame that is not an id). The cause says why.
    Reached(&'static str),
    /// Nothing was reached: no answer in time, or a refusal of the dial or of the ALPN. The cause
    /// says why.
    Unknown(&'static str),
}

impl WhoAnswer {
    /// The word of the answer in the log line of the holder probe. A parser reads this word, not the
    /// `Debug` text; the words are pinned by a test.
    pub(crate) fn kind(self) -> &'static str {
        match self {
            Self::Ours => "ours",
            Self::Rival(_) => "rival",
            Self::Reached(_) => "reached",
            Self::Unknown(_) => "unknown",
        }
    }

    /// The cause of a `Reached` or `Unknown`, and the empty text for the others.
    pub(crate) fn cause(self) -> &'static str {
        match self {
            Self::Reached(cause) | Self::Unknown(cause) => cause,
            Self::Ours | Self::Rival(_) => "",
        }
    }
}

/// Ask the beacon at `target` which member serves it. `own` is the member that asks. `timeout` is
/// the budget of the whole ask. Each answer that is not `Ours` or `Rival` is logged with its cause,
/// so that the rate of them can be read from a log.
pub(crate) async fn ask_who(
    prober: &Endpoint,
    target: EndpointAddr,
    own: EndpointId,
    timeout: Duration,
) -> WhoAnswer {
    let started = Instant::now();
    let dialed = time::timeout(timeout, prober.connect(target, BEACON_WHO_ALPN)).await;
    let connection = match dialed {
        Ok(Ok(connection)) => connection,
        Ok(Err(_)) => return nobody("the dial failed or the ALPN was refused"),
        Err(_) => return nobody("no connection in the budget"),
    };
    let left = timeout.saturating_sub(started.elapsed());
    let frame = time::timeout(left, read_frame(&connection)).await;
    // An orderly close lets the beacon end its wait at once.
    connection.close(0u32.into(), b"who");
    let frame = match frame {
        Ok(Ok(frame)) => frame,
        Ok(Err(cause)) => return somebody(cause),
        Err(_) => return somebody("no frame in the budget"),
    };
    let Ok(bytes) = <[u8; 32]>::try_from(frame) else {
        return somebody("the frame is not 32 bytes");
    };
    match EndpointId::from_bytes(&bytes) {
        Ok(holder) if holder == own => WhoAnswer::Ours,
        Ok(holder) => WhoAnswer::Rival(holder),
        Err(_) => somebody("the frame is not an endpoint id"),
    }
}

/// The frame that the beacon on `connection` sends, or why there is none.
async fn read_frame(connection: &Connection) -> Result<Vec<u8>, &'static str> {
    let mut recv = connection
        .accept_uni()
        .await
        .map_err(|_| "the beacon opened no stream")?;
    recv.read_to_end(MAX_FRAME_BYTES)
        .await
        .map_err(|_| "the frame was not read")
}

fn nobody(cause: &'static str) -> WhoAnswer {
    tracing::debug!(target: "habilis_network::beacon", cause, "ask who: nobody reached");
    WhoAnswer::Unknown(cause)
}

fn somebody(cause: &'static str) -> WhoAnswer {
    tracing::debug!(target: "habilis_network::beacon", cause, "ask who: reached, no valid frame");
    WhoAnswer::Reached(cause)
}
