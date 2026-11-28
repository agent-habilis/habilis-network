//! The question "who serves this beacon?". Two holders share one endpoint id, so a dial that
//! connects cannot tell them apart. The answer can: it names the member that serves the beacon
//! that was reached.

use std::fmt;
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

/// Why an ask read nothing, or no id. The causes are a closed list: each has one word with no space,
/// which the log line of the holder probe carries and a parser reads. A new cause is a new word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cause {
    /// The dial failed, or the beacon refused the ALPN.
    DialOrAlpnRefused,
    /// No connection came up in the budget.
    NoConnection,
    /// A connection came up and no frame followed in the budget.
    NoFrame,
    /// The frame is not 32 bytes.
    FrameNot32Bytes,
    /// The frame holds 32 bytes that are not an endpoint id.
    FrameNotAnId,
    /// The beacon opened no stream.
    NoStream,
    /// The frame was not read to its end.
    FrameNotRead,
    /// The prober endpoint did not bind.
    ProberNotBound,
    /// The task of the probe ended with no answer.
    ProbeTaskEnded,
    /// A departure cancelled the probe.
    Cancelled,
    /// The ladder has no busy rung to ask.
    NoBusyRung,
    /// A rung answered as the id.
    RungAnsweredAsId,
    /// No rung answered as the id.
    NoRungAnswered,
    /// There is no address to dial and no lookup to resolve the id.
    NothingToDial,
}

impl Cause {
    /// The word of the cause in the log line of the holder probe.
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::DialOrAlpnRefused => "dial_or_alpn_refused",
            Self::NoConnection => "no_connection",
            Self::NoFrame => "no_frame",
            Self::FrameNot32Bytes => "frame_not_32_bytes",
            Self::FrameNotAnId => "frame_not_an_id",
            Self::NoStream => "no_stream",
            Self::FrameNotRead => "frame_not_read",
            Self::ProberNotBound => "prober_not_bound",
            Self::ProbeTaskEnded => "probe_task_ended",
            Self::Cancelled => "cancelled",
            Self::NoBusyRung => "no_busy_rung",
            Self::RungAnsweredAsId => "rung_answered_as_id",
            Self::NoRungAnswered => "no_rung_answered",
            Self::NothingToDial => "nothing_to_dial",
        }
    }
}

impl fmt::Display for Cause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.word())
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
    Reached(Cause),
    /// Nothing was reached: no answer in time, or a refusal of the dial or of the ALPN. The cause
    /// says why.
    Unknown(Cause),
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

    /// The cause of a `Reached` or `Unknown`, and nothing for the others.
    pub(crate) fn cause(self) -> Option<Cause> {
        match self {
            Self::Reached(cause) | Self::Unknown(cause) => Some(cause),
            Self::Ours | Self::Rival(_) => None,
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
        Ok(Err(_)) => return nobody(Cause::DialOrAlpnRefused),
        Err(_) => return nobody(Cause::NoConnection),
    };
    let left = timeout.saturating_sub(started.elapsed());
    let frame = time::timeout(left, read_frame(&connection)).await;
    // An orderly close lets the beacon end its wait at once.
    connection.close(0u32.into(), b"who");
    let frame = match frame {
        Ok(Ok(frame)) => frame,
        Ok(Err(cause)) => return somebody(cause),
        Err(_) => return somebody(Cause::NoFrame),
    };
    let Ok(bytes) = <[u8; 32]>::try_from(frame) else {
        return somebody(Cause::FrameNot32Bytes);
    };
    match EndpointId::from_bytes(&bytes) {
        Ok(holder) if holder == own => WhoAnswer::Ours,
        Ok(holder) => WhoAnswer::Rival(holder),
        Err(_) => somebody(Cause::FrameNotAnId),
    }
}

/// The frame that the beacon on `connection` sends, or why there is none.
async fn read_frame(connection: &Connection) -> Result<Vec<u8>, Cause> {
    let mut recv = connection.accept_uni().await.map_err(|_| Cause::NoStream)?;
    recv.read_to_end(MAX_FRAME_BYTES)
        .await
        .map_err(|_| Cause::FrameNotRead)
}

fn nobody(cause: Cause) -> WhoAnswer {
    tracing::debug!(target: "habilis_network::beacon", %cause, "ask who: nobody reached");
    WhoAnswer::Unknown(cause)
}

fn somebody(cause: Cause) -> WhoAnswer {
    tracing::debug!(target: "habilis_network::beacon", %cause, "ask who: reached, no valid frame");
    WhoAnswer::Reached(cause)
}
