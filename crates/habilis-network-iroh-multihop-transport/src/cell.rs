//! The forwarding **cell** — one opaque QUIC packet plus the source route it is
//! travelling — and its length-delimited framing over an underlay uni-stream.
//!
//! A cell carries the whole immutable forward `path` and a `pos` index marking
//! which hop should receive it, so a relay's only decision is "forward to
//! `path[pos + 1]`" or "deliver, I am the destination". `source` rides along so
//! the destination can build the return route without a fresh lookup.
//!
//! Every field here is written by whoever sent the cell, so none of it is
//! trusted on arrival. `path` is a [`Route`], which validates itself while
//! deserializing, and [`read_cell`] settles `pos` against it; whether this node
//! may act on the result at all is
//! [`Forwarder::handle_cell`](crate::underlay::Forwarder::handle_cell)'s
//! decision, since only it knows who this node is and who sent the cell.

use anyhow::{Context, Result, bail};
use iroh::endpoint::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

use crate::route::{Route, RouteHop};

/// A cell exceeding this many bytes is refused — a corrupt/hostile length prefix
/// must never drive an unbounded allocation. A QUIC datagram is a few kilobytes
/// and a bounded route header under one, so this is still ample headroom.
const MAX_CELL_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Cell {
    /// The immutable forward route, `[first_hop, …, destination]`. Typed as a
    /// [`Route`] rather than a bare `Vec` so a cell off the wire inherits every
    /// route invariant — non-empty, bounded, loop-free — during deserialization.
    pub(crate) path: Route,
    /// Index into `path` of the hop that should receive this cell.
    #[serde(rename = "pos")]
    pub(crate) position: u16,
    /// The original sender, so the destination can reverse the route to reply.
    pub(crate) source: RouteHop,
    /// The opaque QUIC packet being relayed.
    pub(crate) packet: Vec<u8>,
}

impl Cell {
    /// The hop this cell is addressed to right now. The receiver must *be* it;
    /// anything else is a sender trying to use us as a reflector.
    pub(crate) fn current_hop(&self) -> Option<&RouteHop> {
        self.path.hop_at(self.position as usize)
    }

    /// The next hop to forward to, or `None` when this hop is the destination.
    /// [`read_cell`] has established that `pos` is in range, so `None` can no
    /// longer also mean "`pos` ran off the end".
    pub(crate) fn next_hop(&self) -> Option<&RouteHop> {
        self.path.hop_at(self.position as usize + 1)
    }

    /// Advance to the successor hop. Caller must have checked `next_hop` first.
    pub(crate) fn advanced(self) -> Cell {
        Cell {
            path: self.path,
            position: self.position + 1,
            source: self.source,
            packet: self.packet,
        }
    }
}

/// Write one length-delimited cell: `[u32 big-endian len][postcard bytes]`.
pub(crate) async fn write_cell(send: &mut SendStream, cell: &Cell) -> Result<()> {
    let bytes = postcard::to_allocvec(cell).context("serialize cell")?;
    let len = u32::try_from(bytes.len()).context("cell too large to frame")?;
    send.write_all(&len.to_be_bytes())
        .await
        .context("write cell length")?;
    send.write_all(&bytes).await.context("write cell body")?;
    Ok(())
}

/// Read one length-delimited cell, refusing an oversized frame.
pub(crate) async fn read_cell(recv: &mut RecvStream) -> Result<Cell> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .context("read cell length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_CELL_BYTES {
        bail!("cell length {len} exceeds bound {MAX_CELL_BYTES}");
    }
    let mut buffer = vec![0u8; len];
    recv.read_exact(&mut buffer)
        .await
        .context("read cell body")?;
    let cell: Cell = postcard::from_bytes(&buffer).context("deserialize cell")?;
    // `path` validated itself while deserializing; `pos` is the one field whose
    // legality is relative to it. Settling that here is what lets `next_hop()`
    // mean "I am the destination" and nothing else.
    if cell.current_hop().is_none() {
        bail!("cell pos {} is past the end of its route", cell.position);
    }
    Ok(cell)
}

#[cfg(test)]
mod tests {
    use super::Cell;
    use crate::app_id::{AppId, UnderlayId};
    use crate::route::{MAX_ROUTE_HOPS, Route, RouteHop};
    use iroh::{EndpointId, SecretKey};

    fn hop(seed: u8) -> RouteHop {
        let id: EndpointId = SecretKey::from_bytes(&[seed; 32]).public();
        RouteHop {
            app_id: AppId::new(id),
            underlay_id: UnderlayId::new(id),
        }
    }

    fn cell(hops: Vec<RouteHop>, position: u16) -> Cell {
        Cell {
            path: Route::try_new(hops).expect("legal route"),
            position,
            source: hop(200),
            packet: Vec::new(),
        }
    }

    /// A cell's wire shape, built from a raw hop vector so a test can mint the
    /// hostile routes `Route::try_new` would refuse.
    fn forged_bytes(hops: Vec<RouteHop>, position: u16) -> Vec<u8> {
        let packet: Vec<u8> = Vec::new();
        postcard::to_allocvec(&(hops, position, hop(200), packet)).expect("serializes")
    }

    #[test]
    fn a_cyclic_route_does_not_deserialize_into_a_cell() {
        let _guard = ::habilis_network_test_tracing::init();
        // The linchpin of the design: `Cell.path` is a `Route`, so a hostile
        // route is refused by the codec and never reaches the forwarder.
        let bytes = forged_bytes(vec![hop(1), hop(2), hop(1)], 0);
        let decoded: Result<Cell, postcard::Error> = postcard::from_bytes(&bytes);
        assert!(
            decoded.is_err(),
            "a cyclic route does not deserialize into a cell"
        );
    }

    #[test]
    fn an_oversized_route_does_not_deserialize_into_a_cell() {
        let _guard = ::habilis_network_test_tracing::init();
        let hops: Vec<RouteHop> = (0..=MAX_ROUTE_HOPS)
            .map(|seed| hop(u8::try_from(seed).expect("seed fits")))
            .collect();
        let decoded: Result<Cell, postcard::Error> = postcard::from_bytes(&forged_bytes(hops, 0));
        assert!(
            decoded.is_err(),
            "an oversized route does not deserialize into a cell"
        );
    }

    #[test]
    fn a_legal_route_still_deserializes_into_a_cell() {
        let _guard = ::habilis_network_test_tracing::init();
        let bytes = forged_bytes(vec![hop(1), hop(2)], 0);
        let decoded: Result<Cell, postcard::Error> = postcard::from_bytes(&bytes);
        assert!(decoded.is_ok(), "a legal route deserializes into a cell");
    }

    #[test]
    fn current_hop_is_none_when_pos_is_past_the_end() {
        let _guard = ::habilis_network_test_tracing::init();
        // Today this falls through `next_hop()`'s `None` arm and delivers an
        // attacker's packet locally as though we were the destination.
        assert!(
            cell(vec![hop(1), hop(2)], 2).current_hop().is_none(),
            "the current hop is none past the end of the route"
        );
    }

    #[test]
    fn current_hop_is_the_addressed_hop() {
        let _guard = ::habilis_network_test_tracing::init();
        let subject = cell(vec![hop(1), hop(2)], 1);
        assert_eq!(
            subject.current_hop(),
            Some(&hop(2)),
            "the current hop is the addressed hop"
        );
        assert!(
            subject.next_hop().is_none(),
            "the subject cell has no next hop"
        );
    }
}
