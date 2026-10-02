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

use crate::addr::{Route, RouteHop};

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
    pub(crate) pos: u16,
    /// The original sender, so the destination can reverse the route to reply.
    pub(crate) source: RouteHop,
    /// The opaque QUIC packet being relayed.
    pub(crate) packet: Vec<u8>,
}

impl Cell {
    /// The hop this cell is addressed to right now. The receiver must *be* it;
    /// anything else is a sender trying to use us as a reflector.
    pub(crate) fn current_hop(&self) -> Option<&RouteHop> {
        self.path.hop_at(self.pos as usize)
    }

    /// The next hop to forward to, or `None` when this hop is the destination.
    /// [`read_cell`] has established that `pos` is in range, so `None` can no
    /// longer also mean "`pos` ran off the end".
    pub(crate) fn next_hop(&self) -> Option<&RouteHop> {
        self.path.hop_at(self.pos as usize + 1)
    }

    /// Advance to the successor hop. Caller must have checked [`next_hop`] first.
    pub(crate) fn advanced(&self) -> Cell {
        Cell {
            path: self.path.clone(),
            pos: self.pos + 1,
            source: self.source.clone(),
            packet: self.packet.clone(),
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
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.context("read cell body")?;
    let cell: Cell = postcard::from_bytes(&buf).context("deserialize cell")?;
    // `path` validated itself while deserializing; `pos` is the one field whose
    // legality is relative to it. Settling that here is what lets `next_hop()`
    // mean "I am the destination" and nothing else.
    if cell.current_hop().is_none() {
        bail!("cell pos {} is past the end of its route", cell.pos);
    }
    Ok(cell)
}

#[cfg(test)]
mod tests {
    use super::Cell;
    use crate::addr::{MAX_ROUTE_HOPS, Route, RouteHop};
    use iroh::{EndpointAddr, EndpointId, SecretKey};

    fn hop(seed: u8) -> RouteHop {
        let id: EndpointId = SecretKey::from_bytes(&[seed; 32]).public();
        RouteHop {
            app_id: id,
            underlay: EndpointAddr::new(id),
        }
    }

    fn cell(hops: Vec<RouteHop>, pos: u16) -> Cell {
        Cell {
            path: Route::new(hops).expect("legal route"),
            pos,
            source: hop(200),
            packet: Vec::new(),
        }
    }

    /// A cell's wire shape, built from a raw hop vector so a test can mint the
    /// hostile routes `Route::new` would refuse.
    fn forged_bytes(hops: Vec<RouteHop>, pos: u16) -> Vec<u8> {
        postcard::to_allocvec(&(hops, pos, hop(200), Vec::<u8>::new())).expect("serializes")
    }

    #[test]
    fn a_cyclic_route_does_not_deserialize_into_a_cell() {
        // The linchpin of the design: `Cell.path` is a `Route`, so a hostile
        // route is refused by the codec and never reaches the forwarder.
        let bytes = forged_bytes(vec![hop(1), hop(2), hop(1)], 0);
        assert!(postcard::from_bytes::<Cell>(&bytes).is_err());
    }

    #[test]
    fn an_oversized_route_does_not_deserialize_into_a_cell() {
        let hops: Vec<RouteHop> = (0..=MAX_ROUTE_HOPS)
            .map(|seed| hop(u8::try_from(seed).expect("seed fits")))
            .collect();
        assert!(postcard::from_bytes::<Cell>(&forged_bytes(hops, 0)).is_err());
    }

    #[test]
    fn a_legal_route_still_deserializes_into_a_cell() {
        let bytes = forged_bytes(vec![hop(1), hop(2)], 0);
        assert!(postcard::from_bytes::<Cell>(&bytes).is_ok());
    }

    #[test]
    fn current_hop_is_none_when_pos_is_past_the_end() {
        // Today this falls through `next_hop()`'s `None` arm and delivers an
        // attacker's packet locally as though we were the destination.
        assert!(cell(vec![hop(1), hop(2)], 2).current_hop().is_none());
    }

    #[test]
    fn current_hop_is_the_addressed_hop() {
        let subject = cell(vec![hop(1), hop(2)], 1);
        assert_eq!(subject.current_hop(), Some(&hop(2)));
        assert!(subject.next_hop().is_none());
    }
}
