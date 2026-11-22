//! The forwarding **cell** — one opaque QUIC packet, the node it is for, the node that made it, and how many
//! more times it may be forwarded — and its length-delimited framing over an underlay uni-stream.
//!
//! A cell carries no route. Each node that holds a cell picks the next hop from its own table (see
//! [`next_hop`](crate::next_hop)), so a link that left the graph costs no more cells than the time that the
//! tables need to agree.
//!
//! Every field here is written by whoever sent the cell, so none of it is trusted on arrival. `src` is a claim:
//! a neighbor can write any value, and QUIC protects the connection that the packet belongs to, so a forged
//! `src` costs a dropped packet and nothing else. `hops_left` is checked against [`MAX_CELL_HOPS`] by
//! [`Forwarder::handle_cell`](crate::underlay::Forwarder::handle_cell), which also decides whether this node may
//! act on the cell at all, since only it knows who this node is and who sent the cell.

use anyhow::{Context, Result, bail};
use iroh::endpoint::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

use crate::app_id::AppId;

/// A cell exceeding this many bytes is refused — a corrupt/hostile length prefix
/// must never drive an unbounded allocation. A QUIC datagram is a few kilobytes
/// and the header of a cell is under a hundred bytes, so this is still ample headroom.
const MAX_CELL_BYTES: usize = 64 * 1024;

/// How many times a cell may be forwarded: the bound on a loop between nodes whose tables disagree, and on the
/// work that one cell can make. A cell made here starts with this value, and a node that gets a cell with a
/// larger value refuses it.
pub(crate) const MAX_CELL_HOPS: u8 = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Cell {
    /// The node that this cell is for.
    pub(crate) dst: AppId,
    /// The node that made the cell, which is where the packet reports that it came from.
    pub(crate) src: AppId,
    /// How many more times a node may forward this cell.
    pub(crate) hops_left: u8,
    /// The opaque QUIC packet being relayed.
    pub(crate) packet: Vec<u8>,
}

impl Cell {
    /// The cell as it leaves a node that forwards it: one forward fewer left.
    pub(crate) fn forwarded(self) -> Self {
        Self {
            hops_left: self.hops_left.saturating_sub(1),
            ..self
        }
    }
}

/// Write `cell` as a 4-byte big-endian length followed by its postcard body.
pub(crate) async fn write_cell(send: &mut SendStream, cell: &Cell) -> Result<()> {
    let bytes = postcard::to_allocvec(cell).context("serialize cell")?;
    let len = u32::try_from(bytes.len()).context("cell too large to frame")?;
    send.write_all(&len.to_be_bytes())
        .await
        .context("write cell length")?;
    send.write_all(&bytes).await.context("write cell body")?;
    Ok(())
}

/// Read one framed cell. A length above [`MAX_CELL_BYTES`] is refused before any allocation. The value of
/// `hops_left` is not judged here: a node counts a cell above the limit and drops it, and keeps the connection.
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
    postcard::from_bytes(&buffer).context("deserialize cell")
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use iroh::SecretKey;

    use super::{Cell, MAX_CELL_HOPS};
    use crate::app_id::AppId;

    fn app(seed: u8) -> AppId {
        AppId::new(SecretKey::from_bytes(&[seed; 32]).public())
    }

    fn cell(hops_left: u8) -> Cell {
        Cell {
            dst: app(1),
            src: app(2),
            hops_left,
            packet: vec![7, 8, 9],
        }
    }

    /// A cell survives its wire form, and the wire form is fixed: the destination, the source, the forwards left
    /// and the packet. A change of it is a wire break, and it is named as one.
    #[test]
    fn a_cell_has_a_fixed_wire_form() {
        let _guard = ::habilis_network_test_tracing::init();
        let bytes = postcard::to_allocvec(&cell(MAX_CELL_HOPS)).expect("a cell serializes");
        let mut hex = String::new();
        for byte in &bytes {
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
        }

        assert_eq!(
            hex,
            concat!(
                "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
                "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
                "08",
                "03070809"
            ),
            "dst, src, hops_left, then the packet with its length"
        );
        let decoded: Cell = postcard::from_bytes(&bytes).expect("a cell deserializes");
        assert_eq!(
            decoded,
            cell(MAX_CELL_HOPS),
            "the cell survives its wire form"
        );
    }

    /// A node that forwards a cell leaves one forward fewer, and the count stops at zero.
    #[test]
    fn a_forwarded_cell_has_one_forward_fewer_and_the_count_stops_at_zero() {
        let _guard = ::habilis_network_test_tracing::init();

        assert_eq!(cell(5).forwarded().hops_left, 4, "one fewer");
        assert_eq!(cell(0).forwarded().hops_left, 0, "the count stops at zero");
        assert_eq!(
            cell(5).forwarded().packet,
            vec![7, 8, 9],
            "the packet is not touched"
        );
    }
}
