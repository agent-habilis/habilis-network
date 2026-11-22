# habilis-network-iroh-multihop-transport

A hop-by-hop multi-hop iroh custom transport. A peer reaches a
destination it cannot dial directly by relaying the destination's QUIC
packets through intermediate peers. Each node picks the next hop of a packet
from its own table.

iroh runs its full QUIC state machine end-to-end, so the two endpoints
share a real `Connection` with QUIC-TLS secrecy. Relays forward opaque,
already-encrypted packets.

- `Topology` — a metric-weighted link-state graph. A node reads from it the
  next hop of a cell toward a destination.
- The `CustomAddr` of a peer holds the id of the peer and no way to it, so it
  never goes stale.
- `MultihopHandle` — owns a dedicated underlay iroh endpoint that carries
  packets hop by hop.

The crate has no habilis-network dependency; any iroh user can take it. A consumer
that patches `iroh` to a fork must patch `iroh-base` to the same repo and
rev, or the graph holds two `iroh_base` versions and `CustomAddr` stops
unifying. See `src/lib.rs` for the API.
