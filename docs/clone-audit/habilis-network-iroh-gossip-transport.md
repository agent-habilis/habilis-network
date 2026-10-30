# Clone and Arc audit: habilis-network-iroh-gossip-transport

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-iroh-gossip-transport/src`, up to the first test region.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every site with its enclosing function.

## Result

- B3: 10 sites before, 10 after. No change.
- B1: 26 sites before, 26 after. No change.

## Sites kept (B3)

- Copies out of a lock (`hub` members and sent frames, the sink option, the handle's sink and sink option in `path_is_valid` and `send_datagram`): each copy is taken so that the lock is released before the copy is used.
- The frame copy into the sent log (`hub`): the frame is borrowed by the flood and owned by the log.
- The handle copies into the member list and the `from` field of the memory sink: the list and the sink each own a handle.
- `local_addr` into the watchable and into each receive info: an owned address per packet, as the types require.

## Sites kept (B1)

- The shared state (`Shared`, the transport, the lookup, the sink's liveness flag, the hub's members) is held by the handle and by the endpoint, the lookup, the sink task, or the hub. Each `Arc::clone` is a second owner.
- Trait objects returned to iroh or stored as sinks (`path_selector`, `custom_transport`, `create_sender`, `attach_gossip`, `attach`, the hub's memory sink): iroh and the handle take the `Arc<dyn ...>`.

## B1 second pass (2026-10-30)

Every `Arc` site was read again with its enclosing function.

- Removed: 0.
- Kept:
  - `Shared`, the transport, the lookup, the sink's liveness flag and the hub's members: each is owned by the handle and by an endpoint, lookup, task or hub that outlives the borrow.
  - `path_selector`, `custom_transport`, `create_sender`, and the sink passed to `attach`: iroh and the handle take `Arc` (or `Arc<dyn ...>`) by value.
  - The memory sink in `Hub::join`: `attach` stores it as a shared trait object.
