# Clone and Arc audit: habilis-network-iroh-multihop-transport

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-iroh-multihop-transport/src`, up to the first test region. Three of the counted lines are inside doc-comment examples (`lib.rs`, `route.rs`, `topology.rs`); they are text, not code.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every site with its enclosing function.

## Result

- B3: 13 counted lines before, 11 after (8 of them code). The two removed clones are in `Cell::advanced`, which now takes `self` (commit `e14f238b`).
- B1: 17 sites before, 17 after. No change.

## Sites kept (B3)

- `topology`: the underlay address of a held vector is returned owned from a borrowed map.
- `paths_of`: the remote address is copied into an owned list; the path belongs to the connection.
- `blocked_by_test`: builds a `Custom` address value to lend as `&Addr` to the id lookup.
- `admits_paths`: `path_list` takes owned pairs, and its caller in the forwarder passes an owned iterator; changing it would add a collect there, which is not simpler.
- `drain_to_hop` (test hooks only): the map keeps a copy of the connection, and the writer uses the original.
- `dial_with_retry`: the destination is borrowed and `connect` takes it owned on each attempt.
- `ForwardAcceptor::accept`: the acceptor is moved into each read task, and the connection is copied per stream into the same task.

## Sites kept (B1)

- The forwarder, the topology, the writer pool, the relay gate and the route-wake signal are each shared between the handle, the transport, the acceptor and the writer tasks. Each `Arc::clone` is a second owner.
- `create_sender` and the path selector are trait objects that iroh takes by `Arc`.
