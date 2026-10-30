# Clone and Arc audit: habilis-network-bench-wasm

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-bench-wasm/src`, up to the first test region.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every site with its enclosing function.

## Result

- B3: 5 sites before, 5 after. No change.
- B1: 0 sites.

## Sites kept

- `complete`: the hub is copied out of the state borrow and returned with the pending negotiation, so the borrow ends before the await.
- `serve`: the endpoint is passed to the router builder, which takes it by value, while the state still holds its own copy.
- `connection_to`: the endpoint and the open connection are returned out of the state borrow. The connection is also stored in the state, so it has two owners.
