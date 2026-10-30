# Clone and Arc audit: habilis-network-logging

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-logging/src`, up to the first test region.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every site with its enclosing function.

## Result

- B3: 2 sites before, 2 after. No change.
- B1: 2 sites before, 2 after. No change.

## Sites kept

- `install` (the global sink): the sink is copied into the global `SINK` and returned to the caller. Two owners share one state.
- `make_writer` (the `tracing` writer): the trait returns an owned writer from `&self`, and the writer is a handle over shared state.
- `LogSink` (Arc): the sink handle is shared between the global slot and every caller, so the state is a shared `Arc<Mutex<_>>`.
- `install` (Arc): creates that shared state.
