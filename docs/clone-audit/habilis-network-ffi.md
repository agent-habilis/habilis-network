# Clone and Arc audit: habilis-network-ffi

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-ffi/src`, up to the first test region.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every `Arc` site with its enclosing function.

## Result

- B3: 0 sites.
- B1: 8 sites before, 8 after. No change.

## Sites kept (B1)

- `mesh::open`: the sink passed to `join` is an `Arc<dyn NodeSink>`, and the event loop keeps it.
- The stream runtime (`Streams`, `Writer`, `ReadEnd`): the runtime is created once in an `Arc`, and each writer and reader holds a clone, because the runtime must outlive every stream handle. The struct fields that hold it are part of the same sharing.
