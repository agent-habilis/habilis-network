# Clone and Arc audit: habilis-network-test-tracing

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-test-tracing/src`, up to the first test region.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every site with its enclosing function.

## Result

- B3: 7 sites before, 7 after. No change.
- B1: 4 sites before, 4 after. No change.

## Sites kept

- `captured_logs`: copies a string out of a locked static.
- `build_guard` (Arc): the live list and the guard share one slot, so the slot is an `Arc`. `Arc::clone` adds the second owner.
- `Drop for Guard`: the ended thread name is copied into the late record while the slot is still held.
- `on_event`: `target`, `text` and `shared_with` are copied into a closure (`logged`) that runs once per live slot, and each run owns its copy. `late.ended` is copied out of a locked record that stays borrowed. The shared list of thread names is owned by each event.
- `static LIVE` (Arc): the global list holds the same slots as the guards.
