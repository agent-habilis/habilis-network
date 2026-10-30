# Clone and Arc audit: habilis-network-wasm

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-wasm/src`, up to the first test region.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every site with its enclosing function.

## Result

- B3: 5 sites before, 5 after. No change.
- B1: 6 sites before, 6 after. No change.

## Sites kept

- Getters on the mesh peer (`id`, `nick`, `name`, `hash`): return owned strings from `&self`, as the JavaScript binding requires.
- The stream node slot (`Rc<RefCell<Option<Rc<StreamNode>>>>`): the shared node is held by the handle and by each producer or reader, and `Rc::try_unwrap` decides which holder closes it. Each `Rc::clone` and each `.clone()` in `node()` is part of that count, so it stays.
- `node()` returns an owned `Rc` from a `RefCell` borrow, so the borrow ends before the await.
