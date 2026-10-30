# Clone and Arc audit: habilis-network-stream-cli

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-stream-cli/src`, up to the first test region.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every site with its enclosing function.

## Result

- B3: 3 sites before, 3 after. No change.
- B1: 0 sites.

## Sites kept

- `options(&self)`: copies the lookup list, transport and relay URLs out of the parsed arguments. `main` calls `options()` and then uses `args` again (for `produce`), so the method must borrow. Taking `self` would break that call.
