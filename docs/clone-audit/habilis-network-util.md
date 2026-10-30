# Clone and Arc audit: habilis-network-util

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-util/src`, up to the first test region.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every site with its enclosing function.

## Result

- B3: 2 sites before, 2 after. No change.
- B1: 0 sites.

## Sites kept

- `bounded_fifo_set` insert: the item is copied into the set and moved into the order queue. Two owners: the set's membership check and the eviction order both keep the value.
- `log_config` config: returns an owned default config copied out of a static `OnceLock`. The static cannot be moved out.
