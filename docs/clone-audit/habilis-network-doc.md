# Clone and Arc audit: habilis-network-doc

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-doc/src`, counted up to the first `cfg(test)` or `#[test]` line.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every site with its enclosing function.

## Result

- B3: 1 site before, 0 after. The `change_body` serializer took `merge` by clone; `StateOp` now holds a `Cow<'_, Value>` for the change merge, so serialization borrows and the owned value is still produced when a body is parsed.
- B1: 0 sites.

## Sites kept

None.
