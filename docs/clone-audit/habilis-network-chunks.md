# Clone and Arc audit: habilis-network-chunks

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-chunks/src`, up to the first test region.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every site with its enclosing function.

## Result

- B3: 15 sites before, 15 after. No change.
- B1: 0 sites.

## Sites kept

- Copies taken out of a locked map (`files`, `chunks`, `maps`, the binds snapshot in the disk store): the copy is used after the lock is released, so the lock is not held while the value is used.
- Map keys and stored values copied from borrowed arguments (`file.key`, `file`, the chunk map): the store owns them after the call.
- IndexedDB request handles (`request.clone()` in the watcher and in the open routines): each handle is moved into a closure that runs later, and the original is still used by the caller.
- The bind list in the IndexedDB store: the key is copied from the borrowed file into an owned tuple.
