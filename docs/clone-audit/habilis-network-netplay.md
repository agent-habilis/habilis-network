# Clone and Arc audit: habilis-network-netplay

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-netplay/src`, up to the first test region.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every site with its enclosing function.

## Result

- B3: 19 sites before, 18 after. One removed: `publish_checksum` sends to each peer in the loop that builds the message, with a borrowed address, instead of collecting owned address and message pairs first and sending in a second loop. The send order is the same.
- B1: 13 sites before, 13 after. No change.

## Sites kept (B3)

- The lobby keeps its own nickname and the copy in its presence record (two owners). Its presence message, the presence list, the duplicate-nickname error and the announcement copy borrowed fields into owned values.
- `propose`: the player list is returned in the message and also passed to `adopt`, which stores it.
- The mesh transport's `Clone` impl and the directory snapshot: the clone shares the mailboxes, and the snapshot copies nicknames out of the lock before they are used.
- Rollback driver: the directory entry owns the author's nickname (the frame is borrowed); the nickname lookup is copied out of the lock before the await.
- Peer replies and events: the address is copied per reply or event into an owned value (the reply list and the event enum own their addresses). The event copies a generic address that the type only knows as `Clone`.
- `StateCell::load` copies the state out of the cell's lock. `SavedStates::push` and `by_frame` return a handle to a shared cell, which is a second owner of the ring slot.

## Sites kept (B1)

- The mailboxes are shared by the driver, the pending transport and each transport clone. The state cell is shared by every handle to it. Each `Arc::clone` is a second owner.
