# Clone and Arc audit: habilis-network-protocol

Covers the two files assigned to this round: `messages/verified.rs` and `messages/message.rs`. The rest of the crate belongs to the anchor-stream audit and is recorded by that round.

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in each file, up to the first test region. The count in `verified.rs` includes one line inside a doc comment; the code count is 3.
- Count method (B1): `Arc` or `Rc` used as a type, a constructor or a clone, outside comments.
- Read in full: yes, every site with its enclosing function.

## messages/verified.rs

- B3: 3 code sites before, 3 after. No change.
- B1: 7 sites before, 7 after. No change.

Kept sites:

- The message behind a `Verified` is an `Arc<Message>`, so the proof and each `Authored` view share one message. This is the sharing the type is built on, and each `Arc::clone` is a second owner.
- `authored()`: the view shares the message through `Arc::clone`, because the view outlives the borrow of the proof.
- `copy_with_body` (two copies, one per impl): a copy of the message is needed to change its body, and the proof keeps its own message. The copy is taken from a borrowed proof, so there is no borrow that can do it.
- `Clone for Verified`: the impl itself.

## messages/message.rs

- B3: 3 sites before, 3 after. No change.
- B1: 0 sites.

Kept sites:

- `Message::new`: the mesh id and the author are borrowed from the caller's context and the message stores owned copies. Most callers pass borrowed values from `HandlerCtx`, so a by-value signature would add a clone at each call site.
- `new_pong`: the probe id is borrowed by callers (`&message.id`), and the `Pong` variant owns its copy.
