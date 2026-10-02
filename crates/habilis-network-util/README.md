# habilis-network-util

Host-level helpers a consumer needs beside the mesh itself: runtime
directories, the clock, bounded containers, cooldowns, and the build
stamp.

Two files matter most:

- `src/tuning.rs` — every operator-tunable dial, each with the reasoning
  beside it.
- `src/consts.rs` — wire-fixed constants that must not change without a
  protocol version bump.

The `host` feature gates everything that needs an OS. See `src/lib.rs`
for the API.
