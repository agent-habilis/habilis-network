# habilis-network-chunks

Content-addressed chunks over data you already own.

A file is a merkle leaf row: fixed 64 KiB chunks, each addressed by `blake3` of
its own bytes, plus an ordered list of those addresses that names the file.

- **A chunk proves itself.** Hash what arrived, compare it to the address you
  asked for. No proof, no tree walk, no outboard.
- **The store never chooses where bytes live.** An origin's file stays where the
  user put it; the store holds addresses beside it and reads through.

No transport, no discovery, no scheduler, no manifests. It takes a hash, some
bytes and a chunk map. See `tests/isolation.rs`.
