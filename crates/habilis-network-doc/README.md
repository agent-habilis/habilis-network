# habilis-network-doc

The shared-state store behind the `state` and `meta` channels.

Each channel holds one signed slice per author key. Only the author
writes its own slice. A slice is a JSON object with a version and a
value, and the store keeps each slice at its newest version.

- Every slice travels inside a signed message. The store takes a slice
  only from the key that signed it.
- A slice of a key that said goodbye is refused. A key that lost its
  nickname keeps its slice in a pending set until it returns.
- A slice of a key outside the roster, or of a lapsed key, waits in a
  pending set, bounded in count and in time, until the key joins or returns.
- A value past one frame is a pointer to chunks (`ChunkPointer`). The view
  keeps the last complete value of an author until the new one is fetched.
  The encoded value is 1 MiB at most.

See `src/lib.rs` for the API: `SliceStore`, `SliceLimits`, and the
sealed-body functions in `wire`.
