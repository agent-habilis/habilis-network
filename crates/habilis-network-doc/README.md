# habilis-network-doc

The shared-document engine behind the `state` and `meta` channels.

Each channel is an [automerge](https://automerge.org) CRDT. A local write
is an RFC 7386 JSON merge, translated into one automerge change. Peers
exchange changes and automerge merges them without conflicts.

- Every change travels inside a signed message and is authorized before
  it touches the live document.
- `SelfWriteGate` applies each change to a throwaway fork first and
  rejects it if it would alter the gated field of another peer's slot.
  The other fields of a slot are not gated.
- Changes that arrive before their causal dependencies wait in a pending
  buffer and drain through the same gate.

See `src/lib.rs` for the API: `MeshDoc`, `SelfWriteGate`, and the body
codec functions.
