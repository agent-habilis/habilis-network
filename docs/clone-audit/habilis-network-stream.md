# Clone and Arc audit: habilis-network-stream

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-stream/src`, up to the first test region.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every site with its enclosing function.

## Result

- B3: 12 sites before, 12 after. No change.
- B1: 7 sites before, 7 after. No change.

## Sites kept (B3)

- `bind_for`: the hash is borrowed, and `bind_with` takes the lookups and the transport owned.
- `bind_with`: the endpoint, the producers book and the WebRTC handle are copied into the acceptor and the node. The node keeps its own copies, which it returns. 
- `create`: the lookups and the transport are copied from `&self` into the stream hash the producer returns.
- `open`: the hash's address is copied for four uses (the book, the signal dial, the connect); the hash is read again after each copy.
- `Producer::new`: the secret is copied for the registry, while the hash keeps its own.
- `StreamAcceptor::accept`: the connection is copied into the link to the producer; the handler closes or waits on the original.

## Sites kept (B1)

- The stream registry is shared by the node, the acceptor and each producer, so it is an `Arc<Registry>`. Each `Arc::clone` is a second owner.
