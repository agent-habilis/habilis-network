# Clone and Arc audit: habilis-network-iroh-webrtc-transport

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network-iroh-webrtc-transport/src`, up to the first test region. The native and browser builds share the crate; both are counted.
- Count method (B1): `Arc` or `Rc` in the same lines.
- Read in full: yes, every site with its enclosing function.

## Result

- B3: 25 sites before, 25 after. No change.
- B1: 60 sites before, 60 after. No change.

## Sites kept (B3)

- Copies out of a registry lock (`with_live` closures returning a peer connection, an output sender, or counters): the lock is released before the copy is used.
- Copies for `FnMut` closures and spawned tasks (`watch_connection_state`, the connection-state hook, the data-channel pump, the inbound pump, the remove-on-close hooks): each closure call needs its own owned handle, and the closure keeps the original.
- Handles shared between the session keepalive and the spawned task (the data channel, the peer connection in the watch): both owners are used afterwards.
- Stats values taken from the stats map (`selected_pair_from_stats`) and returned while the map keeps its copy.
- The `data` value cloned before `dyn_into`, because the fallback cast reads it again.
- The JSEP early handler: a JS function reference moved into the closure while the closure object is kept for the connection's lifetime.
- The STUN server name: copied for the resolver and for the task that reports the result (`gather_with_resolver`); the configuration is borrowed.
- Owned copies of borrowed fields returned in errors (`signal_envelope`), the watchable address of the endpoint, and the local address copied into each receive record.

## Sites kept (B1)

- The session registry, the counters and the hub are shared between the transport, the endpoint, the sender, the handle and each session task. Each `Arc::clone` is a second owner.
- Trait objects that iroh takes by `Arc`: the path selector, the custom sender, the crypto provider.
- The `Rc` backlog and the JSEP callbacks: the backlog is shared between the early handler and the pending answer.
