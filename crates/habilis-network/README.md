# habilis-network

The serverless gossip-network engine. It moves, signs, routes, and heals
bytes between peers. It does not know what the bytes mean.

Peers find each other without a server and form a partial mesh over
[iroh](https://github.com/n0-computer/iroh) QUIC links. The mesh survives
creator departure, sleep, network switches, and churn. Every frame carries
an Ed25519 signature, verified on receipt.

An application implements two traits: `gossip::app::NodeApp` (inbound
frames) and `daemon::app::NodeDriver` (timers and lifecycle). A minimal
receive-only consumer is about 40 lines. See `examples/mesh_peer.rs`.

- The payload stays opaque. The engine routes on a frame's tag and
  addressee. It never parses the body.
- No `iroh` type must cross a consumer's public surface. Consumers reach
  iroh through `habilis_network::iroh`.
- Put an explicit `target: "habilis_network::<subsystem>"` on every `tracing`
  call. A line without a pinned target is dropped from release builds.
- There is no environment-variable configuration. Every knob is a `const`
  in `util::consts`. Only `RUST_LOG` and `NO_COLOR` are read.

Not a general-purpose networking library, and not a bulk-transfer system.
See `src/lib.rs` for the API and the subsystem map.
