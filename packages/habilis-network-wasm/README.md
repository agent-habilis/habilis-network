# habilis-network-wasm (package)

habilis-network in a browser tab: the engine compiled to WebAssembly, over the WebRTC
transport. The Rust half is [`crates/habilis-network-wasm`](../../crates/habilis-network-wasm),
a wasm-bindgen class over `habilis_network::membership` — the same
contract [`habilis-network-ffi`](../habilis-network-ffi) speaks from a terminal, which is why a
tab and a terminal meet on one mesh.

The `join` / `create` entry point lives in `src/index.ts`. `src/backend.ts` is
the [`habilis-network-api`](../habilis-network-api) backend over the wasm class, and
`src/module.ts` loads the wasm-bindgen glue through a dynamic import with a
hand-declared shape — so `tsc` never needs the generated files.

A tab has no UDP socket. Every path is a WebRTC session negotiated over the
relay, and on a lookup-only mesh — the default — payload waits for that session
rather than falling back to the relay.

Build the wasm first, then the harness page serves:

```sh
cargo task build-wasm         # writes wasm/, which is gitignored
bun install                   # once, at the repo root
bun harness/serve.ts          # then open the printed URL
```

`harness/` is a driverless page: it mirrors peers, messages, events and state
into the DOM so a test can read the mesh with no JS bridge.
`cargo task e2e --suite mesh` drives it against a real native peer.

See [`../README.md`](../README.md) for the workspace rules.
