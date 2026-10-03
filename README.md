# `habilis-network` 📡

https://habilis.network

A portable, serverless gossip-network engine that runs on the web and on
native. Peers find each other, form a mesh, and exchange signed messages and
shared state, with no server in the middle. It is built on
[iroh](https://github.com/n0-computer/iroh) for transport and
[automerge](https://automerge.org) for shared state.

## Features

- **Portable** — runs on native, web, FFI, wasm and more.
- **Mixed mesh** — UDP, relay server and WebRTC peers in the same mesh.
- **Serverless** — no server to host, no account to create.
- **Finds peers its own way** — through mDNS, the mainline DHT, pkarr relays
  or a relay, and a peer's endpoint id alone is enough through pkarr.
- **Encrypted** — every link is QUIC over TLS, and every message is signed
  with an [Ed25519](https://ed25519.cr.yp.to/) key and verified on receipt.
- **Shared state** — a [CRDT](https://crdt.tech/) document every member
  converges on.
- **Self-healing** — the mesh re-forms as peers come and go.
- **Byte streams** — direct 1-1 streams between two peers.
- **Embeddable** — joining a mesh is a function call, not a daemon.

## Crates

### Use it

| Crate | What it is |
| --- | --- |
| [`habilis-network`](crates/habilis-network) | The serverless gossip-network engine. |
| [`habilis-network-stream`](crates/habilis-network-stream) | 1-1 byte streams between two peers, addressed by a hash: QUIC direct or over a WebRTC data channel, never through gossip. |
| [`habilis-network-stream-cli`](crates/habilis-network-stream-cli) | The `habilis-network-stream` binary: stdin to one reader, or a stream's bytes to stdout. |
| [`habilis-network-chunks`](crates/habilis-network-chunks) | Content-addressed chunks over data you already own. |
| [`habilis-network-netplay`](crates/habilis-network-netplay) | GGPO-style rollback netcode for peer-to-peer games on a mesh. |

### From other languages

| Crate / package | What it is |
| --- | --- |
| [`habilis-network-ffi`](crates/habilis-network-ffi) | A C-ABI shim over the engine, so a non-Rust process joins a mesh in-process. |
| [`habilis-network-wasm`](crates/habilis-network-wasm) | The mesh peer for the browser, behind a wasm-bindgen class. |
| [`habilis-network-api`](packages/habilis-network-api) | The TypeScript mesh API both backends implement. |
| [`habilis-network-ffi`](packages/habilis-network-ffi) (npm) | The engine on Bun, Deno and Node, over the C ABI. |
| [`habilis-network-wasm`](packages/habilis-network-wasm) (npm) | The engine in the browser, behind the `habilis-network-api` contract. |
| [`habilis-network-stream-web`](packages/habilis-network-stream-web) | One end of a byte stream in a browser tab. |
