# fofoca-bench-wasm

The browser side of `cargo task benchmark`: two iroh endpoints in two
separate browser processes, one QUIC stream over the WebRTC data channel,
and a page (`www/index.html`) that exposes the negotiation and the transfer
on `window.bench` so the runner can drive it over CDP.

`www/raw.html` is the same surface over a bare `RTCDataChannel`, with no
wasm and no QUIC: the ceiling the transport is measured against.

Built and served by the runner; see `tasks/src/bench.rs`.
