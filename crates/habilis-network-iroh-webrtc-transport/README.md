# habilis-network-iroh-webrtc-transport

An iroh custom transport that carries QUIC datagrams over a WebRTC data
channel, on the host and in the browser. One data channel per peer, one
QUIC datagram per SCTP message, no extra framing. The channel is
unreliable and unordered: QUIC above it owns loss recovery.

One crate, two backends behind features, neither on by default:

- `native` — str0m (sans-io) driven by tokio, with its own STUN gathering.
- `web` — the browser's `RTCPeerConnection` via web-sys.

The protocol half (the JSEP envelope, the transport id, the address
convention) is always compiled, so the two backends cannot drift.
Signaling rides the iroh relay: there is no signaling server. TURN is
refused; a peer that cannot pair directly falls back to the iroh relay.

Start with [`examples/chat-webrtc`](examples/chat-webrtc): a chat room a
browser tab and a terminal both join. See `src/lib.rs` for the API.

## Building for wasm on macOS

`ring`'s C core does not compile for wasm32 with Apple clang. Use
Homebrew LLVM:

```bash
CC=/opt/homebrew/opt/llvm/bin/clang \
CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang \
AR=/opt/homebrew/opt/llvm/bin/llvm-ar \
cargo check -p habilis-network-iroh-webrtc-transport --features web --target wasm32-unknown-unknown
```
