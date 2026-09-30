# habilis-network-ffi

A C ABI over the [`habilis-network`](../habilis-network) engine. A C program links one
library, calls a dozen functions, and is a full mesh member. The event
loop runs inside the caller's process. No daemon, no socket.

[`include/habilis_network.h`](include/habilis_network.h) is the committed declaration and
the counterpart of [`src/ffi.rs`](src/ffi.rs). If you change one, change
the other.

- A failed call returns NULL or `-1`. `habilis_network_last_error()` says why. The
  error slot is thread-local.
- Buffers are sized by asking: pass a NULL buffer to get the length, then
  call again with one that fits.
- A handle belongs to one thread. Distinct handles are independent.
- The crate installs no signal handlers. Trap signals yourself and call
  `habilis_network_close`.
- Every entry point catches panics, so an engine panic returns an error
  code instead of unwinding across `extern "C"`.
- `habilis_network_opts` takes four comma-separated lists, one concept each:
  `lookup` (`"mdns,dht,relay,pkarr"`, any subset) is how members find each other,
  `transport` (`"udp,webrtc,relay"`, any subset with `udp` or `webrtc`) is
  what payload may ride, and `relay_urls` is which relay (NULL for the
  default ladder), and `pkarr_urls` is which pkarr relays (NULL for the
  default list; needs `pkarr` in `lookup`). `relay` in `transport`, or a list without `udp`, needs
  `relay` in `lookup`: the relay carries the payload in the first case and
  the WebRTC handshake in the second. Leave
  `transport` NULL and every byte of data goes peer to peer, over UDP or a
  WebRTC data channel.

Test with `cargo test -p habilis-network-ffi`. CI builds the staticlib and makes
sure that every function in the header is exported.

Not a stable ABI, and not published. See `src/lib.rs` for the API.
