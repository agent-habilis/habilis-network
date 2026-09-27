# fofoca-stream

Byte streams between two peers, addressed by a hash. It does not use gossip.

A producer creates a stream and gives its hash to one consumer. The consumer
opens the stream with that hash. The bytes go over one QUIC stream on a direct
path: hole-punched UDP, or a WebRTC data channel when a browser is on either
end. QUIC keeps the bytes in order and paces the producer to the consumer.

A stream is 1-1. Its hash admits exactly one consumer, and a second consumer
gets `Refused::Taken`. The hash is a bearer ticket: whoever holds it can take
the consumer slot.

The crate builds for wasm32, so a browser tab can produce or consume a stream.
It has no features. See `src/lib.rs` for the API: `StreamNode`, `Producer`,
`Reader`, `StreamHash`, and `Refused`.
