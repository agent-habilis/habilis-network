# habilis-network-stream (the binary)

Stdin to one reader, or a stream's bytes to stdout. The bytes go over a
direct path by default (hole-punched UDP, or a WebRTC data channel when a
browser reads or writes), over the relay only with `--transport udp,webrtc,relay`,
and never through gossip.

```sh
cat lorem.txt | habilis-network-stream --web-url http://127.0.0.1:3020/
habilis-network-stream <hash> > received.txt
```

With stdin piped in, the binary creates a stream and prints its hash, and
`open <url>#<hash>` when `--web-url` is set, to stderr. It waits for the one
reader, streams stdin to it, and ends the stream at EOF. The reader paces the
writer, so a slow reader slows the stream down instead of losing bytes.

With a hash as the argument, it reads that stream to stdout and exits at its
end. A stream has exactly one reader: a second one is refused.

Stdout is the stream and nothing else. Every word the binary has to say goes
to stderr, as prose or, with `--robot`, as one JSON object per line
(`{"kind":"ready","hash","url"}` first).

The producer's options: `--lookup` (`mdns,dht,relay` by default; add `pkarr`
for the pkarr relays, and `--pkarr-url` for a custom list of them),
`--transport` (`udp,webrtc` by default; add `relay` for a fallback), and `--relay-url` for a custom relay
ladder. A reader takes all of these from the hash.

The crate is a sibling of `habilis-network-stream` rather than a `[[bin]]` in it: that
crate is built for wasm32 by the gate, and a binary needs the tokio runtime.
