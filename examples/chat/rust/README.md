# chat · rust

The native half of the chat example: a terminal chat on `habilis_network::membership`. It is
the `chat` package, a workspace member, so the e2e suite builds it as
`-p chat --bin chat` against the shared lockfile.

## Run

```sh
cargo run -p chat -- --topic room --nick terminal
```

Flags: `--topic <string>` or `--mesh <id>` selects the mesh; `--nick <name>`;
`--relay-url <url>` (repeatable) swaps in a custom relay ladder;
with neither `--topic` nor `--mesh` the chat creates a mesh, and
`--lookup mdns,dht,relay,pkarr` (any subset) says how its members find each other, and
`--pkarr-url <url>` (repeatable, create only) swaps in custom pkarr relays for the default
list. A topic always uses all four lookups with the default pkarr list;
`--transport udp,webrtc,relay` lets payload fall back to the relay. The relay ladder, the
pkarr list and the transport are part of the mesh id. `--robot` turns the terminal chat into the NDJSON automation contract the e2e suite
drives.

Commands once connected: type to broadcast, `/msg <nick> <text>`, `/peers`,
`/quit`.
