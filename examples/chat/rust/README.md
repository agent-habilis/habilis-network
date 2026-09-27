# chat · rust

The native half of the chat example: a terminal chat on `fofoca::membership`. It is
the `chat` package, a workspace member, so the e2e suite builds it as
`-p chat --bin chat` against the shared lockfile.

## Run

```sh
cargo run -p chat -- --topic room --nick terminal
```

Flags: `--topic <string>` or `--mesh <id>` selects the mesh; `--nick <name>`;
`--relay-url <url>` (repeatable) swaps in a custom relay ladder;
`--transport p2p,relay` lets payload fall back to the relay; `--robot` turns
the terminal chat into the NDJSON automation contract the e2e suite drives.

Commands once connected: type to broadcast, `/msg <nick> <text>`, `/peers`,
`/quit`.
