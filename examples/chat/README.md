# The chat example — one mesh, every client surface

A small chat application in side-by-side variants that all meet on one mesh.
It exists for testing: it is the library's own claim — native↔web p2p — as a
program a person can run, and the same program the e2e suite drives.

| | |
|---|---|
| [`rust/`](rust) | The native half: a terminal chat on `fofoca::membership`, the `chat` package. |
| [`web/`](web) | The browser half: `fofoca-wasm` behind a chat page. |
| [`bun-ffi/`](bun-ffi) | A terminal chat in TypeScript: Bun on `packages/fofoca-ffi`, which `dlopen`s the C ABI. |

There is no `bun-wasm/` variant: the wasm engine is the *web* implementation,
and outside a browser its direct lane has no WebRTC to stand on.

## Run it yourself

Build the wasm once, serve the page, start a terminal peer, meet on a topic:

```sh
cargo task build-wasm                              # once, and after engine changes
cd examples/chat/web && bun run serve              # prints its URL, 3010 or the next free port
cargo run -p chat -- --topic room --nick terminal
```

A third peer from Bun, on the C ABI:

```sh
cargo build --release -p fofoca-ffi                # once
cd examples/chat/bun-ffi && bun run start --topic room --nick bun
```

Open the printed URL with `?topic=room&nick=browser` and chat. Type to
broadcast; `/msg <nick> <text>` sends a direct message (`relay-only` peers
refuse it by design — payload never rides the relay unless the mesh says
so); `/peers` prints the roster; `/quit` leaves.

Both halves accept the same selectors: a `topic` everyone shares, or a
`mesh` id. `--relay-url <url>` / `?relay=<url>` swaps in a custom relay ladder
and is part of the derived id, so every member must pass the same list.
`--transport p2p,relay` / `?transport=p2p,relay` lets payload fall back to
the relay — same rule.

## The e2e suite

```sh
cargo task e2e --suite chat
```

drives exactly what a person runs: a local relay, the native chat in
`--robot` mode (one JSON object per line instead of prose) on its stdin and
stdout, and the served page through a real browser — asserting a message
typed on each side arrives on the other.
