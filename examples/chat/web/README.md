# chat · web

Browser chat over the fofoca mesh: a page on
[`packages/fofoca-wasm`](../../../packages/fofoca-wasm), which runs the engine
as WebAssembly. One of the side-by-side chat clients under `examples/chat/` —
they all meet in the same mesh, so a tab and a terminal chat to each other.

## Run

```sh
cargo task build-wasm    # once, builds the browser peer
bun install              # once, at the repo root

bun run serve            # 3010, or the next free port up to 3019; open the printed URL
bun run serve 4000       # exactly 4000, or fail
```

`serve.ts` bundles `src/chat.ts` on each request and serves the wasm glue from
`packages/fofoca-wasm/wasm/`, so a page reload picks up an edit with no build
step. Without `cargo task build-wasm` there is no glue to serve.

## Selectors

Query parameters, the browser half of the flags the terminal client takes:

| | |
|---|---|
| `?topic=<string>` | join a public topic mesh — every member must pass the same string |
| `?id=<base58>` | or join a mesh by id |
| `?nick=<name>` | the nickname to request; the engine may assign another |
| `?relay=<url>` | a custom relay ladder, repeatable. Part of the derived id, so every member must pass the same list |
| `?transport=p2p,relay` | let payload fall back to the relay. Part of the id too |
| `?log=<level>` | engine tracing level, `warn` by default |

The relay stays a lookup unless `transport` names it: a tab has no UDP
socket, so payload waits for a WebRTC session rather than riding the relay.

`cargo task e2e --suite chat` drives this page against the terminal client.
