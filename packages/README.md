# `packages/` — fofoca from JavaScript

Three packages, so a JS or TS program can join a mesh, send messages, read the
roster and merge the shared document without writing any Rust.

| | |
|---|---|
| [`fofoca-api`](fofoca-api) | The contract, and the machinery both backends share. No runtime dependencies, and no way to join a mesh. |
| [`fofoca-wasm`](fofoca-wasm) | A browser tab. Runs the engine as WebAssembly over the WebRTC transport. |
| [`fofoca-ffi`](fofoca-ffi) | Bun, Deno and Node. `dlopen`s the C ABI in [`crates/fofoca-ffi`](../crates/fofoca-ffi) and gets mDNS, the mainline DHT and the relay ladder. |

Two backends because the two hosts reach the engine differently: a tab has no
UDP socket, a terminal has real ones. They meet on the mesh because both speak
`fofoca::membership` (in [`crates/fofoca`](../crates/fofoca)), which exists as
one module for exactly that reason.

```ts
import { join } from 'fofoca-ffi' // or 'fofoca-wasm'

await using mesh = await join({ topic: 'star-lake', nick: 'caio' })
await mesh.send('hello')

for await (const message of mesh.messages()) {
  console.log(`${message.from}: ${message.text}`)
}
```

## Two things that surprise people

**`join({ topic })` is always public.** A topic mesh is reached over mDNS, the
mainline DHT and the relay ladder, and that is not a default you can change.
The engine mixes the lookup set into the mesh id, so two peers reaching the
same string over different lookups derive two different meshes and never
meet. `JoinOpts` therefore carries no `lookup` — the two choices it does
carry, `transport` and `relayUrls`, are exactly the two that are mixed into
the id, and every member must pass the same values.

**`create({})` is machine-local.** Naming no lookup is not "the default set"
— it resolves to a loopback mesh nothing off this machine can reach. That is
what makes the offline two-peer test possible, and it is surprising
everywhere else. Name the lookups you want: `lookup: ['mdns', 'dht',
'relay']` is the all-on set a topic uses.

**The relay carries no data unless you say so.** Three lists name three
concepts. `lookup: ['relay']` uses the relay as a *lookup*: a meeting point
where peers find each other. Payload then goes peer to peer, and a pair that
cannot open a direct path stays unlinked for data. `transport: ['p2p',
'relay']` lets payload fall back to the relay; it is part of the mesh id, so
joiners inherit whatever the creator chose. `relayUrls` says *which* relay
and nothing about its role.

## Byte streams

A mesh carries short text messages. To move bytes from one peer to one other,
use a stream: it never rides the gossip. By default it rides a direct path (a
WebRTC data channel from a tab), and with `transport: ['p2p', 'relay']` it can
fall back to the relay (the node must also name `relay` among its lookups; a
browser always does).

A write waits for the reader to attach, so the two ends run in two places:
here, two tabs.

```ts
// The producing tab.
import { bindStreams } from 'fofoca-wasm'

const producer = await (await bindStreams({ lookup: ['relay'] })).create()
share(producer.hash) // whoever holds the hash can read the stream, once
await producer.write('hello') // waits here until the reader attaches
await producer.close()
```

```ts
// The reading tab, given the hash.
import { bindStreamsFor } from 'fofoca-wasm'

const reader = await (await bindStreamsFor(hash)).open(hash)
for await (const chunk of reader) { … }
```

[`fofoca-stream-web`](fofoca-stream-web) is a page built on this: it reads the
stream in its URL fragment, or produces one. The `fofoca-stream` binary
(`crates/fofoca-stream-cli`) is the terminal end.

## The harness page

`fofoca-wasm` ships a driverless test page: build the wasm
(`cargo task build-wasm`), serve it
(`bun run harness -- 3000`), and open

```
http://127.0.0.1:3000/?topic=room&transport=p2p&log=fofoca=info
```

The page joins the mesh the query names and mirrors the roster, every message,
every event and the shared state into the DOM; `window.harness` exposes
`send`/`stateMerge`/`close`. `cargo task e2e --suite mesh` drives
this page against a real native peer and a local relay — the native↔web
matrix.

## The workspace

The root `package.json` globs `packages/*` and `examples/chat/*`. It must never
reach into `crates/*/examples/`: light-cycles' `web/` is a Bun workspace root of
its own, with `"workspaces": ["vendor/*"]`, and two overlapping workspaces make
`bun install` resolve the vendored packages twice. `package.json` cannot carry
comments, which is why that rule is written down here.

Every package is `private: true` and points its `exports` at `.ts` source rather
than built output — the shape light-cycles' own `web/vendor/*` already uses.
Publishing needs a build step, for a reason worth knowing: Node refuses to strip
types from a file whose real path is inside `node_modules`, and only the Bun
workspace symlink is what keeps `fofoca-ffi`'s worker loadable under Node today.
