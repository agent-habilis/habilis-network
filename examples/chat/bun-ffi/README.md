# chat · bun-ffi

Terminal chat over the habilis-network mesh: Bun on
[`packages/habilis-network-ffi`](../../../packages/habilis-network-ffi), which loads the C ABI
of `crates/habilis-network-ffi`. One of the side-by-side chat clients under
`examples/chat/` — they all meet in the same mesh.

## Run

```sh
cargo build --release -p habilis-network-ffi   # once
bun install                           # once, at the repo root

bun run start --topic star-lake --nick ana     # join a public topic mesh
bun run start --create --lookup mdns --nick ana  # or create; share the printed id
bun run start --id <base58> --nick bo          # and join it by id
```

`--lookup mdns,dht,relay` (any subset, `--create` only) says how members find
each other; none is a loopback mesh. `--relay-url <url>` (repeatable) swaps in
a custom relay ladder on `--topic` and `--create`, and `--transport udp,webrtc,relay`
lets payload fall back to the relay. Both are part of the mesh id, so every
member must pass the same values; by default the relay stays a lookup and
payload never rides it.

Human mode: type to chat, `/who`, `/state`, `/merge {json}`, `/quit`.

## Automation (`--json`)

NDJSON both ways — a stable contract for scripts and the e2e test, not a
debug view.

stdout events, one JSON object per line:

| event | shape |
|---|---|
| ready | `{"kind":"ready","id","name","nick"}` — always the first line |
| message | `{"kind":"message","from","text"\|"bytesBase64","directed","eof"}` |
| presence | `{"kind":"joined"\|"left","nick"}` |
| error | `{"kind":"error","message"}` |
| closed | `{"kind":"closed","reason"}` — terminal |
| replies | `{"kind":"peers","peers":[…]}` · `{"kind":"state","value":{…}}` · `{"kind":"ok","cmd":…}` |

stdin commands, one JSON object per line:

```json
{"cmd":"send","body":"hello","to":"bo"}   // "to" optional; omitted = broadcast
{"cmd":"peers"}
{"cmd":"state"}
{"cmd":"merge","patch":{"lunch":"yes"}}
{"cmd":"leave"}
```

EOF on stdin leaves the mesh and exits 0. The nick in `ready` is the one the
engine assigned, which is not always the one requested — automation must use
the reported one.

Example: create a mesh, hand the id to a second client:

```sh
bun run start --create --lookup mdns --json <<'EOF'
{"cmd":"peers"}
{"cmd":"leave"}
EOF
```
