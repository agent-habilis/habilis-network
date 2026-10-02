# habilis-network-stream-web

The stream's web app: one end of one byte stream in a tab. With a hash in the
URL it reads that stream; without one it creates a stream, shows its hash, and
writes what you type. The bytes ride a direct path by default (a WebRTC data
channel from a tab), the relay only with `?transport=udp,webrtc,relay`, and never
gossip. The page exposes its runtime to whoever drives the tab:
a person at the composer, a browser agent through WebMCP, or a script through
`window.stream`.

## Run

```sh
cargo task build-wasm                          # the wasm glue, once
bun run --cwd packages/habilis-network-stream-web serve # 3020, or the next free port; prints the URL
```

Then, in a terminal, with the URL the server printed:

```sh
cat lorem.txt | habilis-network-stream --web-url http://127.0.0.1:3020/
```

The CLI prints `open http://127.0.0.1:3020/#<hash>`. Open that URL to read the
stream. The hash rides in the fragment, which a browser never sends to the
server. To send from the tab instead, open the page with no fragment, copy the
hash it shows, and run `habilis-network-stream <hash> > out.txt`.

## Deploy

```sh
bun run --cwd packages/habilis-network-stream-web build   # packages/habilis-network-stream-web/dist/
```

`dist/` is static: `index.html`, `main.js` and the wasm glue under `wasm/`.
Any static host serves it. Point the CLI at the host with `--web-url` or
`HABILIS_NETWORK_STREAM_WEB`.

## URL

- `#<hash>` — read this stream. The hash carries the producer's lookups.
- no fragment — produce a stream. `?relay=` sets a custom relay URL
  (repeatable), and `?transport=udp,webrtc,relay` lets the bytes fall back to the
  relay.
- `?log=` — an `EnvFilter` for the engine's tracing, to the console.

## WebMCP

When the browser has `document.modelContext` (or the older
`navigator.modelContext`), the page registers four tools. Without it, the
same functions are on `window.stream`.

| Tool | Does |
| --- | --- |
| `stream_write` | Write `text` to the stream this tab produces. It waits for the reader, then for room. |
| `stream_close` | End that stream: the reader gets everything, then the end. With no reader yet, the stream is abandoned. |
| `stream_read` | What has arrived on the stream this tab reads, in order, plus a `cursor` to continue from. Reading takes nothing away. When nothing waits, wait up to `waitMs` (at most 25000) for the first entry. `encoding: "base64"` returns bytes that are not text, exactly. |
| `stream_status` | The role, whether the reader attached, whether the stream ended (or why it stopped), the bytes so far, and the read log's cursors. A producing tab also gets the hash, a secret: whoever presents it first becomes the one reader. |

WebMCP has no streaming: a tool is one promise. `stream_read` is the closest
thing: an agent that wants to follow a stream calls it in a loop, passing back
the `cursor` it got. An item with `eof: true` is the end.

The read log is bounded by bytes held (4 MB), not by what anyone has read.
Past that the oldest entries age out, and `oldestCursor` in `stream_status`
says where a reader that fell behind actually resumes.

Two facts about Chrome's implementation (Chrome for Testing 152 ships
`document.modelContext` on): `executeTool` takes the `RegisteredTool` object
from `getTools()`, not a name, and its arguments as a JSON **string**; the
result comes back as a JSON string of `{content: [...]}`.

## Files

- `src/runtime.ts` — `StreamRuntime`, DOM-free: decodes the stream's text,
  keeps the read log, writes for a producer.
- `src/webmcp.ts` — the tool descriptors and the registration.
- `src/main.ts` — the page: URL, DOM, `window.stream`.
- `serve.ts` — the dev server. `build.ts` — the static build.
