/**
 * Serve the chat page: bundle `src/chat.ts` once at startup with Bun's own
 * bundler and serve it beside `index.html` and the generated wasm under
 * `packages/fofoca-wasm/wasm/`. The same shape as the harness's server —
 * no HMR, no watch.
 *
 *   bun run serve [port]          # from examples/chat/web
 *
 * Without a port it takes 3010, or the next free port up to 3019; a named
 * port is bound exactly or not at all.
 *
 * The wasm glue must exist first (`cargo task build-wasm`).
 */

import { join } from 'node:path'
import { serveOnLadder } from '../../../scripts/serve-ladder.ts'

const root = import.meta.dir
const explicit = process.argv[2] === undefined ? undefined : Number(process.argv[2])

const built = await Bun.build({
  entrypoints: [join(root, 'src', 'chat.ts')],
  target: 'browser',
})
if (!built.success) {
  console.error('chat bundle failed:')
  for (const log of built.logs) {
    console.error(String(log))
  }
  process.exit(1)
}
const bundle = built.outputs[0]
if (!bundle) {
  console.error('chat bundle produced no output')
  process.exit(1)
}
const chatJs = await bundle.text()

const wasmDir = join(root, '..', '..', '..', 'packages', 'fofoca-wasm', 'wasm')

function contentType(path: string): string {
  if (path.endsWith('.wasm')) return 'application/wasm'
  if (path.endsWith('.js')) return 'text/javascript'
  if (path.endsWith('.html')) return 'text/html'
  return 'application/octet-stream'
}

const server = serveOnLadder(explicit, 3010, (port) =>
  Bun.serve({
    port,
    async fetch(request) {
      const url = new URL(request.url)
      const path = url.pathname
      if (path === '/' || path === '/index.html') {
        return new Response(Bun.file(join(root, 'index.html')), {
          headers: { 'content-type': 'text/html' },
        })
      }
      if (path === '/chat.js') {
        return new Response(chatJs, { headers: { 'content-type': 'text/javascript' } })
      }
      // The generated glue imports `fofoca_wasm_bg.wasm` relative to itself,
      // and the bundle imports the glue by URL — both land here.
      if (path.startsWith('/wasm/')) {
        const file = Bun.file(join(wasmDir, path.slice('/wasm/'.length)))
        if (await file.exists()) {
          return new Response(file, { headers: { 'content-type': contentType(path) } })
        }
      }
      return new Response('not found', { status: 404 })
    },
  }),
)

console.log(`chat on http://127.0.0.1:${server.port}/ (wasm from ${wasmDir})`)
