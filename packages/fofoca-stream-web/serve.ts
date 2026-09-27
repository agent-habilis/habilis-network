/**
 * The dev server: bundle `src/main.ts` once at startup and serve it beside
 * `index.html` and the wasm glue under `packages/fofoca-wasm/wasm/`. No HMR,
 * no watch — the same shape as the chat example's server.
 *
 *   bun run serve [port]          # from packages/fofoca-stream-web
 *
 * Without a port it takes 3020, or the next free port up to 3029; a named
 * port is bound exactly or not at all.
 *
 * The wasm glue must exist first (`cargo task build-wasm`). For a deployable
 * copy, see `build.ts`.
 */

import { join } from 'node:path'

import { bundle, contentType, wasmDir } from './build.ts'
import { serveOnLadder } from '../../scripts/serve-ladder.ts'

const root = import.meta.dir
const explicit = process.argv[2] === undefined ? undefined : Number(process.argv[2])

const mainJs = await bundle()

const server = serveOnLadder(explicit, 3020, (port) =>
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
      if (path === '/main.js') {
        return new Response(mainJs, { headers: { 'content-type': 'text/javascript' } })
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

console.log(`stream page on http://127.0.0.1:${server.port}/ (wasm from ${wasmDir})`)
