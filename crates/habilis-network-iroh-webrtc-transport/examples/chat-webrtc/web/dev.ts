/**
 * Dev server. Serves the app, serves the wasm under its content hash, and
 * rewrites `src/wasm-path.ts` whenever the Rust is rebuilt so `--hot` picks the
 * new binary up without a manual reload.
 */
import { watch } from 'node:fs'

import index from './index.html'
import { wasmAsset, wasmResponse, writeWasmPath } from './scripts/wasm-asset.ts'
import { serveOnLadder } from './scripts/serve-ladder.ts'

const WASM_DIST = `${import.meta.dir}/../chat-web/dist`
/** Rebuilds touch several files; coalesce them into one reload. */
const DEBOUNCE_MS = 150

let asset = await wasmAsset()
await writeWasmPath(asset)

const explicit = process.env.PORT === undefined ? undefined : Number(process.env.PORT)
const server = serveOnLadder(explicit, 3000, (port) =>
  Bun.serve({
    port,
    routes: {
      // Ahead of the catch-all on purpose: a request for a hash we no longer
      // hold must 404, not fall through to `index.html` and reach the runtime as
      // a `.wasm` whose first bytes are `<!do`.
      '/wasm/:name': (request) => {
        if (request.params.name !== asset.name) {
          return new Response('stale wasm — reload the page', { status: 404 })
        }
        return wasmResponse(asset)
      },
      '/*': index,
    },
    development: { hmr: true, console: true },
  }),
)

let pending: ReturnType<typeof setTimeout> | undefined
watch(WASM_DIST, () => {
  clearTimeout(pending)
  pending = setTimeout(async () => {
    try {
      asset = await wasmAsset()
      await writeWasmPath(asset)
      console.log(`wasm ${asset.name}`)
    } catch (error) {
      console.error(error)
    }
  }, DEBOUNCE_MS)
})

console.log(`dev ${server.url}`)
console.log(`wasm ${asset.name}`)
console.log('open the URL the room printed, or paste a ticket into the page')
