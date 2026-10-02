/**
 * Serve the production build, refusing to if it is stale.
 *
 * A `dist/` whose wasm hash no longer matches the one on disk is the most
 * misleading thing this example could hand someone: it runs, and it runs the
 * wrong code.
 */
import { wasmAsset } from './scripts/wasm-asset.ts'
import { serveOnLadder } from './scripts/serve-ladder.ts'

const asset = await wasmAsset()
const built = Bun.file(`${import.meta.dir}/dist${asset.path}`)
if (!(await built.exists())) {
  console.error(`dist/ does not carry ${asset.name} — run \`bun run build\` first`)
  process.exit(1)
}

const explicit = process.env.PORT === undefined ? undefined : Number(process.env.PORT)
const server = serveOnLadder(explicit, 3001, (port) =>
  Bun.serve({
    port,
    async fetch(request) {
      const { pathname } = new URL(request.url)
      const file = Bun.file(`${import.meta.dir}/dist${pathname}`)
      if (await file.exists()) {
        return new Response(file)
      }
      // Everything else is the app shell; the ticket lives in the fragment, which
      // never reaches the server anyway.
      return new Response(Bun.file(`${import.meta.dir}/dist/index.html`))
    },
  }),
)

console.log(`preview ${server.url}`)
