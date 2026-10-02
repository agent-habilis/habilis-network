/** Production build into `dist/`. Adapted from chat-webrtc's `web/build.ts`. */
import { wasmAsset, writeWasmPath } from './scripts/wasm-asset.ts'

const asset = await wasmAsset()
await writeWasmPath(asset)

const result = await Bun.build({
  entrypoints: ['./src/index.html'],
  outdir: './dist',
  minify: true,
  target: 'browser',
})

if (!result.success) {
  for (const log of result.logs) console.error(log)
  process.exit(1)
}

// Copied by hand: Bun inlines the wasm-bindgen glue but leaves the binary
// behind a `new URL(..., import.meta.url)` it does not follow, and we want it
// at the hashed path the client asks for anyway.
await Bun.write(`./dist${asset.path}`, asset.bytes)

console.log(`built dist/ with ${asset.name}`)
