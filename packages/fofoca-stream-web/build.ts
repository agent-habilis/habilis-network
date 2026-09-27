/**
 * The static build: `dist/` holds `index.html`, the bundled `main.js` and the
 * wasm glue under `dist/wasm/`, so any static host serves the page. The glue
 * lands at the same relative path the dev server serves it from, which is
 * what the bundle's `../wasm/fofoca_wasm.js` import resolves against.
 *
 *   bun run build                 # from packages/fofoca-stream-web
 *
 * The wasm glue must exist first (`cargo task build-wasm`).
 */

import { copyFile, mkdir } from 'node:fs/promises'
import { join } from 'node:path'

const root = import.meta.dir

export const wasmDir = join(root, '..', 'fofoca-wasm', 'wasm')
const glueFiles = ['fofoca_wasm.js', 'fofoca_wasm_bg.wasm']

export function contentType(path: string): string {
  if (path.endsWith('.wasm')) return 'application/wasm'
  if (path.endsWith('.js')) return 'text/javascript'
  if (path.endsWith('.html')) return 'text/html'
  return 'application/octet-stream'
}

/** Bundle `src/main.ts` for the browser; the text of `main.js`. */
export async function bundle(): Promise<string> {
  const built = await Bun.build({
    entrypoints: [join(root, 'src', 'main.ts')],
    target: 'browser',
  })
  if (!built.success) {
    console.error('stream page bundle failed:')
    for (const log of built.logs) {
      console.error(String(log))
    }
    process.exit(1)
  }
  const output = built.outputs[0]
  if (!output) {
    console.error('stream page bundle produced no output')
    process.exit(1)
  }
  return output.text()
}

if (import.meta.main) {
  const dist = join(root, 'dist')
  await mkdir(join(dist, 'wasm'), { recursive: true })
  await Bun.write(join(dist, 'main.js'), await bundle())
  await copyFile(join(root, 'index.html'), join(dist, 'index.html'))
  for (const file of glueFiles) {
    await copyFile(join(wasmDir, file), join(dist, 'wasm', file))
  }
  console.log(`built ${dist}`)
}
