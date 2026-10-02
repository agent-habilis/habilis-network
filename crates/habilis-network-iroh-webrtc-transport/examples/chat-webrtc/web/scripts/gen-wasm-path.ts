/** Regenerate `src/wasm-path.ts`, so `tsc` has something to resolve. */
import { wasmAsset, writeWasmPath } from './wasm-asset.ts'

await writeWasmPath(await wasmAsset())
