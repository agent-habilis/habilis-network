#!/usr/bin/env bun
/**
 * Terminal chat over the habilis-network mesh, on `packages/habilis-network-ffi`.
 *
 * Human mode is a readline loop; `--json` is the NDJSON automation contract.
 * Needs the native library: `cargo build --release -p habilis-network-ffi`.
 */

import { create, join, type Mesh } from 'habilis-network-ffi'
import { parseChatArgs, USAGE } from './args.ts'
import { runHuman } from './human.ts'
import { runJson } from './json.ts'

let args
try {
  args = parseChatArgs(process.argv.slice(2))
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error))
  console.error()
  console.error(USAGE)
  process.exit(2)
}

let mesh: Mesh
try {
  mesh = args.entry.kind === 'create' ? await create(args.entry.opts) : await join(args.entry.opts)
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error))
  process.exit(1)
}

process.on('SIGINT', () => {
  void mesh.leave().finally(() => process.exit(0))
})

if (args.json) {
  await runJson(mesh)
} else {
  await runHuman(mesh)
}
process.exit(0)
