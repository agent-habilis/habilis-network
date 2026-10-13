/**
 * habilis-network in the browser.
 *
 * ```ts
 * import { join } from 'habilis-network-wasm'
 * const mesh = await join({ topic: 'standup' })
 * ```
 *
 * The wasm glue must exist first: `cargo task build-wasm` drops it under
 * `wasm/`.
 */

export * from 'habilis-network-api'

import { openMesh } from 'habilis-network-api'
import type { CreateOpts, JoinOpts, Mesh } from 'habilis-network-api'

import { openWasm } from './backend.ts'
import { loadWasm } from './module.ts'

export { openWasm } from './backend.ts'
export { loadWasm } from './module.ts'
export type { HabilisNetworkWasmModule, MeshPeerHandle } from './module.ts'
export { bindStreams, bindStreamsFor } from './stream.ts'
export type { Producer, Reader, StreamOpts, Streams } from './stream.ts'

/** Extras every open accepts, beside the mesh selectors. */
export interface WasmOpts {
  /**
   * An `EnvFilter` string routed to the browser console
   * (`habilis_network=info,habilis_network::lifecycle=debug`). Omit for `info`.
   */
  log?: string
  /** Where the generated wasm glue lives; see [`loadWasm`]. */
  glueUrl?: string
}

/** Join an existing mesh — by topic string or by id. */
export async function join(opts: JoinOpts & WasmOpts): Promise<Mesh> {
  return open(
    {
      mesh: opts.id,
      topic: opts.topic,
      nick: opts.nick,
      transport: opts.transport ?? [],
      relayUrls: opts.relayUrls ?? [],
      maxPeers: opts.maxPeers ?? 0,
      maxDirect: opts.maxDirect ?? 0,
    },
    opts,
  )
}

/** Create a new mesh. `create({})` is refused in a browser: a loopback mesh
 * is unreachable from a tab — name a lookup (`['relay']` at least). */
export async function create(opts: CreateOpts & WasmOpts): Promise<Mesh> {
  return open(
    {
      name: opts.name,
      nick: opts.nick,
      lookup: opts.lookup ?? [],
      transport: opts.transport ?? [],
      relayUrls: opts.relayUrls ?? [],
      maxPeers: opts.maxPeers ?? 0,
      maxDirect: opts.maxDirect ?? 0,
    },
    opts,
  )
}

async function open(meshOpts: Record<string, unknown>, extras: WasmOpts): Promise<Mesh> {
  const module = await loadWasm(extras.glueUrl)
  module.initTracing(extras.log ?? 'info')
  return openMesh(openWasm(module, JSON.stringify(meshOpts)))
}
