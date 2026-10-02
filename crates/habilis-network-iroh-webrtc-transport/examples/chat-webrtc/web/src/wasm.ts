import init, { ChatPeer } from '../../chat-web/dist/chat_web.js'

import { WASM_PATH } from './wasm-path.ts'

type WasmModule = { ChatPeer: typeof ChatPeer }

/**
 * The *promise* is cached, not the resolved module — and that is load-bearing.
 *
 * `__wbg_init` sets its internal `wasm` global only after its own await, so two
 * overlapping calls each build a `WebAssembly.Instance` while sharing one glue
 * module. The second instance wins the global and the first one's closures are
 * left pointing into a dead heap, which surfaces later as
 * `FnOnce called more than once`, `function signature mismatch`, or
 * `memory access out of bounds` — none of which mention loading.
 */
let loading: Promise<WasmModule> | null = null

export function loadWasm(): Promise<WasmModule> {
  if (!loading) {
    loading = init({ module_or_path: WASM_PATH }).then(() => ({ ChatPeer }))
    // A failed load must not poison every later attempt.
    loading.catch(() => {
      loading = null
    })
  }
  return loading
}
