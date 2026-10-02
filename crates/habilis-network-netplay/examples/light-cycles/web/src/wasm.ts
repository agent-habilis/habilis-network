import init, {
  LightCyclesPeer,
  random_nick,
  random_room_code,
} from '../wasm/dist/light_cycles_web.js'

import { WASM_PATH } from './wasm-path.ts'

type WasmModule = {
  LightCyclesPeer: typeof LightCyclesPeer
  random_room_code: typeof random_room_code
  random_nick: typeof random_nick
}

/**
 * The *promise* is cached, not the resolved module — and that is load-
 * bearing. See the chat-webrtc example's `web/src/wasm.ts` note: two
 * overlapping calls each build a `WebAssembly.Instance` while sharing one
 * glue module, and the second instance wins the glue's internal state —
 * later surfacing as `FnOnce called more than once` or a memory access
 * error, neither of which mention loading.
 */
let loading: Promise<WasmModule> | null = null

export function loadWasm(): Promise<WasmModule> {
  if (!loading) {
    loading = init({ module_or_path: WASM_PATH }).then(() => ({
      LightCyclesPeer,
      random_room_code,
      random_nick,
    }))
    // A failed load must not poison every later attempt.
    loading.catch(() => {
      loading = null
    })
  }
  return loading
}
