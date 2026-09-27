/**
 * The wasm-bindgen module's shape, as this package consumes it.
 *
 * Declared here rather than imported from the generated `.d.ts` because the
 * glue under `../wasm/` is a build artifact (`cargo task build-wasm`), and the
 * package must type-check before it has been built. The contract's source of
 * truth is `crates/fofoca-wasm/src/lib.rs`; change one, change the other.
 */

export interface MeshPeerHandle {
  id(): string
  nick(): string
  name(): string
  /** The longest message in bytes that always fits one frame. */
  maxMsg(): number
  /** One whole message; refused, not split, when it does not fit. `to` absent = broadcast. */
  send(to: string | undefined, text: string): Promise<void>
  /**
   * The next inbound message as JSON (`{nick, directed, text}`), or
   * `undefined` once the mesh is gone. One in-flight call at a time is the
   * intended shape; a concurrent second call waits.
   */
  nextMsg(): Promise<string | undefined>
  /** The next `MembershipEvent` as JSON, or `undefined` once the mesh is gone. */
  nextEvent(): Promise<string | undefined>
  peersJson(): Promise<string>
  peerCount(): Promise<number>
  stateJson(): Promise<string>
  /** Applies an RFC 7386 merge document; resolves with the resulting state. */
  stateMerge(patchJson: string): Promise<string>
  close(): Promise<void>
}

export interface StreamNodeHandle {
  create(): Promise<ProducerHandle>
  open(hash: string): Promise<ReaderHandle>
  close(): Promise<void>
}

export interface ProducerHandle {
  hash(): string
  attached(): Promise<void>
  write(bytes: Uint8Array): Promise<void>
  close(): Promise<void>
  abandon(): Promise<void>
}

export interface ReaderHandle {
  /** The next bytes, or `undefined` at the end of the stream. */
  read(): Promise<Uint8Array | undefined>
  close(): Promise<void>
}

export interface FofocaWasmModule {
  /** wasm-bindgen's init — must resolve before anything else is touched. */
  default(input?: unknown): Promise<unknown>
  /** Route the engine's tracing lines to the console. One-shot. */
  initTracing(filter: string): void
  MeshPeer: {
    open(optsJson: string): Promise<MeshPeerHandle>
  }
  StreamNode: {
    bind(optsJson: string): Promise<StreamNodeHandle>
    forHash(hash: string): Promise<StreamNodeHandle>
  }
}

let cached: Promise<FofocaWasmModule> | null = null

/**
 * Load and initialise the wasm module, once — the *promise* is cached, not
 * the module, so concurrent first calls share one init instead of racing
 * wasm-bindgen's one-shot `default()`.
 *
 * `glueUrl` overrides where the generated glue lives; the default expects
 * `wasm/fofoca_wasm.js` beside `src/`, which `cargo task build-wasm` produces.
 */
export function loadWasm(glueUrl?: string): Promise<FofocaWasmModule> {
  cached ??= (async () => {
    const url = glueUrl ?? new URL('../wasm/fofoca_wasm.js', import.meta.url).href
    const loaded = (await import(url)) as unknown as FofocaWasmModule
    await loaded.default()
    return loaded
  })()
  return cached
}
