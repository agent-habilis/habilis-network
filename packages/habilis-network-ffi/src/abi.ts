/**
 * `crates/habilis-network-ffi/include/habilis_network.h`, transcribed once.
 *
 * The vocabulary is deliberately not any one runtime's type names: `bun:ffi`,
 * `Deno.dlopen` and koffi spell the same C types three different ways, and
 * translating this table into each of them is the whole job of a loader. One
 * table means a signature can be wrong once rather than three times, and
 * `abi.test.ts` holds it against the header.
 */

export type CType =
  /** C `int`. */
  | 'i32'
  /** C `long`. 8 bytes on every target here, so it crosses as a bigint. */
  | 'isize'
  /** C `size_t`. Likewise a bigint. */
  | 'usize'
  /** C `uint32_t`. Fits a number on every runtime. */
  | 'u32'
  /** An opaque address in or out — a handle, or a returned `char *`. */
  | 'ptr'
  /** A caller-owned buffer the callee reads or writes in place. Never NULL. */
  | 'buf'
  /** A NUL-terminated string argument, or NULL. */
  | 'cstr'

export interface Signature {
  readonly args: readonly CType[]
  readonly returns: CType
}

/**
 * The ABI version this package speaks: the `HABILIS_NETWORK_ABI_VERSION` of
 * the header it was written against. A loader asks the library for
 * `habilis_network_abi_version()` right after it opens it and refuses a
 * library that answers anything else, because a struct that gained a field is
 * read at the wrong offsets with no error. `abi.test.ts` holds this equal to
 * the header's macro.
 */
export const ABI_VERSION = 1

export const ABI = {
  habilis_network_mesh_open: { args: ['ptr'], returns: 'ptr' },

  habilis_network_mesh_id: { args: ['ptr'], returns: 'ptr' },
  habilis_network_mesh_name: { args: ['ptr'], returns: 'ptr' },
  habilis_network_mesh_nickname: { args: ['ptr'], returns: 'ptr' },

  habilis_network_msg_send: { args: ['ptr', 'cstr', 'cstr'], returns: 'i32' },
  /**
   * 1 = a message is in `buf` and `out`, 0 = timeout, -1 = failure, -2 = `buf`
   * too small: the message stays queued and `out.len` says how big to retry.
   */
  habilis_network_msg_recv: { args: ['ptr', 'buf', 'usize', 'i32', 'buf'], returns: 'isize' },

  habilis_network_mesh_state_merge: { args: ['ptr', 'cstr'], returns: 'i32' },
  habilis_network_mesh_state_json: { args: ['ptr', 'buf', 'usize'], returns: 'isize' },
  habilis_network_mesh_peers_json: { args: ['ptr', 'buf', 'usize'], returns: 'isize' },
  /**
   * Bound because the header declares it, and never called: `mesh.peers` needs
   * the whole roster anyway, and this one excludes self where the roster
   * document's own `count` includes it. Calling both would be two sources of
   * truth that disagree by one.
   */
  habilis_network_mesh_peer_count: { args: ['ptr'], returns: 'isize' },

  habilis_network_mesh_close: { args: ['ptr'], returns: 'i32' },

  /**
   * Byte streams. Bound because the header declares them; the TS stream API
   * lives in `habilis-network-wasm`, so nothing here calls them yet. A `bun:ffi` or
   * Deno caller builds `habilis_network_streams_bind`'s argument with
   * `encodeStreamOpts` (`dlopen/opts-struct.ts`).
   */
  habilis_network_streams_bind: { args: ['ptr'], returns: 'ptr' },
  habilis_network_streams_bind_for: { args: ['cstr'], returns: 'ptr' },
  habilis_network_streams_close: { args: ['ptr'], returns: 'i32' },
  habilis_network_stream_create: { args: ['ptr'], returns: 'ptr' },
  habilis_network_stream_hash: { args: ['ptr'], returns: 'ptr' },
  /** 1 = written, 0 = no consumer attached in time, -1 = failure. */
  habilis_network_stream_write: { args: ['ptr', 'buf', 'usize', 'i32'], returns: 'i32' },
  habilis_network_stream_close: { args: ['ptr'], returns: 'i32' },
  habilis_network_stream_open: { args: ['ptr', 'cstr'], returns: 'ptr' },
  /** > 0 = bytes, 0 = timeout, -1 = failure, -2 = end of stream. */
  habilis_network_stream_read: { args: ['ptr', 'buf', 'usize', 'i32'], returns: 'isize' },
  habilis_network_reader_close: { args: ['ptr'], returns: 'i32' },
  /**
   * Called before every other symbol, and on its own: a library too old to
   * export it must fail with a message that says so, not with the loader's
   * "symbol not found" for whichever call came first.
   */
  habilis_network_abi_version: { args: [], returns: 'u32' },
  habilis_network_last_error: { args: [], returns: 'ptr' },
  habilis_network_version: { args: [], returns: 'ptr' },
  habilis_network_max_msg: { args: [], returns: 'usize' },
} as const satisfies Record<string, Signature>

export type SymbolName = keyof typeof ABI
